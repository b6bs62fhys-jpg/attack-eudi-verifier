/**
 * Dünne HTTP-Schicht für den Verifier-Dienst (Prototyp, 127.0.0.1).
 *
 * Routes:
 *   POST /v1/verification-requests                  [API-Key] Prüfanfrage erzeugen
 *   GET  /v1/verification-requests/:id/request-object           Request Object für die Wallet
 *   GET  /v1/verification-requests/:id               [API-Key] Ergebnis abfragen
 *   DELETE /v1/verification-requests/:id             [API-Key] Sitzung löschen
 *   POST /direct_post                                         Presentation annehmen (Wallet)
 *
 * Authentifizierung: Bearer <API-Key> (nur Hash wird gespeichert). Mandanten
 * sind strikt getrennt: jede Abfrage läuft über den aus dem API-Key abgeleiteten
 * Mandanten. Eingaben werden validiert.
 */
import http from 'node:http';

import { VerifierService } from './service.ts';
import { hashApiKey, TenantStore, type TenantConfig } from './tenant.ts';
import { ErrTenantNotRegistered, ErrTenantRegistrationInvalid, OnboardingError } from '../onboarding/errors.ts';
import { MAX_BODY_BYTES, ServiceInputError } from './limits.ts';
import type { RegistrationRef } from '../onboarding/registration-ref.ts';
import { logger } from '../lib/logger.ts';
import { ServiceMetrics, type ReadinessSnapshot } from './metrics.ts';
import { DEFAULT_PUBLIC_RATE_LIMIT, DEFAULT_TENANT_RATE_LIMIT, RateLimiter } from './rate-limit.ts';

export interface AppDeps {
  appLabel: string;
  tenants: TenantStore;
  service: VerifierService;
  metrics?: ServiceMetrics;
  readiness?: () => ReadinessSnapshot;
  rateLimiter?: RateLimiter;
  rateLimits?: { publicPerWindow?: number; tenantPerWindow?: number };
}

function bearerToken(req: http.IncomingMessage): string | null {
  const header = req.headers.authorization ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1] : null;
}

function sendJson(res: http.ServerResponse, status: number, data?: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(data === undefined ? undefined : JSON.stringify(data));
}

class PayloadTooLargeError extends Error {
  constructor() {
    super('payload_too_large');
    this.name = 'PayloadTooLargeError';
  }
}

/** Liest den Körper mit harter Byte-Grenze (zählt beim Lesen, bricht sofort ab). */
async function readBody(req: http.IncomingMessage, maxBytes = MAX_BODY_BYTES): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = typeof chunk === 'string' ? Buffer.from(chunk) : (chunk as Buffer);
    total += buf.length;
    if (total > maxBytes) throw new PayloadTooLargeError();
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function sendTooLarge(req: http.IncomingMessage, res: http.ServerResponse): void {
  res.writeHead(413, { 'content-type': 'application/json; charset=utf-8', connection: 'close' });
  res.end(JSON.stringify({ error: 'payload_too_large' }));
  // Restlichen Körper verwerfen, ohne ihn zu puffern.
  req.resume();
}

type DirectPostBody =
  | { kind: 'envelope'; vpToken: Record<string, Array<string | object>>; state: string }
  | { kind: 'jwe'; jwe: string }
  | { kind: 'error'; error: string };

/** Form-Post (application/x-www-form-urlencoded): response=<JWE> oder vp_token/state. */
function parseFormDirectPost(raw: string): DirectPostBody {
  const params = new URLSearchParams(raw);
  const response = params.get('response');
  if (response !== null && response.length > 0) return { kind: 'jwe', jwe: response };
  const state = params.get('state');
  const vpToken = params.get('vp_token');
  if (state === null || vpToken === null || state.length === 0 || vpToken.length === 0) {
    return { kind: 'error', error: 'invalid_request' };
  }
  return { kind: 'envelope', vpToken: coerceFormVpToken(vpToken), state };
}

/**
 * Interop-Shim (TEST): Bei single-credential DCQL-Posts senden Wallets
 * `vp_token` im Formular als JSON-Objekt (DCQL-Envelope), als JSON-Array oder
 * als rohen SD-JWT-String. Der Dienst erzeugt selbst ausschließlich die
 * credential id `pid`; deshalb werden Array und roher String deterministisch
 * in den DCQL-Envelope `{ pid: [...] }` gewickelt. Ein JSON-Objekt wird
 * unverändert übernommen.
 */
function coerceFormVpToken(value: string): Record<string, Array<string | object>> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    parsed = value;
  }
  if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
    return parsed as Record<string, Array<string | object>>;
  }
  return { pid: (Array.isArray(parsed) ? parsed : [parsed]) as Array<string | object> };
}

function parseJsonDirectPost(raw: string): DirectPostBody {
  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    return { kind: 'error', error: 'invalid_request' };
  }
  if (typeof decoded === 'object' && decoded !== null) {
    const d = decoded as Record<string, unknown>;
    if (typeof d.response === 'string' && d.response.length > 0) return { kind: 'jwe', jwe: d.response };
    if (typeof d.state === 'string' && typeof d.vp_token === 'object' && d.vp_token !== null) {
      return { kind: 'envelope', vpToken: d.vp_token as Record<string, Array<string | object>>, state: d.state };
    }
  }
  return { kind: 'error', error: 'invalid_request' };
}

/** Zugriffsart einer Route. `tenant` verlangt einen gültigen API-Schlüssel. */
export type RouteAccess = 'public' | 'tenant';

export interface RouteContext {
  req: http.IncomingMessage;
  res: http.ServerResponse;
  deps: AppDeps;
  params: Record<string, string>;
  /** Nur bei `access: 'tenant'` gesetzt. */
  tenant?: TenantConfig;
}

export interface RouteDef {
  method: 'GET' | 'POST' | 'DELETE';
  /** Pfadmuster, Parameter mit `:name` (genau ein Segment). */
  path: string;
  access: RouteAccess;
  /**
   * Mandanten-Ressource hinter dem Pfadparameter. `session`: gehört genau
   * einem Mandanten; ein fremder Mandant erhält 404 (wie „nie vorhanden").
   */
  resource: 'session' | 'none';
  handle(ctx: RouteContext): Promise<void> | void;
}

/** Einheitliche 404-Antwort: fremder Mandant, gelöscht, verbraucht und unbekannt sind nicht unterscheidbar. */
const NOT_FOUND = { error: 'not_found' };

function clientIdentity(req: http.IncomingMessage, apiKey: string | null): string {
  return apiKey ? `api:${hashApiKey(apiKey)}` : `ip:${req.socket.remoteAddress ?? 'unknown'}`;
}

function rateLimitResponse(res: http.ServerResponse, result: { limit: number; remaining: number; retryAfterSeconds: number }): void {
  res.writeHead(429, {
    'content-type': 'application/json; charset=utf-8',
    'x-ratelimit-limit': String(result.limit),
    'x-ratelimit-remaining': String(result.remaining),
    'retry-after': String(result.retryAfterSeconds),
  });
  res.end(JSON.stringify({ error: 'rate_limited' }));
}

function shouldRateLimit(route: RouteDef | undefined): boolean {
  return route !== undefined && !['/live', '/health', '/ready', '/metrics'].includes(route.path);
}

/**
 * Alle Routen des Dienstes. Die Mandanten-Testmatrix liest diese Tabelle
 * automatisch aus (src/service/mandanten-matrix.test.ts). Neue Routen sind
 * standardmäßig nur mit API-Schlüssel erreichbar; öffentliche Routen müssen
 * dort ausdrücklich freigegeben sein.
 */
export const ROUTES: readonly RouteDef[] = [
  {
    // Liveness is deliberately independent of external dependencies.
    method: 'GET',
    path: '/live',
    access: 'public',
    resource: 'none',
    handle: ({ res, deps }) => sendJson(res, 200, { ok: true, status: 'live', app: deps.appLabel }),
  },
  {
    method: 'GET',
    path: '/health',
    access: 'public',
    resource: 'none',
    handle: ({ res, deps }) => sendJson(res, 200, { ok: true, status: 'live', app: deps.appLabel }),
  },
  {
    method: 'GET',
    path: '/ready',
    access: 'public',
    resource: 'none',
    handle: ({ res, deps }) => {
      const readiness = deps.readiness?.() ?? { ready: true, checks: { service: 'ok' as const } };
      return sendJson(res, readiness.ready ? 200 : 503, { ok: readiness.ready, status: readiness.ready ? 'ready' : 'not_ready', checks: readiness.checks });
    },
  },
  {
    method: 'GET',
    path: '/metrics',
    access: 'public',
    resource: 'none',
    handle: ({ res, deps }) => {
      res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4; charset=utf-8' });
      res.end(deps.metrics?.toPrometheus() ?? '');
    },
  },
  {
    // Request Object hosten (öffentlich, wird von der Wallet abgerufen)
    method: 'GET',
    path: '/v1/verification-requests/:id/request-object',
    access: 'public',
    resource: 'session',
    handle: ({ res, deps, params }) => {
      const requestObject = deps.service.getRequestObject(params.id);
      if (!requestObject) return sendJson(res, 404, NOT_FOUND);
      res.writeHead(200, { 'content-type': 'application/oauth-authz-req+jwt' });
      res.end(requestObject);
    },
  },
  {
    // Präsentation annehmen (öffentlich, kommt von der Wallet).
    // Eingabeformate: application/json (Envelope) und
    // application/x-www-form-urlencoded (Envelope-Felder oder response=<JWE>
    // für direct_post.jwt). JWE wird ausschließlich über die Bibliothek
    // entschlüsselt (kein eigener Krypto-Bau, RFC 7516 über @openeudi/openid4vp).
    method: 'POST',
    path: '/direct_post',
    access: 'public',
    resource: 'none',
    handle: async ({ req, res, deps }) => {
      const contentType = (req.headers['content-type'] ?? '').toLowerCase();
      const raw = await readBody(req);
      const parsed = contentType.includes('application/x-www-form-urlencoded') ? parseFormDirectPost(raw) : parseJsonDirectPost(raw);
      if (parsed.kind === 'error') return sendJson(res, 400, { error: parsed.error });
      const outcome =
        parsed.kind === 'jwe'
          ? await deps.service.handleEncryptedPresentation(parsed.jwe)
          : await deps.service.handlePresentation(parsed.state, parsed.vpToken);
      // 422 und nicht 401: die Route ist öffentlich, es gab also nie etwas zu
      // authentifizieren. 401 bleibt exklusiv für fehlenden oder unbekannten
      // API-Schlüssel reserviert, sonst kann ein Client nicht mehr unterscheiden,
      // ob er sich anmelden oder seine Präsentation korrigieren muss.
      // Betroffen sind die Präsentationen, die der Dienst nicht verarbeiten
      // konnte (`ok: false`) und die deshalb 422 tragen: unknown_state,
      // state_invalid, vp_token_invalid, Replay und die JWE-Fehlerpfade.
      // Davon zu unterscheiden sind die inhaltlich abgelehnten Präsentationen
      // (falscher Aussteller, fehlender Claim, abgelaufen). Die wurden
      // verarbeitet und liefern deshalb 200 mit `valid: false` und dem
      // Ablehnungsgrund in `error` — 422 würde dort etwas Falsches sagen.
      return sendJson(res, outcome.ok ? 200 : 422, outcome);
    },
  },
  {
    method: 'POST',
    path: '/v1/verification-requests',
    access: 'tenant',
    resource: 'none',
    handle: async ({ req, res, deps, tenant }) => {
      let input: Record<string, unknown> = {};
      try {
        const raw = await readBody(req);
        if (raw.trim()) input = JSON.parse(raw) as Record<string, unknown>;
      } catch (e) {
        if (e instanceof PayloadTooLargeError) throw e;
        return sendJson(res, 400, { error: 'invalid_json' });
      }
      if (typeof input !== 'object' || input === null || Array.isArray(input)) return sendJson(res, 400, { error: 'invalid_json' });
      try {
        const out = await deps.service.createRequest((tenant as TenantConfig).id, {
          claims: input.claims as string[] | undefined,
          vct: input.vct as string | undefined,
          registrationRef: input.registration_ref as RegistrationRef | undefined,
        });
        return sendJson(res, 201, out);
      } catch (e) {
        if (e instanceof ErrTenantNotRegistered || e instanceof ErrTenantRegistrationInvalid) {
          deps.metrics?.recordOnboardingRejection(e.code);
          return sendJson(res, 403, { error: e.code });
        }
        if (e instanceof ServiceInputError || e instanceof OnboardingError) {
          // Feste Codes (claims_invalid, vct_invalid, registration_ref_invalid,
          // registration_ref_mismatch); niemals e.message.
          return sendJson(res, 400, { error: e.code });
        }
        throw e;
      }
    },
  },
  {
    method: 'GET',
    path: '/v1/verification-requests/:id',
    access: 'tenant',
    resource: 'session',
    handle: ({ res, deps, params, tenant }) => {
      const status = deps.service.getResult((tenant as TenantConfig).id, params.id);
      if (status.status === 'not_found') return sendJson(res, 404, NOT_FOUND);
      return sendJson(res, 200, status);
    },
  },
  {
    method: 'DELETE',
    path: '/v1/verification-requests/:id',
    access: 'tenant',
    resource: 'session',
    handle: ({ res, deps, params, tenant }) => {
      const deleted = deps.service.expireRequest((tenant as TenantConfig).id, params.id);
      if (!deleted) return sendJson(res, 404, NOT_FOUND);
      return sendJson(res, 204);
    },
  },
];

/** Pfad gegen ein Muster prüfen; liefert Parameter oder `undefined`. */
export function matchPath(pattern: string, pathname: string): Record<string, string> | undefined {
  const want = pattern.split('/').filter(Boolean);
  const got = pathname.split('/').filter(Boolean);
  if (want.length !== got.length) return undefined;
  const params: Record<string, string> = {};
  for (let i = 0; i < want.length; i += 1) {
    if (want[i].startsWith(':')) params[want[i].slice(1)] = got[i];
    else if (want[i] !== got[i]) return undefined;
  }
  return params;
}

/**
 * Sicherheits-Header, die auf **jeder** Antwort des Dienstes stehen.
 *
 * Bewusst an einer Stelle und nicht pro Route: eine Route, die ihre eigenen
 * Header schreibt, darf die Basis nicht verlieren. Die Header werden gesetzt,
 * bevor irgendein `writeHead` läuft, und deshalb nicht überschrieben.
 *
 * Begründung je Header, inklusive der bewusst weggelassenen:
 *
 * - `x-content-type-options: nosniff` ist der wichtigste hier. Der Dienst
 *   liefert neben JSON auch `application/oauth-authz-req+jwt` und Prometheus-
 *   Text aus. Ohne nosniff darf ein Browser den Inhalt als HTML deuten. Das
 *   Request Object ist zudem Wallet-beeinflusst, seine Bytes sind also nicht
 *  trivialer Herkunft.
 * - `cache-control: no-store` verhindert, dass ein Zwischenproxy eine
 *   Sitzung, ein Ergebnis oder ein Request Object zwischenspeichert. Ohne
 *   diese Angabe darf eine Antwort eines autorisierten Aufrufs in einem
 *   gemeinsamen Cache landen.
 * - `x-frame-options: deny` verhindert, dass eine Antwort in einen Frame
 *   gesetzt wird. Das Request Object ist Text und damit darstellbar.
 *
 * Bewusst **nicht** gesetzt:
 *
 * - `strict-transport-security` wäre auf einer reinen HTTP-Verbindung ohne
 *   Wirkung und vor dem TLS-Abschluss sogar schädlich, weil die Regel nur über
 *   HTTPS gilt. Der Dienst spricht HTTP; HSTS gehört an den TLS-Abschluss des
 *   Reverse Proxy, siehe docs/deployment.md.
 * - `content-security-policy` wirkt nur auf Dokumentantworten. Der Dienst
 *   liefert keine HTML-Dokumente aus; ein `default-src 'none'` hier wäre eine
 *   Überschrift ohne Wirkung.
 * - `referrer-policy` steuert das Verhalten bei Navigation und für
 *   Unterressourcen; für eine API, die nicht navigiert wird, ist sie Wirkung
 *   mit Namen. Sinnvoll gesetzt wird sie dort, wo es zählt.
 * - `access-control-allow-origin` fehlt absichtlich. Der Dienst wird von
 *   Servern und nativen Wallets aufgerufen, nicht von fremden Browserherkünften.
 *   Ohne CORS-Header greift die Same-Origin-Policy des Browsers vollständig,
 *   und ein Preflight auf eine unbekannte Methode wird wie jeder unbekannte
 *   Pfad mit 401 beantwortet, ohne die Existenz von Routen preiszugeben.
 */
function setzeSicherheitsHeader(res: http.ServerResponse): void {
  res.setHeader('x-content-type-options', 'nosniff');
  res.setHeader('cache-control', 'no-store');
  res.setHeader('x-frame-options', 'DENY');
}

export function createApp(deps: AppDeps): http.Server {
  const { tenants } = deps;
  const runtimeDeps: AppDeps = {
    ...deps,
    metrics: deps.metrics ?? new ServiceMetrics(),
    rateLimiter: deps.rateLimiter ?? new RateLimiter(),
  };

  return http.createServer((req, res) => {
    setzeSicherheitsHeader(res);
    const url = new URL(req.url ?? '/', 'http://localhost');
    const startedAt = performance.now();
    let route: RouteDef | undefined;
    void (async () => {
      try {
        // Größengrenze auf allen Endpunkten, vor Authentifizierung und Routing.
        const declared = Number(req.headers['content-length'] ?? '0');
        if (!Number.isFinite(declared) || declared > MAX_BODY_BYTES) return sendTooLarge(req, res);

        let params: Record<string, string> = {};
        for (const candidate of ROUTES) {
          if (candidate.method !== req.method) continue;
          const matched = matchPath(candidate.path, url.pathname);
          if (matched) {
            route = candidate;
            params = matched;
            break;
          }
        }

        const publicApiKey = bearerToken(req);
        if (route?.access === 'public') {
          if (shouldRateLimit(route)) {
            const limit = runtimeDeps.rateLimits?.publicPerWindow ?? DEFAULT_PUBLIC_RATE_LIMIT;
            const result = runtimeDeps.rateLimiter?.consume(`${route.path}|${clientIdentity(req, publicApiKey)}|public`, limit);
            if (result && !result.allowed) return rateLimitResponse(res, result);
          }
          return await route.handle({ req, res, deps: runtimeDeps, params });
        }

        // Ab hier: Authentifizierung erforderlich (auch für unbekannte Pfade,
        // damit ohne Schlüssel nicht erkennbar ist, welche Routen existieren).
        const apiKey = bearerToken(req);
        const tenant = apiKey ? tenants.byApiKey(apiKey) : undefined;
        if (!tenant) return sendJson(res, 401, { error: 'unauthorized' });

        if (!route) return sendJson(res, 404, NOT_FOUND);
        if (shouldRateLimit(route)) {
          const limit = runtimeDeps.rateLimits?.tenantPerWindow ?? DEFAULT_TENANT_RATE_LIMIT;
          const result = runtimeDeps.rateLimiter?.consume(`${route.path}|${clientIdentity(req, apiKey)}|tenant`, limit);
          if (result && !result.allowed) return rateLimitResponse(res, result);
        }
        return await route.handle({ req, res, deps: runtimeDeps, params, tenant });
      } catch (e) {
        if (e instanceof PayloadTooLargeError) return sendTooLarge(req, res);
        // Nur stabile Felder loggen, niemals Rohmeldungen oder Eingabewerte.
        logger.error('http_request_failed', { method: req.method ?? 'UNKNOWN', route: route?.path ?? 'unmatched', error_type: e instanceof Error ? e.name : typeof e });
        if (!res.headersSent) sendJson(res, 500, { error: 'internal_error' });
        else res.end();
      } finally {
        runtimeDeps.metrics?.recordHttpRequest(req.method ?? 'UNKNOWN', route?.path ?? 'unmatched', res.statusCode || 500, performance.now() - startedAt);
      }
    })();
  });
}
