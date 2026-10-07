/**
 * Schritt 2: Lauffähige lokale Demo des Attack-Verifiers.
 *
 * Start:  npm run demo
 *
 * Der lokale HTTP-Server (127.0.0.1) trägt zwei Rollen im selben Prozess:
 *   Verifier  – hält Sitzungen, hostet das signierte Request Object unter
 *               requestUri und validiert Präsentationen unter `/direct_post`
 *   Mock-Wallet – ruft die Request-URI ab, prüft die Signatur, baut eine
 *               SD-JWT-VC aus TEST-Material im Arbeitsspeicher (PID, given_name)
 *               und POSTet sie an response_uri (direct_post, JSON)
 *
 * Den Ablauf starten per «POST /demo/run» oder im Browser. Ergebnis landet im
 * flüchtigen Zustand, nichts wird persistiert. Alle Schlüssel im Speicher,
 * keine echten Daten, keine privaten Inhalte in Logs.
 *
 * Testmaterial (fail closed): Die Demo ist ein lokales Entwicklungs-/
 * Vorführwerkzeug mit TEST-Aussteller und Mock-Wallet. Sie startet NUR mit
 * ATTACK_DEV_MODE=true (ausdrücklicher Entwicklungsschalter) außerhalb von
 * Produktion; sonst wird der Start mit klarer Meldung abgebrochen.
 */
import http from 'node:http';
import { decodeProtectedHeader, jwtVerify, createLocalJWKSet } from 'jose';

import {
  buildHaipQuery,
  createSignedAuthorizationRequest,
  verifyAuthorizationResponse,
} from '@openeudi/openid4vp';

import { VpSessionStore } from '../lib/session.ts';
import { buildSdJwtVc, generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { announceDevMode, announceSelfSignedCertificate, ConfigError, ENV_ATTACK_DEV_MODE, loadConfig, startupFailureMessage, type AppConfig } from '../config.ts';
import { resolveVerifierIdentity } from '../service/verifier-identity.ts';
import { MAX_BODY_BYTES, presentationErrorCode } from '../service/limits.ts';

const PID_VCT = 'urn:eu.europa.ec.eudi:pid:1';
/** Angefragte PID-Claims der Demo. */
const DEMO_CLAIMS = ['given_name', 'family_name', 'birthdate', 'address'];
/** TEST-Werte der Mock-Wallet (erfunden, keine echte Person). */
const DEMO_VALUES: Record<string, unknown> = {
  family_name: 'Mustermann-TEST',
  birthdate: '1984-01-26',
  address: { street_address: 'Heidestraße 17', locality: 'Köln', postal_code: '51147', country: 'DE' },
};

/** Abbruch beim Start: klare Meldung, kein Stacktrace, Exit-Code 1. */
function abortStart(e: unknown): never {
  console.error(startupFailureMessage(e));
  process.exit(1);
}

let config: AppConfig;
try {
  config = loadConfig(process.env, 3000);
  // Die Demo erzeugt TEST-Aussteller, TEST-Anker und eine Mock-Wallet:
  // Testmaterial nur mit Entwicklungsschalter (Haertung 5).
  if (!config.devMode) {
    throw new ConfigError(
      `Die Demo verwendet TEST-Aussteller und Mock-Wallet und startet nur mit ${ENV_ATTACK_DEV_MODE}=true (niemals in Produktion). Start abgebrochen.`,
    );
  }
} catch (e) {
  abortStart(e);
}
announceDevMode(config);
announceSelfSignedCertificate(config);
const PORT = config.port;
const HOST = '127.0.0.1';

interface DemoContext {
  verifierKey: TestKeyMaterial;
  issuerKey: TestKeyMaterial;
  holderKey: TestKeyMaterial;
  sessions: VpSessionStore;
  servedRequestObject: string;
  pendingByState: Map<string, { nonce: string; audience: string }>;
  lastRun?: { at: string; valid: boolean; claims: unknown; issuerCountry: string; error: string };
  runCount: number;
}

async function mockWalletPresent(ctx: DemoContext): Promise<void> {
  // 1) Request-URI abrufen
  const requestObj = await fetch(`http://${HOST}:${PORT}/openid4vp/sd.jwt`).then((r) => r.text());
  const { alg } = decodeProtectedHeader(requestObj);
  if (alg !== 'ES256') throw new Error('Mock-Wallet: unerwartetes Signierverfahren im Request Object');
  // 2) Signatur des Request Objects prüfen (Mock-Wallet erkennt den Demo-Verifier)
  const walletKeys = createLocalJWKSet({ keys: [ctx.verifierKey.publicJwk] });
  const { payload } = await jwtVerify(requestObj, walletKeys);
  if (typeof payload.nonce !== 'string' || typeof payload.response_uri !== 'string' || typeof payload.client_id !== 'string') {
    throw new Error('Mock-Wallet: Request Object ohne nonce/response_uri/client_id');
  }
  // 3) Präsentation bauen und an response_uri POSTen (direct_post, JSON)
  const built = await buildSdJwtVc({
    issuerKey: ctx.issuerKey,
    holderKey: ctx.holderKey,
    claimName: 'given_name',
    claimValue: 'Erika',
    additionalDisclosures: DEMO_VALUES,
    nonce: payload.nonce,
    audience: payload.client_id,
  });
  const post = await fetch(payload.response_uri, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ vp_token: { pid: [built.sdJwt] }, state: payload.state }),
  });
  if (!post.ok) throw new Error(`Mock-Wallet: Verifier meldet HTTP ${post.status}`);
}

async function startNewRun(ctx: DemoContext): Promise<void> {
  // Verifier-Seite: Sitzung + signiertes Request Object mit DCQL
  const session = ctx.sessions.create({
    audience: 'placeholder',
    clientId: 'placeholder',
    responseUri: `http://${HOST}:${PORT}/direct_post`,
  });
  const requestUri = `http://${HOST}:${PORT}/openid4vp/sd.jwt`;

  const signed = await createSignedAuthorizationRequest(
    {
      clientIdPrefix: 'x509_hash',
      requestUri,
      responseUri: session.responseUri,
      nonce: session.nonce,
      state: session.id,
      responseMode: 'direct_post',
      signer: { privateKey: ctx.verifierKey.privateKey, publicKey: ctx.verifierKey.publicKey },
      signingAlgorithm: 'ES256',
      certificateChain: [ctx.verifierKey.certDerBytes],
      allowSelfSignedCertificate: config.allowSelfSignedCertificate,
      vpFormatsSupported: { 'dc+sd-jwt': { sd_jwt_alg_values: ['ES256'], kb_jwt_alg_values: ['ES256'] } },
    },
    buildHaipQuery({ credentialId: 'pid', format: 'dc+sd-jwt', vctValues: [PID_VCT], claims: DEMO_CLAIMS }),
  );

  const { payload } = await jwtVerify(signed.requestObject, createLocalJWKSet({ keys: [ctx.verifierKey.publicJwk] }));
  const audience = typeof payload.client_id === 'string' ? payload.client_id : '';

  ctx.servedRequestObject = signed.requestObject;
  ctx.pendingByState.set(session.id, { nonce: session.nonce, audience });
  ctx.runCount += 1;
}

async function buildVerifierMaterial(): Promise<TestKeyMaterial> {
  const { keys, usedTestFallback } = await resolveVerifierIdentity(config, async () => {
    const t = await generateTestKeyMaterial('Demo Verifier');
    return { privateKey: t.privateKey, publicKey: t.publicKey, publicJwk: t.publicJwk, certificateChain: [t.certDerBytes] };
  });
  if (usedTestFallback) {
    console.warn('!!! Verifier-Identität: TEST-MATERIAL wird verwendet (ATTACK_DEV_MODE aktiv). !!!');
  }
  const leaf = keys.certificateChain[0];
  return {
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    publicJwk: keys.publicJwk,
    x5cBase64: Buffer.from(leaf).toString('base64'),
    certDerBytes: leaf,
  };
}

async function buildDemoContext(): Promise<DemoContext> {
  return {
    verifierKey: await buildVerifierMaterial(),
    issuerKey: await generateTestKeyMaterial('Demo Issuer'),
    holderKey: await generateTestKeyMaterial('Demo Holder'),
    sessions: new VpSessionStore(),
    servedRequestObject: '',
    pendingByState: new Map(),
    runCount: 0,
  };
}

function escapeHtml(value: unknown): string {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);
}

function sendJson(res: http.ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

let ctx: DemoContext;
try {
  ctx = await buildDemoContext();
} catch (e) {
  abortStart(e);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://${HOST}:${PORT}`);
  void (async () => {
    try {
      if (req.method === 'GET' && url.pathname === '/health') return sendJson(res, 200, { ok: true });

      if (req.method === 'GET' && url.pathname === '/openid4vp/sd.jwt') {
        if (!ctx.servedRequestObject) return sendJson(res, 404, { error: 'not_found' });
        res.writeHead(200, { 'content-type': 'application/oauth-authz-req+jwt' });
        return res.end(ctx.servedRequestObject);
      }

      if (req.method === 'POST' && url.pathname === '/direct_post') {
        let raw = '';
        let size = 0;
        for await (const chunk of req) {
          size += (chunk as Buffer).length;
          if (size > MAX_BODY_BYTES) return sendJson(res, 413, { error: 'payload_too_large' });
          raw += chunk;
        }
        let parsed: { vp_token?: Record<string, Array<string | object>>; state?: string };
        try {
          parsed = JSON.parse(raw);
        } catch {
          return sendJson(res, 400, { error: 'invalid_json' });
        }
        if (typeof parsed.state !== 'string') return sendJson(res, 400, { error: 'invalid_request' });
        const pending = ctx.pendingByState.get(parsed.state);
        if (!pending) return sendJson(res, 404, { error: 'not_found' });

        const claimed = ctx.sessions.consume(parsed.state);
        // 422 wie in der Haupt-API: die Route ist öffentlich, es gab nichts zu
        // authentifizieren. 401 bleibt dort exklusiv für den API-Schlüssel.
        if (!('session' in claimed)) return sendJson(res, 422, { error: claimed.reason });

        let valid = false;
        let claims: unknown;
        let issuerCountry = '';
        let error = '';
        try {
          const ver = await verifyAuthorizationResponse(
            { vp_token: parsed.vp_token ?? {}, state: parsed.state },
            buildHaipQuery({ credentialId: 'pid', format: 'dc+sd-jwt', vctValues: [PID_VCT], claims: DEMO_CLAIMS }),
            { trustedCertificates: [ctx.issuerKey.certDerBytes], nonce: pending.nonce, audience: pending.audience },
          );
          valid = ver.valid;
          claims = ver.parsed.claims;
          issuerCountry = ver.parsed.issuer.country;
          // Freitext der Bibliothek geht nie nach außen.
          error = valid ? '' : 'presentation_invalid';
        } catch (e) {
          valid = false;
          error = presentationErrorCode(e);
        }
        ctx.lastRun = { at: new Date().toISOString(), valid, claims, issuerCountry, error };
        if (valid) ctx.pendingByState.delete(parsed.state);
        return sendJson(res, 200, { direct_post: 'ok', valid, error });
      }

      if (req.method === 'POST' && url.pathname === '/demo/run') {
        await startNewRun(ctx);
        await mockWalletPresent(ctx);
        return sendJson(res, 200, ctx.lastRun ?? { error: 'kein Ergebnis' });
      }

      if (req.method === 'GET' && url.pathname === '/') {
        const last = ctx.lastRun
          ? `<section class="run"><h2>Letzter Durchlauf</h2><dl>
              <dt>Zeitpunkt</dt><dd>${escapeHtml(ctx.lastRun.at)}</dd>
              <dt>Gültig</dt><dd>${ctx.lastRun.valid ? 'ja' : 'nein'}</dd>
              <dt>Claims</dt><dd><pre>${escapeHtml(JSON.stringify(ctx.lastRun.claims, null, 2))}</pre></dd>
              <dt>Aussteller-Land</dt><dd>${escapeHtml(ctx.lastRun.issuerCountry)}</dd>
              ${ctx.lastRun.error ? `<dt>Fehler</dt><dd>${escapeHtml(ctx.lastRun.error)}</dd>` : ''}
            </dl></section>`
          : '<p>Noch kein Lauf.</p>';
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        return res.end(`<!doctype html><html lang="de"><head><meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Attack Demo</title>
          <style>
            body{font:16px/1.5 system-ui,sans-serif;margin:0;padding:16px;max-width:640px;background:#f7f7f5;color:#222}
            h1{font-size:1.4em;margin:.4em 0} h2{font-size:1.1em;margin:.8em 0 .4em}
            button{font-size:1em;padding:.7em 1.2em;border-radius:8px;border:0;background:#0b57d0;color:#fff}
            pre{white-space:pre-wrap;word-break:break-word;background:#fff;border:1px solid #ddd;border-radius:6px;padding:8px}
            dl{display:grid;grid-template-columns:auto 1fr;gap:.3em .8em} dt{font-weight:600} dd{margin:0}
          </style></head>
          <body><main>
            <h1>Attack Verifier Demo</h1>
            <p>Läufe: ${ctx.runCount} · nur Testmaterial, nur lokal (127.0.0.1).</p>
            ${last}
            <form action="/demo/run" method="post"><button type="submit">Neuen Durchlauf starten</button></form>
          </main></body></html>`);
      }

      return sendJson(res, 404, { error: 'not_found' });
    } catch (e) {
      console.error(`Demo: interner Fehler (${e instanceof Error ? e.name : typeof e})`);
      if (!res.headersSent) sendJson(res, 500, { error: 'internal_error' });
    }
  })();
});

server.listen(PORT, HOST, () => {
  console.log(`Attack Demo läuft auf http://${HOST}:${PORT}`);
  console.log('Enter drücken für den ersten Durchlauf (oder im Browser POST /demo/run).');
  process.stdin.resume();
  process.stdin.setEncoding('utf8');
  let started = false;
  process.stdin.on('data', async () => {
    if (started) return;
    started = true;
    try {
      await startNewRun(ctx);
      await mockWalletPresent(ctx);
      // Nur Claim-NAMEN ins Log, nie Werte (Haertung 6).
      const names = Object.keys((ctx.lastRun?.claims ?? {}) as Record<string, unknown>).sort();
      console.log(`DURCHLAUF 1: valid=${ctx.lastRun?.valid}, freigegebene Claims=${names.join(',')}, Issuer-Land=${ctx.lastRun?.issuerCountry}`);
      if (ctx.lastRun?.valid) console.log('  Präsentation akzeptiert (TEST-Material, nur lokal, 127.0.0.1).');
      else console.log(`  abgelehnt: ${ctx.lastRun?.error}`);
      console.log(`Browser: http://${HOST}:${PORT} – POST /demo/run macht weitere Durchläufe.`);
    } catch (e) {
      console.error(`Demo-Fehler (${e instanceof Error ? e.name : typeof e})`);
    }
  });
});