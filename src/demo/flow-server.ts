import 'reflect-metadata';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { announceDevMode, announceSelfSignedCertificate, ConfigError, ENV_ATTACK_ALLOW_SELF_SIGNED, ENV_ATTACK_DEV_MODE, loadConfig } from '../config.ts';
import { generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { NO_CREDENTIAL_STATUS } from '../service/credential-status.ts';
import { NO_REVOCATION } from '../onboarding/revocation.ts';
import { PID_VCT_DEFAULT } from '../service/profile.ts';
import { createApp } from '../service/app.ts';
import { AuditLog } from '../service/audit.ts';
import { MAX_BODY_BYTES } from '../service/limits.ts';
import { VerifierService, type VerifierServiceOptions } from '../service/service.ts';
import { DEV_MODE } from '../service/test-support.ts';
import { TenantStore } from '../service/tenant.ts';
import { buildDemoTestEnvironment, DEMO_SUBJECT_CN, DEMO_TENANT_ID, type DemoTestEnvironment } from './test-environment.ts';
import { DEMO_CHECKS, DEMO_CLAIMS, DEMO_SCENARIOS, isDemoScenarioId, type DemoScenarioId } from './scenarios.ts';
import { runScenario } from './scenario-runner.ts';
import { RelyingPartyOnboardingGate } from '../onboarding/onboarding-gate.ts';
import { TEST_ENTITLEMENT_MAP } from '../onboarding/mock-pki.ts';

export const FLOW_HOST = '127.0.0.1';
export const FLOW_API_KEY = 'flow-page-demo-api-key';
/** API-Schlüssel des Kurzzeit-Mandanten für das Szenario `expired_session`. */
export const FLOW_API_KEY_EXPIRING = 'flow-page-demo-api-key-expiring';
export const DEMO_TENANT_ID_EXPIRING = 'flow-demo-expired';
/** Endpunkte der Demo-Oberfläche. */
export const FLOW_SCENARIOS_PATH = '/demo/scenarios';
export const FLOW_RUN_PATH = '/demo/scenario';
const FLOW_DIR = fileURLToPath(new URL('./flow/', import.meta.url));
const ASSETS: Record<string, string> = {
  '/': 'index.html',
  '/index.html': 'index.html',
  '/status.js': 'status.js',
};
const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
};

export function isFlowApiRequest(method: string, pathname: string): boolean {
  return (method === 'POST' && pathname === '/v1/verification-requests') || (method === 'GET' && /^\/v1\/verification-requests\/[^/]+$/.test(pathname));
}

export function flowAssetPath(pathname: string): string | null {
  const asset = ASSETS[pathname];
  return asset ? join(FLOW_DIR, asset) : null;
}

class PayloadTooLargeError extends Error {}

async function readBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : (chunk as Buffer);
    total += buffer.length;
    if (total > MAX_BODY_BYTES) throw new PayloadTooLargeError();
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

function sendJson(res: http.ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(data));
}

function proxyToApi(req: http.IncomingMessage, res: http.ServerResponse, apiPort: number, apiKey: string, pathname: string): void {
  const headers: Record<string, string> = { accept: 'application/json', authorization: `Bearer ${apiKey}` };
  const body = req.method === 'POST' ? readBody(req) : Promise.resolve(undefined);
  void body
    .then((payload) => {
      if (payload) {
        const contentType = req.headers['content-type'];
        if (typeof contentType === 'string') headers['content-type'] = contentType;
        headers['content-length'] = String(payload.length);
      }
      const upstream = http.request(
        { hostname: FLOW_HOST, port: apiPort, method: req.method, path: pathname, headers },
        (response) => {
          const contentType = response.headers['content-type'];
          res.writeHead(response.statusCode ?? 502, {
            'content-type': typeof contentType === 'string' ? contentType : 'application/json; charset=utf-8',
            'cache-control': 'no-store',
          });
          response.on('error', () => res.end());
          response.pipe(res);
        },
      );
      upstream.on('error', () => {
        if (!res.headersSent) sendJson(res, 502, { error: 'upstream_unavailable' });
        else res.end();
      });
      req.on('aborted', () => upstream.destroy());
      if (payload) upstream.end(payload);
      else upstream.end();
      return undefined;
    })
    .catch((error: unknown) => {
      req.resume();
      if (res.destroyed) return;
      if (!res.headersSent) {
        if (error instanceof PayloadTooLargeError) sendJson(res, 413, { error: 'payload_too_large' });
        else sendJson(res, 400, { error: 'invalid_request' });
      } else res.end();
    });
}

export function createFlowHttpServer(options: {
  apiPort: number;
  apiKey: string;
  /**
   * Führt ein Szenario mit der Mock-Wallet aus. Läuft hier auf dem Server,
   * damit der Browser keinen API-Key sieht und jedes Szenario seinen eigenen
   * Mandanten benutzen darf.
   */
  runScenario?: (scenario: DemoScenarioId) => Promise<unknown>;
}): http.Server {
  return http.createServer((req, res) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? '/', `http://${FLOW_HOST}`);
        const asset = flowAssetPath(url.pathname);
        if (asset) {
          if (req.method !== 'GET') return sendJson(res, 404, { error: 'not_found' });
          const data = await readFile(asset);
          res.writeHead(200, { 'content-type': MIME[extname(asset)] ?? 'application/octet-stream', 'cache-control': 'no-store' });
          return res.end(data);
        }
        if (isFlowApiRequest(req.method ?? '', url.pathname)) {
          return proxyToApi(req, res, options.apiPort, options.apiKey, `${url.pathname}${url.search}`);
        }
        if (url.pathname === FLOW_SCENARIOS_PATH) {
          if (req.method !== 'GET') return sendJson(res, 405, { error: 'method_not_allowed' });
          return sendJson(res, 200, { scenarios: DEMO_SCENARIOS, checks: DEMO_CHECKS, requestedClaims: DEMO_CLAIMS });
        }
        if (url.pathname === FLOW_RUN_PATH) {
          if (req.method !== 'POST') return sendJson(res, 405, { error: 'method_not_allowed' });
          if (!options.runScenario) return sendJson(res, 501, { error: 'not_available' });
          const raw = await readBody(req);
          let scenarioId: unknown;
          try {
            scenarioId = (JSON.parse(raw.toString('utf8') || '{}') as { scenario?: unknown }).scenario;
          } catch {
            return sendJson(res, 400, { error: 'invalid_json' });
          }
          if (typeof scenarioId !== 'string' || !isDemoScenarioId(scenarioId)) {
            return sendJson(res, 400, { error: 'unknown_scenario' });
          }
          return sendJson(res, 200, await options.runScenario(scenarioId));
        }
        return sendJson(res, 404, { error: 'not_found' });
      } catch {
        if (!res.headersSent) sendJson(res, 500, { error: 'internal_error' });
        else res.end();
      }
    })();
  });
}

export interface FlowDemo {
  apiServer: http.Server;
  flowServer: http.Server;
  port: number;
  service: VerifierService;
  env: DemoTestEnvironment;
  /**
   * Basis-URL des Verifierdienstes auf 127.0.0.1. Die Mock-Wallet der Demo
   * spricht den Dienst direkt an, nicht über den Flow-Proxy: der Proxy hängt
   * einen festen API-Key an, und das Szenario `expired_session` braucht einen
   * eigenen Mandanten mit kurzem Zeitfenster.
   */
  apiBaseUrl: string;
  /**
   * Öffentlicher JWK des TEST-Verifier-Zertifikats. Er ist kein Geheimnis:
   * er steht so auch im ausgestellten Request Object. Die Demo braucht ihn,
   * um Nonce und Zielgruppe zu lesen.
   */
  verifierPublicJwk: JsonWebKey;
}

/**
 * Mandant und Schlüssel, gegen die ein Szenario läuft. Nur `expired_session`
 * braucht den Kurzzeit-Mandanten; alle anderen laufen gegen den Hauptmandanten
 * mit komfortablem Zeitfenster.
 */
export function demoScenarioTarget(scenario: DemoScenarioId): { tenantId: string; apiKey: string } {
  if (scenario === 'expired_session') return { tenantId: DEMO_TENANT_ID_EXPIRING, apiKey: FLOW_API_KEY_EXPIRING };
  return { tenantId: DEMO_TENANT_ID, apiKey: FLOW_API_KEY };
}

/**
 * Startet Verifier und Flowseite mit verdrahteter TEST-Umgebung.
 *
 * Anders als der Platzhalter-Stand vor diesem Commit schaltet die Demo die
 * Prüfpfade nicht ab: Die Trust List wird als signierte JWS geprüft, das
 * Onboarding-Gate ist das gehärtete Gate mit TEST-WRPAC/WRPRC, und die
 * Sperrprüfung ist der echte `OcspRevocationChecker` gegen den lokalen
 * TEST-Responder. Abgeschaltet bleibt nur die Credential-Statusliste
 * (Token Status List), weil es dafür kein TEST-Material gibt; die
 * Sperrprüfung der Ausstellerkette läuft trotzdem.
 */
export async function startFlowDemo(env: Record<string, string | undefined> = process.env): Promise<FlowDemo> {
  const config = loadConfig(env, 3001);
  if (!config.devMode) {
    throw new ConfigError(`Die Flow-Demo verwendet TEST-Material und startet nur mit ${ENV_ATTACK_DEV_MODE}=true. Start abgebrochen.`);
  }
  if (!config.allowSelfSignedCertificate) {
    throw new ConfigError(`Die Flow-Demo benötigt ${ENV_ATTACK_ALLOW_SELF_SIGNED}=true für ihr TEST-Verifier-Zertifikat. Start abgebrochen.`);
  }
  announceDevMode(config);
  announceSelfSignedCertificate(config);

  const tenants = new TenantStore();
  // Das Gate braucht den TenantStore, also erst die Umgebung mit dem Store
  // bauen und danach den Mandanten mit dem Registrierungsmaterial anlegen.
  const testEnv = await buildDemoTestEnvironment({});
  const requestProfile = { id: 'demo', vct: PID_VCT_DEFAULT, claims: [...DEMO_CLAIMS], credentialId: 'pid' };
  tenants.add({
    id: DEMO_TENANT_ID,
    name: `Flow-Demo ${DEMO_SUBJECT_CN}`,
    apiKey: FLOW_API_KEY,
    requestTtlSeconds: 300,
    registration: testEnv.registration,
    requestProfile,
  });
  // Zweiter Mandant mit Ein-Sekunden-Fenster, ausschließlich für das Szenario
  // `expired_session`. Damit ist der Fall echt (die Sitzung läuft ab, während
  // der Verifier sie noch kennt) und nicht simuliert (Eintrag löschen ergäbe
  // `unknown_state`, also einen anderen Fall).
  tenants.add({
    id: DEMO_TENANT_ID_EXPIRING,
    name: `Flow-Demo ${DEMO_SUBJECT_CN} (Ablauf, TEST)`,
    apiKey: FLOW_API_KEY_EXPIRING,
    requestTtlSeconds: 1,
    registration: testEnv.registration,
    requestProfile,
  });
  // Das Gate bekommt den echten TenantStore, damit `materialFor` den
  // Mandanten findet. Anker kommen aus der TEST-Umgebung.
  //
  // Für die Registrierungskette des Mandanten wird `NO_REVOCATION` genutzt,
  // weil die TEST-WRPAC/WRPRC-Kette aus mock-pki keine OCSP-Adresse trägt und
  // der Checker sonst jede Anfrage mit `revocation_source_missing` abweisen
  // würde. Die Sperrprüfung, auf die es für das Szenario `revoked_wrpac`
  // ankommt, läuft weiter über den echten `OcspRevocationChecker` in
  // `issuerRevocation` — dort wird die Kette des präsentierten Nachweises
  // geprüft, und die TEST-Aussteller tragen eine OCSP-Adresse.
  const gate = new RelyingPartyOnboardingGate({
    tenants,
    accessCaAnchors: testEnv.accessCaAnchors,
    wrprcIssuerAnchors: testEnv.wrprcIssuerAnchors,
    entitlementMap: TEST_ENTITLEMENT_MAP,
    revocation: NO_REVOCATION,
    mode: DEV_MODE,
  });

  const verifierKey = await generateTestKeyMaterial('Flow Demo Verifier TEST');
  // Alle TEST-Aussteller als Anker; die Trust List entscheidet danach, welche
  // davon als vertrauenswürdig gelten.
  const issuerAnchors = [testEnv.issuer.certDerBytes, testEnv.revokedIssuer.certDerBytes, testEnv.untrustedIssuer.certDerBytes];
  const options: VerifierServiceOptions = {
    mode: DEV_MODE,
    credentialStatus: NO_CREDENTIAL_STATUS,
    issuerRevocation: testEnv.ocspChecker,
  };
  const service = new VerifierService(
    tenants,
    new AuditLog(),
    {
      privateKey: verifierKey.privateKey,
      publicKey: verifierKey.publicKey,
      publicJwk: verifierKey.publicJwk,
      certificateChain: [verifierKey.certDerBytes],
    },
    issuerAnchors,
    undefined,
    undefined,
    testEnv.issuerTrust,
    gate,
    config.allowSelfSignedCertificate,
    options,
  );

  const apiServer = createApp({ appLabel: 'flow-demo-api', tenants, service });
  await new Promise<void>((resolve) => apiServer.listen(0, FLOW_HOST, resolve));
  const apiPort = (apiServer.address() as { port: number }).port;
  service.baseUrl = `http://${FLOW_HOST}:${apiPort}`;

  // Die Mock-Wallet läuft hier auf dem Server, nicht im Browser. Grund: der
  // Browser soll keinen API-Key sehen, und das Szenario `expired_session`
  // braucht einen eigenen Mandanten mit einem Sekunden-Zeitfenster, während
  // der Flow-Proxy aus genau einem Grund einen festen Schlüssel setzt.
  const runDemoScenario = async (scenario: DemoScenarioId) => {
    const target = demoScenarioTarget(scenario);
    return runScenario({
      env: testEnv,
      service,
      apiKey: target.apiKey,
      tenantId: target.tenantId,
      verifierPublicJwk: verifierKey.publicJwk,
      scenario,
      baseUrl: service.baseUrl,
    });
  };

  const flowServer = createFlowHttpServer({
    apiPort,
    apiKey: FLOW_API_KEY,
    runScenario: runDemoScenario,
  });
  await new Promise<void>((resolve) => flowServer.listen(config.port, FLOW_HOST, resolve));
  return {
    apiServer,
    flowServer,
    port: config.port,
    service,
    env: testEnv,
    apiBaseUrl: service.baseUrl,
    verifierPublicJwk: verifierKey.publicJwk,
  };
}
