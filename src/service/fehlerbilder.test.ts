/**
 * Härtung 6: Eingabegrenzen und Fehlerbilder.
 *
 *   a) Größengrenze auf ALLEN Endpunkten (automatisch aus ROUTES), mit
 *      Content-Length und gestreamt (chunked); Gegenprobe knapp unter der Grenze
 *   b) Obergrenzen für Disclosures, Tokenlänge, state, JWE, claims, vct
 *   c) Für jeden Fehlercode: Antwort ist ein fester, dokumentierter Code, ohne
 *      Stacktrace, internen Pfad oder Rohmeldung aus Bibliotheken
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import http from 'node:http';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';
import { createLocalJWKSet, jwtVerify } from 'jose';

import { buildSdJwtVc, generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { createAccessCa, createWrprcIssuer, createWrprcLeaf, signWrprc, TEST_ENTITLEMENT_MAP } from '../onboarding/mock-pki.ts';
import { RelyingPartyOnboardingGate } from '../onboarding/onboarding-gate.ts';
import { WRPRC_POLICY_OID } from '../onboarding/oid.ts';
import { NO_REVOCATION } from '../onboarding/revocation.ts';
import { createApp, ROUTES, type AppDeps } from './app.ts';
import { AuditLog } from './audit.ts';
import { MAX_BODY_BYTES, MAX_CLAIMS, MAX_DISCLOSURES, MAX_JWE_CHARS, MAX_VP_TOKEN_CHARS } from './limits.ts';
import { VerifierService } from './service.ts';
import { TenantStore } from './tenant.ts';
import { DEV_MODE, DEV_TEST_OPTIONS } from './test-support.ts';

const KEY_A = 'test-api-key-fehler-A';
const KEY_UNREG = 'test-api-key-fehler-U';
const KEY_BROKEN = 'test-api-key-fehler-X';
const KEY_REG = 'test-api-key-fehler-R';

const DOCUMENTED = new Set([...readFileSync(new URL('../../docs/fehlercodes.md', import.meta.url), 'utf8').matchAll(/`([a-z][a-z0-9_]*)`/g)].map((m) => m[1]));

let verifier!: TestKeyMaterial;
let issuer!: TestKeyMaterial;
let holder!: TestKeyMaterial;
let service!: VerifierService;
let gatedService!: VerifierService;
let app!: http.Server;
let gatedApp!: http.Server;
let base!: string;
let gatedBase!: string;

async function listen(deps: AppDeps): Promise<{ server: http.Server; url: string }> {
  const server = createApp(deps);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  deps.service.baseUrl = url;
  return { server, url };
}

function newService(tenants: TenantStore, gate?: RelyingPartyOnboardingGate): VerifierService {
  return new VerifierService(
    tenants,
    new AuditLog(),
    { privateKey: verifier.privateKey, publicKey: verifier.publicKey, publicJwk: verifier.publicJwk, certificateChain: [verifier.certDerBytes] },
    issuer.certDerBytes,
    undefined,
    undefined,
    undefined,
    gate,
    true,
    DEV_TEST_OPTIONS,
  );
}

beforeAll(async () => {
  verifier = await generateTestKeyMaterial('Fehler Verifier TEST');
  issuer = await generateTestKeyMaterial('Fehler Issuer TEST');
  holder = await generateTestKeyMaterial('Fehler Holder TEST');

  const tenants = new TenantStore();
  tenants.add({ id: 'tenant-a', name: 'Kunde A (TEST)', apiKey: KEY_A, requestProfile: { id: 'test-given-name', claims: ['given_name'] } });
  service = newService(tenants);
  ({ server: app, url: base } = await listen({ appLabel: 'fehler-test', tenants, service }));

  // Dienst mit Onboarding-Gate für tenant_not_registered / _invalid / registration_ref_*.
  const accessCa = await createAccessCa();
  const wrprcIssuer = await createWrprcIssuer();
  const wrpac = await accessCa.issueWrpac({ subjectCn: 'Fehler GmbH (TEST)', entitlementOids: [Object.keys(TEST_ENTITLEMENT_MAP)[0]] });
  const leaf = await createWrprcLeaf(wrprcIssuer, 'Fehler GmbH (TEST)');
  const now = Math.floor(Date.now() / 1000);
  const wrprc = await signWrprc(
    { sub: 'wrp-fehler', iat: now, exp: now + 3600, registry_uri: 'https://TEST-registrar.example/api/v1', entitlements: [TEST_ENTITLEMENT_MAP['0.4.0.19475.1.1']], policy_id: [WRPRC_POLICY_OID] },
    leaf.key.privateKey,
    [leaf.certDer, wrprcIssuer.certDer],
  );
  const gatedTenants = new TenantStore();
  gatedTenants.add({ id: 'tenant-u', name: 'Unregistriert (TEST)', apiKey: KEY_UNREG });
  gatedTenants.add({ id: 'tenant-x', name: 'Kaputt (TEST)', apiKey: KEY_BROKEN, registration: { wrpacChain: [new Uint8Array([1, 2, 3])], wrprc: 'kaputt' } });
  gatedTenants.add({ id: 'tenant-r', name: 'Registriert (TEST)', apiKey: KEY_REG, registration: { wrpacChain: wrpac.chain, wrprc } });
  const gate = new RelyingPartyOnboardingGate({
    tenants: gatedTenants,
    accessCaAnchors: [accessCa.caCertDer],
    wrprcIssuerAnchors: [wrprcIssuer.certDer],
    entitlementMap: TEST_ENTITLEMENT_MAP,
    revocation: NO_REVOCATION,
    mode: DEV_MODE,
  });
  gatedService = newService(gatedTenants, gate);
  ({ server: gatedApp, url: gatedBase } = await listen({ appLabel: 'fehler-gate-test', tenants: gatedTenants, service: gatedService }));
});

afterAll(async () => {
  for (const s of [app, gatedApp]) {
    s.closeAllConnections();
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
});

async function session(): Promise<{ state: string; nonce: string; clientId: string }> {
  const created = await service.createRequest('tenant-a', {});
  const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
  return { state: created.state, nonce: String(payload.nonce), clientId: String(payload.client_id) };
}

async function sdJwt(s: { nonce: string; clientId: string }, extra: Parameters<typeof buildSdJwtVc>[0] extends infer O ? Partial<O> : never = {}): Promise<string> {
  return (await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: s.nonce, audience: s.clientId, ...extra })).sdJwt;
}

function postDirect(url: string, body: unknown): Promise<Response> {
  return fetch(`${url}/direct_post`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
}

/** Sendet einen Körper gestreamt (chunked, ohne Content-Length). */
function sendChunked(url: string, method: string, path: string, totalBytes: number, token?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const target = new URL(path, url);
    const headers: Record<string, string> = { 'content-type': 'application/json', 'transfer-encoding': 'chunked' };
    if (token) headers.authorization = `Bearer ${token}`;
    const req = http.request({ host: target.hostname, port: target.port, path: target.pathname, method, headers }, (res) => {
      let body = '';
      res.on('data', (d) => (body += d));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
    });
    req.on('error', reject);
    const chunk = Buffer.alloc(8 * 1024, 0x61);
    let sent = 0;
    const pump = () => {
      while (sent < totalBytes) {
        sent += chunk.length;
        if (!req.write(chunk)) return req.once('drain', pump);
      }
      req.end();
    };
    pump();
  });
}

// ---------------------------------------------------------------------------
describe('a) Größengrenze auf allen Endpunkten', () => {
  const tooBig = 'x'.repeat(MAX_BODY_BYTES + 1);
  for (const route of ROUTES) {
    const path = route.path.replace(':id', crypto.randomUUID());
    it(`${route.method} ${route.path}: zu großer Körper -> 413 payload_too_large (mit und ohne Anmeldung)`, async () => {
      for (const token of [undefined, KEY_A]) {
        const headers: Record<string, string> = { 'content-type': 'application/json' };
        if (token) headers.authorization = `Bearer ${token}`;
        // fetch erlaubt bei GET/DELETE keinen Körper; dort per http.request mit Content-Length.
        const res = await new Promise<{ status: number; body: string }>((resolve, reject) => {
          const target = new URL(path, base);
          const req = http.request({ host: target.hostname, port: target.port, path: target.pathname, method: route.method, headers: { ...headers, 'content-length': String(Buffer.byteLength(tooBig)) } }, (r) => {
            let body = '';
            r.on('data', (d) => (body += d));
            r.on('end', () => resolve({ status: r.statusCode ?? 0, body }));
          });
          req.on('error', reject);
          req.end(tooBig);
        });
        assert.equal(res.status, 413, `${route.method} ${path} token=${Boolean(token)}`);
        assert.deepEqual(JSON.parse(res.body), { error: 'payload_too_large' });
      }
    });
  }

  it('gestreamter Körper ohne Content-Length über der Grenze -> 413 (direct_post, verification-requests)', async () => {
    assert.equal((await sendChunked(base, 'POST', '/direct_post', MAX_BODY_BYTES + 16 * 1024)).status, 413);
    assert.equal((await sendChunked(base, 'POST', '/v1/verification-requests', MAX_BODY_BYTES + 16 * 1024, KEY_A)).status, 413);
  });

  it('Mehrbyte-Zeichen werden als Bytes gezählt', async () => {
    const res = await fetch(`${base}/direct_post`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: 'ä'.repeat(MAX_BODY_BYTES / 2 + 1) });
    assert.equal(res.status, 413);
  });

  it('knapp unter der Grenze wird angenommen und inhaltlich geprüft (Gegenprobe)', async () => {
    const body = JSON.stringify({ state: 'x', vp_token: { pid: ['y'] }, pad: 'z'.repeat(MAX_BODY_BYTES - 200) });
    assert.ok(Buffer.byteLength(body) < MAX_BODY_BYTES);
    const res = await fetch(`${base}/direct_post`, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
    assert.notEqual(res.status, 413);
  });
});

// ---------------------------------------------------------------------------
describe('b) Obergrenzen für Disclosures, Tokenlänge und Eingaben', () => {
  it(`${MAX_DISCLOSURES} Disclosures -> gültig (Gegenprobe)`, async () => {
    const s = await session();
    const extra = Object.fromEntries(Array.from({ length: MAX_DISCLOSURES - 1 }, (_, i) => [`extra_${i}`, i]));
    const token = await sdJwt(s, { additionalDisclosures: extra });
    const outcome = await service.handlePresentation(s.state, { pid: [token] });
    assert.equal(outcome.valid, true, JSON.stringify(outcome));
  });

  it(`${MAX_DISCLOSURES + 1} Disclosures -> too_many_disclosures, Sitzung nicht verbraucht`, async () => {
    const s = await session();
    const extra = Object.fromEntries(Array.from({ length: MAX_DISCLOSURES }, (_, i) => [`extra_${i}`, i]));
    const outcome = await service.handlePresentation(s.state, { pid: [await sdJwt(s, { additionalDisclosures: extra })] });
    assert.deepEqual(outcome, { ok: false, valid: false, error: 'too_many_disclosures' });
    assert.equal((await service.handlePresentation(s.state, { pid: [await sdJwt(s)] })).valid, true);
  });

  it('Token länger als die Grenze -> vp_token_too_long', async () => {
    const s = await session();
    const token = await sdJwt(s, { additionalDisclosures: { note: 'n'.repeat(MAX_VP_TOKEN_CHARS) } });
    assert.ok(token.length > MAX_VP_TOKEN_CHARS);
    assert.equal((await service.handlePresentation(s.state, { pid: [token] })).error, 'vp_token_too_long');
  });

  it('mehrere Credentials oder Präsentationen -> vp_token_invalid', async () => {
    const s = await session();
    const t = await sdJwt(s);
    assert.equal((await service.handlePresentation(s.state, { pid: [t, t] })).error, 'vp_token_invalid');
    assert.equal((await service.handlePresentation(s.state, { pid: [t], other: [t] })).error, 'vp_token_invalid');
    assert.equal((await service.handlePresentation(s.state, { pid: [] })).error, 'vp_token_invalid');
  });

  it('state zu lang -> state_invalid', async () => {
    assert.equal((await service.handlePresentation('s'.repeat(129), { pid: ['x'] })).error, 'state_invalid');
  });

  it('JWE zu lang -> jwe_too_long', async () => {
    assert.equal((await service.handleEncryptedPresentation('j'.repeat(MAX_JWE_CHARS + 1))).error, 'jwe_too_long');
  });

  it(`claims: mehr als ${MAX_CLAIMS}, unzulässige Zeichen -> claims_invalid; vct zu lang -> vct_invalid`, async () => {
    const post = (body: unknown) => fetch(`${base}/v1/verification-requests`, { method: 'POST', headers: { authorization: `Bearer ${KEY_A}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
    assert.equal((await (await post({ claims: Array.from({ length: MAX_CLAIMS + 1 }, (_, i) => `c${i}`) })).json()).error, 'claims_invalid');
    assert.equal((await (await post({ claims: ['given name<script>'] })).json()).error, 'claims_invalid');
    assert.equal((await (await post({ vct: 'v'.repeat(257) })).json()).error, 'vct_invalid');
    assert.equal((await post({ claims: Array.from({ length: MAX_CLAIMS }, (_, i) => `c${i}`) })).status, 400, 'Claims außerhalb des Mandantenprofils werden abgelehnt');
  });
});

// ---------------------------------------------------------------------------
const FORBIDDEN = [
  /\n\s+at\s/, // Stacktrace
  /\bError\b/, // Fehlerklassen-/Rohmeldung
  /\/Users\/|\/home\/|node_modules|file:\/\/|\.ts\b|\.js\b/, // interne Pfade
  /[A-Z][a-z]+ [a-z]+ [a-z]+/, // Freitext-Sätze aus Bibliotheken
];

function assertCleanError(label: string, status: number, raw: string, expected: string): void {
  for (const pattern of FORBIDDEN) assert.doesNotMatch(raw, pattern, `${label}: verbotener Inhalt`);
  const body = JSON.parse(raw) as { error?: string; ok?: boolean };
  assert.equal(body.error, expected, label);
  assert.match(expected, /^[a-z][a-z0-9_]*$/);
  assert.ok(DOCUMENTED.has(expected), `${label}: Code ${expected} fehlt in docs/fehlercodes.md`);
  assert.ok(status >= 400 || (body as { valid?: boolean }).valid === false, `${label}: Fehler darf kein positives Ergebnis sein`);

  // Zwei Invarianten, die vorher nicht geprüft wurden und beide echte Befunde
  // aus dem Audit vom 27.09.2026 durchgelassen hätten:
  //
  // 1. 401 ist exklusiv für den API-Schlüssel. `/direct_post` ist öffentlich,
  //    es gab dort nie etwas zu authentifizieren. Ein 401 mit einem anderen
  //    Code bringt einen Client dazu, den Schlüssel zu erneuern, obwohl die
  //    Präsentation das Problem war.
  if (status === 401) {
    assert.equal(expected, 'unauthorized', `${label}: 401 ist nur für fehlenden oder unbekannten API-Schlüssel erlaubt, nicht für "${expected}"`);
  }
  // 2. Eine abgelehnte Präsentation (`ok: false`) trägt 422 Unprocessable
  //    Entity, nicht 401.
  if (body.ok === false) {
    assert.equal(status, 422, `${label}: abgelehnte Präsentation muss 422 sein, bekam ${status}`);
  }
}

describe('c) Jeder Fehlercode: fester, dokumentierter Code ohne interne Details', () => {
  const scenarios: Array<{ label: string; expected: string; run: () => Promise<Response> }> = [
    { label: '401 ohne Schlüssel', expected: 'unauthorized', run: () => fetch(`${base}/v1/verification-requests`, { method: 'POST' }) },
    { label: '404 unbekannte Sitzung', expected: 'not_found', run: () => fetch(`${base}/v1/verification-requests/${crypto.randomUUID()}`, { headers: { authorization: `Bearer ${KEY_A}` } }) },
    { label: '404 Request Object', expected: 'not_found', run: () => fetch(`${base}/v1/verification-requests/${crypto.randomUUID()}/request-object`) },
    { label: '404 unbekannte Route', expected: 'not_found', run: () => fetch(`${base}/v1/nichts`, { headers: { authorization: `Bearer ${KEY_A}` } }) },
    { label: '400 kaputtes JSON', expected: 'invalid_json', run: () => fetch(`${base}/v1/verification-requests`, { method: 'POST', headers: { authorization: `Bearer ${KEY_A}` }, body: '{kaputt' }) },
    { label: '400 JSON-Array statt Objekt', expected: 'invalid_json', run: () => fetch(`${base}/v1/verification-requests`, { method: 'POST', headers: { authorization: `Bearer ${KEY_A}` }, body: '[1]' }) },
    { label: '400 claims', expected: 'claims_invalid', run: () => fetch(`${base}/v1/verification-requests`, { method: 'POST', headers: { authorization: `Bearer ${KEY_A}` }, body: '{"claims":"given_name"}' }) },
    { label: '400 vct', expected: 'vct_invalid', run: () => fetch(`${base}/v1/verification-requests`, { method: 'POST', headers: { authorization: `Bearer ${KEY_A}` }, body: '{"vct":""}' }) },
    { label: '400 registration_ref', expected: 'registration_ref_invalid', run: () => fetch(`${base}/v1/verification-requests`, { method: 'POST', headers: { authorization: `Bearer ${KEY_A}` }, body: '{"registration_ref":{"x":1}}' }) },
    { label: '403 nicht registriert', expected: 'tenant_not_registered', run: () => fetch(`${gatedBase}/v1/verification-requests`, { method: 'POST', headers: { authorization: `Bearer ${KEY_UNREG}` }, body: '{}' }) },
    { label: '403 Registrierung ungültig', expected: 'tenant_registration_invalid', run: () => fetch(`${gatedBase}/v1/verification-requests`, { method: 'POST', headers: { authorization: `Bearer ${KEY_BROKEN}` }, body: '{}' }) },
    {
      label: '400 registration_ref passt nicht',
      expected: 'registration_ref_mismatch',
      run: () =>
        fetch(`${gatedBase}/v1/verification-requests`, {
          method: 'POST',
          headers: { authorization: `Bearer ${KEY_REG}` },
          body: JSON.stringify({ registration_ref: { clientName: 'X', clientId: 'fremd', registryUri: 'https://TEST-registrar.example/api/v1', intendedUseId: 'https://x.example/use' } }),
        }),
    },
    { label: '400 direct_post ohne Felder', expected: 'invalid_request', run: () => postDirect(base, {}) },
    { label: '400 direct_post kein JSON', expected: 'invalid_request', run: () => fetch(`${base}/direct_post`, { method: 'POST', body: 'x' }) },
    { label: 'direct_post unbekannter state', expected: 'unknown_state', run: () => postDirect(base, { state: crypto.randomUUID(), vp_token: { pid: ['a.b.c~'] } }) },
    { label: 'direct_post vp_token ungültig', expected: 'vp_token_invalid', run: () => postDirect(base, { state: 'x', vp_token: { pid: [1] } }) },
    { label: 'direct_post state ungültig', expected: 'state_invalid', run: () => postDirect(base, { state: 's'.repeat(200), vp_token: { pid: ['x'] } }) },
    { label: 'direct_post JWE mit kaputtem Header', expected: 'malformed_jwe_header', run: () => postDirect(base, { response: 'a.b.c.d.e' }) },
    {
      label: 'direct_post manipulierte Disclosure (Bibliotheksfehler)',
      expected: 'presentation_invalid',
      run: async () => {
        const s = await session();
        return postDirect(base, { state: s.state, vp_token: { pid: [await sdJwt(s, { tamperDisclosure: true })] } });
      },
    },
    {
      // Die Bibliothek wirft hier nicht, sondern liefert valid=false mit Freitext.
      label: 'direct_post falsche Nonce (Bibliotheksfehler)',
      expected: 'presentation_invalid',
      run: async () => {
        const s = await session();
        return postDirect(base, { state: s.state, vp_token: { pid: [await sdJwt({ ...s, nonce: 'falsch' })] } });
      },
    },
    {
      label: 'direct_post kaputtes SD-JWT (Bibliotheksfehler)',
      expected: 'credential_malformed',
      run: async () => {
        const s = await session();
        return postDirect(base, { state: s.state, vp_token: { pid: ['kein.sd.jwt~'] } });
      },
    },
    {
      label: 'direct_post Sitzung verbraucht',
      expected: 'session_reused',
      run: async () => {
        const s = await session();
        const token = await sdJwt(s);
        await postDirect(base, { state: s.state, vp_token: { pid: [token] } });
        return postDirect(base, { state: s.state, vp_token: { pid: [token] } });
      },
    },
  ];

  for (const scenario of scenarios) {
    it(`${scenario.label} -> ${scenario.expected}`, async () => {
      const res = await scenario.run();
      assertCleanError(scenario.label, res.status, await res.text(), scenario.expected);
    });
  }

  it('500: interne Ausnahme mit Pfad in der Meldung -> nur internal_error', async () => {
    const tenants = new TenantStore();
    const exploding = {
      baseUrl: '',
      getRequestObject: () => {
        throw new Error('ENOENT: /Users/geheim/projekt/src/service/app.ts Zeile 170 kaputt');
      },
    } as unknown as VerifierService;
    const originalError = console.error;
    const logged: string[] = [];
    console.error = (...args: unknown[]) => logged.push(args.map(String).join(' '));
    try {
      const { server, url } = await listen({ appLabel: 'explodiert', tenants, service: exploding });
      const res = await fetch(`${url}/v1/verification-requests/x/request-object`);
      assert.equal(res.status, 500);
      assertCleanError('500', res.status, await res.text(), 'internal_error');
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    } finally {
      console.error = originalError;
    }
    assert.ok(logged.every((l) => !l.includes('/Users/geheim')), 'auch das Betriebslog enthält die Rohmeldung nicht');
  });

  it('Audit-Einträge enthalten bei Bibliotheksfehlern nur Codes', async () => {
    const s = await session();
    await postDirect(base, { state: s.state, vp_token: { pid: [await sdJwt({ ...s, nonce: 'falsch' })] } });
    const audit = (service as unknown as { audit: AuditLog }).audit.list();
    const entry = audit.find((e) => e.detail?.includes(s.state) && e.event === 'presentation_invalid');
    assert.ok(entry);
    assert.match(entry.detail ?? '', /^session=[0-9a-f-]+ reason=[a-z_]+$/);
  });
});
