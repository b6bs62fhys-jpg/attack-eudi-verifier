/**
 * Integrationstests für den Verifier-Dienst (Schritt 3).
 * Laufen gegen einen echten HTTP-Server auf 127.0.0.1 (ephemerer Port).
 * Nur TEST-Material im Speicher.
 */
import assert from 'node:assert/strict';
import { afterAll, beforeAll, describe, it } from 'vitest';
import { createLocalJWKSet, jwtVerify } from 'jose';

import { createApp } from './app.ts';
import { VerifierService, type ServiceKeys } from './service.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';
import { AuditLog } from './audit.ts';
import { TenantStore } from './tenant.ts';
import { buildSdJwtVc, generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';

const KEY_A = 'test-api-key-tenant-A';
const KEY_B = 'test-api-key-tenant-B';

interface TestContext {
  base: string;
  audit: AuditLog;
  issuerKey: Awaited<ReturnType<typeof generateTestKeyMaterial>>;
  on: (method: string, path: string, token?: string, body?: unknown) => Promise<Response>;
  present: (requestObjectUri: string, responseUri: string) => Promise<{ ok: boolean; valid: boolean; error?: string }>;
}

let ctx: TestContext;
let server: Awaited<ReturnType<typeof import('node:http')['createServer']>>;

beforeAll(async () => {
  const tenantStore = new TenantStore();
  tenantStore.add({ id: 'tenant-a', name: 'Kunde A (TEST)', apiKey: KEY_A, requestTtlSeconds: 300 });
  tenantStore.add({ id: 'tenant-b', name: 'Kunde B (TEST)', apiKey: KEY_B, requestTtlSeconds: 300 });

  const verifierKey = await generateTestKeyMaterial('Service Verifier TEST');
  const issuerKey = await generateTestKeyMaterial('Service Issuer TEST');
  const holderKey = await generateTestKeyMaterial('Service Holder TEST');
  const keys: ServiceKeys = {
    privateKey: verifierKey.privateKey,
    publicKey: verifierKey.publicKey,
    publicJwk: verifierKey.publicJwk,
    certificateChain: [verifierKey.certDerBytes],
  };
  const audit = new AuditLog();
  const service = new VerifierService(tenantStore, audit, keys, issuerKey.certDerBytes, undefined, undefined, undefined, undefined, true, DEV_TEST_OPTIONS);

  server = createApp({ appLabel: 'attack-service-test', tenants: tenantStore, service });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as { port: number };
  const base = `http://127.0.0.1:${address.port}`;
  service.baseUrl = base;

  const requestObjectPayload = async (requestObject: string) => {
    const { payload } = await jwtVerify(requestObject, createLocalJWKSet({ keys: [verifierKey.publicJwk] }));
    return payload as { nonce?: string; client_id?: string; response_uri?: string; state?: string };
  };

  ctx = {
    base,
    audit,
    issuerKey,
    on: async (method, path, token, body) => {
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (token) headers.authorization = `Bearer ${token}`;
      const init: RequestInit = { method, headers };
      if (body !== undefined) init.body = JSON.stringify(body);
      return fetch(`${base}${path}`, init);
    },
    present: async (requestObjectUri, responseUri) => {
      const requestObject = await fetch(requestObjectUri).then((r) => r.text());
      const payload = await requestObjectPayload(requestObject);
      const built = await buildSdJwtVc({
        issuerKey: ctx.issuerKey,
        holderKey,
        nonce: payload.nonce ?? '',
        audience: payload.client_id ?? '',
      });
      const post = await fetch(responseUri, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ vp_token: { pid: [built.sdJwt] }, state: payload.state }),
      });
      return (await post.json()) as { ok: boolean; valid: boolean; error?: string };
    },
  };
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('Auth und Isolation (Mandantenmodell)', () => {
  it('ohne und mit falschem API-Schlüssel wird abgelehnt', async () => {
    const noKey = await ctx.on('POST', '/v1/verification-requests');
    assert.equal(noKey.status, 401);
    const badKey = await ctx.on('POST', '/v1/verification-requests', 'test-api-key-falsch');
    assert.equal(badKey.status, 401);
  });

  it('Mandant A kann Mandant B weder Token noch Ergebnis sehen noch löschen', async () => {
    const created = await ctx.on('POST', '/v1/verification-requests', KEY_A, { claims: ['given_name'] });
    assert.equal(created.status, 201);
    const { sessionId } = (await created.json()) as { sessionId: string };

    const bGet = await ctx.on('GET', `/v1/verification-requests/${sessionId}`, KEY_B);
    assert.equal(bGet.status, 404, 'Mandant B darf das Token von A nicht sehen');
    const bDelete = await ctx.on('DELETE', `/v1/verification-requests/${sessionId}`, KEY_B);
    assert.equal(bDelete.status, 404, 'Mandant B darf das Token von A nicht löschen');

    const aGet = await ctx.on('GET', `/v1/verification-requests/${sessionId}`, KEY_A);
    assert.equal(aGet.status, 200);
    const body = (await aGet.json()) as { status: string };
    assert.equal(body.status, 'pending');
  });
});

describe('Eingabevalidierung', () => {
  it('claims muss ein nicht-leeres Array von Zeichenketten sein', async () => {
    const r1 = await ctx.on('POST', '/v1/verification-requests', KEY_A, { claims: 'given_name' });
    assert.equal(r1.status, 400);
    const r2 = await ctx.on('POST', '/v1/verification-requests', KEY_A, { claims: [] });
    assert.equal(r2.status, 400);
    const r3 = await ctx.on('POST', '/v1/verification-requests', KEY_A, { claims: ['given_name', 42] });
    assert.equal(r3.status, 400);
  });

  it('vct muss eine Zeichenkette sein', async () => {
    const r = await ctx.on('POST', '/v1/verification-requests', KEY_A, { vct: 123 });
    assert.equal(r.status, 400);
  });

  it('ungültiges JSON wird abgelehnt', async () => {
    const raw = await fetch(`${ctx.base}/v1/verification-requests`, {
      method: 'POST',
      headers: { authorization: `Bearer ${KEY_A}`, 'content-type': 'application/json' },
      body: 'kein json',
    });
    assert.equal(raw.status, 400);
  });
});

describe('End-to-End mit Mock-Wallet', () => {
  it('Prüfanfrage erzeugt, Präsentation validiert, Ergebnis lieferbar', async () => {
    const created = await ctx.on('POST', '/v1/verification-requests', KEY_A, { claims: ['given_name'] });
    assert.equal(created.status, 201);
    const { requestObjectUri, responseUri, sessionId, requestObject } = (await created.json()) as {
      requestObjectUri: string;
      responseUri: string;
      sessionId: string;
      requestObject: string;
    };
    assert.ok(requestObject.length > 0, 'Request Object ist vorhanden');

    // Request Object ist für die Wallet abrufbar
    const ro = await fetch(requestObjectUri);
    assert.equal(ro.status, 200);
    assert.equal(ro.headers.get('content-type'), 'application/oauth-authz-req+jwt');

    // Präsentation der Mock-Wallet
    const outcome = await ctx.present(requestObjectUri, responseUri);
    assert.equal(outcome.valid, true, `gültige Präsentation muss akzeptiert werden (${JSON.stringify(outcome)})`);

    const result = await ctx.on('GET', `/v1/verification-requests/${sessionId}`, KEY_A);
    assert.equal(result.status, 200);
    const body = (await result.json()) as { status: string; result?: { valid: boolean; claims: Record<string, unknown>; issuerCountry: string } };
    assert.equal(body.status, 'completed');
    assert.equal(body.result?.valid, true);
    assert.equal(body.result?.claims.given_name, 'Ada');

    const auditIds = ctx.audit.list().filter((e) => e.event === 'result_read');
    assert.ok(auditIds.length >= 1, 'Audit-Eintrag result_read vorhanden');
  });

  it('wiederverwendete Nonce wird nach verbrauchter Sitzung abgelehnt', async () => {
    const created = await ctx.on('POST', '/v1/verification-requests', KEY_A, { claims: ['given_name'] });
    const { responseUri, sessionId } = (await created.json()) as { responseUri: string; sessionId: string };
    const first = await ctx.present(`${ctx.base}/v1/verification-requests/${sessionId}/request-object`, responseUri);
    assert.equal(first.valid, true);
    const second = await ctx.on('POST', '/direct_post', undefined, { vp_token: { pid: [] }, state: sessionId });
    // 422 und nicht 401: die Route ist öffentlich, es gab nichts zu
    // authentifizieren. 401 ist exklusiv für den API-Schlüssel reserviert.
    assert.equal(second.status, 422, 'Replay muss abgelehnt werden');
  });
});

describe('Ablauf und Löschung', () => {
  it('Ergebnis wird nach Sitzungsablauf entfernt und die Sitzung abgelehnt', async () => {
    const store = new TenantStore();
    store.add({ id: 'tenant-x', name: 'Kunde X (TEST)', apiKey: 'test-api-key-tenant-X', requestTtlSeconds: 1 });
    const key = await generateTestKeyMaterial('Service Verifier TEST');
    const issuer = await generateTestKeyMaterial('Service Issuer TEST');
    const audit = new AuditLog();
    const service = new VerifierService(store, audit, { privateKey: key.privateKey, publicKey: key.publicKey, publicJwk: key.publicJwk, certificateChain: [key.certDerBytes] }, issuer.certDerBytes, undefined, undefined, undefined, undefined, true, DEV_TEST_OPTIONS);
    service.baseUrl = ctx.base;
    const app = createApp({ appLabel: 'expiry-test', tenants: store, service });
    await new Promise<void>((resolve) => app.listen(0, '127.0.0.1', resolve));
    const port = (app.address() as { port: number }).port;
    const base = `http://127.0.0.1:${port}`;
    service.baseUrl = base;

    const created = await fetch(`${base}/v1/verification-requests`, {
      method: 'POST',
      headers: { authorization: `Bearer test-api-key-tenant-X`, 'content-type': 'application/json' },
      body: JSON.stringify({ claims: ['given_name'] }),
    });
    assert.equal(created.status, 201);
    const { sessionId, responseUri } = (await created.json()) as { sessionId: string; responseUri: string };
    void responseUri;

    await new Promise((r) => setTimeout(r, 1200));

    const expired = await fetch(`${base}/v1/verification-requests/${sessionId}`, {
      headers: { authorization: `Bearer test-api-key-tenant-X` },
    });
    assert.equal(expired.status, 200);
    const body = (await expired.json()) as { status: string };
    assert.equal(body.status, 'expired', 'abgelaufene Sitzung liefert keine Ergebnisse mehr');

    const again = await fetch(`${base}/v1/verification-requests/${sessionId}`, {
      headers: { authorization: `Bearer test-api-key-tenant-X` },
    });
    const body2 = (await again.json()) as { status: string };
    assert.equal(body2.status, 'expired');

    const del = await fetch(`${base}/v1/verification-requests/${sessionId}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer test-api-key-tenant-X` },
    });
    assert.equal(del.status, 204);

    const gone = await fetch(`${base}/v1/verification-requests/${sessionId}`, {
      headers: { authorization: `Bearer test-api-key-tenant-X` },
    });
    assert.equal(gone.status, 404);

    await new Promise<void>((resolve) => app.close(() => resolve()));
  });
});