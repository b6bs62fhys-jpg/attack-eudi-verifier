/**
 * Integrationstests für die Erweiterung „RP-Onboarding und Trust List Monitoring“
 * an der Dienstgrenze: RPRC_19a (registration_ref) im Request Object,
 * JAR-/Bibliothekspfad, Eingabevalidierung und Issuer-Trust-Gate vor der
 * Sitzungsnutzung. Läuft gegen echte HTTP-Server auf 127.0.0.1 (ephemer).
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import { afterAll, beforeAll, describe, it } from 'vitest';
import { createLocalJWKSet, jwtVerify, type JWTPayload } from 'jose';
import 'reflect-metadata';

import { createApp } from './app.ts';
import { VerifierService, type ServiceKeys } from './service.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';
import { AuditLog } from './audit.ts';
import { TenantStore } from './tenant.ts';
import { buildSdJwtVc, generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import {
  JwsTrustListSignatureVerifier,
  TrustListMonitor,
  sha256Hex,
} from '../trustlist/monitor.ts';
import { TrustListServer, buildTrustListDocument, trustListEntry } from '../trustlist/mock-server.ts';
import { REGISTRATION_REF_CLAIM } from '../onboarding/registration-ref.ts';

const KEY_A = 'test-api-key-erweiterung-A';

async function startHttp(app: http.Server): Promise<string> {
  await new Promise<void>((resolve) => app.listen(0, '127.0.0.1', resolve));
  const port = (app.address() as { port: number }).port;
  return `http://127.0.0.1:${port}`;
}

function post(base: string, body: unknown): Promise<Response> {
  return fetch(`${base}/v1/verification-requests`, {
    method: 'POST',
    headers: { authorization: `Bearer ${KEY_A}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function postExpect201(base: string, body: unknown): Promise<{ requestObject: string; state: string; responseUri: string; sessionId: string }> {
  const created = await post(base, body);
  if (created.status !== 201) {
    const text = await created.text();
    assert.equal(created.status, 201, text);
  }
  return (await created.json()) as { requestObject: string; state: string; responseUri: string; sessionId: string };
}

interface Harness {
  base: string;
  service: VerifierService;
  app: http.Server;
  trustServer: TrustListServer;
  audit: AuditLog;
  issuer: Awaited<ReturnType<typeof generateTestKeyMaterial>>;
  holder: Awaited<ReturnType<typeof generateTestKeyMaterial>>;
  decode(requestObject: string): Promise<JWTPayload>;
  present(requestObject: string, responseUri: string, state: string): Promise<{ ok: boolean; valid: boolean; error?: string }>;
}

async function buildHarness(options: { trusted: boolean }): Promise<Harness> {
  const tenantStore = new TenantStore();
  tenantStore.add({ id: 'tenant-a', name: 'Kunde A (TEST)', apiKey: KEY_A, requestTtlSeconds: 300 });

  const verifierKey = await generateTestKeyMaterial('Erweiterung Verifier TEST');
  const issuer = await generateTestKeyMaterial('Erweiterung Issuer TEST');
  const holder = await generateTestKeyMaterial('Erweiterung Holder TEST');
  const authority = await generateTestKeyMaterial('Erweiterung Trustlist Authority TEST');
  const keys: ServiceKeys = {
    privateKey: verifierKey.privateKey,
    publicKey: verifierKey.publicKey,
    publicJwk: verifierKey.publicJwk,
    certificateChain: [verifierKey.certDerBytes],
  };

  const trustServer = new TrustListServer({ authorityKey: authority });
  const nowSeconds = Math.floor(Date.now() / 1000);
  const trustUri = await trustServer.start(
    buildTrustListDocument({
      id: 'erweiterung-trustlist',
      issuer: 'TEST-Trust-List-Authority 1',
      issuedAt: nowSeconds - 60,
      nextUpdate: nowSeconds + 3600,
      version: '1',
      entries: options.trusted
        ? [
            trustListEntry({
              providerName: 'TEST Issuer Anbieter',
              subjectCommonName: 'Erweiterung Issuer TEST',
              anchorFingerprintHex: sha256Hex(issuer.certDerBytes),
            }),
          ]
        : [],
    }),
  );

  const monitor = new TrustListMonitor({
    uri: `${trustUri}/trustlist`,
    fetcher: async (uri) => {
      const res = await fetch(uri);
      return { status: res.status, body: await res.text() };
    },
    verifier: new JwsTrustListSignatureVerifier(authority.publicJwk),
  });
  await monitor.refresh();

  const audit = new AuditLog();
  const service = new VerifierService(
    tenantStore,
    audit,
    keys,
    issuer.certDerBytes,
    undefined,
    undefined,
    monitor.asIssuerTrustPolicy(),
    undefined,
    true,
    DEV_TEST_OPTIONS,
  );
  const app = createApp({ appLabel: 'erweiterung-test', tenants: tenantStore, service });
  const base = await startHttp(app);
  service.baseUrl = base;

  return {
    base,
    service,
    app,
    trustServer,
    audit,
    issuer,
    holder,
    decode: async (requestObject: string) => {
      const { payload } = await jwtVerify(requestObject, createLocalJWKSet({ keys: [verifierKey.publicJwk] }));
      return payload;
    },
    present: async (requestObject, responseUri, state) => {
      const payload = await jwtVerify(requestObject, createLocalJWKSet({ keys: [verifierKey.publicJwk] }));
      const built = await buildSdJwtVc({
        issuerKey: issuer,
        holderKey: holder,
        nonce: (payload.payload.nonce as string) ?? '',
        audience: (payload.payload.client_id as string) ?? '',
      });
      const response = await fetch(responseUri, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ vp_token: { pid: [built.sdJwt] }, state }),
      });
      return (await response.json()) as { ok: boolean; valid: boolean; error?: string };
    },
  };
}

let trusted: Harness;
let untrusted: Harness;

beforeAll(async () => {
  trusted = await buildHarness({ trusted: true });
  untrusted = await buildHarness({ trusted: false });
});

afterAll(async () => {
  const apps = [trusted?.app, untrusted?.app].filter((x): x is http.Server => Boolean(x));
  for (const app of apps) {
    await new Promise<void>((resolve) => {
      app.closeAllConnections();
      app.close(() => resolve());
    });
  }
  const trustServers = [trusted?.trustServer, untrusted?.trustServer].filter((x): x is TrustListServer => Boolean(x));
  for (const ts of trustServers) await ts.close();
});

const VALID_REF = {
  client_name: 'Test GmbH (TEST)',
  client_id: 'test-wrp-1',
  registry_uri: 'https://TEST-registrar.example/api/v1',
  intended_use_id: 'use-pid-1',
};

describe('RP-Onboarding am Verifier-Dienst (RPRC_19a)', () => {
  it('bettet registration_ref in das Request Object ein (JAR-Pfad)', async () => {
    const { requestObject, state, responseUri } = await postExpect201(trusted.base, {
      claims: ['given_name'],
      registration_ref: VALID_REF,
    });

    const payload = await trusted.decode(requestObject);
    const rr = payload.registration_ref as { client_name: string; client_id: string; intended_use_id: string };
    assert.ok(rr, `${REGISTRATION_REF_CLAIM} muss eingebettet sein`);
    assert.equal(rr.client_name, 'Test GmbH (TEST)');
    assert.equal(rr.client_id, 'test-wrp-1');
    assert.equal(rr.intended_use_id, 'use-pid-1');
    assert.equal(typeof payload.client_id, 'string');
    assert.ok((payload.client_id as string).startsWith('x509_hash:'), 'client_id muss dem x509_hash-Format entsprechen');

    const outcome = await trusted.present(requestObject, responseUri, state);
    assert.equal(outcome.valid, true, JSON.stringify(outcome));

    const result = trusted.service.getResult('tenant-a', state);
    assert.equal(result.status, 'completed');
  });

  it('ohne registration_ref bleibt der Bibliothekspfad erhalten (kein Claim)', async () => {
    const { requestObject, state, responseUri } = await postExpect201(trusted.base, { claims: ['given_name'] });

    const payload = await trusted.decode(requestObject);
    assert.equal(payload.registration_ref, undefined, 'ohne registration_ref kein Claim');
    assert.equal((payload.client_id as string).startsWith('x509_hash:'), true);

    const outcome = await trusted.present(requestObject, responseUri, state);
    assert.equal(outcome.valid, true, JSON.stringify(outcome));
  });

  it('ungültige registration_ref wird mit 400 abgelehnt', async () => {
    const created = await post(trusted.base, {
      claims: ['given_name'],
      registration_ref: { client_name: '', client_id: '', registry_uri: 'kein-url', intended_use_id: '' },
    });
    assert.equal(created.status, 400);
  });

  it('falscher registration_ref-Typ wird mit 400 abgelehnt', async () => {
    const created = await post(trusted.base, { claims: ['given_name'], registration_ref: { hallo: 'welt' } });
    assert.equal(created.status, 400);
  });
});

describe('Issuer-Trust-Gate (Trust List Monitoring im Dienst)', () => {
  it('gelisteter Issuer wird akzeptiert', async () => {
    const { requestObject, responseUri, state } = await postExpect201(trusted.base, { claims: ['given_name'] });
    const outcome = await trusted.present(requestObject, responseUri, state);
    assert.equal(outcome.valid, true, JSON.stringify(outcome));
  });

  it('nicht gelisteter Issuer: issuer_not_trusted, Session wird nicht verbraucht', async () => {
    const { requestObject, responseUri, state } = await postExpect201(untrusted.base, { claims: ['given_name'] });

    const first = await untrusted.present(requestObject, responseUri, state);
    assert.equal(first.valid, false);
    assert.equal(first.error, 'issuer_not_trusted');

    const second = await untrusted.present(requestObject, responseUri, state);
    assert.equal(second.error, 'issuer_not_trusted', 'Ablehnung darf die Session nicht verbrauchen');

    const result = untrusted.service.getResult('tenant-a', state);
    assert.equal(result.status, 'pending');

    const invalidAudits = untrusted.audit.list().filter((e) => e.event === 'presentation_invalid');
    assert.ok(invalidAudits.length >= 2, 'Audit-Einträge für die Ablehnung vorhanden');
  });
});

describe('Audit für Ablehnungspfade', () => {
  it('loggt presentation_rejected bei unbekanntem state', async () => {
    const response = await fetch(`${trusted.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ vp_token: { pid: ['x'] }, state: 'state-gibt-es-nicht' }),
    });

    const outcome = (await response.json()) as { ok: boolean; valid: boolean; error: string };
    assert.equal(outcome.ok, false);
    assert.equal(outcome.error, 'unknown_state');

    const rejected = trusted.audit.list().filter((e) => e.event === 'presentation_rejected');
    assert.ok(rejected.some((e) => e.detail?.includes('reason=unknown_state')), 'Audit für unbekannten state vorhanden');
  });

  it('loggt presentation_rejected bei Replay (Session bereits verbraucht)', async () => {
    const { requestObject, responseUri, state } = await postExpect201(trusted.base, { claims: ['given_name'] });

    const first = await trusted.present(requestObject, responseUri, state);
    assert.equal(first.valid, true, JSON.stringify(first));

    const second = await trusted.present(requestObject, responseUri, state);
    assert.equal(second.ok, false);
    assert.equal(second.error, 'session_reused');

    const rejected = trusted.audit.list().filter((e) => e.event === 'presentation_rejected');
    assert.ok(rejected.some((e) => e.detail?.includes('reason=session_reused')), 'Audit für Replay vorhanden');
  });
});