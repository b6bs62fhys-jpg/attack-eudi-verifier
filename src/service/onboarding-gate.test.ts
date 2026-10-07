/**
 * E2E-Tests für das Onboarding-Gate am Verifier-Dienst (Teil 2, Baustein B):
 * Eine Prüfanfrage wird nur akzeptiert, wenn der anfragende Mandant ein
 * gültiges TEST-WRPAC/WRPRC-Registrierungsmaterial besitzt (und der Wallet-
 * Issuer auf der TEST Trust List steht). Nicht registrierter Mandant -> 403
 * `tenant_not_registered`, ungültiges Material -> 403
 * `tenant_registration_invalid`. Läuft gegen echte HTTP-Server (ephemer).
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import { afterAll, beforeAll, describe, it } from 'vitest';
import { createLocalJWKSet, jwtVerify } from 'jose';
import 'reflect-metadata';

import { createApp } from './app.ts';
import { VerifierService, type ServiceKeys } from './service.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';
import { AuditLog } from './audit.ts';
import { TenantStore } from './tenant.ts';
import { buildSdJwtVc, generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { JwsTrustListSignatureVerifier, TrustListMonitor, sha256Hex } from '../trustlist/monitor.ts';
import { TrustListServer, buildTrustListDocument, trustListEntry } from '../trustlist/mock-server.ts';
import { RelyingPartyOnboardingGate } from '../onboarding/onboarding-gate.ts';
import { NO_REVOCATION } from '../onboarding/revocation.ts';
import {
  createAccessCa,
  createWrprcIssuer,
  createWrprcLeaf,
  signWrprc,
  TEST_ENTITLEMENT_MAP,
  type AccessCa,
  type WrprcIssuer,
} from '../onboarding/mock-pki.ts';
import { WRPRC_POLICY_OID } from '../onboarding/oid.ts';
import type { RegistrationMaterial } from './tenant.ts';

const KEY_A = 'test-api-key-onboarding-A';
const KEY_B = 'test-api-key-onboarding-B';
const KEY_C = 'test-api-key-onboarding-C';
const REGISTRY_URI = 'https://TEST-registrar.example/api/v1';
const SERVICE_PROVIDER_URI = TEST_ENTITLEMENT_MAP['0.4.0.19475.1.1'];
const SUB = 'test-wrp-1';

function post(base: string, key: string, body: unknown): Promise<Response> {
  return fetch(`${base}/v1/verification-requests`, {
    method: 'POST',
    headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function postExpect201(base: string, key: string, body: unknown): Promise<{ requestObject: string; state: string; responseUri: string }> {
  const created = await post(base, key, body);
  if (created.status !== 201) {
    const text = await created.text();
    assert.equal(created.status, 201, text);
  }
  return (await created.json()) as { requestObject: string; state: string; responseUri: string };
}

async function buildRegistration(accessCa: AccessCa, wrprcIssuer: WrprcIssuer, options: { iatOffset?: number; expOffset?: number } = {}): Promise<RegistrationMaterial> {
  const wrpac = await accessCa.issueWrpac({
    subjectCn: 'Test GmbH (TEST)',
    entitlementOids: [Object.keys(TEST_ENTITLEMENT_MAP)[0]],
  });
  const leaf = await createWrprcLeaf(wrprcIssuer, 'Test GmbH (TEST)');
  const now = Math.floor(Date.now() / 1000);
  const wrprc = await signWrprc(
    {
      sub: SUB,
      iat: now + (options.iatOffset ?? 0),
      exp: now + (options.expOffset ?? 3600),
      registry_uri: REGISTRY_URI,
      entitlements: [SERVICE_PROVIDER_URI],
      policy_id: [WRPRC_POLICY_OID],
    },
    leaf.key.privateKey,
    [leaf.certDer, wrprcIssuer.certDer],
  );
  return { wrpacChain: wrpac.chain, wrprc };
}

interface Harness {
  base: string;
  service: VerifierService;
  app: http.Server;
  trustServer: TrustListServer;
  audit: AuditLog;
  decode(requestObject: string): Promise<Record<string, unknown>>;
  present(requestObject: string, responseUri: string, state: string): Promise<{ ok: boolean; valid: boolean; error?: string }>;
}

let harness: Harness;

beforeAll(async () => {
  const tenantStore = new TenantStore();
  const accessCa = await createAccessCa();
  const wrprcIssuer = await createWrprcIssuer();
  tenantStore.add({ id: 'tenant-a', name: 'Kunde A (TEST)', apiKey: KEY_A, registration: await buildRegistration(accessCa, wrprcIssuer) });
  tenantStore.add({ id: 'tenant-b', name: 'Kunde B (TEST)', apiKey: KEY_B });
  tenantStore.add({
    id: 'tenant-c',
    name: 'Kunde C (TEST)',
    apiKey: KEY_C,
    registration: await buildRegistration(accessCa, wrprcIssuer, { iatOffset: -7200, expOffset: -3600 }),
  });

  const verifierKey = await generateTestKeyMaterial('Onboarding-Gate Verifier TEST');
  const issuer = await generateTestKeyMaterial('Onboarding-Gate Issuer TEST');
  const holder = await generateTestKeyMaterial('Onboarding-Gate Holder TEST');
  const authority = await generateTestKeyMaterial('Onboarding-Gate Trustlist Authority TEST');
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
      id: 'onboarding-gate-trustlist',
      issuer: 'TEST-Trust-List-Authority 1',
      issuedAt: nowSeconds - 60,
      nextUpdate: nowSeconds + 3600,
      version: '1',
      entries: [
        trustListEntry({
          providerName: 'TEST Issuer Anbieter',
          subjectCommonName: 'Onboarding-Gate Issuer TEST',
          anchorFingerprintHex: sha256Hex(issuer.certDerBytes),
        }),
      ],
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

  const gate = new RelyingPartyOnboardingGate({
    tenants: tenantStore,
    accessCaAnchors: [accessCa.caCertDer],
    wrprcIssuerAnchors: [wrprcIssuer.certDer],
    entitlementMap: TEST_ENTITLEMENT_MAP,
    revocation: NO_REVOCATION,
    mode: { devMode: true, isProduction: false },
  });

  const audit = new AuditLog();
  const service = new VerifierService(tenantStore, audit, keys, issuer.certDerBytes, undefined, undefined, monitor.asIssuerTrustPolicy(), gate, true, DEV_TEST_OPTIONS);
  const app = createApp({ appLabel: 'onboarding-gate-test', tenants: tenantStore, service });
  await new Promise<void>((resolve) => app.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${(app.address() as { port: number }).port}`;
  service.baseUrl = base;

  harness = {
    base,
    service,
    app,
    trustServer,
    audit,
    decode: async (requestObject: string) => {
      const { payload } = await jwtVerify(requestObject, createLocalJWKSet({ keys: [verifierKey.publicJwk] }));
      return payload as Record<string, unknown>;
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
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    harness?.app.closeAllConnections();
    harness?.app.close(() => resolve());
  });
  await harness?.trustServer.close();
});

describe('Onboarding-Gate am Verifier-Dienst (/v1/verification-requests)', () => {
  it('registrierter Mandant kommt durch, registration_ref wird aus der WRPRC abgeleitet', async () => {
    const body = await postExpect201(harness.base, KEY_A, { claims: ['given_name'] });

    const payload = await harness.decode(body.requestObject);
    const ref = payload.registration_ref as Record<string, unknown>;
    assert.deepEqual(ref, {
      client_name: 'Test GmbH (TEST)',
      client_id: SUB,
      registry_uri: REGISTRY_URI,
      intended_use_id: SERVICE_PROVIDER_URI,
    });

    const outcome = await harness.present(body.requestObject, body.responseUri, body.state);
    assert.equal(outcome.valid, true, JSON.stringify(outcome));
  });

  it('mitgelieferter registration_ref muss zur WRPRC passen, sonst 400 registration_ref_mismatch', async () => {
    const created = await post(harness.base, KEY_A, {
      claims: ['given_name'],
      registration_ref: { client_name: 'Anderer Name', client_id: 'falsche-id', registry_uri: REGISTRY_URI, intended_use_id: 'use-pid-1' },
    });
    assert.equal(created.status, 400);
    const body = (await created.json()) as { error: string };
    assert.equal(body.error, 'registration_ref_mismatch');
  });

  it('passender mitgelieferter registration_ref wird übernommen', async () => {
    const body = await postExpect201(harness.base, KEY_A, {
      claims: ['given_name'],
      registration_ref: { client_name: 'Eigener Name GmbH (TEST)', client_id: SUB, registry_uri: REGISTRY_URI, intended_use_id: 'use-pid-1' },
    });
    const payload = await harness.decode(body.requestObject);
    const ref = payload.registration_ref as Record<string, unknown>;
    assert.equal(ref.client_name, 'Eigener Name GmbH (TEST)');
    assert.equal(ref.client_id, SUB);
    assert.equal(ref.registry_uri, REGISTRY_URI);
    assert.equal(ref.intended_use_id, 'use-pid-1');
  });

  it('nicht registrierter Mandant wird mit 403 tenant_not_registered abgelehnt', async () => {
    const rejected = await post(harness.base, KEY_B, { claims: ['given_name'] });
    assert.equal(rejected.status, 403);
    const body = (await rejected.json()) as { error: string };
    assert.equal(body.error, 'tenant_not_registered');

    const rejectedAudits = harness.audit.list().filter((e) => e.event === 'request_rejected');
    assert.ok(rejectedAudits.some((e) => e.tenant === 'tenant-b' && e.detail?.includes('reason=tenant_not_registered')), 'Audit für Ablehnung vorhanden');
  });

  it('ungültiges Registrierungsmaterial (abgelaufene WRPRC) -> 403 tenant_registration_invalid', async () => {
    const created = await post(harness.base, KEY_C, { claims: ['given_name'] });
    assert.equal(created.status, 403);
    const body = (await created.json()) as { error: string };
    assert.equal(body.error, 'tenant_registration_invalid');
  });
});