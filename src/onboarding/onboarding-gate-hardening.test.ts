import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import 'reflect-metadata';
import { X509Certificate } from '@peculiar/x509';

import { TenantStore } from '../service/tenant.ts';
import { ErrTenantNotRegistered, ErrTenantRegistrationInvalid } from './errors.ts';
import {
  createMockOnboardingCertificateProfile,
  MOCK_ONBOARDING_PROFILE_MARKER,
} from './mock-certificate-profiles.ts';
import { MockRevocationList } from './mock-revocation.ts';
import { RelyingPartyOnboardingGate } from './onboarding-gate.ts';
import { WRPRC_POLICY_OID } from './oid.ts';
import { TEST_ENTITLEMENT_MAP, signWrprc } from './mock-pki.ts';

const SERVICE_PROVIDER_URI = TEST_ENTITLEMENT_MAP['0.4.0.19475.1.1'];
const DEV = { devMode: true, isProduction: false };

async function profileRegistration(options: Parameters<typeof createMockOnboardingCertificateProfile>[0] = {}, now = new Date()) {
  const profile = await createMockOnboardingCertificateProfile(options);
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const wrprc = await signWrprc(
    {
      sub: 'ATTACK-TEST-MOCK-NOT-FOR-PRODUCTION tenant',
      iat: nowSeconds - 60,
      exp: nowSeconds + 3600,
      registry_uri: 'https://TEST-registrar.example/api/v1',
      entitlements: [SERVICE_PROVIDER_URI],
      policy_id: [WRPRC_POLICY_OID],
    },
    profile.wrprcLeaf.key.privateKey,
    [profile.wrprcLeaf.certDer, profile.wrprcIssuer.certDer],
  );
  return { profile, wrprc, now };
}

function gateFor(
  registration: Awaited<ReturnType<typeof profileRegistration>>,
  options: { now?: Date; accessCaAnchors?: Uint8Array[]; revocation?: MockRevocationList; clockSkewSeconds?: number } = {},
): RelyingPartyOnboardingGate {
  const tenants = new TenantStore();
  tenants.add({
    id: 'mock-tenant',
    name: `${MOCK_ONBOARDING_PROFILE_MARKER} tenant`,
    apiKey: 'test-api-key-mock-tenant',
    registration: { wrpacChain: registration.profile.wrpac.chain, wrprc: registration.wrprc },
  });
  return new RelyingPartyOnboardingGate({
    tenants,
    accessCaAnchors: options.accessCaAnchors ?? [registration.profile.accessCa.caCertDer],
    wrprcIssuerAnchors: [registration.profile.wrprcIssuer.certDer],
    entitlementMap: TEST_ENTITLEMENT_MAP,
    revocation: options.revocation ?? new MockRevocationList(),
    mode: DEV,
    now: () => options.now ?? registration.now,
    clockSkewSeconds: options.clockSkewSeconds,
  });
}

async function rejectsWithReason(action: () => Promise<unknown>, reason: string): Promise<void> {
  await assert.rejects(action, (error: unknown) => {
    assert.ok(error instanceof ErrTenantRegistrationInvalid);
    assert.equal(error.reason, reason);
    return true;
  });
}

describe('Onboarding Gate: synthetic TEST profile hardening', () => {
  it('marks every generated certificate profile as test-only', async () => {
    const { profile } = await profileRegistration();
    assert.equal(profile.marker, MOCK_ONBOARDING_PROFILE_MARKER);
    assert.match(new X509Certificate(Uint8Array.from(profile.accessCa.caCertDer)).subject, /MOCK-NOT-FOR-PRODUCTION/);
    assert.match(new X509Certificate(Uint8Array.from(profile.wrpac.certDer)).subject, /MOCK-NOT-FOR-PRODUCTION/);
    assert.match(new X509Certificate(Uint8Array.from(profile.wrprcIssuer.certDer)).subject, /MOCK-NOT-FOR-PRODUCTION/);
    assert.match(new X509Certificate(Uint8Array.from(profile.wrprcLeaf.certDer)).subject, /MOCK-NOT-FOR-PRODUCTION/);
  });

  it('accepts a valid profile at the exact certificate boundary with zero skew', async () => {
    const now = new Date();
    const registration = await profileRegistration({
      wrpac: { notBefore: new Date(now.getTime() - 60 * 60_000), notAfter: new Date(now.getTime() + 60 * 60_000) },
    }, now);
    const boundary = new X509Certificate(Uint8Array.from(registration.profile.wrpac.certDer)).notAfter;
    await gateFor(registration, { now: boundary, clockSkewSeconds: 0 }).verifyTenant('mock-tenant');
  });

  it('rejects the same WRPAC one second after notAfter', async () => {
    const now = new Date();
    const registration = await profileRegistration({
      wrpac: { notBefore: new Date(now.getTime() - 60 * 60_000), notAfter: new Date(now.getTime() + 60 * 60_000) },
    }, now);
    const boundary = new X509Certificate(Uint8Array.from(registration.profile.wrpac.certDer)).notAfter;
    await rejectsWithReason(
      () => gateFor(registration, { now: new Date(boundary.getTime() + 1000), clockSkewSeconds: 0 }).verifyTenant('mock-tenant'),
      'certificate_expired',
    );
  });

  it('rejects an already expired WRPAC profile', async () => {
    const now = new Date();
    const registration = await profileRegistration({
      wrpac: { notBefore: new Date(now.getTime() - 3 * 86_400_000), notAfter: new Date(now.getTime() - 86_400_000) },
    }, now);
    await rejectsWithReason(() => gateFor(registration).verifyTenant('mock-tenant'), 'certificate_expired');
  });

  it('rejects missing registration material before certificate validation', async () => {
    const registration = await profileRegistration();
    const tenants = new TenantStore();
    tenants.add({ id: 'empty', name: 'TEST empty', apiKey: 'test-empty', registration: { wrpacChain: [], wrprc: '' } });
    const gate = new RelyingPartyOnboardingGate({
      tenants,
      accessCaAnchors: [registration.profile.accessCa.caCertDer],
      wrprcIssuerAnchors: [registration.profile.wrprcIssuer.certDer],
      entitlementMap: TEST_ENTITLEMENT_MAP,
      revocation: new MockRevocationList(),
      mode: DEV,
    });
    await assert.rejects(() => gate.verifyTenant('empty'), ErrTenantNotRegistered);
  });

  it('rejects an empty trust-anchor directory as a trust-path failure', async () => {
    const registration = await profileRegistration();
    await rejectsWithReason(() => gateFor(registration, { accessCaAnchors: [] }).verifyTenant('mock-tenant'), 'trust_path_not_found');
  });

  it('rejects a revoked WRPAC and does not soften the status', async () => {
    const registration = await profileRegistration();
    const revocation = new MockRevocationList();
    revocation.revoke(registration.profile.wrpac.certDer);
    await rejectsWithReason(() => gateFor(registration, { revocation }).verifyTenant('mock-tenant'), 'certificate_revoked');
  });

  it('rejects a not-yet-valid WRPRC leaf', async () => {
    const now = new Date();
    const registration = await profileRegistration({
      wrprcLeaf: { notBefore: new Date(now.getTime() + 86_400_000), notAfter: new Date(now.getTime() + 31 * 86_400_000) },
    }, now);
    await rejectsWithReason(() => gateFor(registration).verifyTenant('mock-tenant'), 'certificate_not_yet_valid');
  });

  it('rejects a revoked WRPRC leaf', async () => {
    const registration = await profileRegistration();
    const revocation = new MockRevocationList();
    revocation.revoke(registration.profile.wrprcLeaf.certDer);
    await rejectsWithReason(() => gateFor(registration, { revocation }).verifyTenant('mock-tenant'), 'certificate_revoked');
  });

  it('rejects invalid test material rather than returning a partial registration', async () => {
    const registration = await profileRegistration();
    const broken = { ...registration, wrprc: 'not-a-jwt' };
    await rejectsWithReason(() => gateFor(broken).verifyTenant('mock-tenant'), 'wrprc_malformed');
  });
});
