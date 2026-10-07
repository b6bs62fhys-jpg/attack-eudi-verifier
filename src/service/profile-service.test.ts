import 'reflect-metadata';
import assert from 'node:assert/strict';
import { beforeAll, describe, it } from 'vitest';
import { createLocalJWKSet, jwtVerify } from 'jose';

import { generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { AuditLog } from './audit.ts';
import { MAX_CLAIMS, ServiceInputError, validateClaims } from './limits.ts';
import { VerifierService } from './service.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';
import { TenantStore } from './tenant.ts';

interface RequestPayload {
  state?: string;
  response_mode?: string;
  dcql_query?: { credentials?: Array<{ id?: string; claims?: Array<{ path?: string[] }> }> };
  client_metadata?: { jwks?: { keys?: Array<{ kid?: string }> } };
}

let service: VerifierService;
let tenants: TenantStore;
let verifierJwk: JsonWebKey;

beforeAll(async () => {
  tenants = new TenantStore();
  tenants.add({ id: 'pid', name: 'PID (TEST)', apiKey: 'test-api-key-profile-pid' });
  tenants.add({ id: 'age', name: 'Alter (TEST)', apiKey: 'test-api-key-profile-age', requestProfile: 'age_over_18' });
  tenants.add({ id: 'custom', name: 'Custom (TEST)', apiKey: 'test-api-key-profile-custom', requestProfile: { id: 'custom', claims: ['birth_date'] } });
  const verifier = await generateTestKeyMaterial('Profile Verifier TEST');
  const issuer = await generateTestKeyMaterial('Profile Issuer TEST');
  verifierJwk = verifier.publicJwk;
  service = new VerifierService(
    tenants,
    new AuditLog(),
    { privateKey: verifier.privateKey, publicKey: verifier.publicKey, publicJwk: verifier.publicJwk, certificateChain: [verifier.certDerBytes] },
    issuer.certDerBytes,
    undefined,
    undefined,
    undefined,
    undefined,
    true,
    DEV_TEST_OPTIONS,
  );
  service.baseUrl = 'http://127.0.0.1:9';
});

async function payloadFor(tenantId: string, input: { claims?: string[]; vct?: string } = {}): Promise<RequestPayload> {
  const created = await service.createRequest(tenantId, input);
  const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifierJwk] }));
  return payload as RequestPayload;
}

function claimNames(payload: RequestPayload): string[] {
  return (payload.dcql_query?.credentials?.[0]?.claims ?? []).map((claim) => claim.path?.[0] ?? '').filter(Boolean);
}

describe('DCQL-Profile im Verifier-Dienst', () => {
  it('validateClaims akzeptiert genau die obere Grenze', () => {
    const claims = Array.from({ length: MAX_CLAIMS }, (_, index) => `claim_${index}`);
    assert.equal(validateClaims(claims).length, MAX_CLAIMS);
  });

  it('pid_basis fragt given_name und birth_date und aktiviert JWE', async () => {
    const payload = await payloadFor('pid');
    assert.deepEqual(claimNames(payload).sort(), ['birth_date', 'given_name']);
    assert.equal(payload.response_mode, 'direct_post.jwt');
    assert.equal(payload.client_metadata?.jwks?.keys?.[0]?.kid, payload.state);
  });

  it('age_over_18 fragt ausschließlich den Altersclaim', async () => {
    const payload = await payloadFor('age');
    assert.deepEqual(claimNames(payload), ['age_over_18']);
  });

  it('/custom erlaubt nur die konfigurierten Claims', async () => {
    const payload = await payloadFor('custom');
    assert.deepEqual(claimNames(payload), ['birth_date']);
    await assert.rejects(() => service.createRequest('custom', { claims: ['given_name'] }), (error: unknown) => error instanceof ServiceInputError && error.code === 'claims_invalid');
  });

  it('weicht vct und nicht erlaubte Claims mit festen Codes ab', async () => {
    await assert.rejects(() => service.createRequest('pid', { claims: ['family_name'] }), (error: unknown) => error instanceof ServiceInputError && error.code === 'claims_invalid');
    await assert.rejects(() => service.createRequest('pid', { vct: 'urn:example:other' }), (error: unknown) => error instanceof ServiceInputError && error.code === 'vct_invalid');
  });
});
