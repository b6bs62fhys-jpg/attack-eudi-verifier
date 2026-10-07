/**
 * Sperrprüfung für WRPAC/WRPRC (Teil 2). Der Erweiterungspunkt
 * `RevocationChecker` (src/onboarding/revocation.ts) wird über eine
 * Fingerprint-basierte TEST-Mock-Sperrliste (MockRevocationList) geprüft:
 *   - gesperrtes WRPAC-Blatt -> Kettenvalidierung lehnt ab
 *   - gesperrtes WRPRC-Blatt -> WRPRC-Verifikation lehnt ab
 *   - nicht gesperrtes Material wird weiterhin akzeptiert
 *   - am Onboarding-Gate führt ein gesperrtes Blatt zu
 *     tenant_registration_invalid
 * Die Sperrprüfung ist Pflicht; NO_REVOCATION ist nur mit
 * Entwicklungsschalter zulässig (siehe revocation-fail-closed.test.ts).
 */
import assert from 'node:assert/strict';
import { beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';

import { TenantStore } from '../service/tenant.ts';
import { MockRevocationList } from './mock-revocation.ts';
import { NO_REVOCATION } from './revocation.ts';
import { ErrRevokedCertificate, ErrTenantRegistrationInvalid } from './errors.ts';
import { RelyingPartyOnboardingGate } from './onboarding-gate.ts';
import {
  createAccessCa,
  createWrprcIssuer,
  createWrprcLeaf,
  signWrprc,
  TEST_ENTITLEMENT_MAP,
  type AccessCa,
  type IssuedWrpac,
  type WrprcIssuer,
} from './mock-pki.ts';
import { WRPRC_POLICY_OID } from './oid.ts';
import { validateWrpacChain } from './wrpac.ts';
import { verifyWrprc } from './wrprc.ts';

const REGISTRY_URI = 'https://TEST-registrar.example/api/v1';
const SERVICE_PROVIDER_URI = TEST_ENTITLEMENT_MAP['0.4.0.19475.1.1'];

let accessCa!: AccessCa;
let wrprcIssuer!: WrprcIssuer;
let wrpac!: IssuedWrpac;
let wrprcRaw!: string;
let wrprcLeafCert!: Awaited<ReturnType<typeof createWrprcLeaf>>;

beforeAll(async () => {
  accessCa = await createAccessCa();
  wrprcIssuer = await createWrprcIssuer();
  wrpac = await accessCa.issueWrpac({ subjectCn: 'Test GmbH (TEST)', entitlementOids: [Object.keys(TEST_ENTITLEMENT_MAP)[0]] });
  const leaf = await createWrprcLeaf(wrprcIssuer, 'Test GmbH (TEST)');
  wrprcLeafCert = leaf;
  wrprcRaw = await signWrprc(
    {
      sub: 'test-wrp-1',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      registry_uri: REGISTRY_URI,
      entitlements: [SERVICE_PROVIDER_URI],
      policy_id: [WRPRC_POLICY_OID],
    },
    leaf.key.privateKey,
    [leaf.certDer, wrprcIssuer.certDer],
  );
});

const baseWrpacOptions = () => ({ accessCaAnchors: [accessCa.caCertDer] });
const baseWrprcOptions = () => ({ wrprcIssuerAnchors: [wrprcIssuer.certDer], allowedEntitlements: [SERVICE_PROVIDER_URI] });

describe('Sperrprüfung WRPAC (validateWrpacChain)', () => {
  it('nicht gesperrtes Blatt wird mit aktiver Sperrliste akzeptiert', async () => {
    const revocation = new MockRevocationList();
    await validateWrpacChain(wrpac.certDer, { ...baseWrpacOptions(), revocation });
  });

  it('gesperrtes Blatt wird abgelehnt (ErrRevokedCertificate)', async () => {
    const revocation = new MockRevocationList();
    revocation.revoke(wrpac.certDer);
    await assert.rejects(() => validateWrpacChain(wrpac.certDer, { ...baseWrpacOptions(), revocation }), ErrRevokedCertificate);
  });

  it('NO_REVOCATION muss ausdrücklich übergeben werden (kein stiller Default)', async () => {
    await validateWrpacChain(wrpac.certDer, { ...baseWrpacOptions(), revocation: NO_REVOCATION });
  });
});

describe('Sperrprüfung WRPRC (verifyWrprc)', () => {
  it('nicht gesperrtes Blatt wird mit aktiver Sperrliste akzeptiert', async () => {
    const revocation = new MockRevocationList();
    await verifyWrprc(wrprcRaw, { ...baseWrprcOptions(), revocation });
  });

  it('gesperrtes Blatt wird abgelehnt (ErrRevokedCertificate)', async () => {
    const revocation = new MockRevocationList();
    revocation.revoke(wrprcLeafCert.certDer);
    await assert.rejects(() => verifyWrprc(wrprcRaw, { ...baseWrprcOptions(), revocation }), ErrRevokedCertificate);
  });

  it('gesperrter Issuer-Anker wird nicht geprüft (Anker ausgenommen)', async () => {
    const revocation = new MockRevocationList();
    revocation.revoke(wrprcIssuer.certDer);
    await verifyWrprc(wrprcRaw, { ...baseWrprcOptions(), revocation });
  });
});

describe('Sperrprüfung am Onboarding-Gate', () => {
  it('gesperrtes Registrierungsmaterial -> tenant_registration_invalid', async () => {
    const tenants = new TenantStore();
    tenants.add({
      id: 'tenant-x',
      name: 'Kunde X (TEST)',
      apiKey: 'test-api-key-revocation-X',
      registration: {
        wrpacChain: wrpac.chain,
        wrprc: wrprcRaw,
      },
    });
    const revocation = new MockRevocationList();
    revocation.revoke(wrpac.certDer);
    const gate = new RelyingPartyOnboardingGate({
      tenants,
      accessCaAnchors: [accessCa.caCertDer],
      wrprcIssuerAnchors: [wrprcIssuer.certDer],
      entitlementMap: TEST_ENTITLEMENT_MAP,
      revocation,
    });
    await assert.rejects(() => gate.verifyTenant('tenant-x'), ErrTenantRegistrationInvalid);
  });

  it('nicht gesperrtes Registrierungsmaterial läuft durch das Gate', async () => {
    const tenants = new TenantStore();
    tenants.add({
      id: 'tenant-y',
      name: 'Kunde Y (TEST)',
      apiKey: 'test-api-key-revocation-Y',
      registration: {
        wrpacChain: wrpac.chain,
        wrprc: wrprcRaw,
      },
    });
    const gate = new RelyingPartyOnboardingGate({
      tenants,
      accessCaAnchors: [accessCa.caCertDer],
      wrprcIssuerAnchors: [wrprcIssuer.certDer],
      entitlementMap: TEST_ENTITLEMENT_MAP,
      revocation: new MockRevocationList(),
    });
    const verified = await gate.verifyTenant('tenant-y');
    assert.equal(verified.wrpac.subjectCommonName, 'Test GmbH (TEST)');
  });
});