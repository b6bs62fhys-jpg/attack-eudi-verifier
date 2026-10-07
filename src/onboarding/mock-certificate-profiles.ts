/**
 * Synthetische Onboarding-Profile fuer Tests.
 *
 * Jeder Name und jedes Claim ist absichtlich mit TEST ONLY markiert. Diese
 * Profile enthalten keine echten WRPAC/WRPRC-Produktionsdaten und dürfen nicht
 * als Zertifikatsvorlage für produktive Onboarding-Prozesse verwendet werden.
 */
import {
  createAccessCa,
  createWrprcIssuer,
  createWrprcLeaf,
  TEST_ENTITLEMENT_MAP,
  type AccessCa,
  type IssuedWrpac,
  type MockCertificateValidity,
  type WrprcIssuer,
  type WrprcLeaf,
} from './mock-pki.ts';

export const MOCK_ONBOARDING_PROFILE_MARKER = 'ATTACK-TEST-MOCK-NOT-FOR-PRODUCTION';

export interface MockOnboardingCertificateProfile {
  readonly marker: typeof MOCK_ONBOARDING_PROFILE_MARKER;
  readonly accessCa: AccessCa;
  readonly wrpac: IssuedWrpac;
  readonly wrprcIssuer: WrprcIssuer;
  readonly wrprcLeaf: WrprcLeaf;
}

export interface MockOnboardingCertificateProfileOptions {
  accessCa?: MockCertificateValidity;
  wrpac?: MockCertificateValidity;
  wrprcIssuer?: MockCertificateValidity;
  wrprcLeaf?: MockCertificateValidity;
}

/** Erzeugt ein vollständig synthetisches WRPAC-/WRPRC-Testprofil im Speicher. */
export async function createMockOnboardingCertificateProfile(
  options: MockOnboardingCertificateProfileOptions = {},
): Promise<MockOnboardingCertificateProfile> {
  const accessCa = await createAccessCa(`${MOCK_ONBOARDING_PROFILE_MARKER} Access CA`, options.accessCa);
  const wrpac = await accessCa.issueWrpac({
    subjectCn: `${MOCK_ONBOARDING_PROFILE_MARKER} WRPAC`,
    entitlementOids: [Object.keys(TEST_ENTITLEMENT_MAP)[0]],
    validity: options.wrpac,
  });
  const wrprcIssuer = await createWrprcIssuer(`${MOCK_ONBOARDING_PROFILE_MARKER} WRPRC Issuer`, options.wrprcIssuer);
  const wrprcLeaf = await createWrprcLeaf(wrprcIssuer, `${MOCK_ONBOARDING_PROFILE_MARKER} WRPRC`, options.wrprcLeaf);
  return { marker: MOCK_ONBOARDING_PROFILE_MARKER, accessCa, wrpac, wrprcIssuer, wrprcLeaf };
}
