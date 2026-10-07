/**
 * TEST-PKI für das RP-Onboarding (Baustein B, Test).
 *
 * Erzeugt ausschließlich kurzlebige TEST-Schlüssel im Arbeitsspeicher und
 * TEST-Zertifikate (Access-CA/WRPAC bzw. WRPRC-Issuer/Blatt) mit
 * @peculiar/x509. Nichts wird auf die Platte geschrieben oder geloggt.
 * Die Entitlement-OID-Referenznummern in `TEST_ENTITLEMENT_MAP` folgen
 * Annex A.2 der ETSI TS 119 475 V1.2.1 (2026-03), Annex A.1 gibt den
 * Basis-Arc {0 4 0 19475 1} = "0.4.0.19475.1" (id-etsi-wrpa-entitlement).
 */
import {
  CRLDistributionPointsExtension,
  BasicConstraintsExtension,
  CertificatePolicyExtension,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  type JsonGeneralNames,
  X509Certificate,
  X509CertificateGenerator,
} from '@peculiar/x509';
import { SignJWT, type JWTPayload } from 'jose';

import { WRPRC_JWT_TYPE } from './wrprc.ts';
import { ENTITLEMENTS_NS, ID_ETSI_WRPA_POLICY_IDENTIFIERS_ARC, OID_CLIENT_AUTH } from './oid.ts';
import type { EntitlementMap } from './wrpac.ts';
import type { IntendedUseReference, IntendedUseStatus, WrpItem, WrpStatus } from './registrar.ts';

const TEST_SERIAL = () => crypto.randomUUID().replace(/-/g, '');
const NOW = () => new Date(Date.now() - 60_000);
const IN_FUTURE = (days: number) => new Date(Date.now() + days * 24 * 60 * 60 * 1000);

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}

/** TEST-Schlüsselpaar für Registrar/Trust-List-Authority (nur im Speicher). */
export function generateTestKeyPair(): Promise<CryptoKeyPair> {
  return generateKeyPair();
}

/** TEST-Entitlement-OID -> URI (Nummerierung nach Annex A.2, ETSI TS 119 475 V1.2.1). */
export const TEST_ENTITLEMENT_MAP: EntitlementMap = {
  '0.4.0.19475.1.1': `${ENTITLEMENTS_NS}Service_Provider`,
  '0.4.0.19475.1.5': `${ENTITLEMENTS_NS}PID_Provider`,
  '0.4.0.19475.1.6': `${ENTITLEMENTS_NS}QCert_for_ESeal_Provider`,
  '0.4.0.19475.1.7': `${ENTITLEMENTS_NS}QCert_for_ESig_Provider`,
};

/** Unter dem Entitlement-Arc, aber NICHT belegt (A.2.1–A.2.10 = .1–.10) -> Negativtest. */
export const TEST_UNKNOWN_ENTITLEMENT_OID = '0.4.0.19475.1.11';

/** Nicht-EUDIWRP-Policy (Negativtest: Policy-Anforderung). */
export const TEST_NON_WRPA_POLICY = '1.2.3.4';

/** Beispielhafte WRPAC-Policy unter dem EUDIWRP-Policy-Arc (TS 119 411-8 §5.3, TEST-Nummer). */
export const TEST_WRPAC_POLICY_OID = `${ID_ETSI_WRPA_POLICY_IDENTIFIERS_ARC}.1`;

export interface AccessCa {
  caKey: CryptoKeyPair;
  caCertDer: Uint8Array;
  issueWrpac(options: IssueWrpacOptions): Promise<IssuedWrpac>;
}

/** Explizites Zeitfenster für synthetische TEST-Zertifikate. Nie für Produktion. */
export interface MockCertificateValidity {
  notBefore?: Date;
  notAfter?: Date;
}

export interface IssueWrpacOptions {
  subjectCn: string;
  policyOids?: string[];
  entitlementOids?: string[];
  contactSan?: Array<{ type: 'email' | 'url'; value: string }>;
  extendedKeyUsages?: string[];
  keyUsageDigitalSignature?: boolean;
  notAfterDays?: number;
  validity?: MockCertificateValidity;
  /** Optional: CRL-Distribution-Point (http-URL) für die Sperrprüfung. */
  crlUrl?: string;
}

export interface IssuedWrpac {
  certDer: Uint8Array;
  chain: Uint8Array[];
  key: CryptoKeyPair;
}

export async function createAccessCa(cn = 'Access CA TEST ONLY', validity: MockCertificateValidity = {}): Promise<AccessCa> {
  const caKey = await generateKeyPair();
  const caCert = await X509CertificateGenerator.createSelfSigned({
    serialNumber: TEST_SERIAL(),
    name: `CN=${cn}, C=DE`,
    notBefore: validity.notBefore ?? NOW(),
    notAfter: validity.notAfter ?? IN_FUTURE(30),
    keys: caKey,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [
      new BasicConstraintsExtension(true, 1, true),
      new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
    ],
  });
  const caCertDer = new Uint8Array(caCert.rawData);

  return {
    caKey,
    caCertDer,
    issueWrpac: async (options) => issueWrpac(caKey, caCert.subject, caCertDer, options),
  };
}

async function issueWrpac(caKey: CryptoKeyPair, caCn: string, caCertDer: Uint8Array, options: IssueWrpacOptions): Promise<IssuedWrpac> {
  const key = await generateKeyPair();
  const policies = [...(options.policyOids ?? [TEST_WRPAC_POLICY_OID]), ...(options.entitlementOids ?? [])];
  const eku = options.extendedKeyUsages ?? [OID_CLIENT_AUTH];
  const san = (options.contactSan ?? [{ type: 'email' as const, value: 'admin@TEST.example' }]) as JsonGeneralNames;
  const ku = options.keyUsageDigitalSignature === false ? KeyUsageFlags.keyEncipherment : KeyUsageFlags.digitalSignature;

  const cert = await X509CertificateGenerator.create({
    serialNumber: TEST_SERIAL(),
    subject: `CN=${options.subjectCn}, C=DE`,
    issuer: caCn,
    notBefore: options.validity?.notBefore ?? NOW(),
    notAfter: options.validity?.notAfter ?? IN_FUTURE(options.notAfterDays ?? 30),
    publicKey: key.publicKey,
    signingKey: caKey.privateKey,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [
      new BasicConstraintsExtension(false),
      new KeyUsagesExtension(ku, true),
      ...(eku.length > 0 ? [new ExtendedKeyUsageExtension(eku, false)] : []),
      new CertificatePolicyExtension(policies, false),
      new SubjectAlternativeNameExtension(san, false),
      ...(options.crlUrl ? [new CRLDistributionPointsExtension([options.crlUrl], false)] : []),
    ],
  });

  return {
    certDer: new Uint8Array(cert.rawData),
    chain: [new Uint8Array(cert.rawData), caCertDer],
    key,
  };
}

export interface WrprcIssuer {
  certDer: Uint8Array;
  key: CryptoKeyPair;
}

export async function createWrprcIssuer(cn = 'WRPRC Issuer TEST ONLY', validity: MockCertificateValidity = {}): Promise<WrprcIssuer> {
  const key = await generateKeyPair();
  const cert = await X509CertificateGenerator.createSelfSigned({
    serialNumber: TEST_SERIAL(),
    name: `CN=${cn}, C=DE`,
    notBefore: validity.notBefore ?? NOW(),
    notAfter: validity.notAfter ?? IN_FUTURE(30),
    keys: key,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [
      new BasicConstraintsExtension(true, 1, true),
      new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true),
    ],
  });
  return { certDer: new Uint8Array(cert.rawData), key };
}

export interface WrprcLeaf {
  certDer: Uint8Array;
  key: CryptoKeyPair;
}

export async function createWrprcLeaf(issuer: WrprcIssuer, cn = 'WRP Signing TEST ONLY', validity: MockCertificateValidity = {}): Promise<WrprcLeaf> {
  const key = await generateKeyPair();
  const issuerCert = new X509Certificate(new Uint8Array(issuer.certDer));
  const cert = await X509CertificateGenerator.create({
    serialNumber: TEST_SERIAL(),
    subject: `CN=${cn}, C=DE`,
    issuer: issuerCert.subject,
    notBefore: validity.notBefore ?? NOW(),
    notAfter: validity.notAfter ?? IN_FUTURE(30),
    publicKey: key.publicKey,
    signingKey: issuer.key.privateKey,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [
      new BasicConstraintsExtension(false),
      new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
      new ExtendedKeyUsageExtension([OID_CLIENT_AUTH], false),
    ],
  });
  return { certDer: new Uint8Array(cert.rawData), key };
}

export function signWrprc(payload: Record<string, unknown>, leafKey: CryptoKey, x5c: Uint8Array[]): Promise<string> {
  return new SignJWT(payload as JWTPayload)
    .setProtectedHeader({ alg: 'ES256', typ: WRPRC_JWT_TYPE, x5c: x5c.map((der) => Buffer.from(der).toString('base64')) })
    .sign(leafKey);
}

export async function signRegistrarPayload(payload: Record<string, unknown>, key: CryptoKey): Promise<string> {
  return new SignJWT(payload as JWTPayload).setProtectedHeader({ alg: 'ES256', typ: 'registrar-resp+jwt.test' }).sign(key);
}

export interface MockWrpRecord {
  item: WrpItem;
}

export function testWrp(item: Partial<WrpItem> & { identifier: string }, intendedUses?: IntendedUseReference[]): MockWrpRecord {
  return {
    item: {
      legalName: 'Test GmbH (TEST)',
      registrationId: 'TEST-REG-1',
      country: 'DE',
      status: 'active',
      intendedUses: intendedUses ?? [intendedUse('use-pid-1')],
      ...item,
    },
  };
}

export function intendedUse(identifier: string, status: WrpStatus = 'active', days = 30): IntendedUseReference {
  const createdAt = Math.floor(Date.now() / 1000) - days * 24 * 3600;
  return { identifier, status, createdAt };
}

export function toIntendedUseStatus(item: WrpItem, identifier: string): IntendedUseStatus {
  const use = item.intendedUses.find((u) => u.identifier === identifier);
  if (!use) throw new Error('TEST: unbekannter intended use');
  return {
    identifier: use.identifier,
    status: use.status,
    wrpIdentifier: item.identifier,
    active: use.status === 'active',
    createdAt: use.createdAt,
    revokedAt: use.revokedAt,
  };
}
