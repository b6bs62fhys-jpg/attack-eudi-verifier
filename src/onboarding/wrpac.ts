/**
 * WRPAC — Wallet-Relying-Party-Zugriffszertifikat (Baustein B, Prototyp).
 *
 * Profilprüfung nach TS 119 411-8 (EUDIWRP-Policy) und Kettenprüfung gegen
 * feste Access-CA-Anker (TEST). Der vollständige Kern der Prüfung läuft
 * über @peculiar/x509 (RFC 5280); zusätzlich werden die WRPA-spezifischen
 * Anforderungen (Policy-OID unter dem EUDIWRP-Arc, Kontakt-SAN, keyUsage,
 * extendedKeyUsage, Entitlement-OIDs) explizit geprüft.
 */
import {
  CertificatePolicyExtension,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  X509Certificate,
  X509ChainBuilder,
} from '@peculiar/x509';

import { chainValidityFailure } from '../lib/cert-validity.ts';
import { sha256Hex } from '../trustlist/monitor.ts';
import {
  ErrCertificateExpired,
  ErrCertificateNotYetValid,
  ErrTrustPath,
  ErrUnknownEntitlement,
  ErrWrpacContactSan,
  ErrWrpacExtKeyUsage,
  ErrWrpacKeyUsage,
  ErrWrpacPolicy,
} from './errors.ts';
import { ID_ETSI_WRPA_ENTITLEMENT_ARC, ID_ETSI_WRPA_POLICY_IDENTIFIERS_ARC, OID_ANY_EXTENDED_KEY_USAGE, OID_CLIENT_AUTH, isOidUnder } from './oid.ts';
import { enforceRevocation, type RevocationChecker } from './revocation.ts';

export interface EntitlementMap {
  /** Entitlement-OID -> ETSI-Entitlement-URI (TEST-Konfiguration, siehe [interne Notiz, nicht veröffentlicht]). */
  [oid: string]: string;
}

export interface WrpacLoadOptions {
  policyArc?: string;
  entitlementMap?: EntitlementMap;
}

export interface Wrpac {
  subjectCommonName: string;
  policies: readonly string[];
  entitlements: readonly string[];
  contactSanValues: readonly string[];
  fingerprintHex: string;
  notBefore: Date;
  notAfter: Date;
}

export interface WrpacChainOptions {
  /** Zugriffs-CA-Anker (DER). Das Blatt muss sich zu einem dieser Anker schließen. */
  accessCaAnchors: Uint8Array[];
  /**
   * Sperrprüfung (Pflicht, siehe revocation.ts): Blatt und
   * Zwischenzertifikate werden fail closed geprüft (Anker ausgenommen).
   * Ohne Sperrprüfung nur mit NO_REVOCATION (Entwicklungsschalter).
   */
  revocation: RevocationChecker;
  revocationTimeoutMs?: number;
  /** Prüfzeitpunkt (injizierbare Uhr), Standard: jetzt. */
  now?: Date;
  /** Erlaubte Uhrabweichung für notBefore/notAfter in Sekunden, Standard 60. */
  clockSkewSeconds?: number;
}

export async function loadWrpac(certDer: Uint8Array, options: WrpacLoadOptions = {}): Promise<Wrpac> {
  const policyArc = options.policyArc ?? ID_ETSI_WRPA_POLICY_IDENTIFIERS_ARC;
  const entitlementMap = options.entitlementMap ?? {};
  const cert = new X509Certificate(new Uint8Array(certDer));

  const policyExt = cert.getExtension(CertificatePolicyExtension);
  if (!policyExt) throw new ErrWrpacPolicy();
  const policies = [...policyExt.policies];
  if (!policies.some((oid) => isOidUnder(oid, policyArc))) throw new ErrWrpacPolicy();

  const entitlements: string[] = [];
  for (const oid of policies) {
    if (isOidUnder(oid, ID_ETSI_WRPA_ENTITLEMENT_ARC)) {
      const uri = entitlementMap[oid];
      if (!uri) throw new ErrUnknownEntitlement();
      entitlements.push(uri);
    }
  }

  const sanExt = cert.getExtension(SubjectAlternativeNameExtension);
  const contactSanValues = sanExt ? sanExt.names.items.map((n) => `${n.type}:${n.value}`).filter((v) => v.startsWith('email:') || v.startsWith('url:')) : [];
  if (contactSanValues.length === 0) throw new ErrWrpacContactSan();

  const kuExt = cert.getExtension(KeyUsagesExtension);
  if (!kuExt || (kuExt.usages & KeyUsageFlags.digitalSignature) === 0) throw new ErrWrpacKeyUsage();

  const ekuExt = cert.getExtension(ExtendedKeyUsageExtension);
  if (ekuExt && !ekuExt.usages.some((u) => String(u) === OID_CLIENT_AUTH || String(u) === OID_ANY_EXTENDED_KEY_USAGE)) throw new ErrWrpacExtKeyUsage();

  return {
    subjectCommonName: extractCommonName(cert.subject),
    policies: [...policies],
    entitlements,
    contactSanValues,
    fingerprintHex: sha256Hex(new Uint8Array(cert.rawData)),
    notBefore: cert.notBefore,
    notAfter: cert.notAfter,
  };
}

/** Kettenprüfung des Zugriffszertifikats bis zu einem Access-CA-Anker. */
export async function validateWrpacChain(certDer: Uint8Array, options: WrpacChainOptions): Promise<void> {
  const now = options.now ?? new Date();
  const cert = new X509Certificate(new Uint8Array(certDer));
  const anchors = new Set(options.accessCaAnchors.map((der) => sha256Hex(new Uint8Array(der))));

  const builder = new X509ChainBuilder({
    certificates: options.accessCaAnchors.map((der) => new X509Certificate(new Uint8Array(der))),
  });
  const chain = await builder.build(cert);
  if (chain.length < 2) throw new ErrTrustPath();

  const last = chain[chain.length - 1];
  if (!anchors.has(sha256Hex(new Uint8Array(last.rawData)))) throw new ErrTrustPath();
  if (last.subject !== last.issuer) throw new ErrTrustPath();

  // Signatur je Glied (signatureOnly: nur die Signatur). Den Gültigkeitszeitraum
  // prüfen wir danach ausdrücklich für JEDES Zertifikat der Kette (Blatt,
  // Zwischenzertifikate, Anker), mit eigenem Fehlercode (Haertung 9).
  for (let i = 0; i < chain.length - 1; i += 1) {
    const valid = await chain[i].verify({ publicKey: chain[i + 1].publicKey, date: now, signatureOnly: true });
    if (!valid) throw new ErrTrustPath();
  }
  const validity = chainValidityFailure(chain, now, options.clockSkewSeconds);
  if (validity === 'certificate_expired') throw new ErrCertificateExpired();
  if (validity === 'certificate_not_yet_valid') throw new ErrCertificateNotYetValid();

  for (let i = 0; i < chain.length - 1; i += 1) {
    const role = i === 0 ? 'leaf' : 'intermediate';
    await enforceRevocation(options.revocation, new Uint8Array(chain[i].rawData), role, new Uint8Array(chain[i + 1].rawData), options.revocationTimeoutMs);
  }
}

function extractCommonName(subject: string): string {
  const match = /CN=([^,\n]+)/.exec(subject);
  return match ? match[1].trim() : subject;
}