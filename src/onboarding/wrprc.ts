/**
 * WRPRC — Wallet-Relying-Party-Registrierungszertifikat (Baustein B, Prototyp).
 *
 * JWT-Form nach TS 119 475 §5.2 (typ `rc-wrp+jwt`, x5c-Kette):
 * Signaturprüfung über jose, Kettenprüfung der x5c-Kette zu festen
 * WRPRC-Issuer-Ankern über @peculiar/x509, Pflicht-Claims, Gültigkeitsfenster
 * (exp &le; iat + 12 Monate) und Entitlement-Decision.
 *
 * WICHTIG: Im Prototyp wird nur die JWT-Form unterstützt („JWT **oder** CWT“).
 * CWT/COSE_Sign1 ist als bewusste Lücke dokumentiert ([interne Notiz, nicht veröffentlicht]).
 */
import { compactVerify, decodeProtectedHeader } from 'jose';
import { X509Certificate, X509ChainBuilder } from '@peculiar/x509';

import { chainValidityFailure, DEFAULT_CLOCK_SKEW_SECONDS } from '../lib/cert-validity.ts';
import { sha256Hex } from '../trustlist/monitor.ts';
import {
  ErrCertificateExpired,
  ErrCertificateNotYetValid,
  ErrMalformed,
  ErrTrustPath,
  ErrWrprcClaims,
  ErrWrprcEntitlement,
  ErrWrprcExpired,
  ErrWrprcHeader,
  ErrWrprcNotYetValid,
  ErrWrprcPolicyId,
  ErrWrprcSignature,
  ErrWrprcType,
  ErrWrprcUnsupportedSigningAlgorithm,
  ErrWrprcValidity,
} from './errors.ts';
import { WRPRC_POLICY_OID, isEntitlementUri } from './oid.ts';
import { enforceRevocation, type RevocationChecker } from './revocation.ts';

export const WRPRC_JWT_TYPE = 'rc-wrp+jwt';

/** Gültigkeitsfenster-Maximum (ARF): exp darf max. 12 Monate nach iat liegen. */
export const WRPRC_MAX_VALIDITY_SECONDS = 12 * 30 * 24 * 3600;

/** Erlaubte Signaturalgorithmen im Test. */
export const WRPRC_SUPPORTED_ALGS = ['ES256', 'ES384'] as const;


export interface WrprcVerifyOptions {
  /**
   * WRPRC-Issuer-Anker (DER). Die x5c-Kette muss sich zu einem dieser Anker
   * schließen (analog Access-CA, aber separat gemäß Modell).
   */
  wrprcIssuerAnchors: Uint8Array[];
  /** Entitlement-Menge, die fuer die Anfrage zulaessig ist. */
  allowedEntitlements: readonly string[];
  /**
   * Sperrprüfung (Pflicht, siehe revocation.ts): Blatt und
   * Zwischenzertifikate der gebauten Kette werden fail closed geprüft (Anker
   * ausgenommen). Ohne Sperrprüfung nur mit NO_REVOCATION
   * (Entwicklungsschalter).
   */
  revocation: RevocationChecker;
  revocationTimeoutMs?: number;
  policyOid?: string;
  maxValiditySeconds?: number;
  /** Prüfzeitpunkt in Sekunden seit 1970 (injizierbare Uhr), Standard: jetzt. */
  now?: number;
  /**
   * Erlaubte Uhrabweichung in Sekunden, Standard 60: gilt für iat/exp des
   * Tokens und für notBefore/notAfter jedes Zertifikats der Kette.
   */
  clockSkewSeconds?: number;
}

export interface WrprcRead {
  sub: string;
  registryUri: string;
  entitlements: readonly string[];
  policyIds: readonly string[];
  issuedAt: Date;
  expiresAt: Date;
  subjectCommonName: string;
  fingerprintHex: string;
  verifiedAt: Date;
}

export async function verifyWrprc(raw: string, options: WrprcVerifyOptions): Promise<WrprcRead> {
  const nowSeconds = options.now ?? Math.floor(Date.now() / 1000);
  const maxValiditySeconds = options.maxValiditySeconds ?? WRPRC_MAX_VALIDITY_SECONDS;
  const policyOid = options.policyOid ?? WRPRC_POLICY_OID;

  let header: { typ?: string; alg?: string; x5c?: string[] };
  let claims: Record<string, unknown>;
  try {
    header = decodeProtectedHeader(raw);
    const parts = raw.split('.');
    if (parts.length !== 3) throw new Error('kein jws');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
    if (typeof payload !== 'object' || payload === null) throw new Error('payload nicht lesbar');
    claims = payload as Record<string, unknown>;
  } catch {
    throw new ErrMalformed();
  }

  if (header.typ !== WRPRC_JWT_TYPE) throw new ErrWrprcType();
  if (!header.alg || !WRPRC_SUPPORTED_ALGS.includes(header.alg as (typeof WRPRC_SUPPORTED_ALGS)[number])) throw new ErrWrprcUnsupportedSigningAlgorithm();
  if (!Array.isArray(header.x5c) || header.x5c.length === 0) throw new ErrWrprcHeader();

  let leafCert: X509Certificate;
  let chainCerts: X509Certificate[];
  try {
    leafCert = new X509Certificate(Buffer.from(header.x5c[0], 'base64'));
    chainCerts = header.x5c.map((b64) => new X509Certificate(Buffer.from(b64, 'base64')));
  } catch {
    throw new ErrWrprcHeader();
  }

  const leafJwk = (await crypto.subtle.exportKey('jwk', await leafCert.publicKey.export())) as JsonWebKey;
  try {
    // Nur JWS-Signaturprüfung; Zeitfenster/Claims prüfen wir selbst
    // (eigene Fehlerklassen und Prüfreihenfolge).
    await compactVerify(raw, leafJwk, { algorithms: [...WRPRC_SUPPORTED_ALGS] });
  } catch {
    throw new ErrWrprcSignature();
  }

  const clockSkewSeconds = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
  const built = await validateX5cChain(chainCerts, options.wrprcIssuerAnchors, new Date(nowSeconds * 1000), clockSkewSeconds);

  const anchorFingerprints = new Set(options.wrprcIssuerAnchors.map((der) => sha256Hex(new Uint8Array(der))));
  for (let i = 0; i < built.length - 1; i += 1) {
    if (anchorFingerprints.has(sha256Hex(new Uint8Array(built[i].rawData)))) continue;
    const role = i === 0 ? 'leaf' : 'intermediate';
    await enforceRevocation(options.revocation, new Uint8Array(built[i].rawData), role, new Uint8Array(built[i + 1].rawData), options.revocationTimeoutMs);
  }

  const sub = claims.sub;
  if (typeof sub !== 'string' || sub.trim().length === 0) throw new ErrWrprcClaims();
  const iat = claims.iat;
  const exp = claims.exp;
  if (typeof iat !== 'number' || typeof exp !== 'number') throw new ErrWrprcClaims();
  const registryUri = claims.registry_uri;
  if (typeof registryUri !== 'string') throw new ErrWrprcClaims();
  try {
    const url = new URL(registryUri);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('kein http(s)');
  } catch {
    throw new ErrWrprcClaims();
  }
  if (!Array.isArray(claims.entitlements) || claims.entitlements.length === 0 || !claims.entitlements.every((e) => typeof e === 'string' && isEntitlementUri(e))) throw new ErrWrprcClaims();
  if (!Array.isArray(claims.policy_id) || claims.policy_id.length === 0 || !claims.policy_id.every((p) => typeof p === 'string')) throw new ErrWrprcClaims();
  if (!(claims.policy_id as string[]).includes(policyOid)) throw new ErrWrprcPolicyId();

  if (iat > nowSeconds + clockSkewSeconds) throw new ErrWrprcNotYetValid();
  if (exp < nowSeconds - clockSkewSeconds) throw new ErrWrprcExpired();
  if (exp <= iat) throw new ErrWrprcValidity();
  if (exp - iat > maxValiditySeconds) throw new ErrWrprcValidity();

  const entitlements = claims.entitlements as string[];
  const allowed = new Set(options.allowedEntitlements);
  if (!entitlements.some((e) => allowed.has(e))) throw new ErrWrprcEntitlement();

  return {
    sub,
    registryUri: registryUri as string,
    entitlements: [...entitlements],
    policyIds: [...(claims.policy_id as string[])],
    issuedAt: new Date(iat * 1000),
    expiresAt: new Date(exp * 1000),
    subjectCommonName: extractCommonName(leafCert.subject),
    fingerprintHex: sha256Hex(new Uint8Array(leafCert.rawData)),
    verifiedAt: new Date(nowSeconds * 1000),
  };
}

async function validateX5cChain(chainCerts: X509Certificate[], anchors: Uint8Array[], now: Date, clockSkewSeconds: number): Promise<X509Certificate[]> {
  const anchorFingerprints = new Set(anchors.map((der) => sha256Hex(new Uint8Array(der))));
  const builder = new X509ChainBuilder({
    certificates: anchors.map((der) => new X509Certificate(new Uint8Array(der))),
  });

  if (chainCerts.length === 0) throw new ErrTrustPath();
  const leaf = chainCerts[0];
  const built = await builder.build(leaf);
  if (built.length < 1) throw new ErrTrustPath();

  const top = built[built.length - 1];
  if (!anchorFingerprints.has(sha256Hex(new Uint8Array(top.rawData)))) throw new ErrTrustPath();
  if (top.subject !== top.issuer && !chainCerts.some((c) => sha256Hex(new Uint8Array(c.rawData)) === sha256Hex(new Uint8Array(top.rawData)))) {
    throw new ErrTrustPath();
  }

  for (let i = 0; i < built.length - 1; i += 1) {
    const valid = await built[i].verify({ publicKey: built[i + 1].publicKey, date: now, signatureOnly: true });
    if (!valid) throw new ErrTrustPath();
  }
  // Gültigkeitszeitraum jedes Zertifikats der gebauten Kette (Haertung 9).
  const validity = chainValidityFailure(built, now, clockSkewSeconds);
  if (validity === 'certificate_expired') throw new ErrCertificateExpired();
  if (validity === 'certificate_not_yet_valid') throw new ErrCertificateNotYetValid();
  return built;
}

function extractCommonName(subject: string): string {
  const match = /CN=([^,\n]+)/.exec(subject);
  return match ? match[1].trim() : subject;
}