/**
 * JAR-Erweiterung mit `registration_ref` (RPRC_19a) — Baustein B, Prototyp.
 *
 * Die Basisbibliothek `createSignedAuthorizationRequest` erlaubt keine
 * zusätzlichen Claims und exportiert ihren internen Signierer nicht
 * (geprüft an `node_modules/@openeudi/openid4vp/dist/index.js`). Für den
 * Fall, dass ein `registrationRef` angegeben ist, wird hier ein Request
 * Object nach RFC 9101/OpenID4VP-Struktur selbst signiert (jose), **angeglichen
 * an den Bibliothekspfad**: identischer Header `{ typ: 'oauth-authz-req+jwt',
 * alg, x5c }` in identischer Reihenfolge, Payload mit iss/aud/response_type/
 * response_mode/client_id/response_uri/nonce/state/dcql_query/client_metadata/
 * iat/exp (exp = iat + 120, einstellbar über `ttlSeconds`), client_id `x509_hash:<base64url(SHA-256(Blatt-DER))>`.
 * Bewusste Zusätze unseres Pfads sind ausschließlich `request_uri` im Payload und
 * `registration_ref`. Zusätzlich unterstützt unser eigener Pfad — exakt wie der
 * Bibliothekspfad — Response-Verschlüsselung (direct_post.jwt): bei gesetzter
 * `encryption` wird response_mode 'direct_post.jwt' verwendet und jwks +
 * encrypted_response_enc_values_supported in client_metadata eingetragen.
 * Die Gleichheit beider Pfade sichert der Äquivalenztest
 * `src/service/jar-parity.test.ts`. Ohne `registrationRef` und ohne
 * `verifierInfo` bleibt der Bibliothekspfad unverändert (Abwärtskompatibilität).
 *
 * `verifierInfo`: das Registrierungszertifikat für die Wallet, als Liste
 * `[{ format: 'registration_cert', data: <JWT> }]` (OpenID4VP 1.0, offizielle
 * Developer-Doku "Using Registrar Certificates in Presentation Requests",
 * Referenzimplementierung EUDIPLO). Auch dafür wird dieser Pfad verwendet, weil
 * die Bibliothek keine zusätzlichen Claims erlaubt.
 *
 * Dieselben Vorprüfungen wie im Bibliothekspfad (`createSignedAuthorizationRequest`):
 * der Signaturschlüssel muss zum Blattzertifikat passen, und ein
 * selbstsigniertes Blatt wird nur mit `allowSelfSignedCertificate` akzeptiert.
 * Sonst wäre der eigene Pfad lockerer als der Bibliothekspfad.
 */
import 'reflect-metadata';

import { createHash } from 'node:crypto';
import { X509Certificate } from '@peculiar/x509';
import { SignJWT, type JWTPayload } from 'jose';

import { ErrRegistrationRef } from './errors.ts';
import { toRegistrationRefClaim, validateRegistrationRefRaw, type RegistrationRef } from './registration-ref.ts';

/** Fehler beim Bau des Request Objects (Konfiguration, nicht Eingabe des Aufrufers). */
export class JarBuildError extends Error {
  readonly code: 'signing_key_cert_mismatch' | 'self_signed_leaf';
  constructor(code: 'signing_key_cert_mismatch' | 'self_signed_leaf') {
    super(code);
    this.name = 'JarBuildError';
    this.code = code;
  }
}

/** Eintrag in `verifier_info` (OpenID4VP 1.0), z. B. das Registrierungszertifikat. */
export interface JarVerifierInfo {
  format: string;
  data: string;
}

/**
 * VP-Formate des Verifier-Testdienstes, gemeinsame Quelle für beide JAR-Pfade.
 *
 * Die Feldnamen schreiben sich mit Bindestrich: `sd-jwt_alg_values` und
 * `kb-jwt_alg_values`. So stehen sie im Beispiel der offiziellen
 * Developer-Doku ("Presenting a PID online", client_metadata) und in der
 * Referenzimplementierung EUDIPLO. Vorher standen hier Unterstriche.
 */
export const VP_FORMATS_SUPPORTED: Record<string, unknown> = {
  'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] },
};

/** Standard-Verschlüsselungs-Algorithmen für direct_post.jwt (OpenID4VP 1.0 §7.3.2). */
export const DEFAULT_SUPPORTED_ENC_VALUES = ['A128GCM', 'A256GCM'] as const;

export interface JarEncryption {
  /** Öffentlicher Verschlüsselungs-Schlüssel des Verifiers (JWE-Empfänger). */
  publicJwk: JsonWebKey;
  supportedEncValues?: readonly string[];
}

export interface JarBuildOptions {
  requestUri: string;
  responseUri: string;
  nonce: string;
  state: string;
  dcqlQuery: unknown;
  /** Optional: registration_ref (RPRC_19a). */
  registrationRef?: RegistrationRef;
  /** Optional: verifier_info, z. B. das Registrierungszertifikat. */
  verifierInfo?: readonly JarVerifierInfo[];
  privateKey: CryptoKey;
  /** Öffentlicher Schlüssel zu `privateKey`; wird gegen das Blattzertifikat geprüft. */
  publicKey: CryptoKey;
  /** Selbstsigniertes Blattzertifikat zulassen (nur Entwicklung und Tests), wie im Bibliothekspfad. */
  allowSelfSignedCertificate?: boolean;
  certificateChain: Uint8Array[];
  /** Wie im Bibliothekspfad (client_metadata.vp_formats_supported); Default: VP_FORMATS_SUPPORTED. */
  vpFormatsSupported?: Record<string, unknown>;
  /** Wie im Bibliothekspfad: schaltet auf response_mode direct_post.jwt um und trägt jwks + enc-Werte ein. */
  encryption?: JarEncryption;
  /** Für Tests fixierbare Zeit (Sekunden); Default: Zeitpunkt des Aufrufs. */
  now?: number;
  /** Gültigkeit des Request Objects in Sekunden (`exp` = `iat` + Wert); Standard 120, wie im Bibliothekspfad. */
  ttlSeconds?: number;
}

export interface JarResult {
  requestObject: string;
  clientId: string;
}

export async function buildAuthorizationRequestJar(options: JarBuildOptions): Promise<JarResult> {
  const ref = options.registrationRef ? validateRegistrationRefRaw(options.registrationRef) : undefined;
  if (options.certificateChain.length === 0) throw new ErrRegistrationRef();
  const leaf = options.certificateChain[0];
  const leafCert = new X509Certificate(new Uint8Array(leaf));
  const signerSpki = new Uint8Array(await crypto.subtle.exportKey('spki', options.publicKey));
  const leafSpki = new Uint8Array(leafCert.publicKey.rawData);
  if (signerSpki.length !== leafSpki.length || !signerSpki.every((byte, i) => byte === leafSpki[i])) {
    throw new JarBuildError('signing_key_cert_mismatch');
  }
  if (options.allowSelfSignedCertificate !== true && (await leafCert.isSelfSigned())) throw new JarBuildError('self_signed_leaf');
  const clientId = `x509_hash:${createHash('sha256').update(leaf).digest('base64url')}`;
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const vpFormatsSupported = options.vpFormatsSupported ?? VP_FORMATS_SUPPORTED;

  const responseMode = options.encryption ? 'direct_post.jwt' : 'direct_post';
  const clientMetadata: Record<string, unknown> = { vp_formats_supported: vpFormatsSupported };
  if (options.encryption) {
    clientMetadata.jwks = { keys: [{ ...options.encryption.publicJwk, use: 'enc' }] };
    clientMetadata.encrypted_response_enc_values_supported = options.encryption.supportedEncValues
      ? [...options.encryption.supportedEncValues]
      : [...DEFAULT_SUPPORTED_ENC_VALUES];
  }

  const payload: Record<string, unknown> = {
    iss: clientId,
    aud: 'https://self-issued.me/v2',
    response_type: 'vp_token',
    response_mode: responseMode,
    client_id: clientId,
    request_uri: options.requestUri,
    response_uri: options.responseUri,
    nonce: options.nonce,
    state: options.state,
    dcql_query: options.dcqlQuery,
    client_metadata: clientMetadata,
    iat: now,
    exp: now + (options.ttlSeconds ?? 120),
    ...(ref ? toRegistrationRefClaim(ref) : {}),
    ...(options.verifierInfo && options.verifierInfo.length > 0
      ? { verifier_info: options.verifierInfo.map((entry) => ({ format: entry.format, data: entry.data })) }
      : {}),
  };

  const requestObject = await new SignJWT(payload as JWTPayload)
    .setProtectedHeader({
      typ: 'oauth-authz-req+jwt',
      alg: 'ES256',
      x5c: options.certificateChain.map((der) => Buffer.from(der).toString('base64')),
    })
    .sign(options.privateKey);

  return { requestObject, clientId };
}