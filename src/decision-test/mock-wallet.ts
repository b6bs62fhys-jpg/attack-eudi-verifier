/**
 * TEST-Material und Mock-Wallet für Schritt 1 (Basisentscheidungstest).
 *
 * Nur für Automatiktests / lokale Demo. Es entstehen ausschließlich kurzlebige
 * TEST-Schlüssel im Arbeitsspeicher (CryptoKey + selbstsigniertes TEST-Zertifikat),
 * die nie auf die Platte geschrieben oder geloggt werden. Signaturprüfung und
 * OpenID4VP/SD-JWT-Verarbeitung übernimmt die Bibliothek @openeudi/openid4vp
 * beziehungsweise jose/@peculiar/x509 (Plattform-Standard-Implementierungen).
 */
import { SignJWT, type JWTPayload } from 'jose';
import { X509CertificateGenerator } from '@peculiar/x509';

export interface TestKeyMaterial {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: JsonWebKey;
  x5cBase64: string;
  certDerBytes: Uint8Array;
}

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

/** TEST-Herausgeber-/Inhaberschlüsselpaar (nur im Speicher) plus selbstsigniertes TEST-Zertifikat. */
export async function generateTestKeyMaterial(name: string, validity?: { notBefore: Date; notAfter: Date }): Promise<TestKeyMaterial> {
  const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);

  const cert = await X509CertificateGenerator.createSelfSigned({
    serialNumber: crypto.randomUUID().replace(/-/g, ''),
    name: `CN=${name} TEST ONLY, C=DE`,
    notBefore: validity?.notBefore ?? new Date(Date.now() - 60_000),
    notAfter: validity?.notAfter ?? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    keys: keyPair,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
  });

  const certDerBytes = new Uint8Array(cert.rawData);
  const publicJwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey;
  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicJwk,
    x5cBase64: bytesToBase64(certDerBytes),
    certDerBytes,
  };
}

function base64urlEncodeString(value: string): string {
  return Buffer.from(value, 'utf-8').toString('base64url');
}

async function sha256Base64url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Buffer.from(digest).toString('base64url');
}

export interface BuildSdJwtOptions {
  issuerKey: TestKeyMaterial;
  holderKey?: TestKeyMaterial;
  claimName?: string;
  claimValue?: unknown;
  vct?: string;
  nonce?: string;
  audience?: string;
  expSeconds?: number;
  tamperDisclosure?: boolean;
  /** Zusätzliche, nicht selektiv offengelegte Claims im Issuer-JWT (z. B. `status`). */
  extraClaims?: Record<string, unknown>;
  /** Weitere selektiv offenlegbare Claims (Name -> Wert). */
  additionalDisclosures?: Record<string, unknown>;
  /**
   * Claims, die im Credential **enthalten** sind (der Hash steht im
   * Issuer-JWT), aber in der Präsentation **nicht** offengelegt werden.
   *
   * Das bildet Datenminimierung echt ab: die Wallet hält mehr, als sie
   * herausgibt. Der Prüfer sieht nur, was offengelegt wurde, und eine
   * DCQL-Abfrage nach einem zurückgehaltenen Claim schlägt fehl, weil kein
   * Hash im Issuer-JWT zu einer Offenlegung passt.
   */
  withheldDisclosures?: Record<string, unknown>;
  /** Zusätzliche Zertifikate (Base64-DER) hinter dem Aussteller-Zertifikat im x5c-Header. */
  extraX5c?: string[];
  /**
   * `iat` des KB-JWT in Sekunden. Standard: jetzt. Für Tests mit einer
   * verstellten Dienstuhr, damit das KB-JWT zur Uhr des Dienstes passt.
   */
  kbIat?: number;
}

export interface BuildSdJwtResult {
  sdJwt: string;
  issuerJwt: string;
  disclosures: string[];
  kbJwt?: string;
}

/**
 * Mock-Wallet: stellt eine SD-JWT-VC (PID) für die Präsentation her.
 * Issuer-JWT mit x5c + _sd-Hashes, Disclosures im Anhang, ggf. KB-JWT.
 */
export async function buildSdJwtVc(options: BuildSdJwtOptions): Promise<BuildSdJwtResult> {
  const {
    issuerKey,
    holderKey,
    claimName = 'given_name',
    claimValue = 'Ada',
    vct = 'urn:eu.europa.ec.eudi:pid:1',
    nonce,
    audience,
    expSeconds = 3600,
    tamperDisclosure = false,
    extraClaims = {},
    additionalDisclosures = {},
    withheldDisclosures = {},
    extraX5c = [],
  } = options;

  const salt = crypto.randomUUID();
  const disclosureJson = JSON.stringify([salt, claimName, claimValue]);
  const disclosureB64 = base64urlEncodeString(disclosureJson);
  const sdHash = await sha256Base64url(disclosureB64);

  let presentedDisclosure = disclosureB64;
  if (tamperDisclosure) {
    const tampered: unknown = claimValue === true ? false : typeof claimValue === 'number' ? claimValue + 1 : 'Eve';
    presentedDisclosure = base64urlEncodeString(JSON.stringify([salt, claimName, tampered]));
  }

  const extraDisclosures: string[] = [];
  const extraHashes: string[] = [];
  for (const [name, value] of Object.entries(additionalDisclosures)) {
    const encoded = base64urlEncodeString(JSON.stringify([crypto.randomUUID(), name, value]));
    extraDisclosures.push(encoded);
    extraHashes.push(await sha256Base64url(encoded));
  }
  // Zurückgehaltene Offenlegungen: Hash kommt in den Issuer-JWT, die
  // Offenlegung selbst nicht in die Präsentation.
  for (const [name, value] of Object.entries(withheldDisclosures)) {
    const encoded = base64urlEncodeString(JSON.stringify([crypto.randomUUID(), name, value]));
    extraHashes.push(await sha256Base64url(encoded));
  }

  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    ...extraClaims,
    iss: 'https://TEST-issuer.de',
    vct,
    iat: now,
    exp: now + expSeconds,
    _sd_alg: 'sha-256',
    _sd: [sdHash, ...extraHashes],
  };
  if (holderKey) {
    const holderJwk = (await crypto.subtle.exportKey('jwk', holderKey.publicKey)) as JsonWebKey;
    delete holderJwk.d;
    payload.cnf = { jwk: holderJwk };
  }

  const issuerJwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256', typ: 'vc+sd-jwt', x5c: [issuerKey.x5cBase64, ...extraX5c] })
    .sign(issuerKey.privateKey);

  const disclosurePart = [presentedDisclosure, ...extraDisclosures].map((d) => d + '~').join('');
  let sdJwt = `${issuerJwt}~${disclosurePart}`;
  let kbJwt: string | undefined;

  if (holderKey && nonce) {
    const sdHashOfToken = await sha256Base64url(sdJwt);
    const kbPayload: Record<string, unknown> = { iat: options.kbIat ?? now, nonce, sd_hash: sdHashOfToken };
    if (audience) kbPayload.aud = audience;
    kbJwt = await new SignJWT(kbPayload as JWTPayload).setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' }).sign(holderKey.privateKey);
    sdJwt += kbJwt;
  }

  return { sdJwt, issuerJwt, disclosures: [disclosureB64, ...extraDisclosures], kbJwt };
}