/**
 * Dünner Verifier-Dienst (Prototyp) auf Basis von @openeudi/openid4vp v0.11.1.
 *
 * Schnittstellen:
 *   - Prüfanfrage erzeugen (createRequest, mit DCQL-SD-JWT-Query)
 *   - Ergebnis abfragen (getResult, getrennt pro Mandant)
 *   - Sitzung ablaufen lassen / löschen (expireRequest)
 *
 * Mandantenisolation: eigene Sitzungs- und Ergebnis-Sammlung je Mandant.
 * Ergebnisse werden nach Ablauf der Sitzung (TTL) gelöscht. Alle Zustände nur
 * im Arbeitsspeicher; Schlüssel/Zertifikate nur im Speicher, ausschließlich
 * TEST-Material.
 */
import {jwtVerify, createLocalJWKSet, decodeProtectedHeader} from 'jose';

import {buildHaipQuery, createSignedAuthorizationRequest, decryptAuthorizationResponse, StaticTrustStore, verifyAuthorizationResponse, type AuthorizationResponse} from '@openeudi/openid4vp';

import {VpSessionStore} from '../lib/session.ts';
import {AuditLog, type AuditEvent} from './audit.ts';
import {TenantStore} from './tenant.ts';
import {buildAuthorizationRequestJar, DEFAULT_SUPPORTED_ENC_VALUES, VP_FORMATS_SUPPORTED} from '../onboarding/jar.ts';
import {ErrTenantRegistrationInvalid, OnboardingError} from '../onboarding/errors.ts';
import {ConfigError} from '../config.ts';
import {validateRegistrationRefRaw, type RegistrationRef} from '../onboarding/registration-ref.ts';
import type { IssuerTrustPolicy } from '../trustlist/monitor.ts';
import type { OnboardingGatePolicy } from '../onboarding/onboarding-gate.ts';
import {assertRevocationAllowed, DEFAULT_REVOCATION_TIMEOUT_MS, STRICT_MODE, type RevocationChecker, type RuntimeMode} from '../onboarding/revocation.ts';
import {assertCredentialStatusAllowed, CredentialStatusError, type CredentialStatusChecker} from './credential-status.ts';
import {enforceIssuerChainRevocation} from './issuer-revocation.ts';
import {MAX_JWE_CHARS, presentationErrorCode, ServiceInputError, validateClaims, validateVct, vpTokenLimitError} from './limits.ts';
import {certificateValidityFailure, chainValidityFailure, DEFAULT_CLOCK_SKEW_SECONDS, type ValidityFailure} from '../lib/cert-validity.ts';
import {nurAngefragteClaims} from './profile.ts';

export interface CreateRequestInput {
  claims?: string[];
  vct?: string;
  /**
   * RPRC_19a: Registrierungsnachweis des onboardschalteten WP, wird in den
   * Authorization Request eingebettet. Optional; ohne `registrationRef`
   * bleibt der Bibliothekspfad unverändert.
   */
  registrationRef?: RegistrationRef;
}

export interface VerificationResult {
  at: string;
  valid: boolean;
  claims: Record<string, unknown>;
  issuerCountry: string;
  error: string;
}

export interface CreateRequestOutput {
  sessionId: string;
  state: string;
  expiresAt: number;
  requestObject: string;
  responseUri: string;
  requestObjectUri: string;
}

export type ResultStatus =
  | { status: 'completed'; result: VerificationResult }
  | { status: 'pending' }
  | { status: 'expired' }
  | { status: 'not_found' };

export interface ServiceKeys {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: JsonWebKey;
  certificateChain: Uint8Array[];
  encryptionKey?: { privateKey: CryptoKey; publicJwk: JsonWebKey };
}

/** Zusätzliche, benannte Einstellungen (Härtung). */
export interface VerifierServiceOptions {
  /** Laufzeitmodus aus der zentralen Konfiguration; Standard: streng. */
  mode?: RuntimeMode;
  /**
   * Statusprüfung der vorgelegten Credentials (Pflicht). NO_CREDENTIAL_STATUS
   * nur mit Entwicklungsschalter, sonst bricht der Aufbau ab.
   */
  credentialStatus?: CredentialStatusChecker;
  /**
   * Sperrprüfung der Issuer-Zertifikatskette (Pflicht). NO_REVOCATION ist
   * nur mit Entwicklungsschalter außerhalb von Produktion zulässig
   * (`assertRevocationAllowed`). In Produktion liefert
   * `bootstrapService` den `OcspRevocationChecker`.
   */
  issuerRevocation?: RevocationChecker;
  /**
   * Lebensdauer eines fertigen Ergebnisses in Millisekunden. Danach wird es
   * auch ohne Abruf gelöscht (Standard 60 s).
   */
  resultTtlMs?: number;
  /** Uhr (nur für Tests). */
  now?: () => number;
  /** Erlaubte Uhrabweichung in Sekunden für Gültigkeitszeiträume, Standard 60. */
  clockSkewSeconds?: number;
  /** Zeitgrenze je Sperrquelle der Issuer-Kette (ms), Standard 5.000. */
  revocationTimeoutMs?: number;
  /**
   * Zähler für Verwendungen der OCSP-Gnadenfrist (B8). Der OCSP-Beobachter in
   * `bootstrapService` erhöht ihn; der Dienst vergleicht den Wert vor und nach
   * der Kettenprüfung und schreibt bei Bedarf ein Audit-Ereignis.
   */
  gracePeriodSeen?: { count: number };
}

/**
 * Das eigene Verifier-Zertifikat ist abgelaufen oder noch nicht gültig. Kein
 * Eingabefehler des Aufrufers: der HTTP-Rahmen antwortet mit 500
 * `internal_error`, der Grund steht im Audit-Log.
 */
export class VerifierCertificateError extends Error {
  readonly code: ValidityFailure;
  constructor(code: ValidityFailure) {
    super(code);
    this.name = 'VerifierCertificateError';
    this.code = code;
  }
}

export const DEFAULT_RESULT_TTL_MS = 60_000;

interface StoredResult {
  result: VerificationResult;
  expiresAt: number;
}

interface PendingPresentation {
  tenantId: string;
  sessionId: string;
  nonce: string;
  audience: string;
  vct: string;
  claims: string[];
  credentialId: string;
}

type EncryptionPublicJwk = JsonWebKey & { kid?: string };

/**
 * Übersetzt die Sperrcodes der Issuer-Kette in die nach außen dokumentierten
 * Codes aus docs/fehlercodes.md. Unbekanntes wird zu
 * `issuer_revocation_check_failed`; es verlässt keine Rohmeldung das Modul.
 */
function issuerRevocationErrorCode(e: unknown): string {
  if (e instanceof OnboardingError) {
    if (e.code === 'certificate_revoked') return 'issuer_certificate_revoked';
    if (e.code === 'certificate_suspended') return 'issuer_certificate_suspended';
    if (e.code === 'certificate_expired') return 'certificate_expired';
    if (e.code === 'certificate_not_yet_valid') return 'certificate_not_yet_valid';
    if (e.code === 'revocation_source_missing') return 'revocation_source_missing';
    if (e.code === 'revocation_status_unknown') return 'revocation_status_unknown';
  }
  return 'issuer_revocation_check_failed';
}

/** x5c-Zertifikate (DER) aus dem Issuer-JWT-Header des vorgelegten SD-JWT oder `undefined`. */
function issuerCertificatesOf(vpToken: Record<string, Array<string | object>>): Uint8Array[] | undefined {
  const first = Object.values(vpToken)[0]?.[0];
  if (typeof first !== 'string') return undefined;
  const header = first.split('~')[0].split('.')[0];
  try {
    const decoded: unknown = JSON.parse(Buffer.from(header, 'base64url').toString('utf-8'));
    const x5c = (decoded as { x5c?: unknown }).x5c;
    if (!Array.isArray(x5c) || x5c.length === 0 || !x5c.every((c) => typeof c === 'string')) return undefined;
    return x5c.map((c: string) => new Uint8Array(Buffer.from(c, 'base64')));
  } catch {
    return undefined;
  }
}

/** Issuer-JWT-Payload des (einzigen) vorgelegten SD-JWT oder `undefined`. */
function issuerPayloadOf(vpToken: Record<string, Array<string | object>>): Record<string, unknown> | undefined {
  const first = Object.values(vpToken)[0]?.[0];
  if (typeof first !== 'string') return undefined;
  const parts = first.split('~')[0].split('.');
  if (parts.length !== 3) return undefined;
  try {
    const payload: unknown = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
    return typeof payload === 'object' && payload !== null && !Array.isArray(payload) ? (payload as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

export class VerifierService {
  /** Basis-URL wird nach dem Start des HTTP-Servers gesetzt. */
  baseUrl = '';

  private readonly sessionsByTenant = new Map<string, VpSessionStore>();
  private readonly resultsByTenant = new Map<string, Map<string, StoredResult>>();
  private readonly requestObjects = new Map<string, string>();
  private readonly pendingByState = new Map<string, PendingPresentation>();

  private readonly tenants: TenantStore;
  private readonly audit: AuditLog;
  private readonly keys: ServiceKeys;
  /** Aussteller-Vertrauensanker; zur Laufzeit abgefragt (leer -> jede Prüfung abgelehnt). */
  private readonly issuerAnchors: () => readonly Uint8Array[];
  private readonly issuerTrust?: IssuerTrustPolicy;
  private readonly onboarding?: OnboardingGatePolicy;
  private readonly defaultVct: string;
  private readonly defaultClaims: string[];
  private readonly allowSelfSignedCertificate: boolean;
  private readonly credentialStatus: CredentialStatusChecker;
  /** Sperrprüfung der Issuer-Kette (fail closed, siehe issuer-revocation.ts). */
  private readonly issuerRevocation: RevocationChecker;
  /**
   * Anzahl der Verwendungen einer veralteten `good`-OCSP-Antwort (Gnadenfrist).
   * Der OCSP-Checker kennt keinen Mandanten, deshalb wird hier — wo der Mandant
   * bekannt ist — ein Audit-Ereignis geschrieben. Details ohne Zertifikatsdaten
   * (B8).
   */
  /** Gemeinsamer Zähler mit dem OCSP-Beobachter, siehe `gracePeriodSeen`. */
  private readonly gracePeriodSeen: { count: number };
  private readonly resultTtlMs: number;
  private readonly now: () => number;
  private readonly clockSkewSeconds: number;
  private readonly revocationTimeoutMs: number;

  constructor(
    tenants: TenantStore,
    audit: AuditLog,
    keys: ServiceKeys,
    issuerAnchors: Uint8Array | readonly Uint8Array[] | (() => readonly Uint8Array[]),
    defaultVct = 'urn:eu.europa.ec.eudi:pid:1',
    defaultClaims = ['given_name'],
    issuerTrust?: IssuerTrustPolicy,
    onboarding?: OnboardingGatePolicy,
    allowSelfSignedCertificate = false,
    options: VerifierServiceOptions = {},
  ) {
    const mode = options.mode ?? STRICT_MODE;
    assertCredentialStatusAllowed(options.credentialStatus, mode);
    this.credentialStatus = options.credentialStatus as CredentialStatusChecker;
    // Kein Checker bedeutet: es wurde nichts konfiguriert. Das ist in
    // Produktion ein Startabbruch, nicht eine stillschweigende Abschaltung.
    if (options.issuerRevocation === undefined) {
      throw new ConfigError(
        'Keine Sperrprüfung für Aussteller-Zertifikate konfiguriert (OcspRevocationChecker). Start abgebrochen.',
      );
    }
    assertRevocationAllowed(options.issuerRevocation, mode);
    this.issuerRevocation = options.issuerRevocation;
    const resultTtlMs = options.resultTtlMs ?? DEFAULT_RESULT_TTL_MS;
    if (!Number.isFinite(resultTtlMs) || resultTtlMs <= 0) throw new Error('resultTtlMs muss positiv sein');
    this.resultTtlMs = resultTtlMs;
    this.now = options.now ?? (() => Date.now());
    this.clockSkewSeconds = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
    this.revocationTimeoutMs = options.revocationTimeoutMs ?? DEFAULT_REVOCATION_TIMEOUT_MS;
    this.gracePeriodSeen = options.gracePeriodSeen ?? { count: 0 };
    this.tenants = tenants;
    this.audit = audit;
    this.keys = keys;
    if (typeof issuerAnchors === 'function') this.issuerAnchors = issuerAnchors;
    else if (issuerAnchors instanceof Uint8Array) this.issuerAnchors = () => [issuerAnchors];
    else {
      const fixed = [...issuerAnchors];
      this.issuerAnchors = () => fixed;
    }
    this.issuerTrust = issuerTrust;
    this.onboarding = onboarding;
    this.defaultVct = defaultVct;
    this.defaultClaims = defaultClaims;
    this.allowSelfSignedCertificate = allowSelfSignedCertificate;
  }

  private sessionsFor(tenantId: string): VpSessionStore {
    let store = this.sessionsByTenant.get(tenantId);
    if (!store) {
      store = new VpSessionStore(this.tenants.byId(tenantId)?.requestTtlSeconds ?? 300);
      this.sessionsByTenant.set(tenantId, store);
    }
    return store;
  }

  private resultsFor(tenantId: string): Map<string, StoredResult> {
    let results = this.resultsByTenant.get(tenantId);
    if (!results) {
      results = new Map();
      this.resultsByTenant.set(tenantId, results);
    }
    return results;
  }

  private auditTenant(tenantId: string, event: AuditEvent, detail?: string): void {
    this.audit.record(tenantId, event, detail);
  }

  /**
   * Schreibt das Audit-Ereignis für die Gnadenfrist, wenn sie zwischen den
   * beiden Zeitpunkten verwendet wurde (B8). Format wie im übrigen Dienst:
   * `session=<uuid> reason=<code>`, keine Claim-, Zertifikats- oder
   * Responder-Daten.
   */
  private auditGracePeriodIfUsed(tenantId: string, state: string, vorher: number): void {
    if (this.gracePeriodSeen.count === vorher) return;
    this.auditTenant(tenantId, 'issuer_revocation_grace_period', `session=${state} reason=stale_good_reused`);
  }

  /** Entfernt alle Spuren einer Sitzung (Ergebnis, Zuordnung, Request Object, Sitzung). */
  private forget(tenantId: string, sessionId: string): void {
    this.resultsFor(tenantId).delete(sessionId);
    this.pendingByState.delete(sessionId);
    this.requestObjects.delete(sessionId);
    this.sessionsFor(tenantId).delete(sessionId);
  }

  /** Löscht Ergebnisse, deren Lebensdauer abgelaufen ist (auch ohne Abruf). */
  purgeExpiredResults(): void {
    for (const sessions of this.sessionsByTenant.values()) sessions.clearExpiredKeys();
    const now = this.now();
    for (const [tenantId, results] of this.resultsByTenant) {
      for (const [sessionId, stored] of results) {
        if (stored.expiresAt <= now) {
          this.forget(tenantId, sessionId);
          this.auditTenant(tenantId, 'result_expired', `session=${sessionId}`);
        }
      }
    }
  }

  private async freshEncryptionKeyPair(sessionId: string): Promise<{ publicJwk: EncryptionPublicJwk; privateKey: CryptoKey }> {
    const keyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const publicJwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as EncryptionPublicJwk;
    publicJwk.alg = 'ECDH-ES';
    publicJwk.use = 'enc';
    publicJwk.kid = sessionId;
    return { publicJwk, privateKey: keyPair.privateKey };
  }

  /** Prüfanfrage für einen Mandanten erzeugen. Validiert alle Eingaben. */
  async createRequest(tenantId: string, input: CreateRequestInput): Promise<CreateRequestOutput> {
    this.purgeExpiredResults();
    // Eigenes Verifier-Zertifikat muss jetzt gültig sein (Haertung 9): ein
    // Zertifikat kann während des Betriebs ablaufen.
    const verifierValidity = chainValidityFailure(this.keys.certificateChain, new Date(this.now()), this.clockSkewSeconds);
    if (verifierValidity) {
      this.auditTenant(tenantId, 'request_rejected', `reason=verifier_${verifierValidity}`);
      throw new VerifierCertificateError(verifierValidity);
    }
    const tenant = this.tenants.byId(tenantId);
    if (!tenant) throw new Error('unbekannter Mandant');

    const profile = tenant.requestProfile;
    const claims = validateClaims(input.claims ?? profile.claims);
    if (claims.some((claim) => !profile.claims.includes(claim))) throw new ServiceInputError('claims_invalid');
    const vct = validateVct(input.vct ?? profile.vct);
    if (vct !== profile.vct) throw new ServiceInputError('vct_invalid');

    if (!this.baseUrl) throw new Error('baseUrl ist nicht gesetzt');
    const sessions = this.sessionsFor(tenantId);
    const responseUri = `${this.baseUrl}/direct_post`;
    const session = sessions.create({ audience: '', clientId: '', responseUri });
    let enc: { publicJwk: EncryptionPublicJwk; privateKey: CryptoKey };
    try {
      enc = await this.freshEncryptionKeyPair(session.id);
    } catch (error) {
      sessions.delete(session.id);
      throw error;
    }
    session.decryptionKey = enc.privateKey;
    const requestUri = `${this.baseUrl}/v1/verification-requests/${session.id}/request-object`;

    const haipQuery = buildHaipQuery({ credentialId: profile.credentialId, format: 'dc+sd-jwt', vctValues: [vct], claims });

    // Gate: Ist das onboardschaltete Onboarding-Gate aktiv, muss der anfragende
    // Mandant eine gültige TEST-WRPAC/WRPRC-Registrierung besitzen. Der
    // eingebettete registration_ref (RPRC_19a) wird gegen die WRPRC geprüft
    // (registry_uri + client_id/sub) bzw. aus dem verifizierten Material abgeleitet.
    let registrationRef: RegistrationRef | undefined;
    if (this.onboarding) {
      let registration: Awaited<ReturnType<typeof this.onboarding.verifyTenant>>;
      try {
        registration = await this.onboarding.verifyTenant(tenantId);
      } catch (e) {
        const code = e instanceof OnboardingError ? e.code : 'tenant_not_registered';
        const cause = e instanceof ErrTenantRegistrationInvalid ? ` cause=${e.reason}` : '';
        this.auditTenant(tenantId, 'request_rejected', `reason=${code}${cause}`);
        throw e;
      }
      if (input.registrationRef) {
        const ref = validateRegistrationRefRaw(input.registrationRef);
        this.onboarding.assertRegistrationRefMatches(ref, registration);
        registrationRef = ref;
      } else {
        registrationRef = this.onboarding.deriveRegistrationRef(registration);
      }
    } else if (input.registrationRef) {
      registrationRef = validateRegistrationRefRaw(input.registrationRef);
    }

    let requestObject: string;
    let audience: string;
    try {
      if (registrationRef) {
        const jar = await buildAuthorizationRequestJar({
          requestUri,
          responseUri,
          nonce: session.nonce,
          state: session.id,
          dcqlQuery: haipQuery as unknown,
          registrationRef,
          privateKey: this.keys.privateKey,
          certificateChain: this.keys.certificateChain,
          vpFormatsSupported: VP_FORMATS_SUPPORTED,
          encryption: { publicJwk: enc.publicJwk, supportedEncValues: DEFAULT_SUPPORTED_ENC_VALUES },
        });
        requestObject = jar.requestObject;
      } else {
        const signed = await createSignedAuthorizationRequest(
          {
            clientIdPrefix: 'x509_hash',
            requestUri,
            responseUri,
            nonce: session.nonce,
            state: session.id,
            responseMode: 'direct_post.jwt',
            signer: { privateKey: this.keys.privateKey, publicKey: this.keys.publicKey },
            signingAlgorithm: 'ES256',
            certificateChain: this.keys.certificateChain,
            allowSelfSignedCertificate: this.allowSelfSignedCertificate,
            vpFormatsSupported: VP_FORMATS_SUPPORTED,
            encryptionKey: { publicJwk: enc.publicJwk, supportedEncValues: [...DEFAULT_SUPPORTED_ENC_VALUES] },
          },
          haipQuery,
        );
        requestObject = signed.requestObject;
      }

      const { payload } = await jwtVerify(requestObject, createLocalJWKSet({ keys: [this.keys.publicJwk] }));
      audience = typeof payload.client_id === 'string' ? payload.client_id : '';
    } catch (error) {
      this.pendingByState.delete(session.id);
      this.requestObjects.delete(session.id);
      sessions.delete(session.id);
      throw error;
    }

    this.pendingByState.set(session.id, { tenantId, sessionId: session.id, nonce: session.nonce, audience, vct, claims, credentialId: profile.credentialId });
    this.requestObjects.set(session.id, requestObject);
    this.auditTenant(tenantId, 'request_created', `session=${session.id}`);

    return {
      sessionId: session.id,
      state: session.id,
      expiresAt: session.expiresAt,
      requestObject,
      responseUri,
      requestObjectUri: requestUri,
    };
  }

  getRequestObject(sessionId: string): string | undefined {
    return this.requestObjects.get(sessionId);
  }

  private trustedIssuerAnchors(pending: PendingPresentation): { error?: string; anchors: readonly Uint8Array[] } {
    const configuredAnchors = this.issuerAnchors();
    if (configuredAnchors.length === 0) {
      this.auditTenant(pending.tenantId, 'presentation_invalid', `session=${pending.sessionId} reason=issuer_trust_anchors_empty`);
      return { error: 'issuer_trust_anchors_empty', anchors: [] };
    }
    const checkTime = new Date(this.now());
    const validAnchors = configuredAnchors.filter((der) => !certificateValidityFailure(der, checkTime, this.clockSkewSeconds));
    if (validAnchors.length === 0) {
      const failure = certificateValidityFailure(configuredAnchors[0], checkTime, this.clockSkewSeconds) ?? 'certificate_expired';
      this.auditTenant(pending.tenantId, 'presentation_invalid', `session=${pending.sessionId} reason=${failure}`);
      return { error: failure, anchors: [] };
    }
    const trustedAnchors = this.issuerTrust ? validAnchors.filter((der) => this.issuerTrust?.isIssuerTrusted(der)) : [...validAnchors];
    if (trustedAnchors.length === 0) {
      this.auditTenant(pending.tenantId, 'presentation_invalid', `session=${pending.sessionId} reason=issuer_not_trusted`);
      return { error: 'issuer_not_trusted', anchors: [] };
    }
    return { anchors: trustedAnchors };
  }

  private async processPresentation(
    pending: PendingPresentation,
    state: string,
    vpToken: Record<string, Array<string | object>>,
    trustedAnchors: readonly Uint8Array[],
  ): Promise<{ ok: boolean; valid: boolean; error?: string }> {
    // Ohne Initialwert: try und catch weisen beide zu, ein Vorgabewert würde
    // von keinem Pfad gelesen und wäre toter Code.
    let valid: boolean;
    let claims: Record<string, unknown> = {};
    let issuerCountry = '';
    let error: string;
    try {
      const ver = await verifyAuthorizationResponse(
        { vp_token: vpToken, state },
        buildHaipQuery({
          credentialId: pending.credentialId,
          format: 'dc+sd-jwt',
          vctValues: [pending.vct],
          claims: pending.claims,
        }),
        {
          trustedCertificates: [],
          trustStore: new StaticTrustStore([...trustedAnchors]),
          // 'prefer' und nicht 'require': die verbindliche Sperrprüfung ist der
          // eigene OcspRevocationChecker (siehe enforceIssuerChainRevocation,
          // weiter unten). Er darf nach [interne Notiz, nicht veröffentlicht]
          // (Option B) eine veraltete, verifizierte `good`-Antwort bis 24 h
          // weiterverwenden. Die Bibliothek läuft als zweite, unabhaengige
          // Instanz: sie kann durch `revoked` nur ablehnen, nie annehmen, und
          // ihr Ausfall darf die Freigabe nicht verhindern. Mit 'require' wuerde
          // sie genau das erzwingen und die Entscheidung aushebeln.
          revocationPolicy: 'prefer',
          clockSkewTolerance: this.clockSkewSeconds,
          nonce: pending.nonce,
          audience: pending.audience,
        },
      );
      valid = ver.valid;
      // Nur die angefragten und offengelegten Claims dürfen ins Ergebnis. Die
      // Bibliothek liefert in `parsed.claims` auch Klartext-Angaben aus dem
      // Aussteller-JWT, die der Prüfer nie angefragt hat. Gehashte Angaben
      // betrifft das nicht, weil ohne Offenlegung kein passender Wert
      // existiert — deshalb blieb der Fehler lange unbemerkt.
      claims = ver.valid ? nurAngefragteClaims(ver.parsed.claims as Record<string, unknown>, pending.claims) : {};
      issuerCountry = ver.parsed.issuer.country;
      error = valid ? '' : 'presentation_invalid';
    } catch (e) {
      valid = false;
      error = presentationErrorCode(e);
    }

    if (valid) {
      const issuerCerts = issuerCertificatesOf(vpToken);
      const failure = issuerCerts ? chainValidityFailure(issuerCerts, new Date(this.now()), this.clockSkewSeconds) : 'credential_malformed';
      if (failure) {
        this.auditTenant(pending.tenantId, 'presentation_invalid', `session=${state} reason=${failure}`);
        return { ok: true, valid: false, error: failure };
      }
    }

    if (valid) {
      // Zertifikatssperrung (OCSP) vor dem Credential-Status. Wird hier
      // abgelehnt, ist die Praesentation ungueltig.
      const presented = issuerCertificatesOf(vpToken);
      if (!presented) {
        this.auditTenant(pending.tenantId, 'presentation_invalid', `session=${state} reason=issuer_chain_invalid`);
        return { ok: true, valid: false, error: 'issuer_chain_invalid' };
      }
      const gnadenfristVorher = this.gracePeriodSeen.count;
      try {
        await enforceIssuerChainRevocation(this.issuerRevocation, presented, trustedAnchors, this.revocationTimeoutMs);
        this.auditGracePeriodIfUsed(pending.tenantId, state, gnadenfristVorher);
      } catch (e) {
        const code = issuerRevocationErrorCode(e);
        this.auditTenant(pending.tenantId, 'presentation_invalid', `session=${state} reason=${code}`);
        return { ok: true, valid: false, error: code };
      }
    }

    if (valid) {
      const issuerPayload = issuerPayloadOf(vpToken);
      try {
        if (!issuerPayload) throw new CredentialStatusError('credential_status_reference_invalid');
        await this.credentialStatus.check(issuerPayload);
      } catch (e) {
        valid = false;
        error = e instanceof CredentialStatusError ? e.code : 'credential_status_unknown';
        this.auditTenant(pending.tenantId, 'presentation_invalid', `session=${state} reason=${error}`);
        // `valid` statt eines zweiten Literals: sonst stand die Zuweisung oben
        // tot neben einem doppelten false.
        return { ok: true, valid, error };
      }
    }

    if (valid) {
      this.resultsFor(pending.tenantId).set(state, {
        result: { at: new Date().toISOString(), valid, claims, issuerCountry, error },
        expiresAt: this.now() + this.resultTtlMs,
      });
    }
    this.auditTenant(pending.tenantId, valid ? 'presentation_valid' : 'presentation_invalid', valid ? `session=${state}` : `session=${state} reason=${error}`);
    return { ok: true, valid, ...(error ? { error } : {}) };
  }

  /** Präsentation (direct_post) verarbeiten. Zustand enthält Auftragszuordnung. */
  async handlePresentation(state: string, vpToken: Record<string, Array<string | object>>): Promise<{ ok: boolean; valid: boolean; error?: string }> {
    const limitError = vpTokenLimitError(state, vpToken);
    if (limitError) {
      this.audit.record('unknown', 'presentation_rejected', `reason=${limitError}`);
      return { ok: false, valid: false, error: limitError };
    }
    const pending = this.pendingByState.get(state);
    if (!pending) {
      this.audit.record('unknown', 'presentation_rejected', 'reason=unknown_state');
      return { ok: false, valid: false, error: 'unknown_state' };
    }

    const trust = this.trustedIssuerAnchors(pending);
    if (trust.error) return { ok: true, valid: false, error: trust.error };

    const sessions = this.sessionsFor(pending.tenantId);
    const claimed = sessions.consume(state);
    if (!('session' in claimed)) {
      sessions.dropDecryptionKey(state);
      this.auditTenant(pending.tenantId, 'presentation_rejected', `session=${state} reason=${claimed.reason}`);
      return { ok: false, valid: false, error: claimed.reason };
    }
    if (claimed.session.id !== pending.sessionId) {
      sessions.dropDecryptionKey(state);
      this.auditTenant(pending.tenantId, 'presentation_rejected', `session=${state} reason=state_mismatch`);
      return { ok: false, valid: false, error: 'state_mismatch' };
    }

    try {
      return await this.processPresentation(pending, state, vpToken, trust.anchors);
    } finally {
      sessions.dropDecryptionKey(state);
    }
  }

  async handleEncryptedPresentation(jwe: string): Promise<{ ok: boolean; valid: boolean; error?: string }> {
    if (typeof jwe !== 'string' || jwe.length > MAX_JWE_CHARS) {
      this.audit.record('unknown', 'presentation_rejected', 'reason=jwe_too_long');
      return { ok: false, valid: false, error: 'jwe_too_long' };
    }
    let kid: unknown;
    try {
      kid = decodeProtectedHeader(jwe).kid;
    } catch {
      this.audit.record('unknown', 'presentation_rejected', 'reason=malformed_jwe_header');
      return { ok: false, valid: false, error: 'malformed_jwe_header' };
    }
    if (typeof kid !== 'string' || kid.length === 0 || kid.length > 128) {
      this.audit.record('unknown', 'presentation_rejected', 'reason=missing_kid');
      return { ok: false, valid: false, error: 'missing_kid' };
    }

    const pending = this.pendingByState.get(kid);
    if (!pending) {
      this.audit.record('unknown', 'presentation_rejected', 'reason=unknown_state');
      return { ok: false, valid: false, error: 'unknown_state' };
    }

    const trust = this.trustedIssuerAnchors(pending);
    if (trust.error) return { ok: true, valid: false, error: trust.error };

    const sessions = this.sessionsFor(pending.tenantId);
    const claimed = sessions.consume(kid);
    if (!('session' in claimed)) {
      sessions.dropDecryptionKey(kid);
      this.auditTenant(pending.tenantId, 'presentation_rejected', `session=${kid} reason=${claimed.reason}`);
      return { ok: false, valid: false, error: claimed.reason };
    }
    if (claimed.session.id !== pending.sessionId) {
      sessions.dropDecryptionKey(kid);
      this.auditTenant(pending.tenantId, 'presentation_rejected', `session=${kid} reason=state_mismatch`);
      return { ok: false, valid: false, error: 'state_mismatch' };
    }
    if (!claimed.session.decryptionKey) {
      this.auditTenant(pending.tenantId, 'presentation_rejected', `session=${kid} reason=jwe_not_supported`);
      return { ok: false, valid: false, error: 'jwe_not_supported' };
    }

    let envelope: AuthorizationResponse;
    try {
      envelope = await decryptAuthorizationResponse(jwe, claimed.session.decryptionKey);
    } catch {
      sessions.dropDecryptionKey(kid);
      this.auditTenant(pending.tenantId, 'presentation_rejected', `session=${kid} reason=jwe_decrypt_failed`);
      return { ok: false, valid: false, error: 'jwe_decrypt_failed' };
    }

    if (typeof envelope.state !== 'string' || envelope.state.length === 0 || envelope.state.length > 128) {
      sessions.dropDecryptionKey(kid);
      this.auditTenant(pending.tenantId, 'presentation_rejected', `session=${kid} reason=missing_state_in_jwe`);
      return { ok: false, valid: false, error: 'missing_state_in_jwe' };
    }
    if (envelope.state !== kid) {
      sessions.dropDecryptionKey(kid);
      this.auditTenant(pending.tenantId, 'presentation_rejected', `session=${kid} reason=state_mismatch`);
      return { ok: false, valid: false, error: 'state_mismatch' };
    }
    const limitError = vpTokenLimitError(envelope.state, envelope.vp_token);
    if (limitError) {
      sessions.dropDecryptionKey(kid);
      this.auditTenant(pending.tenantId, 'presentation_rejected', `session=${kid} reason=${limitError}`);
      return { ok: false, valid: false, error: limitError };
    }

    sessions.dropDecryptionKey(kid);
    return this.processPresentation(pending, envelope.state, envelope.vp_token, trust.anchors);
  }

  /**
   * Ergebnis eines Mandanten abfragen – ohne Zugriff auf fremde Mandanten.
   *
   * Genau einmal: Ein fertiges Ergebnis wird beim Abruf verbraucht und die
   * Sitzung vollständig entfernt. Jeder weitere Abruf liefert `not_found`,
   * ununterscheidbar von einer Sitzung, die nie existierte. Die Methode ist
   * synchron; zwei gleichzeitige Abrufe werden daher nacheinander bedient und
   * nur der erste erhält das Ergebnis.
   */
  getResult(tenantId: string, sessionId: string): ResultStatus {
    this.purgeExpiredResults();
    const sessions = this.sessionsFor(tenantId);
    const session = sessions.get(sessionId);
    if (!session) return { status: 'not_found' };
    if (sessions.isExpired(sessionId)) {
      this.resultsFor(tenantId).delete(sessionId);
      this.auditTenant(tenantId, 'session_expired', `session=${sessionId}`);
      return { status: 'expired' };
    }
    const stored = this.resultsFor(tenantId).get(sessionId);
    if (!stored) return { status: 'pending' };
    this.forget(tenantId, sessionId);
    this.auditTenant(tenantId, 'result_read', `session=${sessionId}`);
    return { status: 'completed', result: stored.result };
  }

  /** Sitzung ablaufen lassen / löschen (nur für den zugehörigen Mandanten). */
  expireRequest(tenantId: string, sessionId: string): boolean {
    const sessions = this.sessionsFor(tenantId);
    const session = sessions.get(sessionId);
    if (!session) return false;
    this.pendingByState.delete(sessionId);
    this.requestObjects.delete(sessionId);
    this.resultsFor(tenantId).delete(sessionId);
    sessions.delete(sessionId);
    this.auditTenant(tenantId, 'session_deleted', `session=${sessionId}`);
    return true;
  }
}