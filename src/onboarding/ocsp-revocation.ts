/**
 * Sperrprüfung über OCSP (RFC 6960) — fail closed.
 *
 * Zweck: ersetzt den Platzhalter `revocationPolicy: 'skip'` für die
 * Issuer-Zertifikatskette eines vorgelegten Credentials. Der Client hängt
 * sich bewusst an die bestehende Abstraktion `RevocationChecker`
 * (revocation.ts) an, ist also die Schwester von `CrlRevocationChecker`
 * (crl-revocation.ts) und benutzt dieselben festen Fehlercodes. Es wird kein
 * eigener Fehlerkanal und keine eigene Status-Maschine eingeführt.
 *
 * Ablauf je Zertifikat (nur Leaf/Intermediate, Anker werden nie geprüft):
 *   1. OCSP-Adresse aus der AIA-Erweiterung (id-ad-ocsp) des Zertifikats.
 *      Keine Adresse                         -> revocation_source_missing
 *      Nicht https (ohne Testschalter)       -> revocation_source_missing
 *   2. Cache nach RFC-6960-CertID (siehe unten).
 *   3. OCSPRequest mit CertID (SHA-1, RFC-6960-Default) und frischem Nonce
 *      (16 Zufallsbytes) bauen, POST `application/ocsp-request`.
 *      Nicht erreichbar / HTTP-Fehler        -> revocation_unavailable
 *      Zeitüberschreitung                    -> revocation_timeout
 *      Zu groß                               -> revocation_list_too_large
 *   4. OCSPResponse parsen (striktes Schema, @peculiar/asn1-ocsp).
 *      responseStatus != successful          -> revocation_unavailable
 *      Kein id-pkix-ocsp-basic               -> revocation_list_malformed
 *   5. Signatur der BasicOCSPResponse prüfen (RFC 6960 §4.2.2.2): direkt vom
 *      Aussteller oder von einem eingebetteten, vom Aussteller ausgestellten
 *      Zertifikat mit id-kp-OCSPSigning-EKU.
 *      Unbekannter Algorithmus / falsche oder fehlende Signatur
 *                                            -> revocation_list_signature_invalid
 *   6. Nonce (Replay-Schutz): beantwortet der Responder die Nonce-Erweiterung,
 *      muss sie exakt der gesendeten Nonce entsprechen. Antwortet er ohne
 *      Nonce, gilt allein die Zeitbindung aus Schritt 7.
 *      Falsche Nonce / unlesbare Nonce       -> revocation_list_malformed
 *   7. Zeitbindung: `thisUpdate` darf nicht in der Zukunft liegen, `nextUpdate`
 *      ist Pflicht und darf nicht überschritten sein.
 *      Ohne nextUpdate / abgelaufen          -> revocation_list_expired
 *   8. Status des passenden SingleResponse (Zuordnung über die CertID):
 *      good                                  -> 'good'
 *      revoked, Grund certificateHold        -> 'suspended'
 *      revoked, sonst                        -> 'revoked'
 *      unknown / kein eindeutiger Eintrag    -> revocation_status_unknown
 *
 * Cache (Schritt 4 der Aufgabe): Schlüssel ist der RFC-6960-CertID
 * (Hashalgorithmus, issuerNameHash, issuerKeyHash, Seriennummer). Gespeichert
 * wird nur das vollständig verifizierte Ergebnis zusammen mit `nextUpdate`.
 * Ein Eintrag gilt höchstens bis `nextUpdate` und zusätzlich höchstens
 * `maxCacheTtlMs` (Standard 24 h), damit ein fehlerhaft konfigurierter
 * Responder kein „gültig" festnageln kann. Es gibt bewusst keine
 * Mindestgültigkeit: eine Antwort kurz vor `nextUpdate` wird nicht künstlich
 * verlängert, sondern neu geholt. Fehler, Zeitüberschreitungen und
 * unvollständig verifizierte Antworten werden **nicht** gecacht. Der Cache
 * gehört zur Instanz (kein modulweiter Zustand) und ist über `clearCache()`
 * leertbar (Schlüsselrotation, Tests).
 *
 * Fail-Mode (Entscheidung in [interne Notiz, nicht veröffentlicht], Option B):
 * Der Standard ist strikt fail closed. Freigegeben und im Dienststart verwendet
 * ist `bounded-soft-fail`: Ist eine `good`-Antwort einmal erfolgreich und
 * vollständig verifiziert worden, darf sie bei Ausfall der Sperrquelle bis
 * `softFailMaxStaleMs` (Standard und freigegebener Wert: 24 Stunden) über ihr
 * `nextUpdate` hinaus weiterverwendet werden. Danach gilt wieder Ablehnung.
 * `revoked`/`suspended` werden nie weich behandelt, und Fehler werden nie
 * gecacht.
 *
 * Die drei Zustände je Zertifikat:
 *   A) `jetzt < nextUpdate`                        -> gecachter Status, keine Abfrage
 *   B) `nextUpdate <= jetzt <= nextUpdate + Frist` -> nur bei letztem Status
 *                                                    `good` **und** wenn die
 *                                                    Abfrage scheitert: `good`
 *      Die Frist endet exakt bei `nextUpdate + softFailMaxStaleMs`; zu diesem
 *      Zeitpunkt ist die Verwertung noch erlaubt, eine Millisekunde später
 *      nicht mehr.
 *   C) alles andere (kein Eintrag, `revoked`, Fehler ohne Vorabantwort,
 *      Frist abgelaufen)                          -> Ablehnung mit festem Code
 */
import { createHash } from 'node:crypto';

import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
  BasicOCSPResponse,
  CertID,
  id_pkix_ocsp_basic,
  id_pkix_ocsp_nonce,
  OCSPRequest,
  OCSPResponse,
  OCSPResponseStatus,
  Request,
  TBSRequest,
} from '@peculiar/asn1-ocsp';
import { AlgorithmIdentifier as AsnAlgorithmIdentifier, Extension, type Certificate as AsnCertificate } from '@peculiar/asn1-x509';
import { AuthorityInfoAccessExtension, ExtendedKeyUsageExtension, X509Certificate } from '@peculiar/x509';

import { fetchLimited, LimitedFetchError, type FetchImpl } from '../lib/limited-fetch.ts';
import { certificateValidityFailure, DEFAULT_CLOCK_SKEW_SECONDS } from '../lib/cert-validity.ts';
import {
  ErrRevocationListExpired,
  ErrRevocationListMalformed,
  ErrRevocationListSignature,
  ErrRevocationListTooLarge,
  ErrRevocationSourceMissing,
  ErrRevocationStatusUnknown,
  ErrRevocationTimeout,
  ErrRevocationUnavailable,
} from './errors.ts';
import { DEFAULT_REVOCATION_TIMEOUT_MS, type RevocationChecker, type RevocationRole, type RevocationStatus } from './revocation.ts';

/** OID id-kp-OCSPSigning (delegierter Responder, RFC 6960 §4.2.2.2). */
const ID_KP_OCSPSIGNING = '1.3.6.1.5.5.7.3.9';
/** OID id-sha1 (Default-Hash der CertID nach RFC 6960 §4.1.1). */
const OID_SHA1 = '1.3.14.3.2.26';
/** GeneralName uniformResourceIdentifier: Tag 6 oder Typname 'url'. */
const GENERAL_NAME_URI_TAGS: ReadonlySet<unknown> = new Set([6, 'url']);
/** CRLReason certificateHold (6): ausgesetzt, nicht endgültig gesperrt. */
const CRL_REASON_CERTIFICATE_HOLD = 6;

/** Höchstgröße einer OCSP-Antwort (Bytes). OCSP-Antworten sind klein. */
export const DEFAULT_OCSP_MAX_BYTES = 64 * 1024;
/** Obergrenze für die Cache-Gültigkeit, auch wenn `nextUpdate` weiter weg ist. */
export const DEFAULT_OCSP_MAX_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
/**
 * Höchstalter einer veralteten `good`-Antwort im Modus `bounded-soft-fail`
 * (Option B aus [interne Notiz, nicht veröffentlicht]): 24 Stunden.
 */
export const DEFAULT_OCSP_SOFT_FAIL_MAX_STALE_MS = 24 * 60 * 60 * 1000;

/**
 * Verhalten bei nicht verwertbarer Sperrquelle:
 *   - `fail-closed`         jede unbrauchbare Antwort bedeutet Ablehnung.
 *   - `bounded-soft-fail`   eine zuvor erfolgreich verifizierte `good`-Antwort
 *                           darf bis `softFailMaxStaleMs` über `nextUpdate`
 *                           hinaus weiterverwendet werden (Option B).
 */
export type OcspUnavailableMode = 'fail-closed' | 'bounded-soft-fail';

interface SignatureAlgorithm {
  /** Parameter für WebCrypto `subtle.verify` (Schlüssel ist bereits importiert). */
  webcrypto: AlgorithmIdentifier | EcdsaParams | RsaPssParams;
  /** Byte-Länge einer Kurvenhälfte, nur für DER-kodierte ECDSA-Signaturen. */
  rawLength?: number;
}

/**
 * Unterstützte Signaturalgorithmen der OCSP-Antwort. Alles andere wird
 * abgewiesen (fail closed), insbesondere SHA-1-basierte Verfahren und
 * RSA-PSS, weil der Prüfer dafür keine eigene Parameterprüfung hätte.
 */
const SIGNATURE_ALGORITHMS: Readonly<Record<string, SignatureAlgorithm>> = Object.freeze({
  '1.2.840.113549.1.1.11': { webcrypto: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } },
  '1.2.840.113549.1.1.12': { webcrypto: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' } },
  '1.2.840.113549.1.1.13': { webcrypto: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' } },
  '1.2.840.10045.4.3.2': { webcrypto: { name: 'ECDSA', hash: 'SHA-256' }, rawLength: 32 },
  '1.2.840.10045.4.3.3': { webcrypto: { name: 'ECDSA', hash: 'SHA-384' }, rawLength: 48 },
  '1.2.840.10045.4.3.4': { webcrypto: { name: 'ECDSA', hash: 'SHA-512' }, rawLength: 66 },
});

/**
 * Meldung, wenn eine veraltete `good`-Antwort aus der Gnadenfrist verwendet
 * wurde (Zustand B aus [interne Notiz, nicht veröffentlicht]). Wird ohne
 * Kenntnis von Zertifikatsdaten befüllt: nur Alter und Frist, kein Subject,
 * keine Seriennummer, keine Responder-Adresse.
 */
export interface OcspGracePeriodUse {
  /** Wie alt die verwendete Antwort in Sekunden war. */
  ageSeconds: number;
  /** Wie lange die Antwort höchstens noch hätte verwendet werden dürfen (s). */
  maxStaleSeconds: number;
}

/**
 * Optionaler Beobachter für Ereignisse, die der Dienst protokollieren soll. Der
 * Checker kennt das Audit-Log nicht; der Dienst entscheidet, was er daraus
 * macht. Bewusst additiv: ohne Beobachter ändert sich nichts.
 */
export interface OcspRevocationObserver {
  onGracePeriodUse?(use: OcspGracePeriodUse): void;
  onCacheHit?(): void;
  onCacheMiss?(): void;
}

export interface OcspRevocationCheckerOptions {
  /** Zeitgrenze je Abruf (ms). Standard: 5.000 wie alle anderen Sperrquellen. */
  timeoutMs?: number;
  /** Größengrenze je Antwort (Bytes). */
  maxBytes?: number;
  /** Erlaubte Uhrabweichung für thisUpdate/nextUpdate (Sekunden). */
  clockSkewSeconds?: number;
  /** Obergrenze der Cache-Gültigkeit (ms). */
  maxCacheTtlMs?: number;
  /**
   * Fail-Mode bei nicht verwertbarer Sperrquelle. Standard ist
   * `fail-closed`; `bounded-soft-fail` ist die freigegebene Option B und darf
   * nur mit ausdrücklich gesetzter `softFailMaxStaleMs` sinnvoll sein.
   */
  unavailableMode?: OcspUnavailableMode;
  /** Höchstalter veralteter `good`-Antworten im Soft-Fail-Betrieb (ms). */
  softFailMaxStaleMs?: number;
  /** OCSP über http statt https zulassen (nur lokale Tests). Standard: aus. */
  allowInsecureHttp?: boolean;
  /** Delegierte Responder (eingebettetes Zertifikat) zulassen. Standard: an. */
  allowDelegatedResponder?: boolean;
  fetchImpl?: FetchImpl;
  now?: () => Date;
  /** Nonce-Quelle (nur Tests: deterministisch statt zufällig). */
  nonceFactory?: () => Uint8Array;
  /** Optionaler Beobachter, siehe `OcspRevocationObserver`. */
  observer?: OcspRevocationObserver;
  /** Adresse selbst festlegen (Standard: AIA-Erweiterung des Zertifikats). */
  responderUrlFor?: (cert: X509Certificate) => string | undefined;
}

interface CacheEntry {
  status: RevocationStatus;
  /** `nextUpdate` der verifizierten Antwort (ms). Zustand A gilt bis hierher. */
  nextUpdateMs: number;
}

export class OcspRevocationChecker implements RevocationChecker {
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly clockSkewMs: number;
  private readonly clockSkewSeconds: number;
  private readonly maxCacheTtlMs: number;
  private readonly mode: OcspUnavailableMode;
  private readonly softFailMaxStaleMs: number;
  private readonly allowInsecureHttp: boolean;
  private readonly allowDelegatedResponder: boolean;
  private readonly fetchImpl?: FetchImpl;
  private readonly now: () => Date;
  private readonly nonceFactory: () => Uint8Array;
  private readonly responderUrlFor: (cert: X509Certificate) => string | undefined;
  private readonly observer?: OcspRevocationObserver;
  private readonly cache = new Map<string, CacheEntry>();
  /** Gemeinsame Fetch-/Validierungsoperation je CertID für parallele Cache-Misses. */
  private readonly inFlight = new Map<string, Promise<CacheEntry>>();

  constructor(options: OcspRevocationCheckerOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? DEFAULT_REVOCATION_TIMEOUT_MS;
    this.maxBytes = options.maxBytes ?? DEFAULT_OCSP_MAX_BYTES;
    this.clockSkewSeconds = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
    this.clockSkewMs = this.clockSkewSeconds * 1000;
    this.maxCacheTtlMs = options.maxCacheTtlMs ?? DEFAULT_OCSP_MAX_CACHE_TTL_MS;
    this.mode = options.unavailableMode ?? 'fail-closed';
    this.softFailMaxStaleMs = options.softFailMaxStaleMs ?? DEFAULT_OCSP_SOFT_FAIL_MAX_STALE_MS;
    this.allowInsecureHttp = options.allowInsecureHttp ?? false;
    this.allowDelegatedResponder = options.allowDelegatedResponder ?? true;
    this.fetchImpl = options.fetchImpl;
    this.now = options.now ?? (() => new Date());
    this.nonceFactory = options.nonceFactory ?? (() => crypto.getRandomValues(new Uint8Array(16)));
    this.responderUrlFor = options.responderUrlFor ?? ocspUrlFromAuthorityInformationAccess;
    this.observer = options.observer;
  }

  async checkRevoked(certDer: Uint8Array, _role: RevocationRole, issuerDer: Uint8Array): Promise<RevocationStatus> {
    const cert = new X509Certificate(new Uint8Array(certDer));
    const issuer = new X509Certificate(new Uint8Array(issuerDer));

    // Der übergebene Aussteller muss der Aussteller dieses Zertifikats sein,
    // sonst wäre die CertID bedeutungslos und die Antwort nicht zuordenbar.
    if (cert.issuer !== issuer.subject) throw new ErrRevocationListMalformed();

    const certId = await buildCertId(cert, issuer);
    const cacheKey = certIdCacheKey(certId);
    const nowMs = this.now().getTime();
    const cached = this.cache.get(cacheKey);

    // Zustand A: innerhalb von nextUpdate ist die verifizierte Antwort gültig.
    if (cached && nowMs < cached.nextUpdateMs) {
      this.observer?.onCacheHit?.();
      return cached.status;
    }

    const pending = this.inFlight.get(cacheKey);
    if (pending) return (await pending).status;

    this.observer?.onCacheMiss?.();
    const refresh = this.refreshCacheEntry(cacheKey, cert, certId, issuer, nowMs, cached);
    this.inFlight.set(cacheKey, refresh);
    try {
      return (await refresh).status;
    } finally {
      // Nur den eigenen Lauf entfernen; ein späterer Lauf darf nicht gelöscht
      // werden, falls die Map zwischenzeitlich neu befüllt wurde.
      if (this.inFlight.get(cacheKey) === refresh) this.inFlight.delete(cacheKey);
    }
  }

  private async refreshCacheEntry(
    cacheKey: string,
    cert: X509Certificate,
    certId: CertID,
    issuer: X509Certificate,
    nowMs: number,
    cached: CacheEntry | undefined,
  ): Promise<CacheEntry> {
    const url = this.responderUrlFor(cert);
    if (!url) throw new ErrRevocationSourceMissing();
    if (!this.allowInsecureHttp && !url.startsWith('https://')) throw new ErrRevocationSourceMissing();

    const nonce = this.nonceFactory();
    let body: Uint8Array;
    try {
      body = await this.post(url, buildOcspRequest(certId, nonce));
    } catch (e) {
      // Zustand B: letzter verifizierter Status war 'good', und wir befinden uns
      // noch in der begrenzten Gnadenfrist (Option B, max. 24 h über
      // nextUpdate). Dann wird die Ausfall-Ablehnung auf 'good' abgemildert.
      // Alles andere (kein Cache, Status 'revoked'/'suspended', Frist abgelaufen)
      // bleibt Ablehnung mit dem ursprünglichen Fehlercode.
      if (this.mode === 'bounded-soft-fail' && cached?.status === 'good' && nowMs <= cached.nextUpdateMs + this.softFailMaxStaleMs) {
        // Kein Subject, keine Seriennummer, keine Responder-Adresse: nur Alter
        // und Frist. Der Dienst schreibt das ins Audit-Log (B8).
        this.observer?.onGracePeriodUse?.({
          ageSeconds: Math.max(0, Math.floor((nowMs - cached.nextUpdateMs) / 1000)),
          maxStaleSeconds: Math.floor(this.softFailMaxStaleMs / 1000),
        });
        return { status: 'good', nextUpdateMs: cached.nextUpdateMs };
      }
      throw e;
    }

    const verdict = await this.evaluate(body, certId, nonce, issuer, nowMs);
    this.cache.set(cacheKey, verdict);
    return verdict;
  }

  /** Entfernt alle Cache-Einträge dieser Instanz (Schlüsselrotation, Tests). */
  clearCache(): void {
    this.cache.clear();
  }

  private async post(url: string, requestDer: Uint8Array): Promise<Uint8Array> {
    try {
      const { body } = await fetchLimited(url, {
        timeoutMs: this.timeoutMs,
        maxBytes: this.maxBytes,
        method: 'POST',
        body: requestDer,
        contentType: 'application/ocsp-request',
        accept: 'application/ocsp-response',
        fetchImpl: this.fetchImpl,
      });
      return body;
    } catch (e) {
      if (e instanceof LimitedFetchError && e.code === 'fetch_timeout') throw new ErrRevocationTimeout();
      if (e instanceof LimitedFetchError && e.code === 'fetch_too_large') throw new ErrRevocationListTooLarge();
      throw new ErrRevocationUnavailable();
    }
  }

  /**
   * Parst, verifiziert und bewertet die Antwort. Jeder Fehlerpfad wirft einen
   * festen Code; Rohmeldungen der Laufzeit verlassen dieses Modul nicht.
   */
  private async evaluate(body: Uint8Array, certId: CertID, nonce: Uint8Array, issuer: X509Certificate, nowMs: number): Promise<CacheEntry> {
    let response: OCSPResponse;
    try {
      response = AsnConvert.parse(body, OCSPResponse);
    } catch {
      throw new ErrRevocationListMalformed();
    }
    // tryLater, unauthorized und alle anderen Status: die Sperrquelle hat gerade
    // kein verwertbares Ergebnis. Nach außen ein einziger fester Code.
    if (response.responseStatus !== OCSPResponseStatus.successful) throw new ErrRevocationUnavailable();
    if (!response.responseBytes || response.responseBytes.responseType !== id_pkix_ocsp_basic) throw new ErrRevocationListMalformed();

    let basic: BasicOCSPResponse;
    try {
      basic = AsnConvert.parse(bytesOf(response.responseBytes.response), BasicOCSPResponse);
    } catch {
      // Die Bibliothek wirft hier mit sprechender Meldung, aber der Fehler darf
      // nicht nach außen: er nennt ASN.1-Strukturen, nicht den Grund der
      // Ablehnung.
      throw new ErrRevocationListMalformed();
    }
    if (!basic.tbsResponseData) throw new ErrRevocationListMalformed();

    // Für die Signaturprüfung müssen exakt die signierten Bytes verwendet
    // werden; eine Re-Serialisierung kann sie verändern.
    const tbsDer = basic.tbsResponseDataRaw ? new Uint8Array(basic.tbsResponseDataRaw as ArrayBuffer) : new Uint8Array(AsnConvert.serialize(basic.tbsResponseData));
    if (tbsDer.byteLength === 0) throw new ErrRevocationListMalformed();

    await this.verifySignature(basic, tbsDer, issuer);

    // Nonce: beantwortet der Responder, muss es unsere Nonce sein.
    const echoed = responseNonce(basic);
    if (echoed && !constantTimeEqual(echoed, nonce)) throw new ErrRevocationListMalformed();

    const single = this.matchSingleResponse(basic, certId);
    this.assertFresh(single);

    // Nie über `nextUpdate` hinaus, zusätzlich hart gedeckelt: Zustand A endet
    // spätestens nach `maxCacheTtlMs`, die Gnadenfrist (Option B) reicht
    // höchstens bis `nextUpdate + softFailMaxStaleMs` an diese Grenze.
    const nextUpdateMs = Math.min((single.nextUpdate as Date).getTime(), nowMs + this.maxCacheTtlMs);
    return { status: statusOf(single), nextUpdateMs };
  }

  private matchSingleResponse(basic: BasicOCSPResponse, certId: CertID): BasicOcspSingleResponse {
    const responses = basic.tbsResponseData.responses;
    if (!Array.isArray(responses) || responses.length === 0) throw new ErrRevocationListMalformed();
    const matches = responses.filter((entry) => certIdEquals(entry.certID, certId));
    // Genau ein passender Eintrag: kein Treffer oder zwei widersprüchliche
    // Einträge sind kein verwertbares Ergebnis.
    const [single] = matches;
    if (matches.length !== 1 || !single) throw new ErrRevocationListMalformed();
    return single;
  }

  private assertFresh(single: BasicOcspSingleResponse): void {
    const nowMs = this.now().getTime();
    const thisUpdate = single.thisUpdate;
    if (!(thisUpdate instanceof Date) || !Number.isFinite(thisUpdate.getTime())) throw new ErrRevocationListMalformed();
    if (thisUpdate.getTime() - this.clockSkewMs > nowMs) throw new ErrRevocationListMalformed();
    // Ohne nextUpdate ist die Aktualität nicht beurteilbar: ablehnen.
    const nextUpdate = single.nextUpdate;
    if (!(nextUpdate instanceof Date) || !Number.isFinite(nextUpdate.getTime())) throw new ErrRevocationListExpired();
    if (nextUpdate.getTime() + this.clockSkewMs < nowMs) throw new ErrRevocationListExpired();
  }

  private async verifySignature(basic: BasicOCSPResponse, tbsDer: Uint8Array, issuer: X509Certificate): Promise<void> {
    const algorithm = SIGNATURE_ALGORITHMS[basic.signatureAlgorithm.algorithm];
    if (!algorithm) throw new ErrRevocationListSignature();
    const signature = new Uint8Array(basic.signature as ArrayBuffer);

    if (await signatureFrom(tbsDer, signature, algorithm, issuer)) return;

    if (!this.allowDelegatedResponder) throw new ErrRevocationListSignature();
    for (const candidate of (basic.certs ?? []).filter((asn) => isDelegatedResponder(asn, issuer))) {
      const cert = new X509Certificate(new Uint8Array(AsnConvert.serialize(candidate)));
      // Ein delegierter Responder muss im Gültigkeitszeitraum liegen.
      if (certificateValidityFailure(cert, this.now(), this.clockSkewSeconds)) continue;
      if (await signatureFrom(tbsDer, signature, algorithm, cert)) return;
    }
    throw new ErrRevocationListSignature();
  }
}

type BasicOcspSingleResponse = NonNullable<ReturnType<BasicOCSPResponse['tbsResponseData']['responses']['at']>>;

/**
 * Signaturprüfung mit einem möglichen Signaturinhaber: Der `responderID` der
 * Antwort (RFC 6960 §4.2.2.1) muss zu diesem Zertifikat passen, sonst wird die
 * Antwort auch bei gültiger Signatur abgewiesen.
 */
async function signatureFrom(tbsDer: Uint8Array, signature: Uint8Array, algorithm: SignatureAlgorithm, signer: X509Certificate): Promise<boolean> {
  if (!responderIdMatches(tbsDer, signer)) return false;
  return verifySignatureWith(tbsDer, signature, algorithm, await importPublicKey(signer));
}

/**
 * Prüft den `responderID` direkt an den signierten Bytes:
 * ResponseData ::= SEQUENCE { version [0] EXPLICIT OPTIONAL, responderID
 * ResponderID, producedAt GeneralizedTime, responses, ... } und
 * ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }.
 * byName wird mit den DER-Bytes des Subject des Signaturinhabers verglichen,
 * byKey (implizit getaggt) mit dem SHA-1 über dessen SubjectPublicKey.
 */
function responderIdMatches(tbsDer: Uint8Array, signer: X509Certificate): boolean {
  const view = tbsDer;
  const sequence = readTlv(view, 0);
  if (sequence.tag !== 0x30) return false;
  let offset = sequence.start;
  const first = readTlv(view, offset);
  offset = first.end;
  const responder = first.tag === 0xa0 ? readTlv(view, offset) : first;
  try {
    // byName [1]: der Inhalt ist der Name-TLV des Signaturinhabers.
    if (responder.tag === 0xa1) return equalBytes(view.subarray(responder.start, responder.end), subjectNameDer(signer));
    if (responder.tag === 0xa2) {
      const expected = responderKeyHash(signer);
      // byKey wird in der Praxis implizit ([2] mit den Hash-Bytes) oder explizit
      // ([2] mit OCTET STRING darin) kodiert; beide Formen werden akzeptiert,
      // jede andere nicht.
      if (equalBytes(view.subarray(responder.start, responder.end), expected)) return true;
      const inner = readTlv(view, responder.start);
      return inner.tag === 0x04 && inner.end === responder.end && equalBytes(view.subarray(inner.start, inner.end), expected);
    }
  } catch {
    return false;
  }
  return false;
}

/** SHA-1 über das SubjectPublicKey-BitString (CertID- und responderID-Format). */
export function responderKeyHash(cert: X509Certificate): Uint8Array {
  // SHA-1 ist hier von RFC 6960 vorgegeben, keine eigene Kryptoentscheidung.
  return sha1Sync(subjectPublicKeyBits(cert));
}

/** Verifiziert die Antwortsignatur mit einem Schlüssel; kein Detail nach außen. */
async function verifySignatureWith(tbsDer: Uint8Array, signature: Uint8Array, algorithm: SignatureAlgorithm, key: CryptoKey): Promise<boolean> {
  try {
    const raw = algorithm.rawLength === undefined ? signature : ecdsaDerToRaw(signature, algorithm.rawLength);
    return await crypto.subtle.verify(algorithm.webcrypto as unknown as globalThis.AlgorithmIdentifier, key, raw as unknown as BufferSource, tbsDer as unknown as BufferSource);
  } catch {
    return false;
  }
}

async function importPublicKey(cert: X509Certificate): Promise<CryptoKey> {
  try {
    return (await cert.publicKey.export()) as CryptoKey;
  } catch {
    throw new ErrRevocationListSignature();
  }
}

/** Eingebettetes Zertifikat: vom Aussteller ausgestellt und darf OCSP signieren. */
function isDelegatedResponder(asn: AsnCertificate, issuer: X509Certificate): boolean {
  try {
    const cert = new X509Certificate(new Uint8Array(AsnConvert.serialize(asn)));
    if (cert.issuer !== issuer.subject) return false;
    const eku = cert.getExtension(ExtendedKeyUsageExtension);
    return eku !== null && eku.usages.includes(ID_KP_OCSPSIGNING);
  } catch {
    return false;
  }
}

/**
 * Wandelt eine DER-kodierte ECDSA-Signatur (SEQUENCE aus zwei INTEGERn) in die
 * von WebCrypto erwartete rohe Form r||s. Strikte Prüfung: nur definite
 * minimale Längen, genau zwei INTEGER, keine Restbytes. Alles andere wirft.
 */
export function ecdsaDerToRaw(der: Uint8Array, length: number): Uint8Array {
  if (der.length < 8 || der.length > 140) throw new Error('Signaturlaenge unplausibel');
  if (der[0] !== 0x30) throw new Error('kein SEQUENCE');
  let offset = 1;
  const seqLength = readLength(der, offset);
  offset = seqLength.next;
  if (offset + seqLength.length !== der.length) throw new Error('Laenge passt nicht zum Inhalt');

  const raw = new Uint8Array(length * 2);
  for (let part = 0; part < 2; part += 1) {
    if (der[offset] !== 0x02) throw new Error('kein INTEGER');
    const intLength = readLength(der, offset + 1);
    offset = intLength.next;
    if (intLength.length === 0 || offset + intLength.length > der.length) throw new Error('INTEGER-Laenge unplausibel');
    let start = offset;
    let size = intLength.length;
    // Führendes 0x00 bei positiven Werten ist DER-konform und kein Sign.
    let padded = false;
    if (der[start] === 0x00) {
      if (size < 2) throw new Error('INTEGER zu kurz');
      start += 1;
      size -= 1;
      padded = true;
    }
    // Ohne führendes 0x00 muss das höchste Bit 0 sein, sonst wäre der Wert negativ.
    if (!padded && der[start] & 0x80) throw new Error('negativer Wert');
    if (size > length) throw new Error('INTEGER zu lang');
    raw.set(der.subarray(start, start + size), part * length + (length - size));
    offset += intLength.length;
  }
  if (offset !== der.length) throw new Error('Restbytes');
  return raw;
}

/** Liest eine definite, minimal kodierte DER-Länge (max. 4 Längenbytes). */
function readLength(der: Uint8Array, offset: number): { length: number; next: number } {
  const first = der[offset];
  if (first === undefined) throw new Error('Laenge fehlt');
  if ((first & 0x80) === 0) return { length: first, next: offset + 1 };
  const count = first & 0x7f;
  // 0 wäre unbestimmt (BER), mehr als 4 Längenbytes sind hier sinnlos.
  if (count === 0 || count > 4) throw new Error('unplausible Laenge');
  let length = 0;
  for (let i = 1; i <= count; i += 1) {
    const byte = der[offset + i];
    if (byte === undefined) throw new Error('Laenge fehlt');
    if (i === 1 && byte === 0x00) throw new Error('nicht minimal kodiert');
    length = length * 256 + byte;
  }
  if (length < 0x80) throw new Error('nicht minimal kodiert');
  return { length, next: offset + 1 + count };
}

/**
 * CertID nach RFC 6960 §4.1.1: SHA-1 über den DER-kodierten Namen des
 * Ausstellers und über sein SubjectPublicKey-BitString. Beide Bytes werden
 * direkt aus dem Zertifikat gelesen, nicht re-serialisiert: eine
 * Re-Serialisierung könnte andere Bytes liefern als die, die der Aussteller
 * in seiner CertID verwendet.
 */
export async function buildCertId(cert: X509Certificate, issuer: X509Certificate): Promise<CertID> {
  const issuerNameHash = await sha1(subjectNameDer(issuer));
  const issuerKeyHash = await sha1(subjectPublicKeyBits(issuer));
  return new CertID({
    hashAlgorithm: new AsnAlgorithmIdentifier({ algorithm: OID_SHA1 }),
    issuerNameHash: new OctetString(issuerNameHash),
    issuerKeyHash: new OctetString(issuerKeyHash),
    serialNumber: serialNumberBytes(cert.serialNumber),
  });
}

/** Baut die OCSPRequest inkl. Nonce-Erweiterung (DER). */
export function buildOcspRequest(certId: CertID, nonce: Uint8Array): Uint8Array {
  const request = new OCSPRequest({
    tbsRequest: new TBSRequest({
      requestList: [new Request({ reqCert: certId })],
      requestExtensions: [new Extension({ extnID: id_pkix_ocsp_nonce, extnValue: new OctetString(nonce), critical: false })],
    }),
  });
  return new Uint8Array(AsnConvert.serialize(request));
}

function certIdCacheKey(certId: CertID): string {
  return [certId.hashAlgorithm.algorithm, hex(bytesOf(certId.issuerNameHash)), hex(bytesOf(certId.issuerKeyHash)), hex(bytesOf(certId.serialNumber))].join(':');
}

function certIdEquals(a: CertID, b: CertID): boolean {
  return a.hashAlgorithm.algorithm === b.hashAlgorithm.algorithm && equalBytes(bytesOf(a.issuerNameHash), bytesOf(b.issuerNameHash)) && equalBytes(bytesOf(a.issuerKeyHash), bytesOf(b.issuerKeyHash)) && equalBytes(bytesOf(a.serialNumber), bytesOf(b.serialNumber));
}

function bytesOf(value: ArrayBufferLike | { buffer: ArrayBufferLike; byteOffset: number; byteLength: number }): Uint8Array {
  if (typeof (value as ArrayBuffer).byteLength === 'number' && typeof (value as ArrayBuffer).slice === 'function' && !('byteOffset' in (value as object))) {
    return new Uint8Array(value as ArrayBuffer);
  }
  if (ArrayBuffer.isView(value as ArrayBufferView)) {
    const view = value as ArrayBufferView;
    return new Uint8Array(view.buffer as ArrayBuffer, view.byteOffset, view.byteLength);
  }
  // OctetString und ähnliche ASN.1-Werte: buffer zeigt in den Originalpuffer,
  // deshalb sind byteOffset und byteLength zwingend zu beachten.
  const view = value as { buffer: ArrayBufferLike; byteOffset: number; byteLength: number };
  return new Uint8Array(view.buffer as ArrayBuffer, view.byteOffset, view.byteLength);
}

function hex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Nonce aus der Nonce-Erweiterung der Einzelantworten, falls beantwortet. */
function responseNonce(basic: BasicOCSPResponse): Uint8Array | undefined {
  for (const single of basic.tbsResponseData.responses ?? []) {
    for (const ext of single.singleExtensions ?? []) {
      if (ext.extnID !== id_pkix_ocsp_nonce) continue;
      return bytesOf(ext.extnValue);
    }
  }
  return undefined;
}

function statusOf(single: BasicOcspSingleResponse): RevocationStatus {
  const status = single.certStatus;
  if (!status) throw new ErrRevocationStatusUnknown();
  if (status.good !== undefined) return 'good';
  // CRLReason ist in @peculiar/asn1-x509 zur Laufzeit nicht als Wert verfügbar;
  // der Grund wird deshalb numerisch verglichen (certificateHold = 6, RFC 5280).
  if (status.revoked) return isCertificateHold(status.revoked.revocationReason) ? 'suspended' : 'revoked';
  throw new ErrRevocationStatusUnknown();
}

/**
 * certificateHold (6, RFC 5280) bedeutet "ausgesetzt" und nicht endgültig
 * gesperrt. Das Objekt der Bibliothek trägt den Zahlenwert in `reason`; ein
 * unerwarteter Aufbau gilt konservativ als einfache Sperrung.
 */
function isCertificateHold(reason: unknown): boolean {
  const value = (reason as { reason?: unknown } | undefined)?.reason;
  return typeof value === 'number' && value === CRL_REASON_CERTIFICATE_HOLD;
}

/**
 * Erste http(s)-OCSP-Adresse aus der AIA-Erweiterung (id-ad-ocsp) oder
 * `undefined`. Die GeneralNames werden über Typ (6 = URI) und Wert gelesen,
 * weil die Bibliothek sie als generische Objekte liefert.
 */
export function ocspUrlFromAuthorityInformationAccess(cert: X509Certificate): string | undefined {
  const ext = cert.getExtension(AuthorityInfoAccessExtension);
  if (!ext) return undefined;
  for (const location of ext.ocsp ?? []) {
    const name = location as unknown as { type?: number; value?: unknown; uniformResourceIdentifier?: string };
    const uri = name.uniformResourceIdentifier ?? (GENERAL_NAME_URI_TAGS.has(name.type) && typeof name.value === 'string' ? name.value : undefined);
    if (typeof uri !== 'string' || !/^https?:\/\//i.test(uri)) continue;
    return uri;
  }
  return undefined;
}

/**
 * Minimaler, strikter DER-TLV-Walker: liefert Tag sowie Bytebereich des
 * Wertes. Nur definite, minimal kodierte Längen; alles andere wirft.
 */
function readTlv(view: Uint8Array, offset: number): { tag: number; tlvStart: number; start: number; end: number } {
  const tag = view[offset];
  if (tag === undefined) throw new ErrRevocationListMalformed();
  const parsed = readLength(view, offset + 1);
  const end = parsed.next + parsed.length;
  if (end > view.length) throw new ErrRevocationListMalformed();
  return { tag, tlvStart: offset, start: parsed.next, end };
}

/**
 * Ganzes Subject (Name) als Original-DER-Bytes aus dem Zertifikat.
 * Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { version [0] EXPLICIT
 * OPTIONAL, serialNumber INTEGER, signature AlgorithmIdentifier, issuer Name,
 * validity SEQUENCE, subject Name, ... } }
 */
export function subjectNameDer(cert: X509Certificate): Uint8Array {
  const view = new Uint8Array(cert.rawData);
  const outer = readTlv(view, 0);
  if (outer.tag !== 0x30) throw new ErrRevocationListMalformed();
  const tbs = readTlv(view, outer.start);
  if (tbs.tag !== 0x30) throw new ErrRevocationListMalformed();

  let offset = tbs.start;
  const step = (): { tag: number; tlvStart: number; start: number; end: number } => {
    const next = readTlv(view, offset);
    offset = next.end;
    return next;
  };
  // Elemente in fester Reihenfolge: [version], serialNumber, signature,
  // issuer, validity, subject. Nur diese Reihenfolge wird akzeptiert.
  const elements: { tag: number; tlvStart: number; start: number; end: number }[] = [];
  for (let i = 0; i < 6; i += 1) {
    const element = step();
    if (element.tag === 0xa0 && elements.length === 0) continue; // version [0] EXPLICIT
    elements.push(element);
    if (elements.length === 5) break;
  }
  const tags = elements.map((element) => element.tag);
  // INTEGER (serialNumber) und vier SEQUENCEs (signature, issuer, validity, subject).
  if (tags.join(',') !== ['0x02', '0x30', '0x30', '0x30', '0x30'].map((tag) => Number.parseInt(tag, 16).toString(10)).join(',')) {
    throw new ErrRevocationListMalformed();
  }
  // Der Subject-TLV wird inklusive Tag und Längenfeld benötigt.
  return view.subarray(elements[4].tlvStart, elements[4].end);
}

/**
 * Rohbytes des SubjectPublicKey-BitString (ohne Tag/Länge und ohne
 * ungenutzte-Bits-Byte), RFC 6960 §4.1.1. Strikter Minimalparser: nur
 * SEQUENCE { SEQUENCE {...}, BIT STRING }; alles andere wird abgewiesen.
 */
function subjectPublicKeyBits(issuer: X509Certificate): Uint8Array {
  const view = new Uint8Array(issuer.publicKey.rawData);
  const spki = readTlv(view, 0);
  if (spki.tag !== 0x30) throw new ErrRevocationListMalformed();
  const algorithm = readTlv(view, spki.start);
  if (algorithm.tag !== 0x30) throw new ErrRevocationListMalformed();
  const bits = readTlv(view, algorithm.end);
  if (bits.tag !== 0x03 || bits.end - bits.start === 0) throw new ErrRevocationListMalformed();
  if (bits.end !== view.length) throw new ErrRevocationListMalformed();
  // Erstes Octett des BIT STRING zählt die ungenutzten Bits (0 bei Schlüsseln).
  if (view[bits.start] !== 0x00) throw new ErrRevocationListMalformed();
  return view.subarray(bits.start + 1, bits.end);
}

function serialNumberBytes(hexValue: string): ArrayBuffer {
  const clean = hexValue.replace(/[^0-9a-fA-F]/g, '');
  if (clean.length === 0 || clean.length % 2 !== 0) throw new ErrRevocationListMalformed();
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  // RFC 6960: positiver INTEGER-Wert, führendes 0x00 falls das höchste Bit gesetzt ist.
  if (bytes[0] & 0x80) {
    const padded = new Uint8Array(bytes.length + 1);
    padded.set(bytes, 1);
    return padded.buffer;
  }
  return bytes.buffer;
}

async function sha1(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-1', data as unknown as BufferSource));
}

/** SHA-1 als Extra: der ResponderID-Hash wird in der Bibliothek-API synchron gebraucht. */
function sha1Sync(data: Uint8Array): Uint8Array {
  // Node-Krypto liefert SHA-1 synchron; WebCrypto nicht, daher hier der Umweg
  // über createHash, um den Aufrufer synchron halten zu können.
  return new Uint8Array(createHash('sha1').update(data).digest());
}
