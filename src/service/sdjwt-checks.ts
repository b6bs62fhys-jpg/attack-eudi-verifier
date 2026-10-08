/**
 * Strukturprüfung einer SD-JWT-VC-Präsentation vor der Bibliothek.
 *
 * Die Bibliothek (@openeudi/openid4vp) nimmt fünf Dinge an, die RFC 9901
 * verbietet. Gefunden mit den Härtungstests in `sdjwt-haertung.test.ts`:
 *
 *   1. Dieselbe Offenlegung zweimal. RFC 9901 Abschnitt 7.1 Schritt 5: eine
 *      Offenlegung, die nicht über ihren Digest referenziert ist, lässt den
 *      SD-JWT scheitern; die zweite Kopie ist nicht referenziert, weil der
 *      Digest nur einmal vorkommt.
 *   2. Derselbe Digest mehrfach in `_sd`. Abschnitt 7.1 Schritt 4: "If any
 *      digest value is encountered more than once in the Issuer-signed JWT
 *      payload (directly or recursively via other Disclosures), the SD-JWT MUST
 *      be rejected."
 *   3. Ein Salt, das kein Text ist. Abschnitt 4.2.1: "The salt value. MUST be a
 *      string."
 *   5. Ein Key-Binding-JWT, dessen `typ` nicht `kb+jwt` ist. Abschnitt 4.3: das
 *      KB-JWT trägt den Header-Parameter `typ` mit dem Wert `kb+jwt`.
 *   4. Ein Key-Binding-JWT mit beliebig altem `iat`. Abschnitt 7.3 Schritt 5:
 *      der Zeitpunkt muss in einem akzeptablen Fenster liegen. Die Nonce bindet
 *      die Präsentation zwar an die Anfrage, ein Zeitfenster begrenzt aber
 *      zusätzlich, wie lange ein abgefangenes KB-JWT brauchbar ist.
 *
 * Signaturen, Nonce, Audience und `sd_hash` prüft weiter die Bibliothek. Diese
 * Datei liest nur Form und Zeit und gibt entweder einen festen Grund zurück
 * oder `undefined`.
 */
import { createHash } from 'node:crypto';

/** Tiefste erlaubte Verschachtelung beim Einsammeln von Digests. */
const MAX_DEPTH = 32;

export type SdJwtStructureFailure =
  | 'sd_jwt_malformed'
  | 'disclosure_malformed'
  | 'disclosure_duplicate'
  | 'digest_duplicate'
  | 'kb_jwt_missing'
  | 'kb_jwt_typ_invalid'
  | 'kb_jwt_iat_invalid'
  | 'kb_jwt_too_old'
  | 'kb_jwt_in_future';

function decodeJson(part: string): unknown {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

/** Sammelt alle Digests (`_sd`-Listen und `{"...": digest}`-Elemente), auch verschachtelt. */
function collectDigests(value: unknown, into: string[], depth = 0): boolean {
  if (depth > MAX_DEPTH) return false;
  if (Array.isArray(value)) {
    for (const item of value) {
      if (typeof item === 'object' && item !== null && !Array.isArray(item) && Object.prototype.hasOwnProperty.call(item, '...')) {
        const digest = (item as Record<string, unknown>)['...'];
        if (typeof digest !== 'string') return false;
        into.push(digest);
      } else if (!collectDigests(item, into, depth + 1)) return false;
    }
    return true;
  }
  if (typeof value === 'object' && value !== null) {
    for (const [key, item] of Object.entries(value)) {
      if (key === '_sd') {
        if (!Array.isArray(item) || !item.every((d) => typeof d === 'string')) return false;
        into.push(...(item as string[]));
      } else if (!collectDigests(item, into, depth + 1)) return false;
    }
  }
  return true;
}

export interface SdJwtStructureOptions {
  now: Date;
  /** Älter als dies darf das KB-JWT nicht sein (Sekunden). */
  maxKbAgeSeconds: number;
  /** Erlaubte Uhrabweichung in Sekunden (KB-JWT darf nicht weiter in der Zukunft liegen). */
  clockSkewSeconds: number;
}

/**
 * Prüft Form der Offenlegungen und Eindeutigkeit der Digests. Liefert den
 * Fehlergrund oder `undefined`. Das KB-JWT prüft `kbJwtFailure`, später.
 */
export function sdJwtStructureFailure(token: string): SdJwtStructureFailure | undefined {
  const parts = token.split('~');
  if (parts.length < 2) return 'sd_jwt_malformed';
  const issuerJwt = parts[0] as string;
  const kbJwt = parts[parts.length - 1] as string;
  const disclosures = parts.slice(1, -1);
  if (kbJwt === '') return 'kb_jwt_missing';

  let payload: unknown;
  try {
    payload = decodeJson(issuerJwt.split('.')[1] ?? '');
  } catch {
    return 'sd_jwt_malformed';
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return 'sd_jwt_malformed';

  const digests: string[] = [];
  if (!collectDigests(payload, digests)) return 'sd_jwt_malformed';

  const seenDisclosures = new Set<string>();
  for (const disclosure of disclosures) {
    if (disclosure === '') return 'disclosure_malformed';
    const digest = createHash('sha256').update(disclosure).digest('base64url');
    if (seenDisclosures.has(digest)) return 'disclosure_duplicate';
    seenDisclosures.add(digest);

    let value: unknown;
    try {
      value = decodeJson(disclosure);
    } catch {
      return 'disclosure_malformed';
    }
    if (!Array.isArray(value) || (value.length !== 2 && value.length !== 3)) return 'disclosure_malformed';
    if (typeof value[0] !== 'string' || value[0] === '') return 'disclosure_malformed';
    if (value.length === 3 && typeof value[1] !== 'string') return 'disclosure_malformed';
    // Digests innerhalb der Offenlegung (verschachtelte Offenlegungen) zählen mit.
    if (!collectDigests(value[value.length - 1], digests)) return 'disclosure_malformed';
  }

  if (new Set(digests).size !== digests.length) return 'digest_duplicate';

  return undefined;
}

/**
 * Prüft Header und Zeitfenster des KB-JWT (Punkte 4 und 5 oben). Läuft erst
 * nach den Echtheitsprüfungen (Signaturen, Zertifikatsgültigkeit, Sperrung,
 * Status), damit deren genauere Fehlercodes Vorrang behalten und ein
 * abgelaufenes Zertifikat nicht als "KB-JWT zu alt" erscheint.
 */
export function kbJwtFailure(token: string, options: SdJwtStructureOptions): SdJwtStructureFailure | undefined {
  const kbJwt = token.split('~').pop() ?? '';
  if (kbJwt === '') return 'kb_jwt_missing';
  let kbHeader: unknown;
  let kbPayload: unknown;
  try {
    kbHeader = decodeJson(kbJwt.split('.')[0] ?? '');
    kbPayload = decodeJson(kbJwt.split('.')[1] ?? '');
  } catch {
    return 'kb_jwt_missing';
  }
  if (typeof kbHeader !== 'object' || kbHeader === null || (kbHeader as Record<string, unknown>).typ !== 'kb+jwt') return 'kb_jwt_typ_invalid';
  const iat = typeof kbPayload === 'object' && kbPayload !== null ? (kbPayload as Record<string, unknown>).iat : undefined;
  if (typeof iat !== 'number' || !Number.isFinite(iat)) return 'kb_jwt_iat_invalid';
  const nowSeconds = options.now.getTime() / 1000;
  if (iat < nowSeconds - options.maxKbAgeSeconds) return 'kb_jwt_too_old';
  if (iat > nowSeconds + options.clockSkewSeconds) return 'kb_jwt_in_future';
  return undefined;
}

/**
 * Fehlercode nach außen. Unlesbare Token und ein fehlendes KB-JWT überlässt der
 * Dienst der Bibliothek, die dafür feste, dokumentierte Codes liefert
 * (`credential_malformed` und andere). Was die Bibliothek annimmt und RFC 9901
 * verbietet, bekommt hier einen Code: kaputte oder doppelte Offenlegungen und
 * Digests `credential_malformed`, ein unzulässiges KB-JWT `presentation_invalid`.
 */
export function publicCodeFor(failure: SdJwtStructureFailure): string | undefined {
  switch (failure) {
    case 'sd_jwt_malformed':
    case 'kb_jwt_missing':
      return undefined;
    case 'disclosure_malformed':
    case 'disclosure_duplicate':
    case 'digest_duplicate':
      return 'credential_malformed';
    default:
      return 'presentation_invalid';
  }
}
