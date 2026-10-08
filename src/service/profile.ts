import { buildHaipQuery, type DcqlQuery } from '@openeudi/openid4vp';

export type QueryFormat = 'dc+sd-jwt';

export interface RequestProfile {
  id: string;
  vct: string;
  claims: string[];
  credentialId: string;
  /**
   * Angefragte Claims, die genau `true` sein müssen (Altersprüfung). Ist einer
   * `false`, endet die Prüfung mit `age_requirement_not_met` und einem klaren
   * Nein im Ergebnis; fehlt oder hat er einen anderen Typ, wird die
   * Präsentation abgelehnt. Muss eine Teilmenge von `claims` sein.
   */
  mustBeTrue?: string[];
}

/**
 * Altersschwellen der deutschen PID im SD-JWT-Format. Beleg: offizielle
 * Developer-Doku, PID-Referenz ("Age Verification Thresholds"): Schwellen 12,
 * 14, 16, 18, 21 und 65, in SD-JWT VC gruppiert im Objekt `age_equal_or_over`
 * (Schlüssel "18" und so weiter), in mdoc als einzelne Claims `age_over_NN`.
 */
export const GERMAN_PID_AGE_THRESHOLDS = [12, 14, 16, 18, 21, 65] as const;
const AGE_PATH = /^age_equal_or_over\.(\d{1,3})$/;

/**
 * DCQL-Pfad eines Claim-Namens. Ein Name der Form `age_equal_or_over.18` ist
 * der verschachtelte Pfad `["age_equal_or_over", "18"]`; jeder andere Name ist
 * ein Schlüssel der obersten Ebene, auch wenn er einen Punkt enthält.
 */
export function claimPath(name: string): string[] {
  const m = AGE_PATH.exec(name);
  return m ? ['age_equal_or_over', m[1] as string] : [name];
}

/** Wert eines Claim-Namens im geparsten Credential (oberste Ebene oder `age_equal_or_over`). */
function claimValue(parsed: Record<string, unknown>, name: string): { present: boolean; value?: unknown } {
  const path = claimPath(name);
  let current: unknown = parsed;
  for (const key of path) {
    if (typeof current !== 'object' || current === null || Array.isArray(current) || !Object.prototype.hasOwnProperty.call(current, key)) {
      return { present: false };
    }
    current = (current as Record<string, unknown>)[key];
  }
  return { present: true, value: current };
}

/**
 * DCQL-Abfrage für ein Profil: `buildHaipQuery` der Bibliothek, danach die
 * Pfade der Claims (verschachtelte Altersschwellen). Dieselbe Funktion bildet
 * die Anfrage an die Wallet und die Abfrage der Prüfung.
 */
export function buildProfileQuery(input: { credentialId: string; vct: string; claims: string[] }): DcqlQuery {
  const query = buildHaipQuery({ credentialId: input.credentialId, format: 'dc+sd-jwt', vctValues: [input.vct], claims: input.claims });
  for (const credential of query.credentials) {
    (credential as { claims?: Array<{ path: string[] }> }).claims = input.claims.map((name) => ({ path: claimPath(name) }));
  }
  return query;
}

export const PID_VCT_DEFAULT = 'urn:eu.europa.ec.eudi:pid:1';
/**
 * vct der deutschen PID im Format SD-JWT VC. Beleg: offizielle Developer-Doku,
 * "Wallet Use Instructions" (vct_values für den deutschen PID-Aussteller) und
 * "Presenting a PID online" (Beispielanfrage mit given_name, family_name,
 * birthdate).
 */
export const PID_VCT_DE = 'urn:eudi:pid:de:1';

export const REQUEST_PROFILE_TEMPLATES: Record<string, RequestProfile> = {
  pid_basis: {
    id: 'pid_basis',
    vct: PID_VCT_DEFAULT,
    claims: ['given_name', 'birth_date'],
    credentialId: 'pid',
  },
  age_over_18: {
    id: 'age_over_18',
    vct: PID_VCT_DEFAULT,
    claims: ['age_over_18'],
    credentialId: 'pid',
    mustBeTrue: ['age_over_18'],
  },
  // Altersprüfung 18+ für die deutsche PID: nur der Schwellwert, kein
  // Geburtsdatum (Datenminimierung nach der PID-Referenz).
  age_over_18_de: {
    id: 'age_over_18_de',
    vct: PID_VCT_DE,
    claims: ['age_equal_or_over.18'],
    credentialId: 'pid',
    mustBeTrue: ['age_equal_or_over.18'],
  },
  // Deutsche PID aus der Sandbox-Wallet. Die Claim-Namen folgen der
  // SD-JWT-Beispielanfrage der offiziellen Doku (birthdate, nicht birth_date).
  pid_de: {
    id: 'pid_de',
    vct: PID_VCT_DE,
    claims: ['given_name', 'family_name', 'birthdate'],
    credentialId: 'pid',
  },
};

const KNOWN_CLAIMS = new Set([
  ...GERMAN_PID_AGE_THRESHOLDS.map((n) => `age_equal_or_over.${n}`),
  'given_name',
  'family_name',
  'birth_date',
  'birthdate',
  'age_over_18',
  'age_over_21',
  'nationality',
  'resident_address',
  'resident_country',
  'nationality_country',
]);

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

export function parseRequestProfile(value: unknown, fallbackId: string): RequestProfile {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`Anfrageprofil "${fallbackId}" muss ein Objekt sein`);
  }
  const record = value as Record<string, unknown>;
  const allowed = new Set(['id', 'vct', 'claims', 'credentialId', 'mustBeTrue']);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) throw new Error(`Anfrageprofil "${fallbackId}" enthält unbekanntes Feld: "${key}"`);
  }
  if (record.claims !== undefined && !Array.isArray(record.claims)) {
    throw new Error(`Anfrageprofil "${fallbackId}": claims muss eine Liste sein`);
  }
  const claims = record.claims ?? [];
  if (!Array.isArray(claims) || claims.length === 0) {
    throw new Error(`Anfrageprofil "${fallbackId}": mindestens ein Claim erforderlich`);
  }
  for (const claim of claims) {
    if (!isNonEmptyString(claim)) throw new Error(`Anfrageprofil "${fallbackId}": ungueltiger Claim-Wert`);
    if (!KNOWN_CLAIMS.has(claim)) throw new Error(`Anfrageprofil "${fallbackId}": unbekannter Claim "${claim}" (nicht im PID-Kontext bekannt)`);
  }
  const id = isNonEmptyString(record.id) ? record.id : fallbackId;
  const vct = isNonEmptyString(record.vct) ? record.vct : PID_VCT_DEFAULT;
  const credentialId = isNonEmptyString(record.credentialId) ? record.credentialId : 'pid';
  if (credentialId !== 'pid') throw new Error(`Anfrageprofil "${id}": credentialId "${credentialId}" wird nicht unterstützt`);
  let mustBeTrue: string[] | undefined;
  if (record.mustBeTrue !== undefined) {
    if (!Array.isArray(record.mustBeTrue) || record.mustBeTrue.length === 0 || !record.mustBeTrue.every((c) => typeof c === 'string' && claims.includes(c))) {
      throw new Error(`Anfrageprofil "${id}": mustBeTrue muss eine nicht leere Liste angefragter Claims sein`);
    }
    mustBeTrue = [...(record.mustBeTrue as string[])];
  }
  return { id, vct, claims: [...claims], credentialId, ...(mustBeTrue ? { mustBeTrue } : {}) };
}

export function resolveRequestProfile(idOrConfig: string | Record<string, unknown>): RequestProfile {
  if (typeof idOrConfig === 'string') {
    const template = REQUEST_PROFILE_TEMPLATES[idOrConfig];
    if (!template) throw new Error(`Unbekannte Vorlage "${idOrConfig}". Bekannt: ${Object.keys(REQUEST_PROFILE_TEMPLATES).join(', ')}`);
    return { ...template, claims: [...template.claims], ...(template.mustBeTrue ? { mustBeTrue: [...template.mustBeTrue] } : {}) };
  }
  const id = isNonEmptyString(idOrConfig.id) ? idOrConfig.id : 'custom';
  return parseRequestProfile(idOrConfig, id);
}

/**
 * Schneidet das geparste Präsentationsergebnis auf die angefragten Claims
 * zurück.
 *
 * Warum das nötig ist: die Bibliothek legt in `parsed.claims` nicht nur die
 * selektiv offengelegten Angaben ab, sondern auch Klartext-Angaben aus dem
 * vom Aussteller signierten JWT. Ein Credential kann dort Felder tragen, die
 * der Prüfer nie angefragt hat und die die Wallet nie offengelegt hat. Ohne
 * diesen Schnitt landen sie im Ergebnis, obwohl der Prüfer sie nicht braucht
 * und der Nutzer sie nicht verlangt hat.
 *
 * Gehashte Angaben sind davon nicht betroffen: für einen Hash im Issuer-JWT
 * gibt es ohne zugehörige Offenlegung keinen passenden Wert, die Bibliothek
 * kann sie also gar nicht ausgeben. Genau deshalb war der Fehler lange
 * unbemerkt — die vorhandenen Prüfungen deckten nur den Hash-Fall ab.
 *
 * Dieselbe Liste der angefragten Claims ist die Grundlage: sie hat schon die
 * DCQL-Abfrage gebildet (`buildHaipQuery`), wird also gegen dieselbe Quelle
 * geprüft, gegen die der Prüfer ohnehin arbeitet.
 *
 * Es wird nicht nach Herkunft der Angabe unterschieden, sondern ausschließlich
 * nach Zugehörigkeit zur Anfrageliste. Ein nicht angefragtes Feld bleibt
 * draußen, egal ob es als Hash, als Klartext oder unter einem unbekannten
 * Namen im Credential stand.
 */
export function nurAngefragteClaims(
  parsed: Record<string, unknown>,
  angefragt: readonly string[],
): Record<string, unknown> {
  const gefiltert: Record<string, unknown> = {};
  const erlaubtOben = new Set(angefragt.filter((name) => claimPath(name).length === 1));
  for (const [name, wert] of Object.entries(parsed)) {
    // Die Zugehörigkeit zur Anfrageliste ist die einzige Bedingung. Damit
    // fliegt auch ein Claim heraus, dessen Name nichts mit den bekannten
    // PID-Attributen zu tun hat — die Validierung der Anfrageliste selbst
    // bleibt davon unberührt.
    if (erlaubtOben.has(name)) gefiltert[name] = wert;
  }
  // Verschachtelte Angaben (Altersschwellen): nur der angefragte Schlüssel, nicht
  // das ganze Objekt. Hat die Wallet mehr Schwellen offengelegt als angefragt,
  // bleiben diese draußen. Im Ergebnis steht der Claim unter seinem Namen,
  // z. B. `age_equal_or_over.18`.
  for (const name of angefragt) {
    if (claimPath(name).length === 1) continue;
    const gefunden = claimValue(parsed, name);
    if (gefunden.present) gefiltert[name] = gefunden.value;
  }
  return gefiltert;
}

export type RequirementCheck = { met: true } | { met: false; reason: 'age_requirement_not_met' | 'age_claim_invalid' };

/**
 * Prüft die Bedingungen des Profils (`mustBeTrue`) an den bereits gefilterten
 * Claims. Genau `true` besteht, genau `false` ist ein klares Nein, alles andere
 * (fehlt, falscher Typ) ist eine unbrauchbare Präsentation.
 */
export function checkRequirements(profile: Pick<RequestProfile, 'mustBeTrue'>, claims: Record<string, unknown>): RequirementCheck {
  for (const name of profile.mustBeTrue ?? []) {
    const value = Object.prototype.hasOwnProperty.call(claims, name) ? claims[name] : undefined;
    if (value === false) return { met: false, reason: 'age_requirement_not_met' };
    if (value !== true) return { met: false, reason: 'age_claim_invalid' };
  }
  return { met: true };
}
