export type QueryFormat = 'dc+sd-jwt';

export interface RequestProfile {
  id: string;
  vct: string;
  claims: string[];
  credentialId: string;
}

export const PID_VCT_DEFAULT = 'urn:eu.europa.ec.eudi:pid:1';

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
  },
};

const KNOWN_CLAIMS = new Set([
  'given_name',
  'family_name',
  'birth_date',
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
  const allowed = new Set(['id', 'vct', 'claims', 'credentialId']);
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
  return { id, vct, claims: [...claims], credentialId };
}

export function resolveRequestProfile(idOrConfig: string | Record<string, unknown>): RequestProfile {
  if (typeof idOrConfig === 'string') {
    const template = REQUEST_PROFILE_TEMPLATES[idOrConfig];
    if (!template) throw new Error(`Unbekannte Vorlage "${idOrConfig}". Bekannt: ${Object.keys(REQUEST_PROFILE_TEMPLATES).join(', ')}`);
    return { ...template, claims: [...template.claims] };
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
  const erlaubt = new Set(angefragt);
  const gefiltert: Record<string, unknown> = {};
  for (const [name, wert] of Object.entries(parsed)) {
    // Die Zugehörigkeit zur Anfrageliste ist die einzige Bedingung. Damit
    // fliegt auch ein Claim heraus, dessen Name nichts mit den bekannten
    // PID-Attributen zu tun hat — die Validierung der Anfrageliste selbst
    // bleibt davon unberührt.
    if (erlaubt.has(name)) gefiltert[name] = wert;
  }
  return gefiltert;
}
