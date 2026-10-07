/**
 * Mandantendatei für den Betrieb ohne Entwicklungsschalter.
 *
 * Ohne ATTACK_DEV_MODE legt der Dienst keine Test-Mandanten an. Bisher gab es
 * dann gar keinen Weg zu einem Mandanten, jede Prüfanfrage endete mit 401.
 * Diese Datei schließt die Lücke: Das CLI (`npm run cli -- tenant ...`)
 * schreibt sie, der Dienst liest sie beim Start über ATTACK_TENANTS_FILE.
 *
 * Grundsätze:
 *   - Gespeichert wird nur der SHA-256-Hash des API-Schlüssels. Den Klartext
 *     zeigt das CLI genau einmal auf der Konsole, danach existiert er nur beim
 *     Kunden.
 *   - Fail closed: Ist die Variable gesetzt und die Datei unlesbar, kein JSON,
 *     in falscher Version, mit unbekanntem Feld, doppelter ID, doppeltem Hash
 *     oder unbrauchbarem Profil, bricht der Start ab. Ein Tippfehler darf nicht
 *     zu einem Dienst führen, der stillschweigend ohne einen Teil seiner
 *     Mandanten läuft.
 *   - Gesperrte Mandanten bleiben in der Datei (Nachvollziehbarkeit), werden
 *     aber nicht in den Dienst geladen. Ihr Schlüssel endet damit wie ein
 *     unbekannter Schlüssel mit 401.
 *   - Der Dienst liest die Datei nur beim Start. Anlegen und Sperren wirken
 *     erst nach einem Neustart.
 *
 * Meldungen nennen Pfad, Eintrag und Feld, nie den Hash. Den Zusatz
 * "Start abgebrochen" ergänzt der Dienststart; das CLI nutzt dieselben Meldungen.
 */
import { randomBytes } from 'node:crypto';
import { readFile, rename, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';

import { ConfigError } from '../config.ts';
import { resolveRequestProfile } from './profile.ts';
import { hashApiKey, type TenantStore } from './tenant.ts';

/** Pfad zur Mandantendatei. */
export const ENV_ATTACK_TENANTS_FILE = 'ATTACK_TENANTS_FILE';
export const TENANT_FILE_VERSION = 1;
/** Obergrenze der Dateigröße. Eine Mandantendatei mit mehr als 1 MiB ist ein Fehler, kein Bestand. */
export const TENANT_FILE_MAX_BYTES = 1024 * 1024;
export const TENANT_TTL_MIN_SECONDS = 30;
export const TENANT_TTL_MAX_SECONDS = 3600;
export const TENANT_TTL_DEFAULT_SECONDS = 300;

const TENANT_ID = /^[a-z0-9][a-z0-9-]{0,62}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const ENTRY_FIELDS = new Set(['id', 'name', 'apiKeySha256', 'requestProfile', 'requestTtlSeconds', 'status', 'createdAt', 'revokedAt']);
const FILE_FIELDS = new Set(['version', 'tenants']);

export type TenantFileStatus = 'active' | 'revoked';

export interface TenantFileEntry {
  id: string;
  name: string;
  /** SHA-256-Hex des API-Schlüssels. */
  apiKeySha256: string;
  /** Name einer Profilvorlage oder ein eigenes Profil (siehe profile.ts). */
  requestProfile: string | Record<string, unknown>;
  requestTtlSeconds: number;
  status: TenantFileStatus;
  /** ISO 8601. */
  createdAt: string;
  /** ISO 8601, nur bei gesperrten Mandanten. */
  revokedAt?: string;
}

export interface TenantFile {
  version: typeof TENANT_FILE_VERSION;
  tenants: TenantFileEntry[];
}

export function emptyTenantFile(): TenantFile {
  return { version: TENANT_FILE_VERSION, tenants: [] };
}

function fail(label: string, detail: string): never {
  throw new ConfigError(`${label}: ${detail}`);
}

function hasControlChars(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function isIsoDate(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 40 && !Number.isNaN(Date.parse(value)) && /^\d{4}-\d{2}-\d{2}T/.test(value);
}

/**
 * Prüft den Inhalt vollständig. `label` steht am Anfang jeder Meldung, damit
 * der Betrieb sieht, welche Datei gemeint ist.
 */
export function parseTenantFile(raw: unknown, label: string): TenantFile {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) fail(label, 'Die Datei muss ein JSON-Objekt sein.');
  const record = raw as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!FILE_FIELDS.has(key)) fail(label, `Unbekanntes Feld "${key}".`);
  }
  if (record.version !== TENANT_FILE_VERSION) fail(label, `Feld "version" muss ${TENANT_FILE_VERSION} sein.`);
  if (!Array.isArray(record.tenants)) fail(label, 'Feld "tenants" muss eine Liste sein.');

  const ids = new Set<string>();
  const hashes = new Set<string>();
  const tenants: TenantFileEntry[] = record.tenants.map((value: unknown, index: number) => {
    const where = `Eintrag ${index + 1}`;
    if (typeof value !== 'object' || value === null || Array.isArray(value)) fail(label, `${where} muss ein Objekt sein.`);
    const entry = value as Record<string, unknown>;
    for (const key of Object.keys(entry)) {
      if (!ENTRY_FIELDS.has(key)) fail(label, `${where}: unbekanntes Feld "${key}".`);
    }
    const { id, name, apiKeySha256, requestProfile, requestTtlSeconds, status, createdAt, revokedAt } = entry;
    if (typeof id !== 'string' || !TENANT_ID.test(id)) {
      fail(label, `${where}: "id" muss aus Kleinbuchstaben, Ziffern und Bindestrich bestehen (höchstens 63 Zeichen).`);
    }
    const at = `${where} (${id})`;
    if (ids.has(id)) fail(label, `${at}: ID ist doppelt vergeben.`);
    ids.add(id);
    if (typeof name !== 'string' || name.trim().length === 0 || name.length > 200 || hasControlChars(name)) {
      fail(label, `${at}: "name" muss Text mit 1 bis 200 Zeichen ohne Steuerzeichen sein.`);
    }
    if (typeof apiKeySha256 !== 'string' || !SHA256_HEX.test(apiKeySha256)) {
      fail(label, `${at}: "apiKeySha256" muss ein SHA-256-Hex-Wert sein (64 Zeichen 0-9 a-f).`);
    }
    if (hashes.has(apiKeySha256)) fail(label, `${at}: derselbe API-Schlüssel ist bereits einem anderen Mandanten zugeordnet.`);
    hashes.add(apiKeySha256);
    const profileInput = requestProfile;
    if (typeof profileInput !== 'string' && (typeof profileInput !== 'object' || profileInput === null || Array.isArray(profileInput))) {
      fail(label, `${at}: "requestProfile" muss ein Vorlagenname oder ein Objekt sein.`);
    }
    try {
      resolveRequestProfile(profileInput as string | Record<string, unknown>);
    } catch (e) {
      fail(label, `${at}: ${e instanceof Error ? e.message : String(e)}.`);
    }
    if (
      typeof requestTtlSeconds !== 'number' ||
      !Number.isInteger(requestTtlSeconds) ||
      requestTtlSeconds < TENANT_TTL_MIN_SECONDS ||
      requestTtlSeconds > TENANT_TTL_MAX_SECONDS
    ) {
      fail(label, `${at}: "requestTtlSeconds" muss eine ganze Zahl zwischen ${TENANT_TTL_MIN_SECONDS} und ${TENANT_TTL_MAX_SECONDS} sein.`);
    }
    if (status !== 'active' && status !== 'revoked') fail(label, `${at}: "status" muss "active" oder "revoked" sein.`);
    if (!isIsoDate(createdAt)) fail(label, `${at}: "createdAt" muss ein ISO-8601-Zeitpunkt sein.`);
    if (status === 'revoked' && !isIsoDate(revokedAt)) fail(label, `${at}: gesperrter Mandant braucht "revokedAt" als ISO-8601-Zeitpunkt.`);
    if (status === 'active' && revokedAt !== undefined) fail(label, `${at}: aktiver Mandant darf kein "revokedAt" tragen.`);

    const parsed: TenantFileEntry = {
      id,
      name,
      apiKeySha256,
      requestProfile: profileInput as string | Record<string, unknown>,
      requestTtlSeconds,
      status,
      createdAt,
    };
    if (status === 'revoked') parsed.revokedAt = revokedAt as string;
    return parsed;
  });

  return { version: TENANT_FILE_VERSION, tenants };
}

/** Liest und prüft die Mandantendatei. Jeder Fehler ist ein ConfigError. */
export async function loadTenantFile(path: string, label = ENV_ATTACK_TENANTS_FILE): Promise<TenantFile> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    fail(label, 'Datei nicht lesbar (Pfad prüfen).');
  }
  if (Buffer.byteLength(text, 'utf8') > TENANT_FILE_MAX_BYTES) fail(label, `Datei ist größer als ${TENANT_FILE_MAX_BYTES} Bytes.`);
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    fail(label, 'Datei ist kein gültiges JSON.');
  }
  return parseTenantFile(raw, label);
}

/**
 * Schreibt die Datei atomar: erst eine temporäre Datei im selben Verzeichnis
 * mit Rechten 0600, dann umbenennen. Ein Abbruch mitten im Schreiben hinterlässt
 * so nie eine halbe Datei, die den nächsten Start scheitern ließe. Vor dem
 * Schreiben wird der Inhalt mit demselben Prüfer geprüft wie beim Start.
 */
export async function writeTenantFile(path: string, file: TenantFile): Promise<void> {
  const checked = parseTenantFile(JSON.parse(JSON.stringify(file)) as unknown, path);
  const tmp = join(dirname(path), `.${basename(path)}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`);
  try {
    await writeFile(tmp, `${JSON.stringify(checked, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    await rename(tmp, path);
  } catch (e) {
    await rm(tmp, { force: true });
    throw e;
  }
}

/** Neuer API-Schlüssel: 32 Zufallsbytes, base64url, mit erkennbarem Präfix. */
export function generateApiKey(): string {
  return `atk_${randomBytes(32).toString('base64url')}`;
}

export interface NewTenantFileEntry {
  id: string;
  name: string;
  requestProfile?: string;
  requestTtlSeconds?: number;
  now?: Date;
}

/**
 * Legt einen Mandanten in der Datei (im Speicher) an und liefert den neuen
 * Klartext-Schlüssel zurück. Der Aufrufer zeigt ihn einmal an und schreibt
 * danach die Datei; der Klartext selbst landet nie in `file`.
 */
export function addTenantEntry(file: TenantFile, input: NewTenantFileEntry): { file: TenantFile; apiKey: string } {
  if (file.tenants.some((t) => t.id === input.id)) {
    throw new ConfigError(`Mandant "${input.id}" existiert bereits (auch gesperrte IDs werden nicht neu vergeben).`);
  }
  const apiKey = generateApiKey();
  const entry: TenantFileEntry = {
    id: input.id,
    name: input.name,
    apiKeySha256: hashApiKey(apiKey),
    requestProfile: input.requestProfile ?? 'pid_basis',
    requestTtlSeconds: input.requestTtlSeconds ?? TENANT_TTL_DEFAULT_SECONDS,
    status: 'active',
    createdAt: (input.now ?? new Date()).toISOString(),
  };
  const next: TenantFile = { version: TENANT_FILE_VERSION, tenants: [...file.tenants, entry] };
  // Dieselbe Prüfung wie beim Start, damit das CLI keine Datei erzeugt, die
  // der Dienst danach ablehnt.
  parseTenantFile(next, 'neuer Eintrag');
  return { file: next, apiKey };
}

/** Sperrt einen Mandanten. Liefert `alreadyRevoked`, wenn er schon gesperrt war. */
export function revokeTenantEntry(file: TenantFile, id: string, now: Date = new Date()): { file: TenantFile; alreadyRevoked: boolean } {
  const existing = file.tenants.find((t) => t.id === id);
  if (!existing) throw new ConfigError(`Mandant "${id}" ist in der Datei nicht vorhanden.`);
  if (existing.status === 'revoked') return { file, alreadyRevoked: true };
  const tenants = file.tenants.map((t) => (t.id === id ? { ...t, status: 'revoked' as const, revokedAt: now.toISOString() } : t));
  return { file: { version: TENANT_FILE_VERSION, tenants }, alreadyRevoked: false };
}

export interface AppliedTenantFile {
  active: number;
  revoked: number;
}

/**
 * Lädt die aktiven Mandanten in den Store, über `addHashed`: der Dienst sieht
 * nur den Hash. Eine Kollision mit einem bereits vorhandenen Mandanten (etwa
 * einem Test-Mandanten im Entwicklungsbetrieb) bricht ab.
 */
export function applyTenantFile(store: TenantStore, file: TenantFile, label = ENV_ATTACK_TENANTS_FILE): AppliedTenantFile {
  let active = 0;
  let revoked = 0;
  for (const entry of file.tenants) {
    if (entry.status === 'revoked') {
      revoked += 1;
      continue;
    }
    try {
      store.addHashed({
        id: entry.id,
        name: entry.name,
        apiKeyHash: entry.apiKeySha256,
        requestProfile: entry.requestProfile,
        requestTtlSeconds: entry.requestTtlSeconds,
      });
    } catch (e) {
      fail(label, `Mandant "${entry.id}" nicht ladbar: ${e instanceof Error ? e.message : String(e)}.`);
    }
    active += 1;
  }
  return { active, revoked };
}
