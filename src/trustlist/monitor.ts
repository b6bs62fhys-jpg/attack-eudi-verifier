/**
 * Trust-List-Monitor (Baustein A, Prototyp).
 *
 * Abruf (nur gegen lokale Mock-Endpunkte), Signaturprüfung, lokaler Cache,
 * Differenz-Erkennung zwischen zwei Abrufen (added/removed/updated) mit
 * Log-Benachrichtigung und Fail-closed-Fragen („Issuer auf der aktuellen
 * Trust List?“). Alle Identifikatoren sind frei von PII; es werden keine
 * Schlüsselwerte ausgegeben.
 */
import { createHash } from 'node:crypto';
import { createLocalJWKSet, jwtVerify } from 'jose';

import type { TrustAnchorChange, TrustListDocument, TrustListEntry } from './types.ts';

export const TRUST_LIST_JWS_TYP = 'trust-list+jwt.test';

export class TrustListError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'TrustListError';
    this.code = code;
  }
}

export class TrustListSignatureError extends TrustListError {
  constructor(message = 'signatur kann nicht gegen den gepinnten Trust-List-Authority-Schluessel verifiziert werden') {
    super('trust_list_signature_invalid', message);
  }
}

export class TrustListFetchError extends TrustListError {
  constructor(message = 'trust list kann nicht abgerufen werden') {
    super('trust_list_fetch_failed', message);
  }
}

export class TrustListFormatError extends TrustListError {
  constructor(message = 'trust list dokument ist ungueltig') {
    super('trust_list_format_invalid', message);
  }
}

export interface TrustListFetchResult {
  status: number;
  body: string;
}

export type TrustListFetcher = (uri: string) => Promise<TrustListFetchResult>;

export interface VerifiedTrustList {
  payload: TrustListDocument;
}

export interface TrustListSignatureVerifier {
  verify(raw: string): Promise<VerifiedTrustList>;
  readonly authorityIdentifier: string;
}

/**
 * TEST-Signatur-Verifier: JWS mit gepinntem Public-Key (TEST-Trust-List-Authority).
 * Produktionsablösung: ETSI TS 119 612 XML-DSig/LoTE prüfen.
 */
export class JwsTrustListSignatureVerifier implements TrustListSignatureVerifier {
  readonly authorityIdentifier: string;
  private readonly publicJwk: JsonWebKey;

  constructor(publicJwk: JsonWebKey, authorityIdentifier = 'TEST-Trust-List-Authority 1') {
    this.publicJwk = publicJwk;
    this.authorityIdentifier = authorityIdentifier;
  }

  async verify(raw: string): Promise<VerifiedTrustList> {
    let payload: Record<string, unknown>;
    try {
      const result = await jwtVerify(raw, createLocalJWKSet({ keys: [this.publicJwk] }), { typ: TRUST_LIST_JWS_TYP });
      payload = result.payload as Record<string, unknown>;
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      const err = new TrustListSignatureError();
      (err as Error & { cause?: string }).cause = message;
      throw err;
    }
    return { payload: parseTrustListDocument(payload) };
  }
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) throw new TrustListFormatError(`feld ${field} fehlt oder ist leer`);
  return value;
}

function requireNumber(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) throw new TrustListFormatError(`feld ${field} fehlt oder ist ungueltig`);
  return value;
}

export function trustAnchorFingerprintHex(entry: TrustListEntry): string {
  return entry.trustAnchorX509Sha256.toLowerCase().replace(/^0x/, '');
}

export function parseTrustListDocument(value: unknown): TrustListDocument {
  if (typeof value !== 'object' || value === null) throw new TrustListFormatError();
  const raw = value as Record<string, unknown>;
  if (!Array.isArray(raw.entries)) throw new TrustListFormatError('feld entries fehlt oder ist keine Liste');
  const entries = raw.entries.map((entry) => parseTrustListEntry(entry));
  return {
    id: requireString(raw.id, 'id'),
    issuer: requireString(raw.issuer, 'issuer'),
    issuedAt: requireNumber(raw.issuedAt, 'issuedAt'),
    nextUpdate: requireNumber(raw.nextUpdate, 'nextUpdate'),
    version: requireString(raw.version, 'version'),
    entries,
  };
}

function parseTrustListEntry(value: unknown): TrustListEntry {
  if (typeof value !== 'object' || value === null) throw new TrustListFormatError();
  const raw = value as Record<string, unknown>;
  const providerName = requireString(raw.providerName, 'providerName');
  const country = requireString(raw.country, 'country');
  if (!/^[A-Za-z]{2}$/.test(country)) throw new TrustListFormatError('feld country ist kein ISO-3166-1-alpha-2');
  const trustAnchorX509Sha256 = requireString(raw.trustAnchorX509Sha256, 'trustAnchorX509Sha256').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(trustAnchorX509Sha256)) throw new TrustListFormatError('feld trustAnchorX509Sha256 ist kein SHA-256-Hex');
  const validFrom = requireNumber(raw.validFrom, 'validFrom');
  const validTo = requireNumber(raw.validTo, 'validTo');
  if (validTo < validFrom) throw new TrustListFormatError('validTo liegt vor validFrom');
  return {
    providerName,
    country,
    serviceType: requireString(raw.serviceType, 'serviceType'),
    trustAnchorX509Sha256,
    subjectCommonName: requireString(raw.subjectCommonName, 'subjectCommonName'),
    validFrom,
    validTo,
  };
}

export function sha256Hex(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

function entryKey(entry: TrustListEntry): string {
  return entry.trustAnchorX509Sha256.toLowerCase();
}

export function computeAnchorChanges(prev: readonly TrustListEntry[] | undefined, next: readonly TrustListEntry[], at = new Date().toISOString()): TrustAnchorChange[] {
  const prevMap = new Map<string, TrustListEntry>();
  for (const entry of prev ?? []) prevMap.set(entryKey(entry), entry);

  const changes: TrustAnchorChange[] = [];
  for (const entry of next) {
    const before = prevMap.get(entryKey(entry));
    if (!before) {
      changes.push({ change: 'added', providerName: entry.providerName, subjectCommonName: entry.subjectCommonName, fingerprintHex: entryKey(entry), serviceType: entry.serviceType, at });
    } else if (before.providerName !== entry.providerName || before.subjectCommonName !== entry.subjectCommonName || before.serviceType !== entry.serviceType) {
      changes.push({ change: 'updated', providerName: entry.providerName, subjectCommonName: entry.subjectCommonName, fingerprintHex: entryKey(entry), serviceType: entry.serviceType, at });
    }
    prevMap.delete(entryKey(entry));
  }
  for (const remaining of prevMap.values()) {
    changes.push({ change: 'removed', providerName: remaining.providerName, subjectCommonName: remaining.subjectCommonName, fingerprintHex: entryKey(remaining), serviceType: remaining.serviceType, at });
  }

  changes.sort((a, b) => (a.fingerprintHex < b.fingerprintHex ? -1 : a.fingerprintHex > b.fingerprintHex ? 1 : 0));
  return changes;
}

export interface IssuerTrustPolicy {
  isIssuerTrusted(issuerCertDer: Uint8Array): boolean;
}

export interface TrustListMonitorOptions {
  uri: string;
  fetcher: TrustListFetcher;
  verifier: TrustListSignatureVerifier;
  cacheTtlMs?: number;
  /**
   * Mindestabstand zwischen zwei Netzabrufen (auch bei `refresh(true)`),
   * um die Upstream-Trust-List nicht zu hoppeln. 0 schaltet die Begrenzung aus.
   */
  minFetchIntervalMs?: number;
  now?: () => number;
  onChange?: (changes: TrustAnchorChange[]) => void;
}

export interface RefreshResult {
  fetched: boolean;
  applied: boolean;
  changes: TrustAnchorChange[];
  currentVersion: string;
  updatedAt: string;
  nextUpdateAt: string;
}

export interface TrustListView {
  document: TrustListDocument;
  isLoaded: boolean;
  lastVerifiedAt?: string;
}

export class TrustListMonitor implements IssuerTrustPolicy {
  private readonly uri: string;
  private readonly fetcher: TrustListFetcher;
  private readonly verifier: TrustListSignatureVerifier;
  private readonly cacheTtlMs: number;
  private readonly minFetchIntervalMs: number;
  private readonly now: () => number;
  private readonly onChange?: (changes: TrustAnchorChange[]) => void;

  private currentDoc: TrustListDocument | undefined;
  private isLoaded = false;
  private lastVerifiedAt?: number;
  private lastFetchStartedAt?: number;
  private inFlight?: Promise<RefreshResult>;

  constructor(options: TrustListMonitorOptions) {
    this.uri = options.uri;
    this.fetcher = options.fetcher;
    this.verifier = options.verifier;
    this.cacheTtlMs = options.cacheTtlMs ?? 3600_000;
    this.minFetchIntervalMs = options.minFetchIntervalMs ?? 1000;
    this.now = options.now ?? (() => Date.now());
    this.onChange = options.onChange;
  }

  view(): TrustListView {
    return {
      document: this.currentDoc as TrustListDocument,
      isLoaded: this.isLoaded,
      lastVerifiedAt: this.isLoaded ? new Date(this.lastVerifiedAt as number).toISOString() : undefined,
    };
  }

  /** Liefert die aktuelle (letzte erfolgreich verifizierte) Trust List. */
  current(): TrustListDocument | undefined {
    return this.currentDoc;
  }

  /**
   * Aktualisieren. Liefert Cache-Ergebnis, wenn ein erfolgreicher Abruf noch
   * innerhalb der Cache-TTL liegt; sonst Netzabruf mit Signaturprüfung.
   * Netzabrufe werden frühestens alle `minFetchIntervalMs` gestartet (auch bei
   * `force`) und gleichzeitige Aufrufe koalesziert (Single-Flight).
   * Bei Fehler bleibt der letzte gültige Stand aktiv (Fail closed).
   */
  async refresh(force = false): Promise<RefreshResult> {
    if (this.inFlight) return this.inFlight;

    const cached = this.isLoaded && this.lastVerifiedAt !== undefined && this.now() - this.lastVerifiedAt < this.cacheTtlMs && !force;
    if (cached) {
      return this.result(false, []);
    }

    if (this.isLoaded && this.lastFetchStartedAt !== undefined && this.now() - this.lastFetchStartedAt < this.minFetchIntervalMs) {
      return this.result(false, []);
    }

    this.lastFetchStartedAt = this.now();
    const run = this.doFetch();
    this.inFlight = run;
    try {
      return await run;
    } finally {
      if (this.inFlight === run) this.inFlight = undefined;
    }
  }

  private async doFetch(): Promise<RefreshResult> {
    let res: TrustListFetchResult;
    try {
      res = await this.fetcher(this.uri);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      const err = new TrustListFetchError();
      (err as Error & { cause?: string }).cause = message;
      throw err;
    }
    if (res.status < 200 || res.status >= 300) {
      throw new TrustListFetchError(`http-status ${res.status}`);
    }

    const verified = await this.verifier.verify(res.body);
    const changes = computeAnchorChanges(this.currentDoc?.entries, verified.payload.entries);

    this.currentDoc = verified.payload;
    this.isLoaded = true;
    this.lastVerifiedAt = this.now();

    if (changes.length > 0) this.onChange?.(changes);
    return this.result(true, changes);
  }

  private result(fetched: boolean, changes: TrustAnchorChange[]): RefreshResult {
    const doc = this.currentDoc as TrustListDocument;
    return {
      fetched,
      applied: true,
      changes,
      currentVersion: doc.version,
      updatedAt: new Date(this.lastVerifiedAt as number).toISOString(),
      nextUpdateAt: new Date(doc.nextUpdate * 1000).toISOString(),
    };
  }

  /** Fail closed: nicht geladen bzw. Anker nicht auf der Liste → nicht vertraut. */
  isIssuerTrusted(issuerCertDer: Uint8Array): boolean {
    if (!this.isLoaded || !this.currentDoc) return false;
    const fingerprint = sha256Hex(new Uint8Array(issuerCertDer));
    return this.currentDoc.entries.some((entry) => entryKey(entry) === fingerprint);
  }

  /** Stabile, an den Dienst andockbare Policy (Byte-Identität per Fingerabdruck). */
  asIssuerTrustPolicy(): IssuerTrustPolicy {
    return { isIssuerTrusted: (issuerCertDer) => this.isIssuerTrusted(issuerCertDer) };
  }
}