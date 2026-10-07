/**
 * Statusprüfung vorgelegter Credentials über eine Token Status List
 * (IETF draft-ietf-oauth-status-list-21, 21.06.2026, Sections 4–8) — fail
 * closed. The draft is still work in progress and has not yet become an RFC.
 *
 * Das Credential verweist mit `status.status_list = { idx, uri }` auf eine
 * signierte Statusliste (`typ: statuslist+jwt`, draft -21 Section 5.1). Die Liste wird mit Zeit- und
 * Größengrenze abgerufen, ihre Signatur gegen die konfigurierten
 * Unterzeichner-Zertifikate geprüft (x5c-Blatt muss byte-gleich einem
 * konfigurierten Zertifikat sein, Signaturprüfung über jose), das Format
 * geprüft, entpackt (node:zlib, mit Größengrenze) und der Wert an `idx`
 * gelesen. Nur 0x00 (VALID) lässt die Prüfung passieren.
 *
 * Jeder Fehlerpfad lehnt ab, mit eigenem Code (siehe docs/fehlercodes.md).
 * Ein Credential OHNE Statusverweis wird abgelehnt
 * (credential_status_missing). `NO_CREDENTIAL_STATUS` schaltet die Prüfung ab
 * und ist nur mit Entwicklungsschalter erlaubt.
 */
import { inflateSync } from 'node:zlib';

import { compactVerify, decodeProtectedHeader } from 'jose';
import { X509Certificate } from '@peculiar/x509';

import { ConfigError, ENV_ATTACK_DEV_MODE } from '../config.ts';
import { certificateValidityFailure, DEFAULT_CLOCK_SKEW_SECONDS } from '../lib/cert-validity.ts';
import { DEFAULT_FETCH_MAX_BYTES, DEFAULT_FETCH_TIMEOUT_MS, fetchLimited, LimitedFetchError, type FetchImpl } from '../lib/limited-fetch.ts';
import { STRICT_MODE, type RuntimeMode } from '../onboarding/revocation.ts';

export const STATUS_LIST_JWT_TYPE = 'statuslist+jwt';
export const STATUS_LIST_SUPPORTED_ALGS = ['ES256', 'ES384'] as const;

export type CredentialStatusErrorCode =
  | 'credential_status_missing'
  | 'credential_status_reference_invalid'
  | 'status_list_unreachable'
  | 'status_list_timeout'
  | 'status_list_too_large'
  | 'status_list_signature_invalid'
  | 'status_list_malformed'
  | 'status_list_expired'
  | 'credential_status_unknown'
  | 'credential_revoked'
  | 'credential_suspended'
  | 'certificate_expired'
  | 'certificate_not_yet_valid';

export class CredentialStatusError extends Error {
  readonly code: CredentialStatusErrorCode;
  constructor(code: CredentialStatusErrorCode) {
    super(code);
    this.name = 'CredentialStatusError';
    this.code = code;
  }
}

export interface CredentialStatusChecker {
  /**
   * Prüft den Status eines (bereits signaturgeprüften) Credentials anhand des
   * Issuer-JWT-Payloads. Wirft CredentialStatusError bei jedem Ergebnis außer
   * „gültig".
   */
  check(issuerPayload: Record<string, unknown>): Promise<void>;
}

/** Keine Statusprüfung. Nur mit ATTACK_DEV_MODE=true außerhalb von Produktion. */
export const NO_CREDENTIAL_STATUS: CredentialStatusChecker = Object.freeze({
  async check(): Promise<void> {
    /* absichtlich ohne Prüfung, nur Entwicklungsschalter */
  },
});

export function assertCredentialStatusAllowed(checker: CredentialStatusChecker | undefined, mode: RuntimeMode = STRICT_MODE): void {
  if (checker === undefined) {
    throw new ConfigError('Keine Statusprüfung für Credentials konfiguriert (TokenStatusListChecker). Start abgebrochen.');
  }
  if (checker !== NO_CREDENTIAL_STATUS) return;
  if (mode.devMode && !mode.isProduction) return;
  throw new ConfigError(
    'Statusprüfung für Credentials ist abgeschaltet (NO_CREDENTIAL_STATUS), das ist nur mit ' +
      `${ENV_ATTACK_DEV_MODE}=true außerhalb von Produktion erlaubt. Start abgebrochen.`,
  );
}

export interface TokenStatusListCheckerOptions {
  /** Zertifikate (DER), die Statuslisten unterschreiben dürfen. Leer: jede Prüfung scheitert. */
  trustedSigners: () => readonly Uint8Array[];
  timeoutMs?: number;
  maxBytes?: number;
  /** Obergrenze für die entpackte Liste (Bytes). */
  maxDecompressedBytes?: number;
  clockSkewSeconds?: number;
  /** Statuslisten über http statt https zulassen (nur lokale Tests). Standard: aus. */
  allowInsecureHttp?: boolean;
  fetchImpl?: FetchImpl;
  now?: () => number;
}

export class TokenStatusListChecker implements CredentialStatusChecker {
  private readonly trustedSigners: () => readonly Uint8Array[];
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly maxDecompressedBytes: number;
  private readonly clockSkewSeconds: number;
  private readonly allowInsecureHttp: boolean;
  private readonly fetchImpl?: FetchImpl;
  private readonly now: () => number;

  constructor(options: TokenStatusListCheckerOptions) {
    this.trustedSigners = options.trustedSigners;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
    this.maxBytes = options.maxBytes ?? DEFAULT_FETCH_MAX_BYTES;
    this.maxDecompressedBytes = options.maxDecompressedBytes ?? 16 * 1024 * 1024;
    // Vorher stand hier die erzwungene 60. Dieselbe Zahl, aber aus dem
    // geteilten Standard: sonst auseinanderlaufen Konfiguration und
    // Standardwert, sobald einer von beiden geaendert wird.
    this.clockSkewSeconds = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
    this.allowInsecureHttp = options.allowInsecureHttp ?? false;
    this.fetchImpl = options.fetchImpl;
    this.now = options.now ?? (() => Date.now());
  }

  async check(issuerPayload: Record<string, unknown>): Promise<void> {
    const { idx, uri } = readStatusReference(issuerPayload);
    if (!this.allowInsecureHttp && !uri.startsWith('https://')) throw new CredentialStatusError('credential_status_reference_invalid');

    let raw: string;
    try {
      const { body } = await fetchLimited(uri, {
        timeoutMs: this.timeoutMs,
        maxBytes: this.maxBytes,
        accept: 'application/statuslist+jwt',
        fetchImpl: this.fetchImpl,
      });
      raw = new TextDecoder('utf-8', { fatal: true }).decode(body).trim();
    } catch (e) {
      if (e instanceof LimitedFetchError && e.code === 'fetch_timeout') throw new CredentialStatusError('status_list_timeout');
      if (e instanceof LimitedFetchError && e.code === 'fetch_too_large') throw new CredentialStatusError('status_list_too_large');
      if (e instanceof LimitedFetchError) throw new CredentialStatusError('status_list_unreachable');
      throw new CredentialStatusError('status_list_malformed');
    }

    const payload = await this.verifyToken(raw);
    const nowSeconds = Math.floor(this.now() / 1000);

    if (payload.sub !== uri) throw new CredentialStatusError('status_list_malformed');
    if (typeof payload.iat !== 'number' || !Number.isFinite(payload.iat)) throw new CredentialStatusError('status_list_malformed');
    // exp ist im Draft -21 Section 5.1 nur RECOMMENDED. Diese Implementierung
    // macht es als lokale fail-closed-Betriebspolitik zur Pflicht; zusätzliche
    // Einschränkungen liegen laut Section 8.3 im Ermessen der Relying Party.
    if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) throw new CredentialStatusError('status_list_malformed');
    if (payload.exp + this.clockSkewSeconds < nowSeconds) throw new CredentialStatusError('status_list_expired');
    if (payload.iat - this.clockSkewSeconds > nowSeconds) throw new CredentialStatusError('status_list_expired');

    const list = payload.status_list;
    if (typeof list !== 'object' || list === null) throw new CredentialStatusError('status_list_malformed');
    const { bits, lst } = list as Record<string, unknown>;
    if (bits !== 1 && bits !== 2 && bits !== 4 && bits !== 8) throw new CredentialStatusError('status_list_malformed');
    if (typeof lst !== 'string' || !/^[A-Za-z0-9_-]+$/.test(lst)) throw new CredentialStatusError('status_list_malformed');

    let bytes: Buffer;
    try {
      bytes = inflateSync(Buffer.from(lst, 'base64url'), { maxOutputLength: this.maxDecompressedBytes });
    } catch {
      throw new CredentialStatusError('status_list_malformed');
    }

    const bitOffset = idx * bits;
    const byteIndex = Math.floor(bitOffset / 8);
    if (byteIndex >= bytes.length) throw new CredentialStatusError('credential_status_reference_invalid');
    const value = (bytes[byteIndex] >> (bitOffset % 8)) & ((1 << bits) - 1);

    if (value === 0x00) return;
    if (value === 0x01) throw new CredentialStatusError('credential_revoked');
    if (value === 0x02) throw new CredentialStatusError('credential_suspended');
    throw new CredentialStatusError('credential_status_unknown');
  }

  private async verifyToken(raw: string): Promise<Record<string, unknown>> {
    let header: { typ?: unknown; alg?: unknown; x5c?: unknown };
    try {
      header = decodeProtectedHeader(raw) as typeof header;
    } catch {
      throw new CredentialStatusError('status_list_malformed');
    }
    if (header.typ !== STATUS_LIST_JWT_TYPE) throw new CredentialStatusError('status_list_malformed');
    if (typeof header.alg !== 'string' || !(STATUS_LIST_SUPPORTED_ALGS as readonly string[]).includes(header.alg)) {
      throw new CredentialStatusError('status_list_signature_invalid');
    }
    if (!Array.isArray(header.x5c) || header.x5c.length === 0 || typeof header.x5c[0] !== 'string') {
      throw new CredentialStatusError('status_list_signature_invalid');
    }

    let leafDer: Buffer;
    try {
      leafDer = Buffer.from(header.x5c[0], 'base64');
    } catch {
      throw new CredentialStatusError('status_list_signature_invalid');
    }
    const trusted = this.trustedSigners().some((der) => Buffer.compare(Buffer.from(der), leafDer) === 0);
    if (!trusted) throw new CredentialStatusError('status_list_signature_invalid');

    // Gültigkeitszeitraum des Unterzeichner-Zertifikats (Haertung 9).
    const validity = certificateValidityFailure(new Uint8Array(leafDer), new Date(this.now()), this.clockSkewSeconds);
    if (validity) throw new CredentialStatusError(validity);

    let payloadBytes: Uint8Array;
    try {
      const cert = new X509Certificate(new Uint8Array(leafDer));
      const key = await cert.publicKey.export();
      ({ payload: payloadBytes } = await compactVerify(raw, key, { algorithms: [...STATUS_LIST_SUPPORTED_ALGS] }));
    } catch {
      throw new CredentialStatusError('status_list_signature_invalid');
    }
    try {
      const payload: unknown = JSON.parse(new TextDecoder().decode(payloadBytes));
      if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new Error('kein objekt');
      return payload as Record<string, unknown>;
    } catch {
      throw new CredentialStatusError('status_list_malformed');
    }
  }
}

/** Liest `status.status_list = { idx, uri }` aus dem Issuer-Payload. */
export function readStatusReference(issuerPayload: Record<string, unknown>): { idx: number; uri: string } {
  const status = issuerPayload.status;
  if (status === undefined) throw new CredentialStatusError('credential_status_missing');
  if (typeof status !== 'object' || status === null) throw new CredentialStatusError('credential_status_reference_invalid');
  const ref = (status as Record<string, unknown>).status_list;
  if (ref === undefined) throw new CredentialStatusError('credential_status_missing');
  if (typeof ref !== 'object' || ref === null) throw new CredentialStatusError('credential_status_reference_invalid');
  const { idx, uri } = ref as Record<string, unknown>;
  if (typeof idx !== 'number' || !Number.isSafeInteger(idx) || idx < 0) throw new CredentialStatusError('credential_status_reference_invalid');
  if (typeof uri !== 'string') throw new CredentialStatusError('credential_status_reference_invalid');
  try {
    const url = new URL(uri);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('kein http(s)');
  } catch {
    throw new CredentialStatusError('credential_status_reference_invalid');
  }
  return { idx, uri };
}
