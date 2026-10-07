/**
 * Typisierter Registrar-Client (Baustein B, Prototyp) — TEST-Adapter für die
 * Anforderungen an nationale Register aus CIR (EU) 2025/848, Artikel 3
 * Absätze 1–6 und Anhang II Abschnitte 1–2. Er ist kein behaupteter
 * Anschluss an eine konkrete nationale EUDI-Registrar-API.
 *
 * Nur gegen lokale Mock-Endpunkte (127.0.0.1) in Tests. Der Mock nutzt JWS-
 * Antworten; das ist durch CIR (EU) 2025/848, Anhang II Abschnitt 1 als
 * Signaturformat gedeckt, aber die konkrete Serialization und Payload dieses
 * Clients sind TEST-Annahmen und kein nationales API-Vertrag.
 * Anfragen werden serialisiert und auf `minRequestIntervalMs` pacet
 * (Rate-Limit gegen den Registrar); ein Timeout je Abruf wird als
 * `ErrRegistrarTimeout` unterschieden von Netzwerkfehlern.
 * Kein echtes Netzwerk, keine echten Schlüssel.
 */
import { createLocalJWKSet, jwtVerify } from 'jose';

import {
  ErrIntendedUseNotFound,
  ErrIntendedUseNotActive,
  ErrRegistrarResponseMalformed,
  ErrRegistrarSignature,
  ErrRegistrarStale,
  ErrRegistrarStatus,
  ErrRegistrarTimeout,
  ErrRegistrarUnavailable,
  ErrWrpNotFound,
} from './errors.ts';
import { CLOCK_SKEW_SECONDS_MAX, ConfigError, ENV_ATTACK_CLOCK_SKEW_SECONDS } from '../config.ts';
import { DEFAULT_CLOCK_SKEW_SECONDS } from '../lib/cert-validity.ts';

export type WrpStatus = 'active' | 'revoked' | 'suspended' | 'expired';

export interface IntendedUseReference {
  identifier: string;
  status: WrpStatus;
  createdAt: number;
  revokedAt?: number;
}

export interface WrpItem {
  identifier: string;
  status: WrpStatus;
  legalName: string;
  registrationId: string;
  country: string;
  intendedUses: IntendedUseReference[];
}

export interface WrpListResponse {
  items: WrpItem[];
  nextCursor?: string;
}

export interface IntendedUseStatus {
  identifier: string;
  status: WrpStatus;
  wrpIdentifier: string;
  active: boolean;
  createdAt: number;
  revokedAt?: number;
}

export const REGISTRAR_DEFAULT_MAX_RESPONSE_AGE_SECONDS = 60;

export interface RegistrarFetchResponse {
  status: number;
  text(): Promise<string>;
}

export type RegistrarFetcher = (url: string, init?: { signal?: AbortSignal }) => Promise<RegistrarFetchResponse>;

export interface RegistrarClientOptions {
  /** Basis der Registry-URL, z. B. `https://TEST-registrar.example/api/v1`. */
  registryUri: string;
  /** Pinned öffentlicher Schlüssel dieser Registry (TEST). */
  pinnedPublicJwk: JsonWebKey;
  fetcher?: RegistrarFetcher;
  maxResponseAgeSeconds?: number;
  /**
   * Erlaubte Uhrabweichung fuer `iat` in Sekunden. Gleiche Grenzen und
   * derselbe Standard wie `ATTACK_CLOCK_SKEW_SECONDS`, damit die
   * Alterspruefung der Registrar-Antwort keine eigene Toleranz fuehrt.
   */
  allowedSkewSeconds?: number;
  now?: () => number;
  timeoutMs?: number;
  /**
   * Min. Abstand zwischen zwei gestarteten Registrar-Anfragen (Rate-Limit).
   * Anfragen werden serialisiert; 0 schaltet die Begrenzung aus.
   */
  minRequestIntervalMs?: number;
  /** Warten auf den Pacing-Slot (testbar). Standard: setTimeout. */
  sleep?: (ms: number) => Promise<void>;
}

export class RegistrarClient {
  private readonly registryUri: string;
  private readonly pinnedKey: ReturnType<typeof createLocalJWKSet>;
  private readonly fetcher: RegistrarFetcher;
  private readonly maxResponseAgeSeconds: number;
  private readonly allowedSkewSeconds: number;
  private readonly now: () => number;
  private readonly timeoutMs: number;
  private readonly minRequestIntervalMs: number;
  private readonly sleepImpl: (ms: number) => Promise<void>;

  private paceTail: Promise<void> = Promise.resolve();
  private lastRequestStartedAtMs = 0;

  constructor(options: RegistrarClientOptions) {
    if (!options.registryUri.trim() || !/^https?:\/\//.test(options.registryUri)) {
      throw new Error('registryUri muss eine http(s)-URL sein');
    }
    this.registryUri = options.registryUri.replace(/\/+$/, '');
    this.pinnedKey = createLocalJWKSet({ keys: [options.pinnedPublicJwk] });
    this.fetcher = options.fetcher ?? ((url, init) => fetch(url, init) as unknown as Promise<RegistrarFetchResponse>);
    this.maxResponseAgeSeconds = options.maxResponseAgeSeconds ?? REGISTRAR_DEFAULT_MAX_RESPONSE_AGE_SECONDS;
    // Dieselbe Pruefung und dieselbe Obergrenze wie in der Konfiguration.
    // Bewusst im Konstruktor und nicht erst beim Abruf: ein unbrauchbarer
    // Wert soll den Aufbau abbrechen, nicht die erste Anfrage.
    const skew = options.allowedSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
    if (!Number.isInteger(skew) || skew < 0 || skew > CLOCK_SKEW_SECONDS_MAX) {
      throw new ConfigError(
        `allowedSkewSeconds muss eine ganze Zahl zwischen 0 und ${CLOCK_SKEW_SECONDS_MAX} sein. ` +
          `Gleichbedeutend mit ${ENV_ATTACK_CLOCK_SKEW_SECONDS}. Aufbau abgebrochen.`,
      );
    }
    this.allowedSkewSeconds = skew;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.minRequestIntervalMs = options.minRequestIntervalMs ?? 100;
    this.sleepImpl = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  }

  /** WRP-Verzeichnis: GET /wrp. */
  async getWrpList(limit?: number, cursor?: string): Promise<WrpListResponse> {
    const query = new URLSearchParams();
    if (limit !== undefined) query.set('limit', String(limit));
    if (cursor) query.set('cursor', cursor);
    const qs = query.toString();
    const result = await this.request<WrpListResponse>(`/wrp${qs ? `?${qs}` : ''}`, { notFoundError: ErrWrpNotFound });
    if (!Array.isArray(result.items)) throw new ErrRegistrarResponseMalformed();
    if (result.nextCursor !== undefined && typeof result.nextCursor !== 'string') throw new ErrRegistrarResponseMalformed();
    return result;
  }

  /** WRP-Eintrag: GET /wrp/{identifier}. */
  async getWrpByIdentifier(identifier: string): Promise<WrpItem> {
    if (!identifier.trim()) throw new ErrWrpNotFound();
    const result = await this.request<WrpItem>(`/wrp/${encodeURIComponent(identifier)}`, { notFoundError: ErrWrpNotFound });
    if (typeof result.identifier !== 'string' || typeof result.status !== 'string' || !Array.isArray(result.intendedUses)) throw new ErrRegistrarResponseMalformed();
    return result;
  }

  /** Intended-use-Prüfung: GET /wrp/check-intended-use. */
  async checkIntendedUse(identifier: string): Promise<IntendedUseStatus> {
    if (!identifier.trim()) throw new ErrIntendedUseNotFound();
    const query = new URLSearchParams({ identifier });
    const result = await this.request<IntendedUseStatus>(`/wrp/check-intended-use?${query.toString()}`, { notFoundError: ErrIntendedUseNotFound });
    if (typeof result.identifier !== 'string' || typeof result.status !== 'string' || typeof result.active !== 'boolean') throw new ErrRegistrarResponseMalformed();
    return result;
  }

  /** Komfort-Prüfung: aktiver Intended Use (sonst Ablehnung). */
  async requireActiveIntendedUse(identifier: string): Promise<IntendedUseStatus> {
    const status = await this.checkIntendedUse(identifier);
    if (!status.active || status.status !== 'active') throw new ErrIntendedUseNotActive();
    return status;
  }

  private async request<T>(path: string, opts: { notFoundError: new () => Error }): Promise<T> {
    return this.requestSigned<T>(path, opts.notFoundError);
  }

  /** Serialisiert Anfragen und hält den Mindestabstand zwischen zwei Starts. */
  private serialized<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.paceTail.then(() => this.paceStart()).then(fn);
    this.paceTail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private async paceStart(): Promise<void> {
    if (this.minRequestIntervalMs > 0) {
      const nowMs = Math.floor(this.now() * 1000);
      const nextAllowed = this.lastRequestStartedAtMs + this.minRequestIntervalMs;
      if (nowMs < nextAllowed) await this.sleepImpl(nextAllowed - nowMs);
    }
    this.lastRequestStartedAtMs = Math.floor(this.now() * 1000);
  }

  private requestSigned<T>(path: string, notFoundError?: new () => Error): Promise<T> {
    return this.serialized(() => this.doRequestSigned<T>(path, notFoundError));
  }

  private async doRequestSigned<T>(path: string, notFoundError?: new () => Error): Promise<T> {
    const url = `${this.registryUri}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let res: RegistrarFetchResponse;
    try {
      res = await this.fetcher(url, { signal: controller.signal });
    } catch {
      if (controller.signal.aborted) throw new ErrRegistrarTimeout();
      throw new ErrRegistrarUnavailable();
    } finally {
      clearTimeout(timer);
    }

    if (res.status === 404) throw notFoundError ? new notFoundError() : new ErrRegistrarStatus();
    if (res.status < 200 || res.status >= 300) throw new ErrRegistrarStatus();

    let raw: string;
    try {
      raw = await res.text();
    } catch {
      throw new ErrRegistrarUnavailable();
    }

    let payload: Record<string, unknown>;
    try {
      const verified = await jwtVerify(raw, this.pinnedKey);
      payload = verified.payload as Record<string, unknown>;
    } catch {
      throw new ErrRegistrarSignature();
    }

    const iat = payload.iat;
    if (typeof iat !== 'number') throw new ErrRegistrarResponseMalformed();
    const age = this.now() - iat;
    if (age < -this.allowedSkewSeconds || age > this.maxResponseAgeSeconds) throw new ErrRegistrarStale();

    // `iat` ist für die Altersprüfung ausgewertet und fliegt danach aus der
    // Antwort heraus. Über eine Kopie mit löschendem Zugriff, damit keine
    // unbenutzte Bindung entsteht.
    const rest: Record<string, unknown> = { ...payload };
    delete rest.iat;
    return rest as T;
  }
}

