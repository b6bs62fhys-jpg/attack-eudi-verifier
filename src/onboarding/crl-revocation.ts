/**
 * Sperrprüfung über CRL (RFC 5280) für WRPAC/WRPRC — fail closed.
 *
 * Parsen und Signaturprüfung der CRL übernimmt @peculiar/x509 (X509Crl);
 * hier wird kein eigenes CRL-Format gebaut. Die CRL-Adresse kommt aus der
 * CRL-Distribution-Points-Erweiterung des Zertifikats (oder aus
 * `crlUrlFor`, z. B. für eine feste Sperrliste je Anker).
 *
 * Jeder Fehlerpfad lehnt ab, mit eigenem Code:
 *   keine Sperrquelle         -> revocation_source_missing
 *   nicht erreichbar / HTTP≠2xx -> revocation_unavailable
 *   Zeitüberschreitung        -> revocation_timeout
 *   zu groß                   -> revocation_list_too_large
 *   kein CRL-Format / fremder Aussteller / kein nextUpdate -> revocation_list_malformed
 *   Signatur ungültig         -> revocation_list_signature_invalid
 *   nextUpdate überschritten oder thisUpdate in der Zukunft -> revocation_list_expired
 *   Eintrag mit certificateHold -> 'suspended'
 *   Eintrag mit removeFromCRL (nur in Delta-CRLs zulässig) -> revocation_status_unknown
 *   sonstiger Eintrag         -> 'revoked'
 *
 * Cache: Gespeichert wird nur eine vollständig geprüfte CRL (Aussteller,
 * Signatur, Zeitfenster), je CRL-Adresse und ausstellendem Zertifikat. Sie gilt
 * höchstens bis zu ihrem `nextUpdate` und zusätzlich höchstens `maxCacheTtlMs`
 * (Standard 24 Stunden) nach dem Abruf; danach wird neu geholt. Fehler werden
 * nie gespeichert. Gleichzeitige Prüfungen gegen dieselbe CRL teilen sich einen
 * Abruf. Eine CRL deckt alle Zertifikate ihres Ausstellers ab, deshalb spart
 * der Cache bei vielen Präsentationen fast alle Abrufe.
 */
import { createHash } from 'node:crypto';

import { CRLDistributionPointsExtension, X509Certificate, X509Crl, X509CrlReason } from '@peculiar/x509';

import { DEFAULT_FETCH_MAX_BYTES, fetchLimited, LimitedFetchError, type FetchImpl } from '../lib/limited-fetch.ts';
import { DEFAULT_CLOCK_SKEW_SECONDS } from '../lib/cert-validity.ts';
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

export interface CrlRevocationCheckerOptions {
  /** Zeitgrenze je Abruf (ms). */
  timeoutMs?: number;
  /** Größengrenze je CRL (Bytes). */
  maxBytes?: number;
  /** Erlaubte Uhrabweichung für thisUpdate/nextUpdate (Sekunden). */
  clockSkewSeconds?: number;
  fetchImpl?: FetchImpl;
  now?: () => Date;
  /** Optional: CRL-Adresse selbst festlegen (Standard: CRL Distribution Points). */
  crlUrlFor?: (cert: X509Certificate) => string | undefined;
  /** Höchste Verweildauer einer CRL im Cache (ms), zusätzlich zu `nextUpdate`. */
  maxCacheTtlMs?: number;
  /** Höchstzahl gespeicherter CRLs; die älteste fällt zuerst heraus. */
  maxCacheEntries?: number;
}

/** Standard für `maxCacheTtlMs`: 24 Stunden, wie beim OCSP-Cache. */
export const DEFAULT_CRL_MAX_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_CRL_MAX_CACHE_ENTRIES = 256;

interface CachedCrl {
  crl: X509Crl;
  /** Zeitpunkt (ms), ab dem die CRL nicht mehr aus dem Cache kommt. */
  validUntil: number;
}

export class CrlRevocationChecker implements RevocationChecker {
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly clockSkewMs: number;
  private readonly fetchImpl?: FetchImpl;
  private readonly now: () => Date;
  private readonly crlUrlFor: (cert: X509Certificate) => string | undefined;
  private readonly maxCacheTtlMs: number;
  private readonly maxCacheEntries: number;
  private readonly cache = new Map<string, CachedCrl>();
  private readonly inflight = new Map<string, Promise<X509Crl>>();

  constructor(options: CrlRevocationCheckerOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? DEFAULT_REVOCATION_TIMEOUT_MS;
    this.maxBytes = options.maxBytes ?? DEFAULT_FETCH_MAX_BYTES;
    // Vorher stand hier die erzwungene 60. Dieselbe Zahl, aber aus dem
    // geteilten Standard, damit Konfiguration und Standardwert nicht
    // auseinanderlaufen koennen.
    this.clockSkewMs = (options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS) * 1000;
    this.fetchImpl = options.fetchImpl;
    this.now = options.now ?? (() => new Date());
    this.crlUrlFor = options.crlUrlFor ?? crlUrlFromDistributionPoints;
    this.maxCacheTtlMs = options.maxCacheTtlMs ?? DEFAULT_CRL_MAX_CACHE_TTL_MS;
    this.maxCacheEntries = options.maxCacheEntries ?? DEFAULT_CRL_MAX_CACHE_ENTRIES;
  }

  /** Leert den Cache (Schlüsselwechsel beim Aussteller, Tests). */
  clearCache(): void {
    this.cache.clear();
  }

  async checkRevoked(certDer: Uint8Array, _role: RevocationRole, issuerDer: Uint8Array): Promise<RevocationStatus> {
    const cert = new X509Certificate(new Uint8Array(certDer));
    const issuer = new X509Certificate(new Uint8Array(issuerDer));

    const url = this.crlUrlFor(cert);
    if (!url) throw new ErrRevocationSourceMissing();

    const crl = await this.verifiedCrl(url, issuer);
    const entry = crl.findRevoked(cert);
    if (!entry) return 'good';
    if (entry.reason === X509CrlReason.certificateHold) return 'suspended';
    if (entry.reason === X509CrlReason.removeFromCRL) throw new ErrRevocationStatusUnknown();
    return 'revoked';
  }

  /** Geprüfte CRL aus dem Cache oder frisch geholt und geprüft. */
  private async verifiedCrl(url: string, issuer: X509Certificate): Promise<X509Crl> {
    // Der Schlüssel bindet die CRL an das ausstellende Zertifikat, gegen das sie
    // geprüft wurde. Dieselbe Adresse mit einem anderen Aussteller ist ein
    // anderer Eintrag und wird neu geprüft.
    const key = `${url}\n${createHash('sha256').update(new Uint8Array(issuer.rawData)).digest('hex')}`;
    const now = this.now().getTime();
    const hit = this.cache.get(key);
    if (hit && now < hit.validUntil) return hit.crl;
    if (hit) this.cache.delete(key);

    const laufend = this.inflight.get(key);
    if (laufend) return laufend;
    const abruf = this.fetchAndVerify(url, issuer).finally(() => this.inflight.delete(key));
    this.inflight.set(key, abruf);
    const crl = await abruf;

    const nextUpdate = (crl.nextUpdate as Date).getTime();
    const validUntil = Math.min(nextUpdate, now + this.maxCacheTtlMs);
    if (validUntil > now) {
      if (this.cache.size >= this.maxCacheEntries) {
        const aeltester = this.cache.keys().next().value;
        if (aeltester !== undefined) this.cache.delete(aeltester);
      }
      this.cache.set(key, { crl, validUntil });
    }
    return crl;
  }

  private async fetchAndVerify(url: string, issuer: X509Certificate): Promise<X509Crl> {
    let body: Uint8Array;
    try {
      ({ body } = await fetchLimited(url, {
        timeoutMs: this.timeoutMs,
        maxBytes: this.maxBytes,
        accept: 'application/pkix-crl',
        fetchImpl: this.fetchImpl,
      }));
    } catch (e) {
      if (e instanceof LimitedFetchError && e.code === 'fetch_timeout') throw new ErrRevocationTimeout();
      if (e instanceof LimitedFetchError && e.code === 'fetch_too_large') throw new ErrRevocationListTooLarge();
      throw new ErrRevocationUnavailable();
    }

    let crl: X509Crl;
    try {
      crl = new X509Crl(Uint8Array.from(body));
    } catch {
      throw new ErrRevocationListMalformed();
    }

    if (crl.issuer !== issuer.subject) throw new ErrRevocationListMalformed();
    // Ohne Initialwert: try und catch weisen beide zu.
    let signatureOk: boolean;
    try {
      signatureOk = await crl.verify({ publicKey: issuer.publicKey });
    } catch {
      signatureOk = false;
    }
    if (!signatureOk) throw new ErrRevocationListSignature();

    const now = this.now().getTime();
    const nextUpdate = crl.nextUpdate;
    // Ohne nextUpdate ist die Aktualität nicht beurteilbar: ablehnen.
    if (!nextUpdate) throw new ErrRevocationListMalformed();
    if (nextUpdate.getTime() + this.clockSkewMs < now) throw new ErrRevocationListExpired();
    if (crl.thisUpdate.getTime() - this.clockSkewMs > now) throw new ErrRevocationListExpired();
    return crl;
  }
}

/** Erste http(s)-Adresse aus den CRL Distribution Points oder `undefined`. */
export function crlUrlFromDistributionPoints(cert: X509Certificate): string | undefined {
  const ext = cert.getExtension(CRLDistributionPointsExtension);
  if (!ext) return undefined;
  for (const point of ext.distributionPoints) {
    const names = point.distributionPoint?.fullName ?? [];
    for (const name of names) {
      const uri = name.uniformResourceIdentifier;
      if (typeof uri === 'string' && /^https?:\/\//i.test(uri)) return uri;
    }
  }
  return undefined;
}
