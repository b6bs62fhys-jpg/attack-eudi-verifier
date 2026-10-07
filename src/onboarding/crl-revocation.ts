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
 */
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
}

export class CrlRevocationChecker implements RevocationChecker {
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly clockSkewMs: number;
  private readonly fetchImpl?: FetchImpl;
  private readonly now: () => Date;
  private readonly crlUrlFor: (cert: X509Certificate) => string | undefined;

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
  }

  async checkRevoked(certDer: Uint8Array, _role: RevocationRole, issuerDer: Uint8Array): Promise<RevocationStatus> {
    const cert = new X509Certificate(new Uint8Array(certDer));
    const issuer = new X509Certificate(new Uint8Array(issuerDer));

    const url = this.crlUrlFor(cert);
    if (!url) throw new ErrRevocationSourceMissing();

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

    const entry = crl.findRevoked(cert);
    if (!entry) return 'good';
    if (entry.reason === X509CrlReason.certificateHold) return 'suspended';
    if (entry.reason === X509CrlReason.removeFromCRL) throw new ErrRevocationStatusUnknown();
    return 'revoked';
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
