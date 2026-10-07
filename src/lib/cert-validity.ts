/**
 * Gültigkeitszeitraum von X.509-Zertifikaten (Haertung 9, fail closed).
 *
 * Eine Stelle für alle Prüfpfade: WRPAC/WRPRC-Ketten, Verifier-Identität,
 * Aussteller-Zertifikate der Credentials, Aussteller-Anker und
 * Statuslisten-Unterzeichner. Zeitpunkt und erlaubte Uhrabweichung werden
 * übergeben (injizierbare Uhr), damit Tests deterministisch sind.
 *
 * Grenzen: gültig, solange notBefore - Abweichung <= jetzt <= notAfter + Abweichung.
 */
import { X509Certificate } from '@peculiar/x509';

/** Standard der erlaubten Uhrabweichung in Sekunden (ATTACK_CLOCK_SKEW_SECONDS). */
export const DEFAULT_CLOCK_SKEW_SECONDS = 60;

export type ValidityFailure = 'certificate_expired' | 'certificate_not_yet_valid';

/**
 * Liefert den Fehlercode, wenn das Zertifikat zum Zeitpunkt `now` nicht gültig
 * ist, sonst `undefined`. Ein nicht lesbares Zertifikat gilt als abgelaufen
 * (im Zweifel ablehnen).
 */
export function certificateValidityFailure(
  cert: X509Certificate | Uint8Array,
  now: Date,
  clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS,
): ValidityFailure | undefined {
  let parsed: X509Certificate;
  try {
    parsed = cert instanceof X509Certificate ? cert : new X509Certificate(new Uint8Array(cert));
  } catch {
    return 'certificate_expired';
  }
  const skewMs = Math.max(0, clockSkewSeconds) * 1000;
  const t = now.getTime();
  if (!Number.isFinite(t)) return 'certificate_expired';
  if (parsed.notBefore.getTime() - skewMs > t) return 'certificate_not_yet_valid';
  if (parsed.notAfter.getTime() + skewMs < t) return 'certificate_expired';
  return undefined;
}

/** Erster Fehler in einer Liste von Zertifikaten (Blatt, Zwischenzertifikate, Anker) oder `undefined`. */
export function chainValidityFailure(
  certs: ReadonlyArray<X509Certificate | Uint8Array>,
  now: Date,
  clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS,
): ValidityFailure | undefined {
  for (const cert of certs) {
    const failure = certificateValidityFailure(cert, now, clockSkewSeconds);
    if (failure) return failure;
  }
  return undefined;
}
