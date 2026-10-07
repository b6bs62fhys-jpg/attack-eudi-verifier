/**
 * Sperrprüfung (Revocation) für WRPAC/WRPRC — fail closed.
 *
 * Ein `RevocationChecker` muss für jedes geprüfte Zertifikat einen
 * ausdrücklichen Status liefern. Nur `'good'` lässt die Prüfung passieren.
 * Alles andere lehnt ab, jeweils mit eigenem Fehlercode:
 *   - `'revoked'`                    -> certificate_revoked
 *   - `'suspended'`                  -> certificate_suspended
 *   - jeder andere Rückgabewert      -> revocation_status_unknown
 *     (auch `undefined`: ein Checker, der „nichts sagt", gilt nicht als gut)
 *   - Zeitgrenze überschritten       -> revocation_timeout
 *   - sonstige Ausnahme              -> revocation_unavailable
 * Checker-eigene Sperrcodes (z. B. revocation_list_expired) werden
 * unverändert durchgereicht.
 *
 * `NO_REVOCATION` (keine Sperrprüfung) ist nur mit aktivem
 * Entwicklungsschalter erlaubt (`assertRevocationAllowed`). Die echte
 * Sperrquelle ist `CrlRevocationChecker` (crl-revocation.ts, CRL nach
 * RFC 5280 über @peculiar/x509).
 */
import { ConfigError, ENV_ATTACK_DEV_MODE, type AppConfig } from '../config.ts';
import {
  ErrRevocationStatusUnknown,
  ErrRevocationTimeout,
  ErrRevocationUnavailable,
  ErrRevokedCertificate,
  ErrSuspendedCertificate,
  OnboardingError,
} from './errors.ts';

/** Rolle eines Zertifikats in der geprüften Kette (für spätere Sperrpolitik). */
export type RevocationRole = 'leaf' | 'intermediate' | 'anchor';

export type RevocationStatus = 'good' | 'revoked' | 'suspended';

export interface RevocationChecker {
  /**
   * Liefert den Sperrstatus des Zertifikats (DER). `issuerDer` ist das
   * ausstellende Zertifikat aus der bereits geprüften Kette (für die
   * Signaturprüfung der Sperrliste). Anker werden nicht übergeben.
   */
  checkRevoked(certDer: Uint8Array, role: RevocationRole, issuerDer: Uint8Array): Promise<RevocationStatus>;
}

/**
 * Keine Sperrprüfung. Nur mit ATTACK_DEV_MODE=true außerhalb von Produktion
 * zulässig; siehe `assertRevocationAllowed`.
 */
export const NO_REVOCATION: RevocationChecker = Object.freeze({
  async checkRevoked(): Promise<RevocationStatus> {
    return 'good';
  },
});

/** Zeitgrenze für eine einzelne Sperrprüfung (inkl. Abruf). */
export const DEFAULT_REVOCATION_TIMEOUT_MS = 5_000;

/** Fehlercodes, die ein Checker selbst werfen darf und die unverändert bleiben. */
export const REVOCATION_ERROR_CODES: ReadonlySet<string> = new Set([
  'certificate_revoked',
  'certificate_suspended',
  'revocation_unavailable',
  'revocation_timeout',
  'revocation_list_too_large',
  'revocation_list_signature_invalid',
  'revocation_list_malformed',
  'revocation_list_expired',
  'revocation_status_unknown',
  'revocation_source_missing',
]);

export type RuntimeMode = Pick<AppConfig, 'devMode' | 'isProduction'>;

/** Ohne Angabe gilt der strenge Modus: kein Entwicklungsschalter. */
export const STRICT_MODE: RuntimeMode = Object.freeze({ devMode: false, isProduction: true });

/** Bricht ab, wenn NO_REVOCATION ohne Entwicklungsschalter (oder in Produktion) verwendet wird. */
export function assertRevocationAllowed(checker: RevocationChecker, mode: RuntimeMode = STRICT_MODE): void {
  if (checker !== NO_REVOCATION) return;
  if (mode.devMode && !mode.isProduction) return;
  throw new ConfigError(
    'Sperrprüfung ist abgeschaltet (NO_REVOCATION), das ist nur mit ' +
      `${ENV_ATTACK_DEV_MODE}=true außerhalb von Produktion erlaubt. ` +
      'Eine echte Sperrquelle (CrlRevocationChecker oder OcspRevocationChecker) konfigurieren. Start abgebrochen.',
  );
}

/**
 * Führt die Sperrprüfung für ein Zertifikat fail closed aus (siehe Kopf).
 * Wirft bei jedem Ergebnis außer `'good'`.
 */
export async function enforceRevocation(
  checker: RevocationChecker,
  certDer: Uint8Array,
  role: RevocationRole,
  issuerDer: Uint8Array,
  timeoutMs = DEFAULT_REVOCATION_TIMEOUT_MS,
): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new ErrRevocationTimeout()), timeoutMs);
  });
  let status: unknown;
  try {
    status = await Promise.race([checker.checkRevoked(certDer, role, issuerDer), timeout]);
  } catch (e) {
    if (e instanceof OnboardingError && REVOCATION_ERROR_CODES.has(e.code)) throw e;
    throw new ErrRevocationUnavailable();
  } finally {
    clearTimeout(timer);
  }
  if (status === 'good') return;
  if (status === 'revoked') throw new ErrRevokedCertificate();
  if (status === 'suspended') throw new ErrSuspendedCertificate();
  throw new ErrRevocationStatusUnknown();
}
