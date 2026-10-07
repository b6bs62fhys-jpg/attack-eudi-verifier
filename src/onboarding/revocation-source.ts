/**
 * Wahl und Kombination der Sperrquellen (OCSP, CRL), fail closed.
 *
 * Warum CRL im Produktionsmodus Pflicht ist: In der offiziellen
 * Sandbox-Vertrauensliste (https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/,
 * Stand 06.10.2026) tragen die Zertifikate der PID-Aussteller-CAs und des
 * "German Registrar" nur CRL-Adressen (CRL Distribution Points), keine
 * OCSP-Adresse. Mit OCSP allein endete jede Prüfung einer solchen Kette mit
 * `revocation_source_missing`, also mit Ablehnung.
 *
 * Konfiguration je Prüfpfad, Reihenfolge = Vorrang:
 *   ATTACK_ISSUER_REVOCATION_SOURCES      Aussteller-Kette vorgelegter Credentials
 *   ATTACK_ONBOARDING_REVOCATION_SOURCES  WRPAC/WRPRC im Onboarding-Gate
 * Erlaubt: "ocsp", "crl", "ocsp,crl", "crl,ocsp". Standard: "ocsp,crl"
 * (OCSP zuerst, CRL als Rückfall). Im Produktionsmodus muss "crl" enthalten
 * sein, sonst bricht der Start ab. Unbekannte Werte brechen immer ab.
 *
 * Kombination (FallbackRevocationChecker):
 *   - Liefert eine Quelle einen Status (good, revoked, suspended oder etwas
 *     anderes), gilt er sofort. Ein "revoked" der ersten Quelle wird also nie
 *     durch die zweite überstimmt.
 *   - Nur wenn eine Quelle mit einem Fehler endet (keine Adresse, nicht
 *     erreichbar, Zeitüberschreitung, ungültige Antwort), wird die nächste
 *     gefragt.
 *   - Scheitern alle, wird ein Fehler geworfen, also abgelehnt. Gemeldet wird
 *     der erste Fehler, der nicht nur "keine Adresse" sagt, weil er mehr über
 *     die Ursache verrät.
 */
import { ConfigError, ENV_NODE_ENV } from '../config.ts';
import { OnboardingError } from './errors.ts';
import type { RevocationChecker, RevocationRole, RevocationStatus, RuntimeMode } from './revocation.ts';

export const ENV_ATTACK_ISSUER_REVOCATION_SOURCES = 'ATTACK_ISSUER_REVOCATION_SOURCES';
export const ENV_ATTACK_ONBOARDING_REVOCATION_SOURCES = 'ATTACK_ONBOARDING_REVOCATION_SOURCES';

export type RevocationSourceName = 'ocsp' | 'crl';

export const DEFAULT_REVOCATION_SOURCES: readonly RevocationSourceName[] = Object.freeze(['ocsp', 'crl']);

/**
 * Zeitgrenzen je Quelle, wenn zwei Quellen kombiniert sind. Zusammen bleiben
 * sie unter der Gesamtgrenze je Zertifikat (`DEFAULT_REVOCATION_TIMEOUT_MS`,
 * 5 Sekunden), damit die Rückfallquelle überhaupt zum Zug kommt, wenn die
 * erste bis zur Zeitgrenze hängt.
 */
export const COMBINED_OCSP_TIMEOUT_MS = 2_000;
export const COMBINED_CRL_TIMEOUT_MS = 2_500;

/** Liest die Quellen eines Prüfpfads aus der Umgebung (fail closed). */
export function parseRevocationSources(
  env: Record<string, string | undefined>,
  key: string,
  mode: RuntimeMode,
): RevocationSourceName[] {
  const raw = env[key];
  const sources: RevocationSourceName[] =
    raw === undefined || raw.trim() === ''
      ? [...DEFAULT_REVOCATION_SOURCES]
      : raw.split(',').map((part) => {
          const name = part.trim().toLowerCase();
          if (name !== 'ocsp' && name !== 'crl') {
            throw new ConfigError(`${key}: unbekannte Sperrquelle "${part.trim()}". Erlaubt sind ocsp und crl, durch Komma getrennt. Start abgebrochen.`);
          }
          return name;
        });
  if (new Set(sources).size !== sources.length) {
    throw new ConfigError(`${key}: jede Sperrquelle darf nur einmal vorkommen. Start abgebrochen.`);
  }
  if (mode.isProduction && !mode.devMode && !sources.includes('crl')) {
    throw new ConfigError(
      `${key}: im Produktionsmodus (${ENV_NODE_ENV}=production) muss "crl" enthalten sein. ` +
        'Die Aussteller-CAs der offiziellen Sandbox-Vertrauensliste tragen nur CRL-Adressen. Start abgebrochen.',
    );
  }
  return sources;
}

export interface NamedRevocationChecker {
  name: RevocationSourceName;
  checker: RevocationChecker;
}

export class FallbackRevocationChecker implements RevocationChecker {
  readonly sources: readonly NamedRevocationChecker[];

  constructor(sources: readonly NamedRevocationChecker[]) {
    if (sources.length === 0) throw new ConfigError('Mindestens eine Sperrquelle ist nötig.');
    this.sources = sources;
  }

  async checkRevoked(certDer: Uint8Array, role: RevocationRole, issuerDer: Uint8Array): Promise<RevocationStatus> {
    const fehler: unknown[] = [];
    for (const { checker } of this.sources) {
      try {
        return await checker.checkRevoked(certDer, role, issuerDer);
      } catch (e) {
        fehler.push(e);
      }
    }
    const aussagekraeftig = fehler.find((e) => !(e instanceof OnboardingError && e.code === 'revocation_source_missing'));
    throw aussagekraeftig ?? fehler[0];
  }
}

/**
 * Baut den Checker für eine Quellenliste. Eine einzelne Quelle wird direkt
 * verwendet, mehrere werden zu einem FallbackRevocationChecker verbunden.
 * Die Fabriken bekommen mit, ob kombiniert wird, damit sie die kürzeren
 * Zeitgrenzen setzen können.
 */
export function buildRevocationChecker(
  sources: readonly RevocationSourceName[],
  factories: Record<RevocationSourceName, (combined: boolean) => RevocationChecker>,
): RevocationChecker {
  const combined = sources.length > 1;
  const named = sources.map((name) => ({ name, checker: factories[name](combined) }));
  if (named.length === 1) return (named[0] as NamedRevocationChecker).checker;
  return new FallbackRevocationChecker(named);
}

/** Lesbare Beschreibung für Startmeldung und CLI, z. B. "ocsp, Rückfall crl". */
export function describeRevocationSources(sources: readonly RevocationSourceName[]): string {
  if (sources.length === 1) return `nur ${sources[0]}`;
  return `${sources[0]}, Rückfall ${sources.slice(1).join(', ')}`;
}
