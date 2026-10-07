/**
 * Auflösung des Onboarding-Gates (B3, strukturelle Vorbereitung).
 *
 * Zweck: Das Onboarding-Gate prüft die **Onboarding-Zertifikate des Dienstes
 * selbst** (WRPAC-Zugriffszertifikat, WRPRC-Registrierungsnachweis). Es war
 * bisher nicht verdrahtet, weil echtes Registrar- und Zertifikatsmaterial fehlt
 * (B1/O-02). Der Prüfpfad ist vorhanden
 * (`src/onboarding/wrpac.ts`, `wrprc.ts`, `onboarding-gate.ts`), nur die
 * Verdrahtung im Dienststart fehlte.
 *
 * Diese Datei bereitet **nur strukturell** vor. Sie verdrahtet bewusst
 * **kein** Gate, solange das Material fehlt: ohne
 * `ATTACK_ONBOARDING_ACCESS_CA_PEM` und `ATTACK_ONBOARDING_WRPRC_ISSUER_PEM`
 * bleibt das Gate `undefined`, und der Dienst startet wie bisher ohne
 * Onboarding-Prüfung. Sobald echtes Material vorliegt, wird die spätere
 * Verdrahtung ein reiner Konfigurationsakt: `bootstrapService` ruft
 * `resolveOnboardingGate` auf, und es genügen die beiden Umgebungsvariablen
 * plus die Wahl der Sperrquelle (siehe `docs/entscheidung-onboarding-gate-
 * vorbereitung.md`, Frage B4).
 *
 * Warum fail closed beim *Material*, aber kein Startabbruch: Der Rest des
 * Systems bricht ab, wenn eine **Pflicht** fehlt (Sperrprüfung, Anker,
 * Statusliste). Das Onboarding-Gate ist derzeit **kein** Pflichtbestandteil des
 * Dienstes — der Dienst prüft ohne Gate weiterhin Credential-Issuer-Kette
 * (OCSP) und Credential-Status. Deshalb wäre ein Startabbruch eine
 * Verhaltensänderung, die B1 vorwegnimmt. Stattdessen wird der fehlende
 * Zustand **laut**: `describeOnboardingState()` liefert einen sprechenden Grund,
 * der beim Start gewarnt wird, sobald das Gate erwartet, aber nicht gebaut
 * werden kann. Sobald die Entscheidung zum Pflichtbetrieb fällt (mit echtem
 * Material), wird derselbe Pfad zu einem `ConfigError` umgestellt — die
 * Stelle ist dafür vorbereitet (`onboardingRequired`-Schalter).
 *
 * Die **Entitlement-Karte** ist davon getrennt und hat seit dem 26.09.2026
 * eine eigene Abstraktion (`src/onboarding/entitlement-source.ts`): im
 * Entwicklungsbetrieb die TEST-Karte, sonst die normative Basis aus ETSI
 * TS 119 475 V1.2.1 (2026-03) Anhang A.2, optional ergänzt um nationale
 * Sub-Entitlements aus `ATTACK_ENTITLEMENT_MAP_JSON`. Vorher war sie
 * außerhalb des Entwicklungsschalters leer, wodurch das Gate jedes WRPAC mit
 * einer Entitlement-OID mit `entitlement_unknown` abgelehnt hat. Siehe
 * `docs/entitlement-recherche.md`.
 */
import { readFile } from 'node:fs/promises';

import { X509Certificate } from '@peculiar/x509';

import { ConfigError } from '../config.ts';
import { RelyingPartyOnboardingGate, type OnboardingGatePolicy } from './onboarding-gate.ts';
import { createEntitlementMapProvider } from './entitlement-source.ts';
import type { EntitlementMap } from './wrpac.ts';
import type { TenantStore } from '../service/tenant.ts';
import { assertRevocationAllowed, type RevocationChecker, type RuntimeMode } from './revocation.ts';

/** Pfad zur PEM-Datei mit den Access-CA-Ankern der WRPAC-Kette. */
export const ENV_ATTACK_ONBOARDING_ACCESS_CA_PEM = 'ATTACK_ONBOARDING_ACCESS_CA_PEM';
/** Pfad zur PEM-Datei mit den WRPRC-Issuer-Ankern. */
export const ENV_ATTACK_ONBOARDING_WRPRC_ISSUER_PEM = 'ATTACK_ONBOARDING_WRPRC_ISSUER_PEM';

export interface OnboardingMaterial {
  accessCaAnchors: Uint8Array[];
  wrprcIssuerAnchors: Uint8Array[];
  /**
   * Entitlement-OID -> URI. Kommt aus der konfigurierten Entitlement-Quelle
   * (siehe `src/onboarding/entitlement-source.ts`): im Entwicklungsbetrieb die
   * TEST-Karte, sonst die normative Basis aus ETSI TS 119 475 V1.2.1 (2026-03)
   * Anhang A.2, optional ergänzt um nationale Sub-Entitlements aus
   * `ATTACK_ENTITLEMENT_MAP_JSON`.
   */
  entitlementMap: EntitlementMap;
}

export interface ResolveOnboardingGateOptions {
  config: RuntimeMode;
  env: Record<string, string | undefined>;
  revocation: RevocationChecker;
  /** Mandantensicht, die das Gate für die Zuordnung braucht. */
  tenants: Pick<TenantStore, 'byId'>;
  /** Uhr/Abweichung werden an das Gate durchgereicht, wenn es gebaut wird. */
  now?: () => Date;
  clockSkewSeconds?: number;
  /**
   * Materialquelle. Standard: die beiden PEM-Dateien aus der Umgebung.
   * Nur für Tests, die TEST-Material injizieren wollen.
   */
  loadMaterial?: () => Promise<OnboardingMaterial>;
  /**
   * Soll ein fehlendes Material den Start abbrechen? Standard: nein, weil das
   * Gate derzeit kein Pflichtbestandteil ist (siehe Kopfkommentar). Mit `true`
   * wird die vorbereitete strenge Variante aktiv — die dann greift, sobald der
   * Betrieb das Gate zur Pflicht macht.
   *
   * Unabhängig davon gilt: ein Fehler der **Entitlement-Quelle** bricht immer ab.
   */
  required?: boolean;
  /**
   * Vom Start bereits aufgelöste Entitlement-Karte. Ohne diese Option wird sie
   * hier aus `config`/`env` aufgelöst. Nur für Tests und für den Dienststart,
   * der die Quelle einmal zentral auflöst und meldet.
   */
  entitlementMap?: EntitlementMap;
}

/** PEM-Datei mit Zertifikaten (Blatt-/Ankerreihenfolge wie in der Datei). */
export async function loadAnchorsPem(path: string, label: string): Promise<Uint8Array[]> {
  let pem: string;
  try {
    pem = await readFile(path, 'utf8');
  } catch {
    throw new ConfigError(`${label}: Datei nicht lesbar (Pfad prüfen).`);
  }
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  if (blocks.length === 0) throw new ConfigError(`${label}: keine Zertifikate gefunden.`);
  return blocks.map((block) => {
    try {
      return new Uint8Array(new X509Certificate(block).rawData);
    } catch {
      throw new ConfigError(`${label}: Zertifikat unbrauchbar.`);
    }
  });
}

/**
 * Baut das Gate, wenn Material vorhanden ist. Fehlt das Material, gibt es
 * `undefined` zurück (kein Gate) — oder bricht bei `required` mit einer
 * sprechenden Meldung ab. Die Sperrquelle wird in jedem Fall fail closed
 * geprüft (`assertRevocationAllowed`), auch wenn kein Gate entsteht: so kann
 * `NO_REVOCATION` nicht unbemerkt durchrutschen, sobald Material nachwächst.
 */
export async function resolveOnboardingGate(options: ResolveOnboardingGateOptions): Promise<OnboardingGatePolicy | undefined> {
  const { config, env, revocation } = options;

  // Fail closed für die Sperrquelle, unabhängig davon, ob ein Gate entsteht.
  assertRevocationAllowed(revocation, config);

  let material: OnboardingMaterial;
  if (options.loadMaterial) {
    // Injiziertes Material bringt seine eigene Karte mit; die Quelle wird dann
    // nicht aufgelöst, sonst hätte ein Test keinen Einfluss auf die Karte.
    material = await options.loadMaterial();
  } else {
    // Fail closed für die Entitlement-Quelle, bewusst **vor** dem try/catch:
    // Eine konfigurierte, aber kaputte Datei darf nicht als „kein Gate"
    // verschluckt werden. Sonst startet der Dienst scheinbar sauber, das Gate ist
    // aber aus, und der Betrieb erfährt es erst an der ersten Registrierung.
    const entitlementMap = options.entitlementMap ?? (await createEntitlementMapProvider(config, env).resolve());
    try {
      material = await loadOnboardingMaterialFromEnv(env, entitlementMap);
    } catch (e) {
      if (options.required) throw e;
      return undefined;
    }
  }

  if (material.accessCaAnchors.length === 0 || material.wrprcIssuerAnchors.length === 0) {
    if (options.required) {
      throw new ConfigError(
        'Onboarding-Gate ist Pflicht, aber es wurden keine Anker konfiguriert. ' +
          `${ENV_ATTACK_ONBOARDING_ACCESS_CA_PEM} und ${ENV_ATTACK_ONBOARDING_WRPRC_ISSUER_PEM} setzen.`,
      );
    }
    return undefined;
  }

  return new RelyingPartyOnboardingGate({
    tenants: options.tenants,
    accessCaAnchors: material.accessCaAnchors,
    wrprcIssuerAnchors: material.wrprcIssuerAnchors,
    entitlementMap: options.entitlementMap ?? material.entitlementMap,
    revocation,
    mode: config,
    ...(options.now ? { now: options.now } : {}),
    ...(options.clockSkewSeconds !== undefined ? { clockSkewSeconds: options.clockSkewSeconds } : {}),
  });
}

/** Liest die beiden Ankerdateien aus der Umgebung. */
async function loadOnboardingMaterialFromEnv(
  env: Record<string, string | undefined>,
  entitlementMap: EntitlementMap,
): Promise<OnboardingMaterial> {
  const accessCa = env[ENV_ATTACK_ONBOARDING_ACCESS_CA_PEM];
  const wrprc = env[ENV_ATTACK_ONBOARDING_WRPRC_ISSUER_PEM];
  if (!accessCa || !wrprc) throw new ConfigError('Onboarding-Material unvollständig.');
  return {
    accessCaAnchors: await loadAnchorsPem(accessCa, ENV_ATTACK_ONBOARDING_ACCESS_CA_PEM),
    wrprcIssuerAnchors: await loadAnchorsPem(wrprc, ENV_ATTACK_ONBOARDING_WRPRC_ISSUER_PEM),
    entitlementMap,
  };
}

/**
 * Sprechender Zustand für die Startmeldung. Wird verwendet, wenn Material
 * fehlt oder unvollständig ist, damit der Betrieb nicht stillschweigend ohne
 * Onboarding-Prüfung startet. Enthält bewusst **keine** Zertifikatsdaten, nur
 * Variablennamen und Zustände.
 */
export function describeOnboardingState(result: { gate: OnboardingGatePolicy | undefined; error?: ConfigError }): string {
  if (result.gate) return 'Onboarding-Gate: aktiv (WRPAC/WRPRC-Prüfung im Standardbetrieb).';
  const grund = result.error ? ` Grund: ${result.error.message}` : '';
  return (
    'Onboarding-Gate: NICHT aktiv (kein echtes WRPAC/WRPRC-Material konfiguriert, ' +
    `${ENV_ATTACK_ONBOARDING_ACCESS_CA_PEM} / ${ENV_ATTACK_ONBOARDING_WRPRC_ISSUER_PEM}).` +
    ` Credential-Issuer-Kette (OCSP) und Credential-Status werden weiterhin fail closed geprüft.${grund}`
  );
}
