/**
 * Entitlement-Quellen: austauschbare Auflösung der Entitlement-OID -> URI.
 *
 * Zweck: Das Onboarding-Gate löst im WRPAC hinterlegte Entitlement-OIDs über
 * eine Karte auf (`src/onboarding/wrpac.ts:82-88`). Diese Datei kapselt, **woher**
 * die Karte kommt, damit der Dienst im Normalbetrieb eine Quelle hat, statt leer
 * zu bleiben.
 *
 * Ausgangslage war eine bewusst leere Karte außerhalb des Entwicklungsschalters
 * (`resolveEntitlementMap`, entfernt in diesem Schritt). Das Sicherheitsproblem
 * daran war nicht das Leersein, sondern der Fehlergrund: ein leeres Vokabular
 * sieht wie ein Fehlkonfigurierter Dienst aus, obwohl die Ursache war, dass die
 * normativ feststehenden Paare nie als Tabelle angelegt worden waren.
 *
 * **Drei Quellen, eine Sicherheitsgrenze:**
 *
 * 1. `normativeEntitlementMapProvider()` — die zehn Paare aus ETSI TS 119 475
 *    V1.2.1 (2026-03), Anhang A.2.1–A.2.10. Normativ und öffentlich, deshalb
 *    immer aktiv und ohne jede Konfiguration. Es fehlt kein Dienst, der sie
 *    liefern könnte: sie stehen wörtlich in der Norm.
 * 2. `staticFileEntitlementMapProvider(pfad)` — ergänzt nationale
 *    Sub-Entitlements aus einer JSON-Datei, Pfad über
 *    `ATTACK_ENTITLEMENT_MAP_JSON`. Fehlt die Datei oder ist sie kaputt, gibt es
 *    einen `ConfigError` und keine stille Teilkarte.
 * 3. `devEntitlementMapProvider()` — die TEST-Karte aus `mock-pki.ts`, nur für
 *    `ATTACK_DEV_MODE` außerhalb der Produktion.
 *
 * **Sicherheitsgrenze, ausdrücklich:** Eine Karte löst Namen auf, sie erteilt
 * keine Berechtigung. Sie beantwortet „welche Rolle bezeichnet diese OID", nicht
 * „was darf dieser WRP". Das zweite entscheidet laut ETSI TS 119 475 V1.2.1
 * (2026-03), Klausel 4.2 das WRPRC zusammen mit dem nationalen Register. Im Code
 * bleibt die Berechtigungsentscheidung an drei Stellen, die keine Karte kennen:
 * `wrprc.ts:157-158` (Entitlement in `allowedEntitlements`),
 * `onboarding-gate.ts:137` (`registry_uri`/`sub` passt zur Registrierung) und
 * `wrpac.ts:121-141` (Kette zum konfigurierten Access-CA-Anker). Deshalb ist
 * eine lokal gepflegte Datei als Zwischenlösung seriös: Sie fügt der Kette keine
 * Berechtigung hinzu.
 *
 * **Keine amtliche Quelle.** Es gibt nach dem in [interne Notiz, nicht veröffentlicht]
 * geprüften Stand keine öffentlich erreichbare zentrale
 * Entitlement-Registry angebunden zu werden; die Norm schreibt nationale
 * Register vor (Klausel 4.6.1), liefert aber keine URL und kein API-Schema. Der
 * Austausch gegen ein echtes Register ist als späterer Schritt vorgesehen
 * (`RegistrarClient`, `src/onboarding/registrar.ts`), nicht als dieser Schritt.
 */
import { readFile } from 'node:fs/promises';

import { ConfigError } from '../config.ts';
import { ID_ETSI_WRPA_ENTITLEMENT_ARC, NORMATIVE_ENTITLEMENT_MAP, isOidUnder } from './oid.ts';
import type { RuntimeMode } from './revocation.ts';
import { TEST_ENTITLEMENT_MAP } from './mock-pki.ts';
import type { EntitlementMap } from './wrpac.ts';

/**
 * Pfad zur JSON-Datei mit nationalen Sub-Entitlements, die die normative Basis
 * aus Anhang A.2 ergänzen. Optional: ohne die Variable gilt die normative Basis
 * allein. Gesetzt und kaputt heißt: Startabbruch mit `ConfigError`.
 */
export const ENV_ATTACK_ENTITLEMENT_MAP_JSON = 'ATTACK_ENTITLEMENT_MAP_JSON';

/** Formatversion der JSON-Datei. Bewusst Pflichtfeld, damit das Format wachsen kann. */
export const ENTITLEMENT_MAP_FILE_VERSION = 1;

/**
 * Obergrenze der JSON-Datei. Eine Entitlement-Karte ist ein Vokabular, keine
 * Datenbank; 64 KiB reichen für nationale Sub-Entitlements um Größenordnungen
 * und halten eine verwechselte Datei (Log, Zertifikat, Schlüssel) beim Lesen auf.
 */
export const MAX_ENTITLEMENT_MAP_BYTES = 64 * 1024;

/** Suffix unter dem Entitlement-Arc muss aus reinen Ziffern und Punkten bestehen. */
const OID_SUFFIX_PATTERN = /^\.\d+(\.\d+)*$/;

/**
 * Liefert die vollständige OID -> URI-Karte.
 *
 * `resolve()` ist async, weil die Dateiquelle liest. Es wirft `ConfigError` bei
 * fehlender oder ungültiger Quelle und liefert **nie** eine leere Karte: eine
 * leere Karte sähe wie ein Konfigurationsfehler aus, während sie in Wahrheit
 * ein fehlendes Vokabular wäre.
 */
export interface EntitlementMapProvider {
  /** Kurze, meldbare Kennung für die Startmeldung. Enthält keine Geheimnisse. */
  readonly label: string;
  resolve(): Promise<EntitlementMap>;
}

/** Basis aus ETSI TS 119 475 V1.2.1 (2026-03), Anhang A.2. Immer aktiv. */
export function normativeEntitlementMapProvider(): EntitlementMapProvider {
  return { label: 'ETSI TS 119 475 V1.2.1 Anhang A.2 (10 Entitlements)', resolve: async () => NORMATIVE_ENTITLEMENT_MAP };
}

/**
 * TEST-Karte aus `mock-pki.ts`, vier OIDs. Nur `ATTACK_DEV_MODE` außerhalb der
 * Produktion — `config.ts` verbietet diese Kombination bereits beim Laden, die
 * zweite Bedingung hier ist die unabhängige Absicherung derselben Zusage.
 */
export function devEntitlementMapProvider(): EntitlementMapProvider {
  return { label: 'TEST-Karte (mock-pki, 4 Entitlements)', resolve: async () => TEST_ENTITLEMENT_MAP };
}

/**
 * Nationale Sub-Entitlements aus einer JSON-Datei.
 *
 * Schema, bewusst klein und ohne neue Abhängigkeit (das Projekt hat kein
 * JSON-Schema-Werkzeug und validiert von Hand, siehe
 * `validateRegistrationRefRaw` in `src/onboarding/registration-ref.ts`):
 *
 * ```json
 * {
 *   "version": 1,
 *   "source": "Bezeichnung der fuer diese Datei verantwortlichen Stelle",
 *   "entitlements": {
 *     "0.4.0.19475.1.11": "https://example.invalid/19475/SubEntitlement/EigeneRolle"
 *   }
 * }
 * ```
 *
 * `version` ist Pflicht, damit das Format später wachsen kann. `source` ist
 * freiwillig und dient nur der Nachvollziehbarkeit; es wird nicht ausgewertet.
 */
export function staticFileEntitlementMapProvider(path: string): EntitlementMapProvider {
  return {
    label: `JSON-Datei ${path}`,
    resolve: async () => parseEntitlementMapJson(await readEntitlementMapFile(path), path),
  };
}

async function readEntitlementMapFile(path: string): Promise<string> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch {
    // Bewusst ohne Systemfehlertext: Eine Meldung mit Pfad und_errno ist eine
    // Information über den Server, wenn sie in ein Log wandert. `Pfad prüfen`
    // sagt dem Betrieb alles, was er braucht.
    throw new ConfigError(`${ENV_ATTACK_ENTITLEMENT_MAP_JSON}: Datei nicht lesbar (${path}). Pfad prüfen.`);
  }
  if (raw.length > MAX_ENTITLEMENT_MAP_BYTES) {
    throw new ConfigError(
      `${ENV_ATTACK_ENTITLEMENT_MAP_JSON}: Datei größer als ${MAX_ENTITLEMENT_MAP_BYTES} Byte. ` +
        'Erwartet wird ein Vokabular, keine Datenbank.',
    );
  }
  return raw;
}

/** Parst und prüft die JSON-Datei. Jeder Fehlerfall endet als `ConfigError`. */
export function parseEntitlementMapJson(raw: string, path: string): EntitlementMap {
  const label = `${ENV_ATTACK_ENTITLEMENT_MAP_JSON} (${path})`;

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ConfigError(`${label}: Datei ist kein gültiges JSON.`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new ConfigError(`${label}: erwartet wird ein JSON-Objekt.`);
  }
  const doc = parsed as Record<string, unknown>;

  if (doc.version !== ENTITLEMENT_MAP_FILE_VERSION) {
    throw new ConfigError(
      `${label}: "version" muss die Zahl ${ENTITLEMENT_MAP_FILE_VERSION} sein. ` +
        `Gefunden: ${describe(doc.version)}.`,
    );
  }
  if (typeof doc.entitlements !== 'object' || doc.entitlements === null || Array.isArray(doc.entitlements)) {
    throw new ConfigError(`${label}: "entitlements" muss ein Objekt mit OID -> URI sein.`);
  }

  const out: Record<string, string> = {};
  for (const [oid, value] of Object.entries(doc.entitlements as Record<string, unknown>)) {
    if (oid === ID_ETSI_WRPA_ENTITLEMENT_ARC) {
      throw new ConfigError(`${label}: "${oid}" ist der Entitlement-Arc selbst, kein Entitlement.`);
    }
    if (!isOidUnder(oid, ID_ETSI_WRPA_ENTITLEMENT_ARC) || !OID_SUFFIX_PATTERN.test(oid.slice(ID_ETSI_WRPA_ENTITLEMENT_ARC.length))) {
      throw new ConfigError(
        `${label}: "${oid}" liegt nicht unter dem Entitlement-Arc ` +
          `${ID_ETSI_WRPA_ENTITLEMENT_ARC}.<Nummer>.`,
      );
    }
    const normativ = NORMATIVE_ENTITLEMENT_MAP[oid];
    if (normativ !== undefined) {
      // Eine Konfiguration darf die Norm nicht überschreiben. Sonst hinge die
      // Bedeutung einer OID an einer lokalen Datei, und derselbe OID-String
      // bedeutete je nach Deployment etwas anderes.
      throw new ConfigError(
        `${label}: "${oid}" ist in ETSI TS 119 475 V1.2.1 Anhang A.2 normativ festgelegt ` +
          `auf "${normativ}" und darf nicht überschrieben werden.`,
      );
    }
    if (typeof value !== 'string' || value.length === 0) {
      throw new ConfigError(`${label}: Wert zu "${oid}" muss ein nicht leerer String sein. Gefunden: ${describe(value)}.`);
    }
    if (value.length > MAX_ENTITLEMENT_MAP_BYTES) {
      throw new ConfigError(`${label}: URI zu "${oid}" ist unplausibel lang.`);
    }
    try {
      // Nur `https`: die URI ist ein Bezeichner, kein Abrufziel. Sie wird
      // verglichen und angezeigt, nie aufgerufen. `http` und andere Schemes
      // würden eine Konfiguration erlauben, die wie eine amtliche Quelle aussieht
      // und es nicht ist.
      const url = new URL(value);
      if (url.protocol !== 'https:') throw new Error('kein https');
    } catch {
      throw new ConfigError(
        `${label}: Wert zu "${oid}" muss eine absolute https-URI sein. ` +
          'Hinweis: Die URI bezeichnet eine Rolle, sie wird nicht abgerufen.',
      );
    }
    out[oid] = value;
  }

  if (Object.keys(out).length === 0) {
    // Eine leere Datei würde stillschweigend nichts tun und trotzdem als
    // "konfiguriert" erscheinen. Das ist die Form von Fehlkonfiguration, die man
    // erst an der ersten abgelehnten Registrierung bemerkt.
    throw new ConfigError(
      `${label}: "entitlements" ist leer. Die Datei muss mindestens einen nationalen ` +
        'Sub-Entitlement-Eintrag enthalten, sonst ist sie wirkungslos.',
    );
  }
  return out;
}

/** Kurzform eines Werts für Fehlermeldungen, ohne Inhalt zu verraten. */
function describe(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'ein Array';
  if (typeof value === 'string') return `der String "${value.length > 24 ? `${value.slice(0, 24)}…` : value}"`;
  return `der Typ ${typeof value}`;
}

/**
 * Legt mehrere Quellen übereinander. Die Karte ist damit nie leer, solange die
 * Basis gefüllt ist, und eine fehlende Datei fällt nicht auf „leer" zurück,
 * sondern wirft.
 */
export function overlayEntitlementMapProvider(...layers: readonly EntitlementMapProvider[]): EntitlementMapProvider {
  if (layers.length === 0) throw new ConfigError('Entitlement-Quelle: keine Quelle konfiguriert.');
  return {
    label: layers.map((l) => l.label).join(' + '),
    resolve: async () => {
      const merged: Record<string, string> = {};
      for (const layer of layers) Object.assign(merged, await layer.resolve());
      return merged;
    },
  };
}

/**
 * Wählt die Quelle nach Betriebsmodus und Umgebung. Das ersetzt das frühere
 * `resolveEntitlementMap(config)`.
 *
 * - Entwicklungsschalter außerhalb der Produktion: TEST-Karte als Basis.
 * - Sonst: normative Basis aus Anhang A.2.
 * - In beiden Fällen zusätzlich die JSON-Datei, wenn `ATTACK_ENTITLEMENT_MAP_JSON`
 *   gesetzt ist. Leere Zeichenkette zählt wie nicht gesetzt, wie bei den
 *   Ankerpfaden.
 */
export function createEntitlementMapProvider(
  config: RuntimeMode,
  env: Record<string, string | undefined>,
): EntitlementMapProvider {
  const dev = config.devMode && !config.isProduction;
  const path = env[ENV_ATTACK_ENTITLEMENT_MAP_JSON];
  const base = dev ? devEntitlementMapProvider() : normativeEntitlementMapProvider();
  if (!path) return base;
  return overlayEntitlementMapProvider(base, staticFileEntitlementMapProvider(path));
}
