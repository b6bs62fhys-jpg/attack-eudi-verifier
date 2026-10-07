/**
 * Die sieben Demo-Szenarien: ein Gutfall und sechs Schlechtfälle.
 *
 * Jedes Szenario beschreibt, worin sich die Mock-Wallet vom Gutfall
 * unterscheidet. Der Verifier-Dienst ist in allen Fällen derselbe; es gibt
 * keinen Szenario-Sonderpfad im Dienst. Genau das ist der Punkt der Demo: die
 * Ablehnung entsteht aus dem echten Prüfpfad, nicht aus einer Demo-Schalter
 * im Code.
 *
 * Die TEST-Schlüssel stammen aus `test-environment.ts` und existieren nur im
 * Arbeitsspeicher.
 */
import { buildSdJwtVc, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import type { DemoTestEnvironment } from './test-environment.ts';

export type DemoScenarioId = 'good' | 'issuer_not_trusted' | 'wrong_nonce' | 'expired_session' | 'expired_credential' | 'revoked_wrpac' | 'tampered_disclosure';

/** Die einzelnen Prüfschritte, die die Oberfläche einzeln zeigt. */
export type DemoCheckId = 'signature' | 'trust_list' | 'revocation' | 'nonce' | 'validity';

export interface DemoCheck {
  id: DemoCheckId;
  label: string;
}

export const DEMO_CHECKS: readonly DemoCheck[] = Object.freeze([
  { id: 'signature', label: 'Signatur des Ausstellers' },
  { id: 'trust_list', label: 'Aussteller auf der Trust List' },
  { id: 'revocation', label: 'Sperrstatus (OCSP)' },
  { id: 'nonce', label: 'Bindung an die Anfrage (Nonce)' },
  { id: 'validity', label: 'Gültigkeit von Sitzung und Nachweis' },
]);

export interface DemoScenario {
  id: DemoScenarioId;
  /** Deutsche Bezeichnung für Oberfläche und Dokumentation. */
  label: string;
  /** Was die Wallet im konkreten Szenario tut. */
  description: string;
  /** Erwartetes Ergebnis: angenommen oder abgelehnt. */
  expected: 'accepted' | 'rejected';
  /** Konkreter Ablehnungscode, den der Dienst nachweislich liefert. */
  expectedError: string;
  /**
   * Welcher Prüfschritt die Wallet bricht. Der Dienst unterscheidet bei
   * Nonce, Credential-Ablauf und Offenlegung absichtlich nicht (siehe
   * `expectedError`), die Demo benennt deshalb den Schritt selbst.
   */
  brokenStep: DemoCheckId | null;
  /** true, wenn die Prüfanfrage abläuft, statt dass die Wallet etwas ändert. */
  expiresSession: boolean;
}

export const DEMO_SCENARIOS: readonly DemoScenario[] = Object.freeze([
  {
    id: 'good',
    label: 'Gutfall: gültiger Aussteller, gültige Attribute',
    description: 'Die Wallet legt genau die angefragten Attribute offen. Der Aussteller steht auf der TEST Trust List, das OCSP meldet "good".',
    expected: 'accepted',
    expectedError: '',
    brokenStep: null,
    expiresSession: false,
  },
  {
    id: 'issuer_not_trusted',
    label: 'Schlechtfall: Aussteller nicht auf der Trust List',
    description: 'Der Aussteller ist technisch gültig, steht aber nicht auf der TEST Trust List. Die Signatur ist echt, das Vertrauen fehlt.',
    expected: 'rejected',
    expectedError: 'issuer_trust_anchor_not_found',
    brokenStep: 'trust_list',
    expiresSession: false,
  },
  {
    id: 'wrong_nonce',
    label: 'Schlechtfall: falsche Nonce',
    description: 'Die Wallet bindet die Präsentation an eine andere Nonce als die der Sitzung. Damit wäre die Antwort nicht an diese Anfrage gebunden.',
    expected: 'rejected',
    expectedError: 'presentation_invalid',
    brokenStep: 'nonce',
    expiresSession: false,
  },
  {
    id: 'expired_session',
    label: 'Schlechtfall: Prüfanfrage abgelaufen',
    description: 'Zwischen Anfrage und Präsentation ist die Sitzung verfallen. Der Nutzer hat zu lange gebraucht; die Antwort kommt zu spät.',
    expected: 'rejected',
    expectedError: 'session_expired',
    brokenStep: 'validity',
    expiresSession: true,
  },
  {
    id: 'expired_credential',
    label: 'Schlechtfall: Nachweis abgelaufen',
    description: 'Die Sitzung ist gültig, das Credential darin nicht. Ein abgelaufener Nachweis wird auch bei frischer Anfrage abgelehnt.',
    expected: 'rejected',
    expectedError: 'presentation_invalid',
    brokenStep: 'validity',
    expiresSession: false,
  },
  {
    id: 'revoked_wrpac',
    label: 'Schlechtfall: Ausstellerzertifikat gesperrt (OCSP)',
    description: 'Der Aussteller steht auf der Trust List, sein Zertifikat ist aber gesperrt. Der OCSP-Responder meldet das, die Prüfung stoppt an der Sperre.',
    expected: 'rejected',
    expectedError: 'issuer_certificate_revoked',
    brokenStep: 'revocation',
    expiresSession: false,
  },
  {
    id: 'tampered_disclosure',
    label: 'Schlechtfall: manipulierte Offenlegung',
    description: 'Die Wallet ändert einen Wert nach der Signierung des Ausstellers. Der Hash im Issuer-JWT passt nicht mehr zur Offenlegung.',
    expected: 'rejected',
    expectedError: 'presentation_invalid',
    brokenStep: 'signature',
    expiresSession: false,
  },
]);

export const DEFAULT_SCENARIO: DemoScenarioId = 'good';

export function isDemoScenarioId(value: unknown): value is DemoScenarioId {
  return typeof value === 'string' && DEMO_SCENARIOS.some((s) => s.id === value);
}

export function findScenario(id: DemoScenarioId): DemoScenario {
  const found = DEMO_SCENARIOS.find((s) => s.id === id);
  if (!found) throw new Error(`Unbekanntes Demo-Szenario: ${id}`);
  return found;
}

/** Die von der Demo angefragten Attribute. Sichtbar für Datenminimierung. */
export const DEMO_CLAIMS: readonly string[] = Object.freeze(['age_over_18', 'given_name']);

/**
 * Attribut, das im TEST-PID enthalten ist, aber von niemandem angefragt wird.
 * Der Hash steht im Issuer-JWT, die Wallet legt es nicht offen. Damit ist
 * Datenminimierung belegbar: das Credential enthält mehr, als der Prüfer sieht.
 */
export const DEMO_CLAIM_NOT_REQUESTED = 'birth_date';

export interface PresentInput {
  env: DemoTestEnvironment;
  scenario: DemoScenario;
  /** Nonce der Sitzung, aus dem Request Object gelesen. */
  nonce: string;
  /** Zielgruppe aus dem Request Object. */
  audience: string;
}

/**
 * Baut die SD-JWT-VC der Mock-Wallet.
 *
 * Datenminimierung: Der Gutfall legt genau die beiden angefragten Attribute
 * offen (`given_name`, `age_over_18`). Das Geburtsdatum ist im Credential
 * enthalten (Hash im Issuer-JWT), wird aber **nicht** offengelegt, weil niemand
 * danach gefragt hat. Im Prüfergebnis darf deshalb nur `given_name` und
 * `age_over_18` stehen.
 */
export async function buildScenarioPresentation(input: PresentInput): Promise<string> {
  const { env, scenario, nonce, audience } = input;

  let issuerKey: TestKeyMaterial = env.issuer;
  if (scenario.id === 'issuer_not_trusted') issuerKey = env.untrustedIssuer;
  if (scenario.id === 'revoked_wrpac') issuerKey = env.revokedIssuer;

  const built = await buildSdJwtVc({
    issuerKey,
    holderKey: env.holder,
    claimName: 'given_name',
    claimValue: 'Erika',
    nonce: scenario.id === 'wrong_nonce' ? 'TEST-abweichende-nonce' : nonce,
    audience,
    additionalDisclosures: { age_over_18: true },
    withheldDisclosures: { [DEMO_CLAIM_NOT_REQUESTED]: '1990-04-01' },
    ...(scenario.id === 'expired_credential' ? { expSeconds: -60 } : {}),
    tamperDisclosure: scenario.id === 'tampered_disclosure',
  });
  return built.sdJwt;
}
