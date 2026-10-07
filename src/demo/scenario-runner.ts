/**
 * Führt ein Demo-Szenario Ende zu Ende gegen den echten Dienst aus.
 *
 * Dieselbe Funktion bedient die Tests und die laufende Demo. Dadurch kann die
 * Oberfläche nichts anzeigen, was nicht auch getestet ist.
 *
 * Ablauf je Szenario: Prüfanfrage anlegen, Request Object lesen (Nonce und
 * Zielgruppe stehen darin), Mock-Wallet bauen, Präsentation per `direct_post`
 * abschicken, Ergebnis und Audit-Ereignis zurückgeben. Der Dienst läuft dabei
 * unverändert; es gibt keinen Szenario-Schalter im Verifier.
 */
import { createLocalJWKSet, jwtVerify, type JWTPayload } from 'jose';

import { buildScenarioPresentation, findScenario, type DemoScenario, type DemoScenarioId } from './scenarios.ts';
import { DEMO_CLAIMS } from './scenarios.ts';
import type { DemoTestEnvironment } from './test-environment.ts';
import type { VerifierService } from '../service/service.ts';

export interface ScenarioRunOptions {
  env: DemoTestEnvironment;
  service: VerifierService;
  /** apiKey des anfragenden Mandanten. */
  apiKey: string;
  /** Mandanten-ID, für Statusabfrage und Ablauf. */
  tenantId: string;
  /** Prüfschlüssel des Verifier, um das Request Object zu lesen. */
  verifierPublicJwk: JsonWebKey;
  scenario: DemoScenarioId;
  /** Basis-URL des Verifierdienstes. */
  baseUrl: string;
  /**
   * Wartet so lange, bis die Sitzung abgelaufen ist. Nur für
   * `expired_session`; die Demo-UI nutzt das, um den Fall vorzuführen.
   */
  waitForSessionExpiryMs?: number;
}

export interface ScenarioRunResult {
  scenario: DemoScenario;
  /** HTTP-Status der Anfrageannahme. */
  createStatus: number;
  /** Antwort der Präsentation, wie der Dienst sie zurückgibt. */
  outcome: { ok: boolean; valid: boolean; error?: string };
  /** Ergebnis, wie es die Oberfläche abfragt. */
  resultStatus: 'completed' | 'pending' | 'expired' | 'not_found';
  valid: boolean;
  error: string;
  claims: Record<string, unknown>;
  issuerCountry: string;
  sessionId: string;
  responseUri: string;
  /** Link, den eine echte Wallet oeffnen wuerde. */
  requestObjectUri: string;
  state: string;
  /** Attribute, die der Prüfer angefragt hat (Datenminimierung). */
  requestedClaims: readonly string[];
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export async function runScenario(options: ScenarioRunOptions): Promise<ScenarioRunResult> {
  const { env, service, apiKey, tenantId, verifierPublicJwk, scenario: scenarioId, baseUrl } = options;
  const scenario = findScenario(scenarioId);

  const created = await fetch(`${baseUrl}/v1/verification-requests`, {
    method: 'POST',
    headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
    body: JSON.stringify({ claims: [...DEMO_CLAIMS] }),
  });
  const createdText = await created.text();
  if (created.status !== 201) {
    throw new Error(`Prüfanfrage abgelehnt: HTTP ${created.status} ${createdText.slice(0, 200)}`);
  }
  const created_ = JSON.parse(createdText) as {
    requestObject: string;
    requestObjectUri: string;
    state: string;
    sessionId: string;
    responseUri: string;
  };

  const payload = (await jwtVerify(created_.requestObject, createLocalJWKSet({ keys: [verifierPublicJwk] }))).payload as JWTPayload;
  const nonce = typeof payload.nonce === 'string' ? payload.nonce : '';
  const audience = typeof payload.client_id === 'string' ? payload.client_id : '';

  if (scenario.expiresSession) {
    // Der Nutzer hat zu lange gebraucht: die Sitzung läuft ab, während der
    // Eintrag beim Verifier bestehen bleibt. Deshalb wird hier gewartet und
    // nicht der Eintrag gelöscht — ein gelöschter Eintrag ergäbe
    // `unknown_state` und wäre ein anderer Fall.
    await sleep(options.waitForSessionExpiryMs ?? 1_200);
  }

  const sdJwt = await buildScenarioPresentation({ env, scenario, nonce, audience });

  const presented = await fetch(created_.responseUri, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ vp_token: { pid: [sdJwt] }, state: created_.state }),
  });
  const outcome = (await presented.json()) as { ok: boolean; valid: boolean; error?: string };

  const status = service.getResult(tenantId, created_.sessionId) as
    | { status: 'completed'; result: { valid: boolean; error: string; claims: Record<string, unknown>; issuerCountry: string } }
    | { status: 'pending' | 'expired' | 'not_found' };

  const result = status.status === 'completed' ? status.result : undefined;
  return {
    scenario,
    createStatus: created.status,
    outcome,
    resultStatus: status.status,
    valid: result?.valid ?? false,
    error: result?.error ?? outcome.error ?? '',
    claims: result?.claims ?? {},
    issuerCountry: result?.issuerCountry ?? '',
    sessionId: created_.sessionId,
    responseUri: created_.responseUri,
    requestObjectUri: created_.requestObjectUri,
    state: created_.state,
    requestedClaims: DEMO_CLAIMS,
  };
}
