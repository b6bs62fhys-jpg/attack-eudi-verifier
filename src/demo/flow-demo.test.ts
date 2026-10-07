/**
 * Integrationstest der Demo so, wie sie real läuft: `startFlowDemo` baut
 * Verifier, signierte TEST-Trust List, OCSP-Responder, Onboarding-Gate und
 * Flowseite. Getestet wird über die Endpunkte, die auch die Oberfläche nutzt.
 *
 * Damit ist abgesichert, dass die verdrahtete Umgebung nicht nur im
 * Einzeltest funktioniert, sondern genau so, wie `npm run demo` sie benutzt.
 */
import assert from 'node:assert/strict';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { FLOW_RUN_PATH, FLOW_SCENARIOS_PATH, startFlowDemo, type FlowDemo } from './flow-server.ts';
import { DEMO_CLAIMS, type DemoScenarioId } from './scenarios.ts';

const PORT = '39871';
let demo!: FlowDemo;
let flow = '';

beforeAll(async () => {
  demo = await startFlowDemo({
    ATTACK_DEV_MODE: 'true',
    ATTACK_ALLOW_SELF_SIGNED: 'true',
    NODE_ENV: 'development',
    PORT,
  });
  flow = `http://127.0.0.1:${PORT}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    demo.apiServer.closeAllConnections();
    demo.apiServer.close();
    demo.flowServer.closeAllConnections();
    demo.flowServer.close(() => resolve());
  });
  // Ohne das blieben OCSP-Responder und Trust-List-Server laufen und der
  // Testprozess hinge fest.
  await demo.env.close();
});

interface RunOutcome {
  valid: boolean;
  error: string;
  claims: Record<string, unknown>;
  requestedClaims: readonly string[];
  scenario: { id: string; label: string; expected: string; expectedError: string; brokenStep: string | null; description: string };
  resultStatus: string;
  requestObjectUri: string;
  walletUrl: string;
  walletQr: string;
}

async function run(scenario: DemoScenarioId): Promise<RunOutcome> {
  const res = await fetch(`${flow}${FLOW_RUN_PATH}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ scenario }),
  });
  // Body genau einmal lesen: eine Fehlermeldung darf ihn nicht verbrauchen.
  const text = await res.text();
  assert.equal(res.status, 200, `Szenario ${scenario} konnte nicht laufen: HTTP ${res.status} ${text}`);
  return JSON.parse(text) as RunOutcome;
}

describe('Demo-Start', () => {
  it('startet Verifier und Flowseite auf 127.0.0.1', () => {
    assert.equal(demo.port, Number(PORT));
    assert.match(demo.apiBaseUrl, /^http:\/\/127\.0\.0\.1:\d+$/, 'Dienst nur an Loopback gebunden');
  });

  it('verweigert den Start ohne ATTACK_DEV_MODE', async () => {
    const { ConfigError } = await import('../config.ts');
    await expect(startFlowDemo({ ATTACK_ALLOW_SELF_SIGNED: 'true', PORT: '39872' })).rejects.toBeInstanceOf(ConfigError);
  });

  it('verweigert den Start in NODE_ENV=production trotz DEV_MODE', async () => {
    await expect(
      startFlowDemo({ ATTACK_DEV_MODE: 'true', ATTACK_ALLOW_SELF_SIGNED: 'true', NODE_ENV: 'production', PORT: '39873' }),
    ).rejects.toThrow();
  });

  it('liefert Szenarien und Prüfschritte für die Oberfläche', async () => {
    const res = await fetch(`${flow}${FLOW_SCENARIOS_PATH}`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      scenarios: { id: string; label: string; description: string; expected: string }[];
      checks: { id: string; label: string }[];
      requestedClaims: string[];
    };
    assert.equal(body.scenarios.length, 7, 'sieben Szenarien: ein Gutfall, sechs Schlechtfälle');
    assert.equal(body.scenarios.filter((s) => s.expected === 'rejected').length, 6, 'davon sechs Schlechtfälle');
    for (const s of body.scenarios) assert.ok(s.label.length > 0 && s.description.length > 0, `${s.id} braucht Beschriftung`);
    assert.equal(body.checks.length, 5, 'fünf einzeln gezeigte Prüfschritte');
    assert.deepEqual([...body.requestedClaims].sort(), [...DEMO_CLAIMS].sort());
  });

  it('lehnt unbekannte Szenarien ab', async () => {
    const res = await fetch(`${flow}${FLOW_RUN_PATH}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ scenario: 'gibt_es_nicht' }),
    });
    assert.equal(res.status, 400);
  });
});

describe('Demo-Szenarien über die Oberflächen-Endpunkte', () => {
  it('Gutfall wird angenommen, und es kommen nur die angefragten Attribute an', async () => {
    const r = await run('good');
    assert.equal(r.valid, true, `Gutfall muss angenommen werden, bekam ${r.error}`);
    assert.deepEqual(Object.keys(r.claims).sort(), [...DEMO_CLAIMS].sort(), 'nur angefragte Attribute im Ergebnis');
    assert.equal(Object.prototype.hasOwnProperty.call(r.claims, 'birth_date'), false, 'nicht angefragt, nicht herausgegeben');
  });

  it('die Flowseite bekommt den Wallet-Aufruf als Link und als QR-Code', async () => {
    const r = await run('good');
    const url = new URL(r.walletUrl);
    assert.equal(url.protocol, 'openid4vp:');
    assert.equal(url.searchParams.get('request_uri'), r.requestObjectUri);
    assert.equal(url.searchParams.get('request_uri_method'), 'get');
    assert.match(url.searchParams.get('client_id') ?? '', /^x509_hash:/);
    assert.ok(r.walletQr.startsWith('data:image/svg+xml;base64,'));
    assert.match(Buffer.from(r.walletQr.slice('data:image/svg+xml;base64,'.length), 'base64').toString('utf8'), /^<svg /);
    const seite = await (await fetch(`${flow}/`)).text();
    assert.match(seite, /id="walletQr"/);
    assert.match(seite, /id="walletUrl"/);
  });

  it('Aussteller nicht auf der Trust List: issuer_trust_anchor_not_found', async () => {
    const r = await run('issuer_not_trusted');
    assert.equal(r.valid, false);
    assert.equal(r.error, 'issuer_trust_anchor_not_found');
    assert.equal(r.scenario.brokenStep, 'trust_list');
  });

  it('falsche Nonce: der Dienst kapselt den Fehler als presentation_invalid', async () => {
    const r = await run('wrong_nonce');
    assert.equal(r.valid, false);
    assert.equal(r.error, 'presentation_invalid');
    assert.equal(r.scenario.brokenStep, 'nonce');
  });

  it('abgelaufene Sitzung: session_expired, nicht unknown_state', async () => {
    const r = await run('expired_session');
    assert.equal(r.valid, false);
    assert.equal(r.error, 'session_expired');
    assert.notEqual(r.error, 'unknown_state', 'unknown_state wäre ein anderer Fall: der Verifier kennt die Sitzung nicht mehr');
  });

  it('abgelaufener Nachweis: abgelehnt, getrennt vom Sitzungsablauf', async () => {
    const r = await run('expired_credential');
    assert.equal(r.valid, false);
    assert.equal(r.error, 'presentation_invalid');
    assert.notEqual(r.error, 'session_expired', 'die Sitzung war gültig, nur der Nachweis ist abgelaufen');
  });

  it('gesperrtes Ausstellerzertifikat: issuer_certificate_revoked aus dem OCSP-Responder', async () => {
    const r = await run('revoked_wrpac');
    assert.equal(r.valid, false);
    assert.equal(r.error, 'issuer_certificate_revoked');
    assert.equal(r.scenario.brokenStep, 'revocation');
  });

  it('manipulierte Offenlegung: der Dienst kapselt den Fehler als presentation_invalid', async () => {
    const r = await run('tampered_disclosure');
    assert.equal(r.valid, false);
    assert.equal(r.error, 'presentation_invalid');
    assert.equal(r.scenario.brokenStep, 'signature');
    assert.deepEqual(r.claims, {}, 'bei Ablehnung werden keine Attribute herausgegeben');
  });
});
