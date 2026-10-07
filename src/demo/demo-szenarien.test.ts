/**
 * Die sieben Demo-Szenarien als automatische Tests (1 Gutfall, 6 Schlechtfälle).
 *
 * Jeder Test prüft zwei Dinge: das Ergebnis (angenommen oder abgelehnt) und
 * einen konkreten Grund. Bei drei Szenarien ist der Code des Dienstes
 * absichtlich generisch (`presentation_invalid`), dort wird zusätzlich der
 * vom Szenario gebrochene Prüfschritt geprüft — siehe `expectedError` in
 * scenarios.ts.
 *
 * Nur TEST-Material im Arbeitsspeicher, alle Server auf 127.0.0.1, nichts wird
 * nach außen gesendet.
 */
import assert from 'node:assert/strict';
import type http from 'node:http';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';

import { createApp } from '../service/app.ts';
import { AuditLog } from '../service/audit.ts';
import { VerifierService } from '../service/service.ts';
import { PID_VCT_DEFAULT } from '../service/profile.ts';
import { DEV_MODE } from '../service/test-support.ts';
import { TenantStore } from '../service/tenant.ts';
import { CredentialStatusError, NO_CREDENTIAL_STATUS } from '../service/credential-status.ts';
import { generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { RelyingPartyOnboardingGate } from '../onboarding/onboarding-gate.ts';
import { NO_REVOCATION } from '../onboarding/revocation.ts';
import { TEST_ENTITLEMENT_MAP } from '../onboarding/mock-pki.ts';
import { buildDemoTestEnvironment, DEMO_TENANT_ID, DEMO_SUBJECT_CN, type DemoTestEnvironment } from './test-environment.ts';
import { DEMO_CLAIM_NOT_REQUESTED, DEMO_CLAIMS, type DemoScenarioId } from './scenarios.ts';
import { runScenario, type ScenarioRunResult } from './scenario-runner.ts';

const KEY = 'demo-szenario-api-key';
/** Zweiter Mandant mit 1-Sekunden-Fenster, ausschließlich für den Ablauffall. */
const KEY_EXPIRING = 'demo-szenario-api-key-expiring';
const TENANT_EXPIRING = 'flow-demo-expired';

let env!: DemoTestEnvironment;
let service!: VerifierService;
let audit!: AuditLog;
let verifierKey!: TestKeyMaterial;
let app!: http.Server;
let base = '';
const tenants = new TenantStore();

beforeAll(async () => {
  env = await buildDemoTestEnvironment({});
  tenants.add({
    id: DEMO_TENANT_ID,
    name: `Flow-Demo ${DEMO_SUBJECT_CN}`,
    apiKey: KEY,
    requestTtlSeconds: 300,
    registration: env.registration,
    requestProfile: { id: 'demo', vct: PID_VCT_DEFAULT, claims: [...DEMO_CLAIMS], credentialId: 'pid' },
  });
  tenants.add({
    id: TENANT_EXPIRING,
    name: 'Flow-Demo Ablauf (TEST)',
    apiKey: KEY_EXPIRING,
    requestTtlSeconds: 1,
    registration: env.registration,
    requestProfile: { id: 'demo', vct: PID_VCT_DEFAULT, claims: [...DEMO_CLAIMS], credentialId: 'pid' },
  });

  // Das Gate prüft die Registrierungskette des Mandanten. Dafür wird
  // `NO_REVOCATION` verwendet, weil die TEST-WRPAC-Kette aus mock-pki keine
  // OCSP-Adresse trägt; die Sperrprüfung der präsentierten Kette läuft weiter
  // über den echten OcspRevocationChecker in `issuerRevocation`.
  const gate = new RelyingPartyOnboardingGate({
    tenants,
    accessCaAnchors: env.accessCaAnchors,
    wrprcIssuerAnchors: env.wrprcIssuerAnchors,
    entitlementMap: TEST_ENTITLEMENT_MAP,
    revocation: NO_REVOCATION,
    mode: DEV_MODE,
  });

  verifierKey = await generateTestKeyMaterial('Demo Szenario Verifier TEST');
  audit = new AuditLog();
  service = new VerifierService(
    tenants,
    audit,
    {
      privateKey: verifierKey.privateKey,
      publicKey: verifierKey.publicKey,
      publicJwk: verifierKey.publicJwk,
      certificateChain: [verifierKey.certDerBytes],
    },
    [env.issuer.certDerBytes, env.revokedIssuer.certDerBytes, env.untrustedIssuer.certDerBytes],
    undefined,
    undefined,
    env.issuerTrust,
    gate,
    true,
    { mode: DEV_MODE, credentialStatus: NO_CREDENTIAL_STATUS, issuerRevocation: env.ocspChecker },
  );
  app = createApp({ appLabel: 'demo-szenarien-test', tenants, service });
  await new Promise<void>((resolve) => app.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(app.address() as { port: number }).port}`;
  service.baseUrl = base;
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    app.closeAllConnections();
    app.close(() => resolve());
  });
  await env.close();
});

async function run(scenario: DemoScenarioId): Promise<ScenarioRunResult> {
  const expiring = scenario === 'expired_session';
  return runScenario({
    env,
    service,
    apiKey: expiring ? KEY_EXPIRING : KEY,
    tenantId: expiring ? TENANT_EXPIRING : DEMO_TENANT_ID,
    verifierPublicJwk: verifierKey.publicJwk,
    scenario,
    baseUrl: base,
    waitForSessionExpiryMs: 1_400,
  });
}

/**
 * Audit-Ereignisse zur zuletzt ausgewerteten Präsentation. Der Runner liest
 * danach noch das Ergebnis ab, deshalb wird nicht das letzte Ereignis, sondern
 * nach dem passenden innerhalb der Präsentation gesucht.
 */
function auditEvents(): readonly { event: string; detail?: string }[] {
  return audit.list();
}

function hasAuditEvent(event: string, detail?: RegExp): boolean {
  return auditEvents().some((e) => e.event === event && (detail === undefined || detail.test(e.detail ?? '')));
}

describe('Demo-Szenarien: sieben Ergebnisse mit konkretem Grund', () => {
  it('TEST-Statuslisten-Infrastruktur liefert gültig, gesperrt und ausgesetzt', async () => {
    assert.match(env.statusListUri, /^http:\/\/127\.0\.0\.1:/);
    await env.credentialStatus.check({ status: { status_list: { idx: 0, uri: env.statusListUri } } });
    await assert.rejects(
      () => env.credentialStatus.check({ status: { status_list: { idx: 1, uri: env.statusListUri } } }),
      (error: unknown) => error instanceof CredentialStatusError && error.code === 'credential_revoked',
    );
    await assert.rejects(
      () => env.credentialStatus.check({ status: { status_list: { idx: 2, uri: env.statusListUri } } }),
      (error: unknown) => error instanceof CredentialStatusError && error.code === 'credential_suspended',
    );
    // Der eigentliche Demo-Service bleibt absichtlich bei NO_CREDENTIAL_STATUS.
    assert.notEqual(NO_CREDENTIAL_STATUS, env.credentialStatus);
  });

  it('Gutfall: gültiger Aussteller wird angenommen, und nur die angefragten Attribute kommen an', async () => {
    const r = await run('good');

    assert.equal(r.resultStatus, 'completed', JSON.stringify(r));
    assert.equal(r.valid, true, `Gutfall muss angenommen werden, bekam ${r.error}`);
    assert.equal(r.error, '', 'ein angenommenes Ergebnis trägt keinen Ablehnungscode');

    // Datenminimierung: die Wallet legt genau die zwei angefragten Attribute
    // offen. Das Geburtsdatum steckt im Credential (Hash im Issuer-JWT), wurde
    // aber nicht offengelegt und darf deshalb nicht im Ergebnis stehen.
    assert.deepEqual(Object.keys(r.claims).sort(), [...DEMO_CLAIMS].sort(), 'nur angefragte Attribute im Ergebnis');
    assert.equal(r.claims.given_name, 'Erika');
    assert.equal(r.claims.age_over_18, true);
    assert.equal(
      Object.prototype.hasOwnProperty.call(r.claims, DEMO_CLAIM_NOT_REQUESTED),
      false,
      `${DEMO_CLAIM_NOT_REQUESTED} wurde nicht angefragt und darf nicht herausgegeben werden`,
    );
    assert.ok(hasAuditEvent('presentation_valid'), 'Audit protokolliert die Annahme');
  });

  it('issuer_not_trusted: Aussteller nicht auf der Trust List wird abgelehnt', async () => {
    const r = await run('issuer_not_trusted');

    assert.equal(r.valid, false, 'muss abgelehnt werden');
    assert.equal(r.error, 'issuer_trust_anchor_not_found', 'konkreter Ablehnungsgrund');
    assert.equal(r.scenario.brokenStep, 'trust_list', 'gebrochener Prüfschritt ist die Trust List');
    assert.ok(hasAuditEvent('presentation_invalid', /reason=issuer_trust_anchor_not_found/), 'Audit nennt den Grund');
  });

  it('wrong_nonce: Präsentation an eine andere Nonce gebunden wird abgelehnt', async () => {
    const r = await run('wrong_nonce');

    assert.equal(r.valid, false, 'muss abgelehnt werden');
    assert.equal(r.error, 'presentation_invalid', 'der Dienst kapselt den Nonce-Fehler bewusst generisch');
    assert.equal(r.scenario.brokenStep, 'nonce', 'gebrochener Prüfschritt ist die Bindung an die Anfrage');
    assert.equal(r.claims && Object.keys(r.claims).length, 0, 'bei Ablehnung werden keine Attribute herausgegeben');
  });

  it('expired_session: abgelaufene Prüfanfrage wird abgelehnt, nicht als unbekannt', async () => {
    const r = await run('expired_session');

    assert.equal(r.valid, false, 'muss abgelehnt werden');
    assert.equal(r.error, 'session_expired', 'konkreter Ablehnungsgrund: Sitzung abgelaufen');
    assert.notEqual(r.error, 'unknown_state', 'das wäre ein anderer Fall: Eintrag beim Verifier fehlt');
    assert.equal(r.scenario.brokenStep, 'validity', 'gebrochener Prüfschritt ist die Gültigkeit');
  });

  it('expired_credential: abgelaufener Nachweis wird abgelehnt, getrennt von der abgelaufenen Sitzung', async () => {
    const r = await run('expired_credential');

    assert.equal(r.valid, false, 'muss abgelehnt werden');
    assert.equal(r.error, 'presentation_invalid', 'der Dienst kapselt den Ablauf des Nachweises generisch');
    assert.equal(r.scenario.brokenStep, 'validity', 'gebrochener Prüfschritt ist die Gültigkeit des Nachweises');
    // Getrennt vom Sitzungsablauf: hier war die Sitzung gültig, der
    // Ablehnungscode ist deshalb ein anderer als `session_expired`.
    assert.notEqual(r.error, 'session_expired', 'Sitzung war gültig, nur der Nachweis ist abgelaufen');
  });

  it('revoked_wrpac: gesperrtes Ausstellerzertifikat wird über OCSP erkannt', async () => {
    const r = await run('revoked_wrpac');

    assert.equal(r.valid, false, 'muss abgelehnt werden');
    assert.equal(r.error, 'issuer_certificate_revoked', 'konkreter Ablehnungsgrund aus dem OCSP-Responder');
    assert.equal(r.scenario.brokenStep, 'revocation', 'gebrochener Prüfschritt ist die Sperrprüfung');
    assert.ok(hasAuditEvent('presentation_invalid', /reason=issuer_certificate_revoked/), 'Audit nennt den OCSP-Grund');
  });

  it('tampered_disclosure: manipulierte Offenlegung wird abgelehnt', async () => {
    const r = await run('tampered_disclosure');

    assert.equal(r.valid, false, 'muss abgelehnt werden');
    assert.equal(r.error, 'presentation_invalid', 'der Dienst kapselt den Hash-Bruch bewusst generisch');
    assert.equal(r.scenario.brokenStep, 'signature', 'gebrochener Prüfschritt ist die Signatur des Ausstellers');
    assert.equal(r.claims && Object.keys(r.claims).length, 0, 'bei Ablehnung werden keine Attribute herausgegeben');
  });
});
