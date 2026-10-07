/**
 * Befund M4 aus docs/bedrohungsmodell.md: die Aussage „das Audit-Log enthält
 * keine personenbezogenen Daten" ([interne Notiz, nicht veröffentlicht],
 * [interne Notiz, nicht veröffentlicht]) war nicht automatisiert abgesichert. Es gab Tests,
 * die prüfen, OB ein Ereignis entsteht, aber keinen, der prüft, WAS drinsteht.
 *
 * Dieser Test legt einen eindeutigen Markerwert in die Präsentation — in einen
 * angefragten und in einen nicht angefragten Claim — und prüft anschließend, dass
 * der Marker in KEINEM serialisierten Audit-Eintrag auftaucht. Geprüft werden
 * alle vier Fälle, die Audit-Einträge erzeugen: gültige Präsentation, inhaltlich
 * abgelehnte, Replay und unbekannter Zustand.
 *
 * Der Gegenbeweis ist Teil des Tests und steht in [interner Bericht, nicht veröffentlicht]:
 * mit einem absichtlich in einen Audit-Eintrag geschriebenen Marker wird derselbe
 * Test rot.
 *
 * Nicht Gegenstand: der Sitzungs- und der Mandantenbezeichner landen
 * absichtlich im Log (`src/service/service.ts:446, 584`). Beides sind
 * pseudonyme Kennungen, die der Prototyp als zulässig führt. Dieser Test prüft
 * deshalb den **Inhalt der Präsentation**, nicht diese Kennungen.
 */
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeAll, afterAll, describe, it } from 'vitest';
import 'reflect-metadata';
import { createLocalJWKSet, jwtVerify } from 'jose';

import { buildSdJwtVc, generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { AuditLog } from './audit.ts';
import { VerifierService } from './service.ts';
import { TenantStore } from './tenant.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';

/** Der Marker. Taucht er irgendwo im Audit-Log auf, ist der Inhalt nicht PII-frei. */
const MARKER = 'MARKER-PII-4c2e91';

/** Form des vp_token, wie handlePresentation sie erwartet. */
type VpToken = Record<string, (string | object)[]>;

let tmpDir!: string;
let issuer!: TestKeyMaterial;
let holder!: TestKeyMaterial;
let verifier!: TestKeyMaterial;

beforeAll(async () => {
  issuer = await generateTestKeyMaterial('Audit-Inhalt Aussteller TEST');
  holder = await generateTestKeyMaterial('Audit-Inhalt Inhaber TEST');
  verifier = await generateTestKeyMaterial('Audit-Inhalt Verifier TEST');
  tmpDir = await mkdtemp(join(tmpdir(), 'attack-audit-inhalt-'));
});

afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

/**
 * Mandant mit zwei angefragten Claims: `given_name` und `family_name`. Beide
 * werden in der Präsentation mit dem Marker als **Wert** belegt; `family_name`
 * ist zusätzlich der Fall „nicht angefragt", weil der Anfragesteg unten nur
 * `given_name` verlangt.
 */
function build(): { service: VerifierService; audit: AuditLog } {
  const tenants = new TenantStore();
  tenants.add({
    id: 'tenant-audit',
    name: 'Kunde Audit (TEST)',
    apiKey: 'test-api-key-audit-inhalt',
    requestProfile: { id: 'test-given-name', claims: ['given_name'] },
  });
  const audit = new AuditLog();
  const service = new VerifierService(
    tenants,
    audit,
    {
      privateKey: verifier.privateKey,
      publicKey: verifier.publicKey,
      publicJwk: verifier.publicJwk,
      certificateChain: [verifier.certDerBytes],
    },
    () => [issuer.certDerBytes],
    undefined,
    undefined,
    undefined,
    undefined,
    true,
    DEV_TEST_OPTIONS,
  );
  service.baseUrl = 'http://127.0.0.1:9';
  return { service, audit };
}

/**
 * Baut eine Präsentation, deren Claim-Wert der Marker ist.
 * `claimName` wählt den Claim: `given_name` ist angefragt, `family_name` nicht.
 * Zusätzlich trägt `extraClaims` einen weiteren, nicht angefragten Claim.
 */
async function presentationWithMarker(
  service: VerifierService,
  claimName: string,
  extraClaims: Record<string, unknown> = {},
): Promise<{ state: string; vpToken: VpToken }> {
  const created = await service.createRequest('tenant-audit', {});
  const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
  const built = await buildSdJwtVc({
    issuerKey: issuer,
    holderKey: holder,
    nonce: String(payload.nonce),
    audience: String(payload.client_id),
    claimName,
    claimValue: MARKER,
    extraClaims,
  });
  return { state: created.state, vpToken: { pid: [built.sdJwt] } };
}

/** Der Kern: kein serialisierter Audit-Eintrag darf den Marker enthalten. */
function assertMarkerNichtImAudit(audit: AuditLog, label: string): void {
  const eintraege = audit.list();
  const Rohdaten = JSON.stringify(eintraege);
  assert.ok(
    !Rohdaten.includes(MARKER),
    `${label}: Marker im Audit-Log gefunden.\n  Einträge: ${Rohdaten}`,
  );
}

describe('Audit-Log: kein Inhalt aus der Präsentation (Befund M4)', () => {
  it('gültige Präsentation -> kein Marker im Audit-Log', async () => {
    const { service, audit } = build();
    const p = await presentationWithMarker(service, 'given_name');
    const outcome = await service.handlePresentation(p.state, p.vpToken);
    assert.equal(outcome.valid, true, 'Gegenprobe: die Präsentation muss gültig sein');
    assert.ok(audit.list().length > 0, 'Gegenprobe: es muss Audit-Einträge geben');
    assertMarkerNichtImAudit(audit, 'gültige Präsentation');
  });

  it('Präsentation mit nicht angefragtem Claim -> kein Marker im Audit-Log', async () => {
    const { service, audit } = build();
    // `family_name` ist nicht angefragt; zusätzlich ein weiterer fremder Claim.
    const p = await presentationWithMarker(service, 'family_name', { [`${MARKER}`]: MARKER });
    await service.handlePresentation(p.state, p.vpToken);
    assert.ok(audit.list().length > 0, 'Gegenprobe: es muss Audit-Einträge geben');
    assertMarkerNichtImAudit(audit, 'nicht angefragter Claim');
  });

  it('inhaltlich abgelehnte Präsentation (nicht vertrauter Aussteller) -> kein Marker', async () => {
    const { service, audit } = build();
    const fremder = await generateTestKeyMaterial('Fremder Aussteller TEST');
    const created = await service.createRequest('tenant-audit', {});
    const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
    const built = await buildSdJwtVc({
      issuerKey: fremder,
      holderKey: holder,
      nonce: String(payload.nonce),
      audience: String(payload.client_id),
      claimName: 'given_name',
      claimValue: MARKER,
    });
    const outcome = await service.handlePresentation(created.state, { pid: [built.sdJwt] });
    assert.equal(outcome.valid, false, 'Gegenprobe: die Präsentation muss abgelehnt werden');
    assert.ok(
      audit.list().some((e) => e.event === 'presentation_invalid'),
      'Gegenprobe: es muss ein presentation_invalid-Eintrag geben',
    );
    assertMarkerNichtImAudit(audit, 'inhaltlich abgelehnt');
  });

  it('Replay derselben Präsentation -> kein Marker im Audit-Log', async () => {
    const { service, audit } = build();
    const p = await presentationWithMarker(service, 'given_name');
    await service.handlePresentation(p.state, p.vpToken);
    const zweit = await service.handlePresentation(p.state, p.vpToken);
    assert.equal(zweit.ok, false, 'Gegenprobe: der zweite Versuch muss scheitern');
    assert.equal(zweit.error, 'session_reused', 'Gegenprobe: mit session_reused');
    assert.ok(
      audit.list().some((e) => e.event === 'presentation_rejected'),
      'Gegenprobe: es muss ein presentation_rejected-Eintrag geben',
    );
    assertMarkerNichtImAudit(audit, 'Replay');
  });

  it('unbekannter Zustand -> kein Marker im Audit-Log', async () => {
    const { service, audit } = build();
    const outcome = await service.handlePresentation('unbekannter-zustand', { pid: ['nicht-auswertbar'] });
    assert.equal(outcome.ok, false, 'Gegenprobe: der Aufruf muss scheitern');
    assert.equal(outcome.error, 'unknown_state', 'Gegenprobe: mit unknown_state');
    assert.ok(
      audit.list().some((e) => e.event === 'presentation_rejected'),
      'Gegenprobe: es muss ein presentation_rejected-Eintrag geben',
    );
    assertMarkerNichtImAudit(audit, 'unbekannter Zustand');
  });

  /**
   * `detail` enthält bei mehreren Ereignissen `session=${state}` (zum Beispiel
   * `src/service/service.ts:584, 608`). `state` kommt aus dem Request-Body
   * (`src/service/app.ts:249`) und wird nur auf Länge geprüft
   * (`src/service/limits.ts:58`), nicht auf einen Zeichensatz. Dieser Test legt
   * deshalb einen **beliebigen** String als Zustand fest und prüft, dass er
   * nicht ungefiltert ins Log wandert. Das ist der Pfad, an dem Freitext aus
   * Eingaben landen *könnte*.
   */
  it('freier Text im Zustand (clientgeliefert) -> kein Marker im Audit-Log', async () => {
    const { service, audit } = build();
    const outcome = await service.handlePresentation(MARKER, { pid: ['nicht-auswertbar'] });
    assert.equal(outcome.error, 'unknown_state', 'Gegenprobe: der Zustand existiert nicht');
    const Rohdaten = JSON.stringify(audit.list());
    assert.ok(
      !Rohdaten.includes(MARKER),
      `Marker als Zustandswert im Audit-Log gefunden.\n  Einträge: ${Rohdaten}`,
    );
  });
});
