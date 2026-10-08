/**
 * Paket 6 c): Altersprüfung als Pilotfall.
 *
 * Anfrage nur nach dem Altersnachweis, Antwort nur ja oder nein, keine
 * weiteren Claims. Zwei Vorlagen:
 *   age_over_18     flacher Claim `age_over_18` (EU-PID, mdoc-Schreibweise)
 *   age_over_18_de  `age_equal_or_over.18`, so trägt die deutsche PID den
 *                   Schwellwert im SD-JWT laut offizieller PID-Referenz
 * Mock-Wallet und Test-Material. Wie die echte Sandbox-PID den Schwellwert im
 * SD-JWT tatsächlich verpackt (ganzes Objekt oder je Schwelle einzeln
 * offenlegbar), ist öffentlich nicht beschrieben und hier nicht geprüft; der
 * Test nimmt das Objekt als Ganzes an.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import 'reflect-metadata';
import { createHash } from 'node:crypto';
import { createLocalJWKSet, decodeJwt, jwtVerify, SignJWT } from 'jose';

import { buildSdJwtVc, generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { AuditLog } from './audit.ts';
import { checkRequirements, claimPath, nurAngefragteClaims, parseRequestProfile, PID_VCT_DE, PID_VCT_DEFAULT, REQUEST_PROFILE_TEMPLATES, resolveRequestProfile } from './profile.ts';
import { VerifierService } from './service.ts';
import { TenantStore } from './tenant.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';

const ALL_THRESHOLDS = { '12': true, '14': true, '16': true, '18': true, '21': true, '65': false };

async function harness(profile: string | Record<string, unknown>) {
  const tenants = new TenantStore();
  tenants.add({ id: 'alter', name: 'Alter (TEST)', apiKey: 'test-api-key-alter', requestProfile: profile });
  const verifier = await generateTestKeyMaterial('Alter Verifier TEST');
  const issuer = await generateTestKeyMaterial('Alter Issuer TEST');
  const holder = await generateTestKeyMaterial('Alter Holder TEST');
  const service = new VerifierService(
    tenants,
    new AuditLog(),
    { privateKey: verifier.privateKey, publicKey: verifier.publicKey, publicJwk: verifier.publicJwk, certificateChain: [verifier.certDerBytes] },
    issuer.certDerBytes,
    undefined,
    undefined,
    undefined,
    undefined,
    true,
    DEV_TEST_OPTIONS,
  );
  service.baseUrl = 'http://127.0.0.1:9';
  async function present(build: { vct?: string; claimName: string; claimValue: unknown; additionalDisclosures?: Record<string, unknown>; tamperDisclosure?: boolean }) {
    const created = await service.createRequest('alter', {});
    const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
    const built = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: String(payload.nonce), audience: String(payload.client_id), ...build });
    const outcome = await service.handlePresentation(created.state, { pid: [built.sdJwt] });
    return { outcome, payload, result: service.getResult('alter', created.sessionId) };
  }
  /** Legt einen selbst gebauten Token vor; `bauen` bekommt Nonce und Audience der Anfrage. */
  async function presentRaw(bauen: (s: { nonce: string; audience: string; issuer: typeof issuer; holder: typeof holder }) => Promise<string>) {
    const created = await service.createRequest('alter', {});
    const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
    const token = await bauen({ nonce: String(payload.nonce), audience: String(payload.client_id), issuer, holder });
    const outcome = await service.handlePresentation(created.state, { pid: [token] });
    return { outcome, result: service.getResult('alter', created.sessionId) };
  }
  return { present, presentRaw, service };
}

describe('Vorlagen und Anfrage', () => {
  it('beide Vorlagen existieren, fragen genau einen Altersclaim und verlangen true', () => {
    assert.deepEqual(REQUEST_PROFILE_TEMPLATES.age_over_18?.claims, ['age_over_18']);
    assert.deepEqual(REQUEST_PROFILE_TEMPLATES.age_over_18?.mustBeTrue, ['age_over_18']);
    assert.equal(REQUEST_PROFILE_TEMPLATES.age_over_18_de?.vct, PID_VCT_DE);
    assert.deepEqual(REQUEST_PROFILE_TEMPLATES.age_over_18_de?.claims, ['age_equal_or_over.18']);
    assert.deepEqual(REQUEST_PROFILE_TEMPLATES.age_over_18_de?.mustBeTrue, ['age_equal_or_over.18']);
  });

  it('die deutsche Vorlage sendet den verschachtelten Pfad und kein Geburtsdatum', async () => {
    const h = await harness('age_over_18_de');
    const { payload } = await h.present({ vct: PID_VCT_DE, claimName: 'age_equal_or_over', claimValue: ALL_THRESHOLDS });
    const query = payload.dcql_query as { credentials: Array<{ meta: { vct_values: string[] }; claims: Array<{ path: string[] }> }> };
    assert.deepEqual(query.credentials[0]?.claims, [{ path: ['age_equal_or_over', '18'] }]);
    assert.deepEqual(query.credentials[0]?.meta.vct_values, [PID_VCT_DE]);
    const text = JSON.stringify(decodeJwt(await (async () => (await h.service.createRequest('alter', {})).requestObject)()));
    assert.ok(!/birth/.test(text), 'kein Geburtsdatum in der Anfrage');
    assert.ok(!/family_name|given_name/.test(text), 'keine weiteren Claims in der Anfrage');
  });

  it('die flache Vorlage sendet genau den Pfad age_over_18', async () => {
    const h = await harness('age_over_18');
    const { payload } = await h.present({ claimName: 'age_over_18', claimValue: true });
    const query = payload.dcql_query as { credentials: Array<{ claims: Array<{ path: string[] }> }> };
    assert.deepEqual(query.credentials[0]?.claims, [{ path: ['age_over_18'] }]);
  });
});

describe('Antwort: nur ja oder nein', () => {
  it('flach, 18 oder älter: Ja, im Ergebnis genau ein Claim', async () => {
    const h = await harness('age_over_18');
    const { outcome, result } = await h.present({ claimName: 'age_over_18', claimValue: true, additionalDisclosures: { birth_date: '1990-05-01', given_name: 'Ada' } });
    assert.deepEqual(outcome, { ok: true, valid: true });
    assert.equal(result.status, 'completed');
    if (result.status === 'completed') {
      assert.equal(result.result.valid, true);
      assert.deepEqual(result.result.claims, { age_over_18: true }, 'nicht angefragte, aber offengelegte Claims bleiben draußen');
    }
  });

  it('flach, unter 18: klares Nein, abgeschlossenes Ergebnis ohne Claim-Wert', async () => {
    const h = await harness('age_over_18');
    const { outcome, result } = await h.present({ claimName: 'age_over_18', claimValue: false });
    assert.deepEqual(outcome, { ok: true, valid: false, error: 'age_requirement_not_met' });
    assert.equal(result.status, 'completed', 'der Mandant bekommt eine Antwort statt ewig pending');
    if (result.status === 'completed') {
      assert.equal(result.result.valid, false);
      assert.equal(result.result.error, 'age_requirement_not_met');
      assert.deepEqual(result.result.claims, {});
    }
  });

  it('deutsche PID, 18 oder älter: Ja, nur Schwelle 18 im Ergebnis, auch wenn die Wallet alle offenlegt', async () => {
    const h = await harness('age_over_18_de');
    const { outcome, result } = await h.present({ vct: PID_VCT_DE, claimName: 'age_equal_or_over', claimValue: ALL_THRESHOLDS });
    assert.deepEqual(outcome, { ok: true, valid: true });
    assert.equal(result.status, 'completed');
    if (result.status === 'completed') {
      assert.deepEqual(result.result.claims, { 'age_equal_or_over.18': true });
      assert.ok(!JSON.stringify(result.result).includes('"65"') && !JSON.stringify(result.result).includes('"21"'), 'andere Schwellen nicht im Ergebnis');
    }
  });

  it('deutsche PID, unter 18 (Schwelle 21 wahr, 18 falsch kann nicht sein, hier 18 falsch): klares Nein', async () => {
    const h = await harness('age_over_18_de');
    const { outcome, result } = await h.present({ vct: PID_VCT_DE, claimName: 'age_equal_or_over', claimValue: { '12': true, '14': true, '16': true, '18': false, '21': false, '65': false } });
    assert.deepEqual(outcome, { ok: true, valid: false, error: 'age_requirement_not_met' });
    assert.equal(result.status, 'completed');
    if (result.status === 'completed') assert.deepEqual(result.result.claims, {});
  });
});

describe('Fehlender oder unbrauchbarer Altersclaim', () => {
  it('Credential ohne den Altersclaim (nur given_name): abgelehnt, nie ein Ja', async () => {
    const h = await harness('age_over_18');
    const { outcome, result } = await h.present({ claimName: 'given_name', claimValue: 'Ada' });
    assert.equal(outcome.ok, true);
    assert.equal(outcome.valid, false);
    assert.equal(outcome.error, 'presentation_invalid', 'die DCQL-Prüfung der Bibliothek lehnt ein fehlendes Claim ab');
    assert.notEqual(result.status, 'completed', 'kein Ergebnis, das als Ja gelesen werden könnte');
  });

  it('Altersclaim mit falschem Typ ("true" als Text, 1 als Zahl): age_claim_invalid, kein Ergebnis', async () => {
    for (const value of ['true', 1, null, { ja: true }]) {
      const h = await harness('age_over_18');
      const { outcome, result } = await h.present({ claimName: 'age_over_18', claimValue: value });
      assert.equal(outcome.valid, false, JSON.stringify(value));
      assert.equal(outcome.error, 'age_claim_invalid', JSON.stringify(value));
      assert.notEqual(result.status, 'completed');
    }
  });

  it('deutsche PID ohne Schwelle 18 im Objekt: die DCQL-Prüfung der Bibliothek lehnt ab (presentation_invalid)', async () => {
    const h = await harness('age_over_18_de');
    const { outcome, result } = await h.present({ vct: PID_VCT_DE, claimName: 'age_equal_or_over', claimValue: { '21': true, '65': false } });
    assert.deepEqual(outcome, { ok: true, valid: false, error: 'presentation_invalid' });
    assert.notEqual(result.status, 'completed');
  });

  it('deutsche PID mit age_equal_or_over als Text statt Objekt: abgelehnt, kein Ja', async () => {
    const h = await harness('age_over_18_de');
    const { outcome } = await h.present({ vct: PID_VCT_DE, claimName: 'age_equal_or_over', claimValue: 'ja' });
    assert.equal(outcome.valid, false);
    assert.match(String(outcome.error), /^(age_claim_invalid|presentation_invalid)$/);
  });

  it('falsches vct für die deutsche Vorlage: abgelehnt, kein Nein', async () => {
    const h = await harness('age_over_18_de');
    const { outcome, result } = await h.present({ vct: PID_VCT_DEFAULT, claimName: 'age_equal_or_over', claimValue: ALL_THRESHOLDS });
    assert.equal(outcome.valid, false);
    assert.notEqual(outcome.error, 'age_requirement_not_met');
    assert.notEqual(result.status, 'completed');
  });

  it('manipulierte Offenlegung bei einem false: die Echtheit scheitert zuerst, es erscheint kein Nein', async () => {
    const h = await harness('age_over_18');
    const { outcome, result } = await h.present({ claimName: 'age_over_18', claimValue: false, tamperDisclosure: true });
    assert.equal(outcome.valid, false);
    assert.notEqual(outcome.error, 'age_requirement_not_met');
    assert.notEqual(result.status, 'completed');
  });
});

describe('Profil-Bausteine', () => {
  it('claimPath: nur age_equal_or_over.NN ist verschachtelt', () => {
    assert.deepEqual(claimPath('age_equal_or_over.18'), ['age_equal_or_over', '18']);
    assert.deepEqual(claimPath('age_over_18'), ['age_over_18']);
    assert.deepEqual(claimPath('address.street'), ['address.street']);
    assert.deepEqual(claimPath('age_equal_or_over.x'), ['age_equal_or_over.x']);
    assert.deepEqual(claimPath('age_equal_or_over.1234'), ['age_equal_or_over.1234']);
  });

  it('checkRequirements: true besteht, false ist Nein, alles andere ist unbrauchbar', () => {
    const profile = { mustBeTrue: ['a'] };
    assert.deepEqual(checkRequirements(profile, { a: true }), { met: true });
    assert.deepEqual(checkRequirements(profile, { a: false }), { met: false, reason: 'age_requirement_not_met' });
    for (const claims of [{}, { a: 'true' }, { a: 1 }, { a: null }, { b: true }]) {
      assert.deepEqual(checkRequirements(profile, claims), { met: false, reason: 'age_claim_invalid' }, JSON.stringify(claims));
    }
    assert.deepEqual(checkRequirements({}, {}), { met: true }, 'ohne Bedingung nichts zu prüfen');
  });

  it('checkRequirements: ein vererbter Schlüssel zählt nicht (kein Prototyp-Treffer)', () => {
    assert.deepEqual(checkRequirements({ mustBeTrue: ['toString'] }, {}), { met: false, reason: 'age_claim_invalid' });
  });

  it('nurAngefragteClaims: verschachtelte Schwelle wird einzeln herausgelöst', () => {
    const parsed = { age_equal_or_over: ALL_THRESHOLDS, birthdate: '1990-01-01', family_name: 'X' };
    assert.deepEqual(nurAngefragteClaims(parsed, ['age_equal_or_over.18']), { 'age_equal_or_over.18': true });
    assert.deepEqual(nurAngefragteClaims(parsed, ['age_equal_or_over.18', 'family_name']), { family_name: 'X', 'age_equal_or_over.18': true });
    assert.deepEqual(nurAngefragteClaims({ age_equal_or_over: 'kein objekt' }, ['age_equal_or_over.18']), {});
    assert.deepEqual(nurAngefragteClaims({ age_equal_or_over: { '21': true } }, ['age_equal_or_over.18']), {});
  });

  it('eigenes Profil mit mustBeTrue: gültig, wenn eine Teilmenge der Claims', () => {
    const profile = parseRequestProfile({ id: 'mein-alter', vct: PID_VCT_DE, claims: ['age_equal_or_over.21'], mustBeTrue: ['age_equal_or_over.21'] }, 'x');
    assert.deepEqual(profile.mustBeTrue, ['age_equal_or_over.21']);
    assert.deepEqual(resolveRequestProfile('age_over_18_de').mustBeTrue, ['age_equal_or_over.18']);
  });

  it('mustBeTrue außerhalb der Claims oder leer: abgelehnt', () => {
    for (const mustBeTrue of [['family_name'], [], 'age_over_18', [1]]) {
      assert.throws(() => parseRequestProfile({ id: 'x', claims: ['age_over_18'], mustBeTrue }, 'x'), /mustBeTrue/, JSON.stringify(mustBeTrue));
    }
  });

  it('unbekannte Schwelle ist kein bekannter Claim', () => {
    assert.throws(() => parseRequestProfile({ id: 'x', claims: ['age_equal_or_over.19'] }, 'x'), /unbekannter Claim/);
    assert.doesNotThrow(() => parseRequestProfile({ id: 'x', claims: ['age_equal_or_over.65'] }, 'x'));
  });
});

describe('Deutsche PID mit einzeln offenlegbaren Schwellen (so legte die walt.id Wallet sie offen)', () => {
  const b64u = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
  const digest = (t: string) => createHash('sha256').update(t).digest('base64url');

  /** Objekt `age_equal_or_over` mit eigenem `_sd`; die Präsentation legt nur die genannten Schwellen offen. */
  async function bauen(
    k: { nonce: string; audience: string; issuer: Awaited<ReturnType<typeof generateTestKeyMaterial>>; holder: Awaited<ReturnType<typeof generateTestKeyMaterial>> },
    schwellen: Record<string, boolean>,
    offengelegt: string[],
  ): Promise<string> {
    const alle = Object.entries(schwellen).map(([name, wert]) => ({ name, text: b64u([`salz-${name}`, name, wert]) }));
    const holderJwk = (await crypto.subtle.exportKey('jwk', k.holder.publicKey)) as JsonWebKey;
    const now = Math.floor(Date.now() / 1000);
    const jwt = await new SignJWT({ iss: 'https://TEST-issuer.de', vct: PID_VCT_DE, iat: now, exp: now + 3600, _sd_alg: 'sha-256', age_equal_or_over: { _sd: alle.map((a) => digest(a.text)) }, cnf: { jwk: holderJwk } })
      .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: [k.issuer.x5cBase64] })
      .sign(k.issuer.privateKey);
    const praesentiert = alle.filter((a) => offengelegt.includes(a.name)).map((a) => a.text);
    const ohneKb = `${jwt}~${praesentiert.map((d) => `${d}~`).join('')}`;
    const kb = await new SignJWT({ iat: now, nonce: k.nonce, aud: k.audience, sd_hash: digest(ohneKb) }).setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' }).sign(k.holder.privateKey);
    return ohneKb + kb;
  }

  it('nur Schwelle 18 offengelegt, 18 wahr: Ja, genau ein Claim', async () => {
    const h = await harness('age_over_18_de');
    const { outcome, result } = await h.presentRaw((k) => bauen(k, ALL_THRESHOLDS, ['18']));
    assert.deepEqual(outcome, { ok: true, valid: true });
    assert.equal(result.status, 'completed');
    if (result.status === 'completed') assert.deepEqual(result.result.claims, { 'age_equal_or_over.18': true });
  });

  it('nur Schwelle 18 offengelegt, 18 falsch: klares Nein', async () => {
    const h = await harness('age_over_18_de');
    const { outcome, result } = await h.presentRaw((k) => bauen(k, { ...ALL_THRESHOLDS, '18': false }, ['18']));
    assert.deepEqual(outcome, { ok: true, valid: false, error: 'age_requirement_not_met' });
    assert.equal(result.status, 'completed');
  });

  it('Wallet legt mehr Schwellen offen als angefragt: nur 18 im Ergebnis', async () => {
    const h = await harness('age_over_18_de');
    const { outcome, result } = await h.presentRaw((k) => bauen(k, ALL_THRESHOLDS, ['12', '18', '21', '65']));
    assert.equal(outcome.valid, true, JSON.stringify(outcome));
    if (result.status === 'completed') assert.deepEqual(result.result.claims, { 'age_equal_or_over.18': true });
  });

  it('Schwelle 18 nicht offengelegt: abgelehnt, kein Ja', async () => {
    const h = await harness('age_over_18_de');
    const { outcome, result } = await h.presentRaw((k) => bauen(k, ALL_THRESHOLDS, ['21']));
    assert.equal(outcome.valid, false);
    assert.notEqual(result.status, 'completed');
  });
});
