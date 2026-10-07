/**
 * Härtung 2: Prüfergebnis genau einmal.
 *
 *   - Der Abruf verbraucht das Ergebnis atomar; ein zweiter Abruf ist von
 *     „nie vorhanden" nicht zu unterscheiden (Status und Körper identisch).
 *   - Zwei gleichzeitige Abrufe: genau einer erhält das Ergebnis.
 *   - Das Ergebnis verfällt nach konfigurierbarer Zeit auch ohne Abruf.
 * Läuft gegen einen echten HTTP-Server (127.0.0.1, ephemerer Port).
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';
import { createLocalJWKSet, jwtVerify } from 'jose';

import { ConfigError, ENV_ATTACK_RESULT_TTL_SECONDS, loadConfig } from '../config.ts';
import { buildSdJwtVc, generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { createApp } from './app.ts';
import { AuditLog } from './audit.ts';
import { VerifierService } from './service.ts';
import { TenantStore } from './tenant.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';

const KEY = 'test-api-key-einmal-A';

interface Harness {
  base: string;
  app: http.Server;
  service: VerifierService;
  audit: AuditLog;
  clock: { now: number };
  complete(): Promise<string>;
  get(sessionId: string): Promise<{ status: number; body: string }>;
}

let verifier!: TestKeyMaterial;
let issuer!: TestKeyMaterial;
let holder!: TestKeyMaterial;
const harnesses: Harness[] = [];

async function harness(resultTtlMs?: number): Promise<Harness> {
  const tenants = new TenantStore();
  tenants.add({ id: 'tenant-a', name: 'Kunde A (TEST)', apiKey: KEY, requestProfile: { id: 'test-given-name', claims: ['given_name'] } });
  const clock = { now: Date.now() };
  const audit = new AuditLog();
  const service = new VerifierService(
    tenants,
    audit,
    { privateKey: verifier.privateKey, publicKey: verifier.publicKey, publicJwk: verifier.publicJwk, certificateChain: [verifier.certDerBytes] },
    issuer.certDerBytes,
    undefined,
    undefined,
    undefined,
    undefined,
    true,
    { ...DEV_TEST_OPTIONS, resultTtlMs, now: () => clock.now },
  );
  const app = createApp({ appLabel: 'einmal-test', tenants, service });
  await new Promise<void>((resolve) => app.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${(app.address() as { port: number }).port}`;
  service.baseUrl = base;

  const h: Harness = {
    base,
    app,
    service,
    audit,
    clock,
    complete: async () => {
      const created = await service.createRequest('tenant-a', {});
      const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
      const built = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: String(payload.nonce), audience: String(payload.client_id) });
      const outcome = await service.handlePresentation(created.state, { pid: [built.sdJwt] });
      assert.equal(outcome.valid, true, JSON.stringify(outcome));
      return created.sessionId;
    },
    get: async (sessionId) => {
      const res = await fetch(`${base}/v1/verification-requests/${sessionId}`, { headers: { authorization: `Bearer ${KEY}` } });
      return { status: res.status, body: await res.text() };
    },
  };
  harnesses.push(h);
  return h;
}

beforeAll(async () => {
  verifier = await generateTestKeyMaterial('Einmal Verifier TEST');
  issuer = await generateTestKeyMaterial('Einmal Issuer TEST');
  holder = await generateTestKeyMaterial('Einmal Holder TEST');
});

afterAll(async () => {
  for (const h of harnesses) await new Promise<void>((resolve) => h.app.close(() => resolve()));
});

describe('Ergebnis genau einmal', () => {
  it('erster Abruf liefert das Ergebnis (Gegenprobe)', async () => {
    const h = await harness();
    const id = await h.complete();
    const first = await h.get(id);
    assert.equal(first.status, 200);
    assert.equal(JSON.parse(first.body).status, 'completed');
    assert.equal(JSON.parse(first.body).result.valid, true);
  });

  it('zweiter Abruf ist identisch mit „nie vorhanden" (Status und Körper)', async () => {
    const h = await harness();
    const id = await h.complete();
    await h.get(id);
    const second = await h.get(id);
    const never = await h.get(crypto.randomUUID());
    assert.equal(second.status, 404);
    assert.deepEqual(second, never, 'verbraucht und nie vorhanden dürfen sich nicht unterscheiden');
  });

  it('zwei gleichzeitige Abrufe: genau einer erhält das Ergebnis', async () => {
    const h = await harness();
    for (let round = 0; round < 5; round += 1) {
      const id = await h.complete();
      const results = await Promise.all([h.get(id), h.get(id)]);
      const winners = results.filter((r) => r.status === 200);
      const losers = results.filter((r) => r.status === 404);
      assert.equal(winners.length, 1, `Runde ${round}: genau ein Abruf darf das Ergebnis erhalten`);
      assert.equal(losers.length, 1);
      assert.equal(JSON.parse(winners[0].body).status, 'completed');
    }
  });

  it('nach dem Abruf sind auch Request Object und Zuordnung entfernt', async () => {
    const h = await harness();
    const id = await h.complete();
    await h.get(id);
    const ro = await fetch(`${h.base}/v1/verification-requests/${id}/request-object`);
    assert.equal(ro.status, 404);
  });

  it('eine noch offene Sitzung bleibt bei wiederholtem Abruf „pending" (Gegenprobe)', async () => {
    const h = await harness();
    const created = await h.service.createRequest('tenant-a', {});
    assert.equal(JSON.parse((await h.get(created.sessionId)).body).status, 'pending');
    assert.equal(JSON.parse((await h.get(created.sessionId)).body).status, 'pending');
  });
});

describe('Ergebnis verfällt auch ohne Abruf', () => {
  it('vor Ablauf der Lebensdauer abrufbar (Gegenprobe)', async () => {
    const h = await harness(1_000);
    const id = await h.complete();
    h.clock.now += 999;
    assert.equal((await h.get(id)).status, 200);
  });

  it('nach Ablauf: 404 wie „nie vorhanden"', async () => {
    const h = await harness(1_000);
    const id = await h.complete();
    h.clock.now += 1_001;
    const late = await h.get(id);
    assert.deepEqual(late, await h.get(crypto.randomUUID()));
  });

  it('abgelaufene Ergebnisse werden ohne Ergebnisabruf gelöscht (Audit result_expired)', async () => {
    const h = await harness(1_000);
    const id = await h.complete();
    h.clock.now += 1_001;
    // Irgendeine andere Aktivität am Dienst räumt auf, ohne dass das Ergebnis abgerufen wird.
    await h.service.createRequest('tenant-a', {});
    const expired = h.audit.list().filter((e) => e.event === 'result_expired' && e.detail === `session=${id}`);
    assert.equal(expired.length, 1);
    assert.equal(h.audit.list().some((e) => e.event === 'result_read' && e.detail === `session=${id}`), false);
  });

  it('Standard-Lebensdauer und Konfiguration über ATTACK_RESULT_TTL_SECONDS', () => {
    assert.equal(loadConfig({}).resultTtlSeconds, 60);
    assert.equal(loadConfig({ [ENV_ATTACK_RESULT_TTL_SECONDS]: '5' }).resultTtlSeconds, 5);
    for (const bad of ['0', '3601', '-1', 'abc', '1.5']) {
      assert.throws(() => loadConfig({ [ENV_ATTACK_RESULT_TTL_SECONDS]: bad }), ConfigError, `Wert ${bad} muss abbrechen`);
    }
  });

  it('nicht positive Lebensdauer im Dienst wird abgelehnt', async () => {
    await assert.rejects(() => harness(0));
  });
});
