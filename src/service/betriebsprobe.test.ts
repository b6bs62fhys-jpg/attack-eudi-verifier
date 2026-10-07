/**
 * Betriebsproben für die Prozess- und Bereitschaftsrouten.
 *
 * Es gibt bereits /live, /health und /ready, alle in ROUTES als `public`
 * geführt. Geprüft wird hier nur das Verhalten der Antworten, es wird nichts am
 * Dienst geändert.
 *
 * Ergänzt, weil es dazu keinen Test gab: src/cli/main.test.ts:151 prüft nur,
 * dass die Routen in der CLI-Übersicht auftauchen, metrics.test.ts zählt
 * Metriken, logger.test.ts prüft die Feldfilterung. Die HTTP-Antwort selbst war
 * nirgends abgesichert.
 */
import assert from 'node:assert/strict';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';

import { createApp, ROUTES } from './app.ts';
import { AuditLog } from './audit.ts';
import { VerifierService, type ServiceKeys } from './service.ts';
import { TenantStore } from './tenant.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';
import { generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import type { ReadinessSnapshot } from './metrics.ts';

const KEY_A = 'test-api-key-betriebsprobe-A';

interface Harness {
  base: string;
  audit: AuditLog;
  server: Awaited<ReturnType<typeof createApp>>;
  /**
   * Wird von den Tests gesetzt, um den Bereitschaftszustand zu steuern.
   *
   * Eine Variable und keine Funktion: createApp bekommt beim Start einmal einen
   * Funktionswert uebergeben. Wird danach `h.readiness` neu zugewiesen, merkt
   * der Server davon nichts, er haelt die alte Funktion. Darum haelt h hier den
   * Zustand, und der Wrapper liest ihn bei jedem Aufruf.
   */
  zustand: ReadinessSnapshot;
}

let h: Harness;

beforeAll(async () => {
  const tenants = new TenantStore();
  tenants.add({ id: 'tenant-a', name: 'Kunde A (TEST)', apiKey: KEY_A, requestTtlSeconds: 300 });

  const verifierKey = await generateTestKeyMaterial('Betriebsprobe Verifier TEST');
  const issuerKey = await generateTestKeyMaterial('Betriebsprobe Issuer TEST');
  const keys: ServiceKeys = {
    privateKey: verifierKey.privateKey,
    publicKey: verifierKey.publicKey,
    publicJwk: verifierKey.publicJwk,
    certificateChain: [verifierKey.certDerBytes],
  };

  const audit = new AuditLog();
  const service = new VerifierService(tenants, audit, keys, issuerKey.certDerBytes, undefined, undefined, undefined, undefined, true, DEV_TEST_OPTIONS);
  const zustand: ReadinessSnapshot = {
    ready: true,
    checks: { config: 'ok', issuer_trust: 'ok', ocsp: 'degraded', onboarding: 'degraded' },
  };
  const server = createApp({ appLabel: 'betriebsprobe', tenants, service, readiness: () => h.zustand });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  service.baseUrl = base;

  h = { base, audit, server, zustand };
}, 60_000);

afterAll(async () => {
  await new Promise<void>((r) => h.server.close(() => r()));
});

describe('Betriebsproben: Prozess lebt', () => {
  for (const pfad of ['/live', '/health']) {
    it(`GET ${pfad} antwortet 200 ohne Anmeldung`, async () => {
      const antwort = await fetch(`${h.base}${pfad}`);
      assert.equal(antwort.status, 200);
    });

    it(`GET ${pfad} meldet status live und den app-Namen`, async () => {
      const antwort = await fetch(`${h.base}${pfad}`);
      const body = (await antwort.json()) as Record<string, unknown>;
      assert.equal(body.ok, true);
      assert.equal(body.status, 'live');
      assert.equal(body.app, 'betriebsprobe');
    });

    it(`GET ${pfad} nennt weder Anker noch Mandanten noch Konfiguration`, async () => {
      const antwort = await fetch(`${h.base}${pfad}`);
      const roh = await antwort.text();
      for (const verboten of ['issuerAnchors', 'checks', 'tenant', 'apiKey', KEY_A, 'ATTACK_']) {
        assert.equal(roh.includes(verboten), false, `Antwort nennt ${verboten}`);
      }
    });
  }

  it('beide Routen sind in ROUTES als public geführt', () => {
    for (const pfad of ['/live', '/health']) {
      const route = ROUTES.find((r) => r.path === pfad);
      assert.ok(route, `${pfad} fehlt in ROUTES`);
      assert.equal(route.access, 'public', `${pfad} ist nicht public`);
    }
  });
});

describe('Betriebsproben: Bereitschaft', () => {
  it('GET /ready antwortet 200, wenn alle Prüfungen lauten', async () => {
    const antwort = await fetch(`${h.base}/ready`);
    assert.equal(antwort.status, 200);
  });

  it('GET /ready nennt jede Einzelprüfung', async () => {
    const antwort = await fetch(`${h.base}/ready`);
    const body = (await antwort.json()) as { ok: boolean; status: string; checks: Record<string, string> };
    assert.equal(body.ok, true);
    assert.equal(body.status, 'ready');
    assert.deepEqual(Object.keys(body.checks).sort(), ['config', 'issuer_trust', 'ocsp', 'onboarding']);
  });

  it('GET /ready unterscheidet degraded von ok in der Antwort', async () => {
    const antwort = await fetch(`${h.base}/ready`);
    const body = (await antwort.json()) as { checks: Record<string, string> };
    assert.equal(body.checks.config, 'ok');
    assert.equal(body.checks.ocsp, 'degraded');
  });

  it('GET /ready antwortet 503, wenn eine Prüfung failed ist', async () => {
    const vorher = { ...h.zustand };
    h.zustand = { ready: false, checks: { config: 'ok', issuer_trust: 'failed' } };
    try {
      const antwort = await fetch(`${h.base}/ready`);
      assert.equal(antwort.status, 503);
      const body = (await antwort.json()) as { ok: boolean; status: string };
      assert.equal(body.ok, false);
      assert.equal(body.status, 'not_ready');
    } finally {
      h.zustand = vorher;
    }
  });

  it('GET /ready antwortet 200, wenn eine Prüfung degraded ist', async () => {
    const antwort = await fetch(`${h.base}/ready`);
    assert.equal(antwort.status, 200, 'degraded blockiert die Bereitschaft nicht');
  });

  it('GET /ready nennt keine Mandanten-Interna', async () => {
    const antwort = await fetch(`${h.base}/ready`);
    const roh = await antwort.text();
    for (const verboten of ['apiKey', KEY_A, 'tenant-a', 'cert', 'pem']) {
      assert.equal(roh.toLowerCase().includes(verboten.toLowerCase()), false, `Antwort nennt ${verboten}`);
    }
  });

  it('die Bereitschaftsroute ist in ROUTES als public geführt', () => {
    const route = ROUTES.find((r) => r.path === '/ready');
    assert.ok(route, '/ready fehlt in ROUTES');
    assert.equal(route.access, 'public');
  });
});
