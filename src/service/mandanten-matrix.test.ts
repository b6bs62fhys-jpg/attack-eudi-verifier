/**
 * Härtung 3: Mandantentrennung als automatische Routenmatrix.
 *
 * Die Matrix liest ALLE Routen aus `ROUTES` (src/service/app.ts) und prüft
 * für jede Mandantenroute:
 *   - ohne Anmeldung / mit falschem Schlüssel -> 401
 *   - fremder Mandant -> 404, ununterscheidbar von „nie vorhanden", und die
 *     Ressource des Eigentümers bleibt unverändert
 *   - eigener Mandant -> Erfolg (2xx)
 * Öffentliche Routen müssen ausdrücklich freigegeben sein; eine neue Route
 * ohne Eintrag hier fällt auf.
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';

import { generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { createApp, ROUTES, type RouteDef } from './app.ts';
import { AuditLog } from './audit.ts';
import { VerifierService } from './service.ts';
import { TenantStore } from './tenant.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';

const KEY_A = 'test-api-key-matrix-A';
const KEY_B = 'test-api-key-matrix-B';

/** Ausdrücklich öffentliche Routen (Wallet-Seite und Health). */
const EXPECTED_PUBLIC = new Set(['GET /live', 'GET /health', 'GET /ready', 'GET /metrics', 'GET /v1/verification-requests/:id/request-object', 'POST /direct_post']);

/** Anfragekörper für Routen, die einen erwarten (sonst leer). */
const BODY: Record<string, unknown> = {
  'POST /v1/verification-requests': { claims: ['given_name'] },
};

const key = (route: RouteDef) => `${route.method} ${route.path}`;

let app!: http.Server;
let base!: string;
let service!: VerifierService;

async function call(route: RouteDef, id: string, token?: string): Promise<{ status: number; body: string }> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  const body = BODY[key(route)];
  const res = await fetch(`${base}${route.path.replace(':id', id)}`, {
    method: route.method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: await res.text() };
}

async function sessionOf(tenantId: string): Promise<string> {
  return (await service.createRequest(tenantId, {})).sessionId;
}

beforeAll(async () => {
  const tenants = new TenantStore();
  tenants.add({ id: 'tenant-a', name: 'Kunde A (TEST)', apiKey: KEY_A });
  tenants.add({ id: 'tenant-b', name: 'Kunde B (TEST)', apiKey: KEY_B });
  const verifier = await generateTestKeyMaterial('Matrix Verifier TEST');
  const issuer = await generateTestKeyMaterial('Matrix Issuer TEST');
  service = new VerifierService(
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
  app = createApp({ appLabel: 'matrix-test', tenants, service });
  await new Promise<void>((resolve) => app.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(app.address() as { port: number }).port}`;
  service.baseUrl = base;
});

afterAll(async () => {
  await new Promise<void>((resolve) => app.close(() => resolve()));
});

describe('Routentabelle', () => {
  it('enthält Routen (Matrix ist nicht leer)', () => {
    assert.ok(ROUTES.length >= 5);
    assert.ok(ROUTES.some((r) => r.access === 'tenant'));
  });

  it('öffentlich sind genau die freigegebenen Routen', () => {
    const publicRoutes = new Set(ROUTES.filter((r) => r.access === 'public').map(key));
    assert.deepEqual(publicRoutes, EXPECTED_PUBLIC);
  });

  it('jede Mandantenroute mit Pfadparameter ist als Mandanten-Ressource markiert', () => {
    for (const route of ROUTES.filter((r) => r.access === 'tenant')) {
      assert.equal(route.path.includes(':'), route.resource === 'session', `${key(route)}: resource passt nicht zum Pfad`);
    }
  });

  it('der Dienst meldet beim Start die echte Routenzahl', async () => {
    // Regression: src/service/run.ts meldete die Zahl 8 fest eingetragen,
    // obwohl ROUTES neun Eintraege hat. Die CLI listet neun, der Dienst
    // meldete acht, kein Test fiel auf. Geprueft wird die Logzeile beim
    // echten Start des Dienstes.
    const { spawn } = await import('node:child_process');
    const { fileURLToPath } = await import('node:url');
    const { dirname, resolve } = await import('node:path');
    const wurzel = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

    const kind = spawn(
      process.execPath,
      ['--experimental-strip-types', 'src/service/run.ts'],
      {
        cwd: wurzel,
        env: {
          ...process.env,
          NODE_ENV: 'development',
          ATTACK_DEV_MODE: 'true',
          ATTACK_ALLOW_SELF_SIGNED: 'true',
PORT: String(18800 + (process.pid % 90)),
        },
      },
    );
    const zeilen: string[] = [];
    kind.stdout?.on('data', (d: Buffer) => {
      for (const z of d.toString().split('\n')) if (z.includes('service_routes')) zeilen.push(z);
    });
    try {
      await new Promise<void>((r) => {
        const t = setTimeout(r, 5000);
        kind.stdout?.on('data', () => {
          if (zeilen.length > 0) {
            clearTimeout(t);
            r();
          }
        });
      });
    } finally {
      kind.kill('SIGTERM');
    }

    assert.equal(zeilen.length, 1, `service_routes kam ${zeilen.length} mal`);
    const gemeldet = Number(/"count":(\d+)/.exec(zeilen[0] ?? '')?.[1]);
    assert.equal(
      gemeldet,
      ROUTES.length,
      `Dienst meldet ${gemeldet}, ROUTES hat ${ROUTES.length}`,
    );
  }, 15_000);

  it('jede Route hat eindeutige Methode+Pfad', () => {
    assert.equal(new Set(ROUTES.map(key)).size, ROUTES.length);
  });
});

for (const route of ROUTES.filter((r) => r.access === 'tenant')) {
  describe(`Matrix ${key(route)}`, () => {
    it('ohne Anmeldung -> 401', async () => {
      const id = await sessionOf('tenant-a');
      assert.equal((await call(route, id)).status, 401);
    });

    it('falscher Schlüssel -> 401', async () => {
      const id = await sessionOf('tenant-a');
      assert.equal((await call(route, id, 'test-api-key-falsch')).status, 401);
    });

    if (route.resource === 'session') {
      it('fremder Mandant -> 404, identisch mit „nie vorhanden", Ressource bleibt unberührt', async () => {
        const id = await sessionOf('tenant-a');
        const foreign = await call(route, id, KEY_B);
        const never = await call(route, crypto.randomUUID(), KEY_B);
        assert.equal(foreign.status, 404);
        assert.deepEqual(foreign, never);
        assert.equal(service.getResult('tenant-a', id).status, 'pending', 'Ressource des Eigentümers muss unverändert sein');
      });
    } else {
      it('fremder Mandant: Route adressiert keine fremde Ressource (nur eigene Anlage)', async () => {
        const created = await call(route, '', KEY_B);
        assert.ok(created.status >= 200 && created.status < 300);
        const { sessionId } = JSON.parse(created.body) as { sessionId: string };
        assert.equal(service.getResult('tenant-a', sessionId).status, 'not_found', 'Anlage von B darf bei A nicht sichtbar sein');
        assert.equal(service.getResult('tenant-b', sessionId).status, 'pending');
      });
    }

    it('eigener Mandant -> Erfolg (2xx)', async () => {
      const id = await sessionOf('tenant-a');
      const own = await call(route, id, KEY_A);
      assert.ok(own.status >= 200 && own.status < 300, `Status ${own.status}: ${own.body}`);
    });
  });
}

describe('Matrix öffentliche Routen', () => {
  it('GET /health ohne Anmeldung -> 200', async () => {
    assert.equal((await fetch(`${base}/health`)).status, 200);
  });
  it('Liveness, Readiness und Metriken sind getrennt erreichbar', async () => {
    assert.equal((await fetch(`${base}/live`)).status, 200);
    assert.equal((await fetch(`${base}/ready`)).status, 200);
    const metrics = await fetch(`${base}/metrics`);
    assert.equal(metrics.status, 200);
    assert.match(await metrics.text(), /attack_http_requests_total/);
  });
  it('Request Object ohne Anmeldung abrufbar (Wallet), unbekannte Sitzung -> 404', async () => {
    const id = await sessionOf('tenant-a');
    assert.equal((await fetch(`${base}/v1/verification-requests/${id}/request-object`)).status, 200);
    assert.equal((await fetch(`${base}/v1/verification-requests/${crypto.randomUUID()}/request-object`)).status, 404);
  });
  it('POST /direct_post ohne Anmeldung erreichbar (Eingabe wird geprüft, nicht 401)', async () => {
    const res = await fetch(`${base}/direct_post`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(res.status, 400);
  });
});

describe('Unbekannte Pfade verraten ohne Anmeldung nichts', () => {
  it('ohne Schlüssel -> 401, mit Schlüssel -> 404', async () => {
    assert.equal((await fetch(`${base}/v1/gibt-es-nicht`)).status, 401);
    assert.equal((await fetch(`${base}/v1/gibt-es-nicht`, { headers: { authorization: `Bearer ${KEY_A}` } })).status, 404);
  });
});
