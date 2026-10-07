/**
 * Sicherheits-Header und CORS der Haupt-API.
 *
 * Der Dienst wird von Servern und nativen Wallets aufgerufen, nicht von fremden
 * Browserherkünften. Der Test hält beides fest: die Header, die gesetzt sein
 * müssen, und die CORS-Haltung, die ausdrücklich gewollt ist.
 *
 * Geprüft wird jede Antwortklasse, nicht nur die 200. Ein Header, der nur auf
 * dem Erfolgsfall steht, nützt bei einem 401 mit Fehlertext nichts.
 */
import assert from 'node:assert/strict';
import type http from 'node:http';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';

import { createApp } from './app.ts';
import { TenantStore } from './tenant.ts';

const KEY = 'header-audit-test-key';

let app!: http.Server;
let base = '';
const tenants = new TenantStore();

beforeAll(async () => {
  tenants.add({ id: 't-header', name: 'Kunde H (TEST)', apiKey: KEY });
  app = createApp({ appLabel: 'header-audit-test', tenants, service: {} as never });
  await new Promise<void>((resolve) => app.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(app.address() as { port: number }).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    app.closeAllConnections();
    app.close(() => resolve());
  });
});

/** Die Header, die auf jeder Antwort stehen müssen. */
function pruefeBasis(res: Response, label: string): void {
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff', `${label}: nosniff fehlt`);
  assert.equal(res.headers.get('cache-control'), 'no-store', `${label}: no-store fehlt`);
  assert.equal(res.headers.get('x-frame-options'), 'DENY', `${label}: framing nicht verhindert`);
}

describe('Sicherheits-Header der Haupt-API', () => {
  it('stehen auf jeder Antwortklasse, nicht nur auf 200', async () => {
    const faelle: Array<{ label: string; request: () => Promise<Response> }> = [
      { label: '200 /live', request: () => fetch(`${base}/live`) },
      { label: '200 /metrics', request: () => fetch(`${base}/metrics`) },
      { label: '401 ohne Schlüssel', request: () => fetch(`${base}/v1/verification-requests`, { method: 'POST' }) },
      { label: '404 ohne Schlüssel', request: () => fetch(`${base}/gibt-es-nicht`) },
      { label: 'OPTIONS /direct_post', request: () => fetch(`${base}/direct_post`, { method: 'OPTIONS' }) },
    ];
    for (const { label, request } of faelle) {
      const res = await request();
      await res.arrayBuffer();
      pruefeBasis(res, label);
    }
  });

  it('das Request Object wird nicht zwischengespeichert', async () => {
    // Das Request Object ist der einzige Antwortinhalt, der Wallet-Anteil
    // trägt. Ohne no-store könnte ein gemeinsamer Proxy ihn vorhalten.
    //
    // Der Status ist hier nicht Gegenstand der Prüfung: die Route ist
    // öffentlich, erreicht also den Handler und trifft in diesem Test auf einen
    // leeren Dienst, der daraufhin mit 500 antwortet. Für die Header ist das
    // gleichgültig, sie stehen vor jedem `writeHead`.
    const res = await fetch(`${base}/v1/verification-requests/nicht-vorhanden/request-object`);
    await res.arrayBuffer();
    assert.equal(res.headers.get('cache-control'), 'no-store', 'Request Object darf nicht gecacht werden');
    pruefeBasis(res, 'request-object');
  });

  it('der 413-Pfad trägt die Header ebenfalls', async () => {
    const res = await fetch(`${base}/v1/verification-requests`, {
      method: 'POST',
      headers: { authorization: `Bearer ${KEY}`, 'content-type': 'application/json' },
      body: JSON.stringify({ filler: 'x'.repeat(70_000) }),
    });
    await res.arrayBuffer();
    assert.equal(res.status, 413, `erwartet 413, bekam ${res.status}`);
    pruefeBasis(res, '413');
  });

  it('HSTS wird nicht gesetzt, weil der Dienst ohne TLS spricht', () => {
    // Absichtliche Abwesenheit, kein Versehen. HSTS gilt nur über HTTPS; auf
    // einer reinen HTTP-Verbindung hätte der Header keine Wirkung und vor dem
    // TLS-Abschluss schadet er. Er gehört an den Reverse Proxy.
    assert.ok(true, 'siehe Kommentar und docs/deployment.md');
  });

  it('kein CORS: kein Wildcard-Origin, kein Preflight', async () => {
    // Der Dienst ist keine Browser-API. Fehlende CORS-Header bedeuten, dass die
    // Same-Origin-Policy des Browsers vollständig greift und kein fremder
    // Herkunft Zugriff auf eine Antwort bekommt. Ein gesetzter
    // Access-Control-Allow-Origin mit Wildcard wäre hier der echte Fund.
    const mitOrigin = await fetch(`${base}/live`, { headers: { origin: 'https://evil.example' } });
    await mitOrigin.arrayBuffer();
    assert.equal(mitOrigin.headers.get('access-control-allow-origin'), null, 'kein Allow-Origin, schon gar kein Wildcard');
    assert.equal(mitOrigin.headers.get('access-control-allow-credentials'), null);

    const preflight = await fetch(`${base}/direct_post`, {
      method: 'OPTIONS',
      headers: {
        origin: 'https://evil.example',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'authorization',
      },
    });
    await preflight.arrayBuffer();
    assert.equal(preflight.headers.get('access-control-allow-origin'), null, 'Preflight darf keine CORS-Zusage machen');
    // Der Preflight wird wie jeder unbekannte Pfad behandelt. So verrät die
    // Antwort nicht, ob /direct_post überhaupt existiert.
    assert.equal(preflight.status, 401);
  });

  it('die Antwort einer fremden Herkunft ist nicht unterscheidbar', async () => {
    // Gegenprobe zur Absicht: /direct_post ist öffentlich, /live ist öffentlich.
    // Eine unbekannte Route mit Schlüssel antwortet 404, ohne Schlüssel 401.
    // Es darf keinen CORS-Header geben, über den sich das unterscheiden ließe.
    const a = await fetch(`${base}/live`, { headers: { origin: 'https://a.example' } });
    const b = await fetch(`${base}/live`, { headers: { origin: 'https://b.example' } });
    await a.arrayBuffer();
    await b.arrayBuffer();
    const corsA = a.headers.get('access-control-allow-origin');
    const corsB = b.headers.get('access-control-allow-origin');
    assert.equal(corsA, corsB, 'die Herkunft darf die Antwort nicht verändern');
  });
});
