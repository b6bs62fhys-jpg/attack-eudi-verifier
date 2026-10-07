/**
 * Grenzfälle an den öffentlichen Routen, die sonst nirgends geprüft werden.
 *
 * Vorher mit grep geprüft, was schon abgedeckt ist, damit hier nichts doppelt
 * liegt:
 *
 *   überlange Körper        src/service/fehlerbilder.test.ts a) auf allen Routen
 *   ungültiges JSON         src/service/fehlerbilder.test.ts c), zwei Szenarien
 *   Ratenfenster            src/service/rate-limit.test.ts, fünf Tests
 *   Zertifikatsgültigkeit   src/service/gueltigkeit-dienst.test.ts, abgelaufen
 *                           und noch nicht gültig für Identität, Anker,
 *                           Aussteller, Kette und Statusliste
 *
 * Neu und daher hier:
 *   doppelte JSON-Felder    stillschweigend letzter Wert, nirgends geprüft
 *   deklarierter Content-Type wird nicht durchgesetzt
 *   Body genau an der Grenze
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { afterAll, beforeAll, describe, it } from 'vitest';

import { createApp } from './app.ts';
import { VerifierService, type ServiceKeys } from './service.ts';
import { AuditLog } from './audit.ts';
import { TenantStore } from './tenant.ts';
import { generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';
import { MAX_BODY_BYTES } from './limits.ts';

const KEY = 'test-api-key-eingabe-haertung';
const WURZEL = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

interface Harness {
  base: string;
  server: Awaited<ReturnType<typeof createApp>>;
}

let h: Harness;

async function post(
  pfad: string,
  koerper: string,
  headers: Record<string, string>,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const antwort = await fetch(`${h.base}${pfad}`, { method: 'POST', body: koerper, headers });
  const text = await antwort.text();
  let body: Record<string, unknown>;
  try {
    body = text.length > 0 ? (JSON.parse(text) as Record<string, unknown>) : {};
  } catch {
    body = { roh: text };
  }
  return { status: antwort.status, body };
}

const auth = (): Record<string, string> => ({ authorization: `Bearer ${KEY}` });
const json = (): Record<string, string> => ({ 'content-type': 'application/json' });

beforeAll(async () => {
  const tenants = new TenantStore();
  tenants.add({ id: 'tenant-haertung', name: 'Haertung TEST', apiKey: KEY, requestTtlSeconds: 300 });

  const verifierKey = await generateTestKeyMaterial('Haertung Verifier TEST');
  const issuerKey = await generateTestKeyMaterial('Haertung Issuer TEST');
  const keys: ServiceKeys = {
    privateKey: verifierKey.privateKey,
    publicKey: verifierKey.publicKey,
    publicJwk: verifierKey.publicJwk,
    certificateChain: [verifierKey.certDerBytes],
  };

  const audit = new AuditLog();
  const service = new VerifierService(
    tenants,
    audit,
    keys,
    issuerKey.certDerBytes,
    undefined,
    undefined,
    undefined,
    undefined,
    true,
    DEV_TEST_OPTIONS,
  );
  const server = createApp({ appLabel: 'attack-service', tenants, service });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  service.baseUrl = base;
  h = { base, server };
}, 60_000);

afterAll(async () => {
  if (h?.server) await new Promise<void>((r) => h.server.close(() => r()));
});

describe('a) Doppelte JSON-Felder', () => {
  it('der letzte Wert gewinnt, ohne Fehler und ohne Hinweis', async () => {
    // JSON.parse nimmt bei doppelten Schluesseln den letzten. Der erste Wert
    // age_over_18 gehoert nicht zum Standardprofil, der letzte given_name
    // schon. Antwort 201 heisst: der letzte hat gewonnen, stillschweigend.
    const { status, body } = await post(
      '/v1/verification-requests',
      '{"claims":["age_over_18"],"claims":["given_name"]}',
      { ...auth(), ...json() },
    );
    assert.equal(status, 201, `erwartet 201, war ${status} ${JSON.stringify(body)}`);
    assert.equal(typeof body.sessionId, 'string');
  });

  it('umgekehrt: der letzte Wert entscheidet, der erste gilt nicht', async () => {
    // Gleiche Eingage, nur die Reihenfolge der Werte vertauscht. Jetzt ist der
    // letzte age_over_18, der nicht zum Profil gehoert, also 400.
    const { status, body } = await post(
      '/v1/verification-requests',
      '{"claims":["given_name"],"claims":["age_over_18"]}',
      { ...auth(), ...json() },
    );
    assert.equal(status, 400, `erwartet 400, war ${status} ${JSON.stringify(body)}`);
    assert.equal(body.error, 'claims_invalid');
  });

  it('ein doppelter state im Envelope ergibt 422, der letzte zaehlt', async () => {
    // Erwartet hatte ich 400. Tatsaechlich liest src/service/app.ts:123 d.state
    // genau einmal, nach JSON.parse ist das der letzte Wert, also b. Damit ist
    // das Envelope gueltig und der Lauf geht bis zur Fachpruefung, die 422
    // unknown_state liefert. Kein Fehler am Parser, der letzte Wert gewinnt.
    const { status, body } = await post(
      '/direct_post',
      '{"state":"a","state":"b","vp_token":{"pid":["x"]}}',
      json(),
    );
    assert.equal(status, 422, `erwartet 422, war ${status}`);
    assert.equal(body.error, 'unknown_state');
  });

  it('vp_token als String statt Objekt ist 400, nicht 422', async () => {
    // Beleg src/service/app.ts:123: vp_token muss typeof object sein.
    const { status, body } = await post('/direct_post', '{"state":"a","vp_token":"x"}', json());
    assert.equal(status, 400);
    assert.equal(body.error, 'invalid_request');
  });
});

describe('b) Content-Type wird nicht durchgesetzt', () => {
  it('die Anlage akzeptiert text/plain mit JSON-Körper', async () => {
    const { status } = await post('/v1/verification-requests', '{"claims":["given_name"]}', {
      ...auth(),
      'content-type': 'text/plain',
    });
    assert.equal(status, 201, 'der Dienst lehnt den deklarierten Typ nicht ab');
  });

  it('die Anlage akzeptiert application/xml mit JSON-Körper', async () => {
    const { status } = await post('/v1/verification-requests', '{"claims":["given_name"]}', {
      ...auth(),
      'content-type': 'application/xml',
    });
    assert.equal(status, 201);
  });

  it('die Anlage akzeptiert einen fehlenden Content-Type', async () => {
    const { status } = await post('/v1/verification-requests', '{"claims":["given_name"]}', auth());
    assert.equal(status, 201);
  });

  it('der Content-Type mit charset-Parameter wird korrekt erkannt', async () => {
    // Gegenprobe: der Parameter darf die Erkennung nicht verhindern.
    const { status } = await post('/v1/verification-requests', '{"claims":["given_name"]}', {
      ...auth(),
      'content-type': 'application/json; charset=utf-8',
    });
    assert.equal(status, 201);
  });

  it('auf direct_post waehlt der Content-Type den Parser, nicht der Inhalt', async () => {
    // Ohne den Formular-Typ geht derkoerper als JSON durch. Ein Formular-Post
    // mit demselben Inhalt wird genauso gelesen, weil die Erkennung über
    // includes('application/x-www-form-urlencoded') laeuft.
    const alsJson = await post('/direct_post', '{"state":"a","vp_token":{"pid":["x"]}}', {
      'content-type': 'text/plain',
    });
    const alsForm = await post(
      '/direct_post',
      'state=a&vp_token=%7B%22pid%22%3A%5B%22x%22%5D%7D',
      { 'content-type': 'application/x-www-form-urlencoded' },
    );
    assert.equal(alsJson.status, alsForm.status, 'beide Wege muessen gleich antworten');
    assert.equal(alsJson.status, 422);
    assert.equal(alsJson.body.error, 'unknown_state');
  });

  it('x-www-form-urlencoded mit charset-Parameter nimmt den Formularweg', async () => {
    const { status } = await post('/direct_post', 'state=a&vp_token=x', {
      'content-type': 'application/x-www-form-urlencoded; charset=utf-8',
    });
    // Formularweg: vp_token=x wird zu { pid: ['x'] } gewickelt, state=a passt zu
    // keiner Sitzung, also 422 statt 400.
    assert.equal(status, 422, `erwartet 422 als Formularweg, war ${status}`);
  });
});

describe('c) Body genau an der Grenze', () => {
  it('ein Body von genau MAX_BODY_BYTES wird angenommen', async () => {
    // Erster Versuch war "claims":[], das ergab 400 claims_invalid, weil
    // validateClaims keine leere Liste annimmt. Die Grenze wurde daran nicht
    // geprueft. Deshalb eine gueltige Liste im Padding.
    const praefix = '{"claims":["given_name"],"pad":"';
    const suffix = '"}';
    const pad = 'x'.repeat(MAX_BODY_BYTES - Buffer.byteLength(praefix) - Buffer.byteLength(suffix));
    const koerper = `${praefix}${pad}${suffix}`;
    assert.equal(Buffer.byteLength(koerper), MAX_BODY_BYTES, 'der Testkoerper hat nicht die erwartete Laenge');
    const { status } = await post('/v1/verification-requests', koerper, { ...auth(), ...json() });
    assert.equal(status, 201, `genau an der Grenze muss durchgehen, war ${status}`);
  });

  it('ein Byte mehr wird mit 413 abgewiesen', async () => {
    const praefix = '{"claims":["given_name"],"pad":"';
    const suffix = '"}';
    const pad = 'x'.repeat(MAX_BODY_BYTES - Buffer.byteLength(praefix) - Buffer.byteLength(suffix) + 1);
    const koerper = `${praefix}${pad}${suffix}`;
    assert.equal(Buffer.byteLength(koerper), MAX_BODY_BYTES + 1);
    const { status, body } = await post('/v1/verification-requests', koerper, { ...auth(), ...json() });
    assert.equal(status, 413);
    assert.equal(body.error, 'payload_too_large');
  });

  it('ein Body mit Zeichen unter der Grenze, aber Bytes darueber, wird abgewiesen', async () => {
    // Das ist der Fall, der Bytes von Zeichen unterscheidet. Der Koerper hat
    // weniger Zeichen als die Grenze erlaubt, aber mehr Bytes, weil je Zeichen
    // zwei Byte im Spiel sind. Wuerde der Dienst Zeichen zaehlen, waere er
    // durchgegangen.
    const praefix = '{"claims":["given_name"],"pad":"';
    const suffix = '"}';
    const zeichen = MAX_BODY_BYTES - Buffer.byteLength(praefix) - Buffer.byteLength(suffix);
    const koerper = `${praefix}${'ä'.repeat(zeichen)}${suffix}`;
    assert.ok(koerper.length <= MAX_BODY_BYTES, 'der Koerper hat zufaellig zu wenige Zeichen');
    assert.ok(Buffer.byteLength(koerper) > MAX_BODY_BYTES, 'der Koerper hat zufaellig zu wenige Bytes');
    const { status, body } = await post('/v1/verification-requests', koerper, { ...auth(), ...json() });
    assert.equal(status, 413, `Bytes ueber der Grenze muessen abgewiesen werden, war ${status}`);
    assert.equal(body.error, 'payload_too_large');
  });

  it('die Grenze wird in Bytes gezaehlt, nicht in Zeichen', async () => {
    // Beleg src/service/app.ts:60, total += buf.length zaehlt Bytes.
    const praefix = '{"claims":["given_name"],"pad":"';
    const suffix = '"}';
    // Fuenf Byte je Zeichen, also braucht es fuer MAX_BODY_BYTES nur ein Fuenftel.
    const zeichen = Math.floor((MAX_BODY_BYTES - Buffer.byteLength(praefix) - Buffer.byteLength(suffix)) / 5);
    const koerper = `${praefix}${'ä'.repeat(zeichen)}${suffix}`;
    assert.ok(Buffer.byteLength(koerper) <= MAX_BODY_BYTES, 'der Testkoerper ist zu gross');
    const { status } = await post('/v1/verification-requests', koerper, { ...auth(), ...json() });
    assert.equal(status, 201, `mehrbyte Koerper unter der Grenze muss durchgehen, war ${status}`);
  });
});

describe('d) Die Abhaengigkeit dieser Tests vom Code ist belegt', () => {
  it('readBody zaehlt Bytes, nicht Zeichen', () => {
    // Ueber HTTP laesst sich das nicht unterscheiden: bei einer Chunk-Grenze
    // mitten im Zweibytezeichen entstehen Ersatzzeichen, dadurch ueberschreitet
    // auch eine Zeichenzaehlung die Grenze. Geprueft wird deshalb die Zeile,
    // die es entscheidet.
    const quelle = readFileSync(resolve(WURZEL, 'src/service/app.ts'), 'utf8');
    assert.match(quelle, /total \+= buf\.length;/);
    assert.ok(
      !/total \+= buf\.toString/.test(quelle),
      'readBody zaehlt Zeichen statt Bytes, der mehrbyte Grenzfall ist dann nicht korrekt',
    );
  });

  it('readBody vergleicht mit >, nicht mit >=', () => {
    const quelle = readFileSync(resolve(WURZEL, 'src/service/app.ts'), 'utf8');
    assert.match(quelle, /if \(total > maxBytes\) throw new PayloadTooLargeError\(\);/);
  });

  it('der Formularweg haengt an includes, nicht an einer exakten Uebereinstimmung', () => {
    const quelle = readFileSync(resolve(WURZEL, 'src/service/app.ts'), 'utf8');
    assert.match(quelle, /contentType\.includes\('application\/x-www-form-urlencoded'\)/);
  });

  it('die Anlage liest den Body ohne Ruecksicht auf den Content-Type', () => {
    const quelle = readFileSync(resolve(WURZEL, 'src/service/app.ts'), 'utf8');
    const block = /path: '\/v1\/verification-requests',[\s\S]*?handle: async/.exec(quelle);
    assert.ok(block, 'Route nicht gefunden');
    assert.ok(
      !/content-type|contentType/.test(block[0]),
      'die Anlage prueft den Content-Type, dann ist die Aussage im Test falsch',
    );
  });
});
