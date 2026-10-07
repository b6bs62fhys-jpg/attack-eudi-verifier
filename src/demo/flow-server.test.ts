import assert from 'node:assert/strict';
import http from 'node:http';
import { afterAll, beforeAll, describe, it } from 'vitest';

import { MAX_BODY_BYTES } from '../service/limits.ts';
import { FLOW_API_KEY, createFlowHttpServer, isFlowApiRequest, startFlowDemo } from './flow-server.ts';

interface UpstreamRequest {
  method: string;
  url: string;
  authorization: string | undefined;
  body: string;
}

let upstream: http.Server;
let flow: http.Server;
let upstreamPort: number;
let flowPort: number;
const requests: UpstreamRequest[] = [];

beforeAll(async () => {
  upstream = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      requests.push({
        method: req.method ?? '',
        url: req.url ?? '',
        authorization: req.headers.authorization,
        body: Buffer.concat(chunks).toString('utf8'),
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  upstreamPort = (upstream.address() as { port: number }).port;
  flow = createFlowHttpServer({ apiPort: upstreamPort, apiKey: FLOW_API_KEY });
  await new Promise<void>((resolve) => flow.listen(0, '127.0.0.1', resolve));
  flowPort = (flow.address() as { port: number }).port;
});

afterAll(async () => {
  for (const server of [flow, upstream]) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

function url(path: string): string {
  return `http://127.0.0.1:${flowPort}${path}`;
}

describe('Flow-Proxy-Allowlist', () => {
  it('lässt genau die beiden Flow-API-Routen zu', () => {
    assert.equal(isFlowApiRequest('POST', '/v1/verification-requests'), true);
    assert.equal(isFlowApiRequest('GET', '/v1/verification-requests/session-1'), true);
    for (const [method, path] of [
      ['GET', '/v1/verification-requests/session-1/request-object'],
      ['DELETE', '/v1/verification-requests/session-1'],
      ['POST', '/v1/verification-requests/session-1'],
      ['GET', '/direct_post'],
      ['GET', '/health'],
      ['GET', '/v1/verification-requests/session-1/extra'],
    ] as const) {
      assert.equal(isFlowApiRequest(method, path), false, `${method} ${path}`);
    }
  });

  it('verlangt beide Development-Schalter für den Start', async () => {
    await assert.rejects(() => startFlowDemo({ PORT: '34568' }), /ATTACK_DEV_MODE=true/);
    await assert.rejects(() => startFlowDemo({ ATTACK_DEV_MODE: 'true', PORT: '34568' }), /ATTACK_ALLOW_SELF_SIGNED=true/);
  });

  it('liefert statische Dateien ohne API-Schlüssel aus', async () => {
    const page = await fetch(url('/'));
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /<!doctype html>/i);
    assert.equal(html.includes(FLOW_API_KEY), false);
    const script = await fetch(url('/status.js'));
    assert.equal(script.status, 200);
    assert.equal((await script.text()).includes(FLOW_API_KEY), false);
  });

  it('setzt den internen Schlüssel nur bei erlaubten Routen', async () => {
    const created = await fetch(url('/v1/verification-requests'), {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer angreifer' },
      body: JSON.stringify({ claims: ['given_name'] }),
    });
    assert.equal(created.status, 200);
    assert.deepEqual(await created.json(), { ok: true });
    const read = await fetch(url('/v1/verification-requests/session-1'), { headers: { authorization: 'Bearer angreifer' } });
    assert.equal(read.status, 200);
    assert.equal(requests.at(-2)?.authorization, `Bearer ${FLOW_API_KEY}`);
    assert.equal(requests.at(-1)?.authorization, `Bearer ${FLOW_API_KEY}`);
    assert.equal(requests.at(-2)?.body, JSON.stringify({ claims: ['given_name'] }));
  });

  it('proxied nicht erlaubte Pfade und Größenüberschreitungen nicht', async () => {
    const before = requests.length;
    for (const [method, path] of [
      ['GET', '/direct_post'],
      ['GET', '/v1/verification-requests/session-1/request-object'],
      ['DELETE', '/v1/verification-requests/session-1'],
    ] as const) {
      const response = await fetch(url(path), { method });
      assert.equal(response.status, 404, `${method} ${path}`);
    }
    const oversized = await fetch(url('/v1/verification-requests'), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: 'x'.repeat(MAX_BODY_BYTES + 1),
    });
    assert.equal(oversized.status, 413);
    assert.equal(requests.length, before);
  });
});
