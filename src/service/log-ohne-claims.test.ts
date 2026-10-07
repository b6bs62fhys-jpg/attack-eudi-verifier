/**
 * Härtung 6d: Nach einer vollständigen Prüfung steht kein Anspruchswert
 * (Name, Geburtsdatum, Adresse) im Log.
 *
 *   - Demo als echter Prozess: Durchlauf per Enter und per POST /demo/run;
 *     stdout/stderr werden auf die TEST-Werte der Mock-Wallet durchsucht.
 *     Gegenprobe: die HTTP-Antwort enthält die Werte (die Prüfung lief also
 *     wirklich mit diesen Werten).
 *   - Dienst im Prozess: console.* und Audit-Log während eines vollständigen
 *     Ablaufs (Anfrage, Präsentation, Ergebnisabruf).
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';
import { createLocalJWKSet, jwtVerify } from 'jose';

import { buildSdJwtVc, generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { createApp } from './app.ts';
import { AuditLog } from './audit.ts';
import { VerifierService } from './service.ts';
import { TenantStore } from './tenant.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';

/** TEST-Werte der Demo-Mock-Wallet (src/demo/demo.ts). */
const DEMO_VALUES = ['Erika', 'Mustermann-TEST', '1984-01-26', 'Heidestraße 17', 'Köln', '51147'];
/** TEST-Werte für den Dienstablauf. */
const SERVICE_VALUES = { given_name: 'Wilhelmine-TEST', family_name: 'Beispielfrau-TEST', birth_date: '1971-07-19', resident_address: { street_address: 'Lindenallee 99', locality: 'Musterhausen', postal_code: '99999' } };
const SERVICE_STRINGS = ['Wilhelmine-TEST', 'Beispielfrau-TEST', '1971-07-19', 'Lindenallee 99', 'Musterhausen', '99999'];

async function freePort(): Promise<number> {
  const probe = http.createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const port = (probe.address() as { port: number }).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

describe('Demo: kein Anspruchswert im Log', () => {
  it('vollständiger Durchlauf (Enter + POST /demo/run) -> Log ohne Name, Geburtsdatum, Adresse', async () => {
    const port = await freePort();
    const child = spawn(process.execPath, ['--experimental-strip-types', 'src/demo/demo.ts'], {
      cwd: process.cwd(),
      env: { PATH: process.env.PATH ?? '', ATTACK_DEV_MODE: 'true', ATTACK_ALLOW_SELF_SIGNED: 'true', PORT: String(port) },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let log = '';
    child.stdout.on('data', (d) => (log += d));
    child.stderr.on('data', (d) => (log += d));
    const exited = new Promise<void>((resolve) => child.on('exit', () => resolve()));
    const waitFor = async (pattern: RegExp) => {
      for (let i = 0; i < 200 && !pattern.test(log); i += 1) await new Promise((r) => setTimeout(r, 100));
      assert.match(log, pattern);
    };
    let runBody: string;
    try {
      await waitFor(/Attack Demo läuft/);
      child.stdin.write('\n');
      await waitFor(/DURCHLAUF 1/);
      const res = await fetch(`http://127.0.0.1:${port}/demo/run`, { method: 'POST' });
      runBody = await res.text();
      await fetch(`http://127.0.0.1:${port}/`);
    } finally {
      child.kill('SIGTERM');
      await exited;
    }
    // Gegenprobe: die Prüfung lief gültig mit genau diesen Werten.
    assert.match(log, /DURCHLAUF 1: valid=true, freigegebene Claims=address,birthdate,family_name,given_name/);
    for (const value of DEMO_VALUES) assert.ok(runBody.includes(value), `Gegenprobe: ${value} in der Demo-Antwort`);
    for (const value of DEMO_VALUES) assert.ok(!log.includes(value), `Anspruchswert im Log: ${value}`);
  });
});

describe('Dienst: kein Anspruchswert in Konsole und Audit-Log', () => {
  let app!: http.Server;
  const captured: string[] = [];
  const originals: Partial<Record<'log' | 'info' | 'warn' | 'error' | 'debug', (...args: unknown[]) => void>> = {};

  beforeAll(() => {
    for (const level of ['log', 'info', 'warn', 'error', 'debug'] as const) {
      originals[level] = console[level];
      console[level] = (...args: unknown[]) => captured.push(args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' '));
    }
  });

  afterAll(async () => {
    for (const level of Object.keys(originals) as Array<keyof typeof originals>) console[level] = originals[level] as (...args: unknown[]) => void;
    if (app) await new Promise<void>((resolve) => app.close(() => resolve()));
  });

  it('Anfrage, gültige Präsentation, Ergebnisabruf -> Werte nur in der Ergebnisantwort', async () => {
    const tenants = new TenantStore();
    tenants.add({ id: 'tenant-a', name: 'Kunde A (TEST)', apiKey: 'test-api-key-log-A', requestProfile: { id: 'log', claims: ['given_name', 'family_name', 'birth_date', 'resident_address'] } });
    const verifier = await generateTestKeyMaterial('Log Verifier TEST');
    const issuer = await generateTestKeyMaterial('Log Issuer TEST');
    const holder = await generateTestKeyMaterial('Log Holder TEST');
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
      DEV_TEST_OPTIONS,
    );
    app = createApp({ appLabel: 'log-test', tenants, service });
    await new Promise<void>((resolve) => app.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${(app.address() as { port: number }).port}`;
    service.baseUrl = base;
    const auth = { authorization: 'Bearer test-api-key-log-A', 'content-type': 'application/json' };

    const created = (await (await fetch(`${base}/v1/verification-requests`, { method: 'POST', headers: auth, body: JSON.stringify({ claims: Object.keys(SERVICE_VALUES) }) })).json()) as {
      sessionId: string;
      requestObjectUri: string;
      responseUri: string;
    };
    const requestObject = await (await fetch(created.requestObjectUri)).text();
    const { payload } = await jwtVerify(requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
    const { given_name, ...rest } = SERVICE_VALUES;
    const built = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, claimName: 'given_name', claimValue: given_name, additionalDisclosures: rest, nonce: String(payload.nonce), audience: String(payload.client_id) });
    const posted = (await (await fetch(created.responseUri, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ vp_token: { pid: [built.sdJwt] }, state: payload.state }) })).json()) as { valid: boolean };
    assert.equal(posted.valid, true);
    const result = await (await fetch(`${base}/v1/verification-requests/${created.sessionId}`, { headers: auth })).text();
    for (const value of SERVICE_STRINGS) assert.ok(result.includes(value), `Gegenprobe: ${value} im Ergebnis`);

    const logText = captured.join('\n') + '\n' + JSON.stringify(audit.list());
    for (const value of SERVICE_STRINGS) assert.ok(!logText.includes(value), `Anspruchswert im Log: ${value}`);
  });
});
