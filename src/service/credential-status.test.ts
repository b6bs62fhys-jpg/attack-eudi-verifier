/**
 * Härtung 1: Statusprüfung vorgelegter Credentials (Token Status List)
 * fail closed.
 *
 * Statuslisten werden über einen echten lokalen HTTP-Server (127.0.0.1)
 * ausgeliefert. Jeder Fehlerpfad lehnt mit eigenem Code ab, jeweils mit
 * positiver Gegenprobe. Pflichttest: Statusliste nicht erreichbar ->
 * Ablehnung (Einheit und Dienst).
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import { deflateSync } from 'node:zlib';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';
import { createLocalJWKSet, jwtVerify, SignJWT } from 'jose';

import { ConfigError } from '../config.ts';
import { buildSdJwtVc, generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { AuditLog } from './audit.ts';
import {
  assertCredentialStatusAllowed,
  CredentialStatusError,
  NO_CREDENTIAL_STATUS,
  STATUS_LIST_JWT_TYPE,
  TokenStatusListChecker,
  type CredentialStatusChecker,
} from './credential-status.ts';
import { VerifierService } from './service.ts';
import { TenantStore } from './tenant.ts';
import { OcspRevocationChecker } from '../onboarding/ocsp-revocation.ts';

const DEV = { devMode: true, isProduction: false };
const NO_DEV = { devMode: false, isProduction: false };
const PROD = { devMode: false, isProduction: true };

let signer!: TestKeyMaterial;
let stranger!: TestKeyMaterial;
let server!: http.Server;
let base!: string;
const routes = new Map<string, (res: http.ServerResponse) => void>();

/** Packt Statuswerte LSB-zuerst in Bytes und komprimiert (ZLIB/DEFLATE). */
function encodeStatusList(values: number[], bits: 1 | 2 | 4 | 8): string {
  const bytes = new Uint8Array(Math.ceil((values.length * bits) / 8));
  values.forEach((value, idx) => {
    const offset = idx * bits;
    bytes[Math.floor(offset / 8)] |= value << (offset % 8);
  });
  return deflateSync(bytes).toString('base64url');
}

interface TokenOptions {
  values?: number[];
  bits?: 1 | 2 | 4 | 8;
  sub?: string;
  iat?: number;
  exp?: number | null;
  typ?: string;
  key?: TestKeyMaterial;
  x5cKey?: TestKeyMaterial;
  lst?: string;
}

async function statusListToken(uri: string, options: TokenOptions = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    sub: options.sub ?? uri,
    iat: options.iat ?? now - 10,
    status_list: { bits: options.bits ?? 2, lst: options.lst ?? encodeStatusList(options.values ?? [0, 1, 2, 3], options.bits ?? 2) },
  };
  if (options.exp !== null) payload.exp = options.exp ?? now + 3600;
  const key = options.key ?? signer;
  const x5cKey = options.x5cKey ?? key;
  return new SignJWT(payload).setProtectedHeader({ alg: 'ES256', typ: options.typ ?? STATUS_LIST_JWT_TYPE, x5c: [x5cKey.x5cBase64] }).sign(key.privateKey);
}

function serve(path: string, body: string | Uint8Array, status = 200): string {
  routes.set(path, (res) => {
    res.writeHead(status, { 'content-type': 'application/statuslist+jwt' });
    res.end(body);
  });
  return `${base}${path}`;
}

async function serveToken(path: string, options: TokenOptions = {}): Promise<string> {
  const uri = `${base}${path}`;
  serve(path, await statusListToken(uri, options));
  return uri;
}

function checker(extra: Partial<ConstructorParameters<typeof TokenStatusListChecker>[0]> = {}): TokenStatusListChecker {
  return new TokenStatusListChecker({ trustedSigners: () => [signer.certDerBytes], allowInsecureHttp: true, timeoutMs: 1_000, ...extra });
}

const ref = (uri: string, idx: number) => ({ status: { status_list: { idx, uri } } });

async function rejectsWithCode(fn: () => Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(fn, (e: unknown) => {
    assert.ok(e instanceof CredentialStatusError, `kein CredentialStatusError: ${String(e)}`);
    assert.equal(e.code, code);
    return true;
  });
}

async function closedPortUrl(): Promise<string> {
  const probe = http.createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const port = (probe.address() as { port: number }).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return `http://127.0.0.1:${port}/statuslists/1`;
}

beforeAll(async () => {
  signer = await generateTestKeyMaterial('Statuslisten-Signer TEST');
  stranger = await generateTestKeyMaterial('Fremder Signer TEST');
  server = http.createServer((req, res) => {
    const handler = routes.get(req.url ?? '');
    if (handler) return handler(res);
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('TokenStatusListChecker: Statuswerte', () => {
  it('0x00 VALID -> akzeptiert (Gegenprobe)', async () => {
    const uri = await serveToken('/sl/values');
    await checker().check(ref(uri, 0));
  });
  it('0x01 INVALID -> credential_revoked', async () => {
    const uri = await serveToken('/sl/values');
    await rejectsWithCode(() => checker().check(ref(uri, 1)), 'credential_revoked');
  });
  it('0x02 SUSPENDED -> credential_suspended', async () => {
    const uri = await serveToken('/sl/values');
    await rejectsWithCode(() => checker().check(ref(uri, 2)), 'credential_suspended');
  });
  it('0x03 (anwendungsspezifisch/unbekannt) -> credential_status_unknown', async () => {
    const uri = await serveToken('/sl/values');
    await rejectsWithCode(() => checker().check(ref(uri, 3)), 'credential_status_unknown');
  });
  it('1-Bit-Liste: Index 9 gesetzt -> gesperrt, Index 8 frei -> gültig', async () => {
    const values = new Array(16).fill(0);
    values[9] = 1;
    const uri = await serveToken('/sl/bits1', { values, bits: 1 });
    await checker().check(ref(uri, 8));
    await rejectsWithCode(() => checker().check(ref(uri, 9)), 'credential_revoked');
  });
});

describe('TokenStatusListChecker: Fehlerpfade lehnen ab', () => {
  it('Statusliste nicht erreichbar (Mock aus) -> status_list_unreachable', async () => {
    const uri = await closedPortUrl();
    await rejectsWithCode(() => checker().check(ref(uri, 0)), 'status_list_unreachable');
  });
  it('HTTP 503 -> status_list_unreachable', async () => {
    const uri = serve('/sl/503', 'weg', 503);
    await rejectsWithCode(() => checker().check(ref(uri, 0)), 'status_list_unreachable');
  });
  it('Zeitüberschreitung -> status_list_timeout', async () => {
    routes.set('/sl/slow', () => {
      /* antwortet nie */
    });
    await rejectsWithCode(() => checker({ timeoutMs: 100 }).check(ref(`${base}/sl/slow`, 0)), 'status_list_timeout');
  });
  it('größer als die Grenze -> status_list_too_large', async () => {
    const uri = serve('/sl/big', 'x'.repeat(4096));
    await rejectsWithCode(() => checker({ maxBytes: 1024 }).check(ref(uri, 0)), 'status_list_too_large');
  });
  it('Unterzeichner nicht vertraut -> status_list_signature_invalid', async () => {
    const uri = await serveToken('/sl/stranger', { key: stranger });
    await rejectsWithCode(() => checker().check(ref(uri, 0)), 'status_list_signature_invalid');
  });
  it('vertrautes x5c, aber fremder Schlüssel signiert -> status_list_signature_invalid', async () => {
    const uri = await serveToken('/sl/forged', { key: stranger, x5cKey: signer });
    await rejectsWithCode(() => checker().check(ref(uri, 0)), 'status_list_signature_invalid');
  });
  it('leere Unterzeichnerliste -> status_list_signature_invalid', async () => {
    const uri = await serveToken('/sl/values');
    await rejectsWithCode(() => checker({ trustedSigners: () => [] }).check(ref(uri, 0)), 'status_list_signature_invalid');
  });
  it('falscher typ -> status_list_malformed', async () => {
    const uri = await serveToken('/sl/typ', { typ: 'JWT' });
    await rejectsWithCode(() => checker().check(ref(uri, 0)), 'status_list_malformed');
  });
  it('kein JWT -> status_list_malformed', async () => {
    const uri = serve('/sl/garbage', 'kein token');
    await rejectsWithCode(() => checker().check(ref(uri, 0)), 'status_list_malformed');
  });
  it('sub passt nicht zur URI -> status_list_malformed', async () => {
    const uri = await serveToken('/sl/sub', { sub: 'https://anderer.example/sl' });
    await rejectsWithCode(() => checker().check(ref(uri, 0)), 'status_list_malformed');
  });
  it('ohne exp -> status_list_malformed', async () => {
    const uri = await serveToken('/sl/noexp', { exp: null });
    await rejectsWithCode(() => checker().check(ref(uri, 0)), 'status_list_malformed');
  });
  it('unzulässige bits -> status_list_malformed', async () => {
    const uri = await serveToken('/sl/bits3', { bits: 3 as 1 });
    await rejectsWithCode(() => checker().check(ref(uri, 0)), 'status_list_malformed');
  });
  it('lst nicht entpackbar -> status_list_malformed', async () => {
    const uri = await serveToken('/sl/lst', { lst: Buffer.from('kein deflate').toString('base64url') });
    await rejectsWithCode(() => checker().check(ref(uri, 0)), 'status_list_malformed');
  });
  it('abgelaufene Liste -> status_list_expired', async () => {
    const now = Math.floor(Date.now() / 1000);
    const uri = await serveToken('/sl/expired', { iat: now - 7200, exp: now - 3600 });
    await rejectsWithCode(() => checker().check(ref(uri, 0)), 'status_list_expired');
  });
  it('Liste aus der Zukunft (iat) -> status_list_expired', async () => {
    const now = Math.floor(Date.now() / 1000);
    const uri = await serveToken('/sl/future', { iat: now + 3600, exp: now + 7200 });
    await rejectsWithCode(() => checker().check(ref(uri, 0)), 'status_list_expired');
  });
  it('Credential ohne Statusverweis -> credential_status_missing', async () => {
    await rejectsWithCode(() => checker().check({}), 'credential_status_missing');
  });
  it('Index außerhalb der Liste -> credential_status_reference_invalid', async () => {
    const uri = await serveToken('/sl/values');
    await rejectsWithCode(() => checker().check(ref(uri, 10_000)), 'credential_status_reference_invalid');
  });
  it('ungültiger Index / ungültige URI -> credential_status_reference_invalid', async () => {
    await rejectsWithCode(() => checker().check(ref('https://x.example/sl', -1)), 'credential_status_reference_invalid');
    await rejectsWithCode(() => checker().check(ref('ftp://x.example/sl', 0)), 'credential_status_reference_invalid');
    await rejectsWithCode(() => checker().check({ status: 'kaputt' }), 'credential_status_reference_invalid');
  });
  it('http-URI ohne ausdrückliche Freigabe -> credential_status_reference_invalid', async () => {
    const uri = await serveToken('/sl/values');
    await rejectsWithCode(() => checker({ allowInsecureHttp: false }).check(ref(uri, 0)), 'credential_status_reference_invalid');
  });
});

describe('NO_CREDENTIAL_STATUS nur mit Entwicklungsschalter', () => {
  it('Entwicklungsschalter aktiv -> erlaubt (Gegenprobe)', () => {
    assertCredentialStatusAllowed(NO_CREDENTIAL_STATUS, DEV);
  });
  it('ohne Entwicklungsschalter, in Produktion, ohne Modus -> ConfigError', () => {
    assert.throws(() => assertCredentialStatusAllowed(NO_CREDENTIAL_STATUS, NO_DEV), ConfigError);
    assert.throws(() => assertCredentialStatusAllowed(NO_CREDENTIAL_STATUS, PROD), ConfigError);
    assert.throws(() => assertCredentialStatusAllowed(NO_CREDENTIAL_STATUS), ConfigError);
  });
  it('gar keine Statusprüfung konfiguriert -> ConfigError, auch mit Entwicklungsschalter', () => {
    assert.throws(() => assertCredentialStatusAllowed(undefined, DEV), ConfigError);
  });
  it('echter Checker in Produktion -> erlaubt', () => {
    assertCredentialStatusAllowed(checker(), PROD);
  });
});

describe('Dienst: Statusprüfung im Präsentationspfad', () => {
  async function harness(credentialStatus: CredentialStatusChecker, mode = NO_DEV) {
    const tenants = new TenantStore();
    tenants.add({ id: 'tenant-s', name: 'Kunde S (TEST)', apiKey: 'test-api-key-status', requestProfile: { id: 'test-given-name', claims: ['given_name'] } });
    const verifier = await generateTestKeyMaterial('Status Verifier TEST');
    const issuer = await generateTestKeyMaterial('Status Issuer TEST');
    const holder = await generateTestKeyMaterial('Status Holder TEST');
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
      // Echter OCSP-Prüfer wie im Betrieb. Das TEST-Aussteller-Zertifikat ist
      // selbst der Anker, deshalb wird fuer dieses Zertifikat keine Sperrquelle
      // abgefragt; die Kette selbst wird trotzdem durchlaufen.
      { mode, credentialStatus, issuerRevocation: new OcspRevocationChecker({ allowInsecureHttp: true }) },
    );
    service.baseUrl = 'http://127.0.0.1:9';
    const present = async (extraClaims: Record<string, unknown>) => {
      const created = await service.createRequest('tenant-s', {});
      const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
      const built = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: String(payload.nonce), audience: String(payload.client_id), extraClaims });
      const outcome = await service.handlePresentation(created.state, { pid: [built.sdJwt] });
      return { outcome, result: service.getResult('tenant-s', created.sessionId) };
    };
    return { present };
  }

  it('Status gültig -> Präsentation gültig (Gegenprobe)', async () => {
    const uri = await serveToken('/svc/sl');
    const h = await harness(checker());
    const { outcome, result } = await h.present(ref(uri, 0));
    assert.equal(outcome.valid, true, JSON.stringify(outcome));
    assert.equal(result.status, 'completed');
  });

  it('Status gesperrt -> ungültig, kein Ergebnis', async () => {
    const uri = await serveToken('/svc/sl');
    const h = await harness(checker());
    const { outcome, result } = await h.present(ref(uri, 1));
    assert.deepEqual(outcome, { ok: true, valid: false, error: 'credential_revoked' });
    assert.notEqual(result.status, 'completed');
  });

  it('Pflichttest: Statusliste nicht erreichbar -> Ablehnung', async () => {
    const uri = await closedPortUrl();
    const h = await harness(checker());
    const { outcome, result } = await h.present(ref(uri, 0));
    assert.deepEqual(outcome, { ok: true, valid: false, error: 'status_list_unreachable' });
    assert.notEqual(result.status, 'completed');
  });

  it('Credential ohne Statusverweis -> credential_status_missing', async () => {
    const h = await harness(checker());
    const { outcome } = await h.present({});
    assert.deepEqual(outcome, { ok: true, valid: false, error: 'credential_status_missing' });
  });

  it('NO_CREDENTIAL_STATUS mit Entwicklungsschalter -> gültig ohne Statusverweis', async () => {
    const h = await harness(NO_CREDENTIAL_STATUS, DEV);
    const { outcome } = await h.present({});
    assert.equal(outcome.valid, true);
  });

  it('Dienstaufbau mit NO_CREDENTIAL_STATUS ohne Entwicklungsschalter bricht ab', async () => {
    await assert.rejects(() => harness(NO_CREDENTIAL_STATUS, PROD), ConfigError);
    await assert.rejects(() => harness(NO_CREDENTIAL_STATUS, NO_DEV), ConfigError);
  });
});
