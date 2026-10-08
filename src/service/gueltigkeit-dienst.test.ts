/**
 * Härtung 9 (Teil d): dieselbe Lücke an den übrigen Stellen.
 *
 * Die Prüfbibliothek prüft auf dem genutzten Pfad (`trustedCertificates`)
 * den Gültigkeitszeitraum weder beim Aussteller- noch beim
 * Verifier-Zertifikat (nachgestellt 2026-09-24). Geprüft wird deshalb im
 * Dienst:
 *   - Verifier-Identität: beim Start und bei jeder Prüfanfrage
 *   - Aussteller-Zertifikate (x5c) der vorgelegten Credentials
 *   - Aussteller-Vertrauensanker: beim Start und zur Laufzeit
 *   - Signaturzertifikat der Statusliste
 *   - Konfiguration ATTACK_CLOCK_SKEW_SECONDS
 * Jeweils mit Gegenprobe; Zeitpunkte über injizierte Uhren.
 */
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deflateSync } from 'node:zlib';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';
import { X509Certificate } from '@peculiar/x509';
import { createLocalJWKSet, jwtVerify, SignJWT } from 'jose';

import {
  ConfigError,
  ENV_ATTACK_CLOCK_SKEW_SECONDS,
  ENV_ATTACK_DEV_MODE,
  ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM,
  ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM,
  ENV_ATTACK_VERIFIER_KEY_PEM,
  loadConfig,
} from '../config.ts';
import { buildSdJwtVc, generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { createApp } from './app.ts';
import { AuditLog } from './audit.ts';
import { bootstrapService } from './bootstrap.ts';
import { CredentialStatusError, STATUS_LIST_JWT_TYPE, TokenStatusListChecker } from './credential-status.ts';
import { resolveIssuerAnchors } from './issuer-anchors.ts';
import { VerifierCertificateError, VerifierService } from './service.ts';
import { TenantStore } from './tenant.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';
import { resolveVerifierIdentity } from './verifier-identity.ts';

const DAY = 86_400_000;
const DOCUMENTED = new Set([...(await import('node:fs')).readFileSync(new URL('../../docs/fehlercodes.md', import.meta.url), 'utf8').matchAll(/`([a-z][a-z0-9_]*)`/g)].map((m) => m[1]));

let tmpDir!: string;
let valid!: TestKeyMaterial;
let expired!: TestKeyMaterial;
let notYet!: TestKeyMaterial;
let holder!: TestKeyMaterial;
/** Verifier mit langer Laufzeit, damit bei vorgestellter Uhr nur das geprüfte Zertifikat entscheidet. */
let longVerifier!: TestKeyMaterial;

const at = (base: Date, offsetMs: number) => new Date(base.getTime() + offsetMs);
const certOf = (m: TestKeyMaterial) => new X509Certificate(Uint8Array.from(m.certDerBytes));

function derToPem(der: Uint8Array, label: string): string {
  const lines = Buffer.from(der).toString('base64').match(/.{1,64}/g)?.join('\n') ?? '';
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

async function identityEnv(m: TestKeyMaterial, name: string): Promise<Record<string, string>> {
  await writeFile(join(tmpDir, `${name}-key.pem`), derToPem(new Uint8Array(await crypto.subtle.exportKey('pkcs8', m.privateKey)), 'PRIVATE KEY'));
  await writeFile(join(tmpDir, `${name}-chain.pem`), derToPem(m.certDerBytes, 'CERTIFICATE'));
  return { [ENV_ATTACK_VERIFIER_KEY_PEM]: join(tmpDir, `${name}-key.pem`), [ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]: join(tmpDir, `${name}-chain.pem`) };
}

async function anchorFile(m: TestKeyMaterial, name: string): Promise<string> {
  const path = join(tmpDir, `${name}-anchor.pem`);
  await writeFile(path, derToPem(m.certDerBytes, 'CERTIFICATE'));
  return path;
}

beforeAll(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'attack-gueltigkeit-'));
  const now = Date.now();
  valid = await generateTestKeyMaterial('Gueltig', { notBefore: new Date(now - DAY), notAfter: new Date(now + 30 * DAY) });
  expired = await generateTestKeyMaterial('Abgelaufen', { notBefore: new Date(now - 10 * DAY), notAfter: new Date(now - DAY) });
  notYet = await generateTestKeyMaterial('Zukunft', { notBefore: new Date(now + DAY), notAfter: new Date(now + 10 * DAY) });
  holder = await generateTestKeyMaterial('Holder');
  longVerifier = await generateTestKeyMaterial('Verifier lang', { notBefore: new Date(now - DAY), notAfter: new Date(now + 365 * DAY) });
});

afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
describe('Konfiguration ATTACK_CLOCK_SKEW_SECONDS', () => {
  it('Standard 60, gültige Werte 0 und 300', () => {
    assert.equal(loadConfig({}).clockSkewSeconds, 60);
    assert.equal(loadConfig({ [ENV_ATTACK_CLOCK_SKEW_SECONDS]: '0' }).clockSkewSeconds, 0);
    assert.equal(loadConfig({ [ENV_ATTACK_CLOCK_SKEW_SECONDS]: '300' }).clockSkewSeconds, 300);
  });
  it('ungültige Werte brechen ab', () => {
    for (const bad of ['-1', '301', 'abc', '1.5']) assert.throws(() => loadConfig({ [ENV_ATTACK_CLOCK_SKEW_SECONDS]: bad }), ConfigError, bad);
  });
});

// ---------------------------------------------------------------------------
describe('Verifier-Identität beim Start', () => {
  const config = (skew = 60) => ({ ...loadConfig({}), clockSkewSeconds: skew });
  const testFactory = async () => ({ privateKey: valid.privateKey, publicKey: valid.publicKey, publicJwk: valid.publicJwk, certificateChain: [valid.certDerBytes] });

  it('gültige PEM-Identität -> Start (Gegenprobe)', async () => {
    const r = await resolveVerifierIdentity(config(), testFactory, await identityEnv(valid, 'v-ok'));
    assert.equal(r.usedTestFallback, false);
  });
  it('abgelaufene PEM-Identität -> ConfigError mit Code, ohne Schlüsselinhalt', async () => {
    const env = await identityEnv(expired, 'v-exp');
    await assert.rejects(
      () => resolveVerifierIdentity(config(), testFactory, env),
      (e: unknown) => e instanceof ConfigError && /certificate_expired/.test(e.message) && !/BEGIN|PRIVATE/.test(e.message),
    );
  });
  it('noch nicht gültige PEM-Identität -> ConfigError certificate_not_yet_valid', async () => {
    const env = await identityEnv(notYet, 'v-future');
    await assert.rejects(() => resolveVerifierIdentity(config(), testFactory, env), (e: unknown) => e instanceof ConfigError && /certificate_not_yet_valid/.test(e.message));
  });
  it('Grenzen mit injizierter Uhr: notAfter + 60 s Start, + 61 s Abbruch', async () => {
    const env = await identityEnv(valid, 'v-grenze');
    const notAfter = certOf(valid).notAfter;
    await resolveVerifierIdentity(config(), testFactory, env, () => at(notAfter, 60_000));
    await assert.rejects(() => resolveVerifierIdentity(config(), testFactory, env, () => at(notAfter, 61_000)), ConfigError);
  });
  it('auch Testmaterial mit Entwicklungsschalter wird geprüft', async () => {
    const devConfig = { ...config(), devMode: true };
    const expiredFactory = async () => ({ privateKey: expired.privateKey, publicKey: expired.publicKey, publicJwk: expired.publicJwk, certificateChain: [expired.certDerBytes] });
    await assert.rejects(() => resolveVerifierIdentity(devConfig, expiredFactory, {}), ConfigError);
  });
  it('bootstrapService bricht mit abgelaufener Identität ab', async () => {
    const env = { ...(await identityEnv(expired, 'v-boot')), [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: await anchorFile(valid, 'boot') };
    await assert.rejects(() => bootstrapService(env, () => undefined), ConfigError);
  });
  it('bootstrapService übernimmt ATTACK_CLOCK_SKEW_SECONDS', async () => {
    const boot = await bootstrapService({ [ENV_ATTACK_DEV_MODE]: 'true', [ENV_ATTACK_CLOCK_SKEW_SECONDS]: '5' }, () => undefined);
    assert.equal(boot.config.clockSkewSeconds, 5);
  });
});

// ---------------------------------------------------------------------------
describe('Aussteller-Vertrauensanker beim Start', () => {
  const cfg = { devMode: false, isProduction: true, clockSkewSeconds: 60 };
  it('gültiger Anker -> geladen (Gegenprobe)', async () => {
    const r = await resolveIssuerAnchors(cfg, async () => new Uint8Array(), { [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: await anchorFile(valid, 'a-ok') });
    assert.equal(r.anchors.length, 1);
  });
  it('abgelaufener / noch nicht gültiger Anker -> ConfigError', async () => {
    await assert.rejects(
      async () => resolveIssuerAnchors(cfg, async () => new Uint8Array(), { [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: await anchorFile(expired, 'a-exp') }),
      (e: unknown) => e instanceof ConfigError && /certificate_expired/.test(e.message),
    );
    await assert.rejects(
      async () => resolveIssuerAnchors(cfg, async () => new Uint8Array(), { [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: await anchorFile(notYet, 'a-fut') }),
      (e: unknown) => e instanceof ConfigError && /certificate_not_yet_valid/.test(e.message),
    );
  });
  it('Grenze mit injizierter Uhr', async () => {
    const file = await anchorFile(valid, 'a-grenze');
    const notAfter = certOf(valid).notAfter;
    await resolveIssuerAnchors(cfg, async () => new Uint8Array(), { [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: file }, () => at(notAfter, 60_000));
    await assert.rejects(() => resolveIssuerAnchors(cfg, async () => new Uint8Array(), { [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: file }, () => at(notAfter, 61_000)), ConfigError);
  });
});

// ---------------------------------------------------------------------------
interface Harness {
  service: VerifierService;
  audit: AuditLog;
  clock: { now: number };
  present(issuer: TestKeyMaterial, extraX5c?: string[]): Promise<{ state: string; outcome: { ok: boolean; valid: boolean; error?: string } }>;
}

function harness(verifier: TestKeyMaterial, anchors: () => readonly Uint8Array[], clockStart = Date.now()): Harness {
  const tenants = new TenantStore();
  tenants.add({ id: 'tenant-z', name: 'Zeit (TEST)', apiKey: 'test-api-key-zeit-dienst', requestProfile: { id: 'test-given-name', claims: ['given_name'] } });
  const clock = { now: clockStart };
  const audit = new AuditLog();
  const service = new VerifierService(
    tenants,
    audit,
    { privateKey: verifier.privateKey, publicKey: verifier.publicKey, publicJwk: verifier.publicJwk, certificateChain: [verifier.certDerBytes] },
    anchors,
    undefined,
    undefined,
    undefined,
    undefined,
    true,
    { ...DEV_TEST_OPTIONS, now: () => clock.now, resultTtlMs: 10 * 365 * DAY },
  );
  service.baseUrl = 'http://127.0.0.1:9';
  return {
    service,
    audit,
    clock,
    present: async (issuer, extraX5c) => {
      const created = await service.createRequest('tenant-z', {});
      const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
      const built = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: String(payload.nonce), audience: String(payload.client_id), extraX5c, kbIat: Math.floor(clock.now / 1000) });
      return { state: created.state, outcome: await service.handlePresentation(created.state, { pid: [built.sdJwt] }) };
    },
  };
}

describe('Verifier-Zertifikat zur Laufzeit', () => {
  it('Zertifikat läuft während des Betriebs ab: + 60 s noch Anfrage, + 61 s VerifierCertificateError', async () => {
    const h = harness(valid, () => [valid.certDerBytes]);
    const notAfter = certOf(valid).notAfter.getTime();
    h.clock.now = notAfter + 60_000;
    await h.service.createRequest('tenant-z', {});
    h.clock.now = notAfter + 61_000;
    await assert.rejects(() => h.service.createRequest('tenant-z', {}), (e: unknown) => e instanceof VerifierCertificateError && e.code === 'certificate_expired');
    assert.ok(h.audit.list().some((e) => e.event === 'request_rejected' && e.detail === 'reason=verifier_certificate_expired'));
  });
  it('über HTTP: 500 internal_error ohne Details', async () => {
    const tenants = new TenantStore();
    tenants.add({ id: 'tenant-z', name: 'Zeit (TEST)', apiKey: 'test-api-key-zeit-http' });
    const service = new VerifierService(
      tenants,
      new AuditLog(),
      { privateKey: expired.privateKey, publicKey: expired.publicKey, publicJwk: expired.publicJwk, certificateChain: [expired.certDerBytes] },
      [valid.certDerBytes],
      undefined,
      undefined,
      undefined,
      undefined,
      true,
      DEV_TEST_OPTIONS,
    );
    const app = createApp({ appLabel: 'zeit', tenants, service });
    const originalError = console.error;
    console.error = () => undefined;
    try {
      await new Promise<void>((resolve) => app.listen(0, '127.0.0.1', resolve));
      service.baseUrl = `http://127.0.0.1:${(app.address() as { port: number }).port}`;
      const res = await fetch(`${service.baseUrl}/v1/verification-requests`, { method: 'POST', headers: { authorization: 'Bearer test-api-key-zeit-http' }, body: '{}' });
      assert.equal(res.status, 500);
      assert.deepEqual(await res.json(), { error: 'internal_error' });
    } finally {
      console.error = originalError;
      app.closeAllConnections();
      await new Promise<void>((resolve) => app.close(() => resolve()));
    }
  });
});

describe('Aussteller-Zertifikate der Credentials', () => {
  it('gültiger Aussteller -> gültig (Gegenprobe)', async () => {
    const h = harness(longVerifier, () => [valid.certDerBytes]);
    assert.equal((await h.present(valid)).outcome.valid, true);
  });
  it('Aussteller-Zertifikat abgelaufen (Anker = Aussteller) -> certificate_expired', async () => {
    const h = harness(longVerifier, () => [expired.certDerBytes]);
    const { outcome } = await h.present(expired);
    assert.deepEqual(outcome, { ok: true, valid: false, error: 'certificate_expired' });
  });
  it('Aussteller-Zertifikat noch nicht gültig -> certificate_not_yet_valid', async () => {
    const h = harness(longVerifier, () => [notYet.certDerBytes]);
    assert.equal((await h.present(notYet)).outcome.error, 'certificate_not_yet_valid');
  });
  it('abgelaufenes weiteres Zertifikat im x5c (Kette) -> certificate_expired, obwohl die Bibliothek gültig meldet', async () => {
    const h = harness(longVerifier, () => [valid.certDerBytes]);
    assert.equal((await h.present(valid, [expired.x5cBase64])).outcome.error, 'certificate_expired');
    assert.equal((await h.present(valid, [valid.x5cBase64])).outcome.valid, true, 'Gegenprobe: gültiges weiteres Zertifikat');
  });
  it('Anker läuft zur Laufzeit ab: + 60 s gültig, + 61 s certificate_expired', async () => {
    const notAfter = certOf(valid).notAfter.getTime();
    const h = harness(longVerifier, () => [valid.certDerBytes], notAfter + 60_000);
    assert.equal((await h.present(valid)).outcome.valid, true);
    h.clock.now = notAfter + 61_000;
    assert.equal((await h.present(valid)).outcome.error, 'certificate_expired');
  });
  it('ein abgelaufener und ein gültiger Anker: der gültige trägt weiter (Gegenprobe)', async () => {
    const h = harness(longVerifier, () => [expired.certDerBytes, valid.certDerBytes]);
    assert.equal((await h.present(valid)).outcome.valid, true);
  });
});

// ---------------------------------------------------------------------------
describe('Signaturzertifikat der Statusliste', () => {
  const uri = 'https://status.example/lists/1';
  async function token(signer: TestKeyMaterial): Promise<string> {
    const s = Math.floor(Date.now() / 1000);
    return new SignJWT({ sub: uri, iat: s - 10, exp: s + 3600, status_list: { bits: 1, lst: deflateSync(Buffer.from([0])).toString('base64url') } })
      .setProtectedHeader({ alg: 'ES256', typ: STATUS_LIST_JWT_TYPE, x5c: [signer.x5cBase64] })
      .sign(signer.privateKey);
  }
  function checker(signer: TestKeyMaterial, raw: string, now = () => Date.now()) {
    return new TokenStatusListChecker({
      trustedSigners: () => [signer.certDerBytes],
      fetchImpl: async () => new Response(raw, { status: 200 }),
      now,
    });
  }
  const ref = { status: { status_list: { idx: 0, uri } } };

  it('gültiger Unterzeichner -> gültig (Gegenprobe)', async () => {
    await checker(valid, await token(valid)).check(ref);
  });
  it('abgelaufener / noch nicht gültiger Unterzeichner -> eigener Code', async () => {
    for (const [signer, code] of [[expired, 'certificate_expired'], [notYet, 'certificate_not_yet_valid']] as const) {
      const raw = await token(signer);
      await assert.rejects(() => checker(signer, raw).check(ref), (e: unknown) => e instanceof CredentialStatusError && e.code === code);
    }
  });
  it('Grenze mit injizierter Uhr (Signaturzertifikat, Liste selbst noch gültig)', async () => {
    const notAfter = certOf(valid).notAfter.getTime();
    // Liste mit langer Laufzeit, damit nur das Zertifikat entscheidet.
    const s = Math.floor(notAfter / 1000);
    const longRaw = await new SignJWT({ sub: uri, iat: s - 10, exp: s + 3600, status_list: { bits: 1, lst: deflateSync(Buffer.from([0])).toString('base64url') } })
      .setProtectedHeader({ alg: 'ES256', typ: STATUS_LIST_JWT_TYPE, x5c: [valid.x5cBase64] })
      .sign(valid.privateKey);
    await checker(valid, longRaw, () => notAfter + 60_000).check(ref);
    await assert.rejects(() => checker(valid, longRaw, () => notAfter + 61_000).check(ref), (e: unknown) => e instanceof CredentialStatusError && e.code === 'certificate_expired');
  });
});

describe('Fehlercodes dokumentiert', () => {
  it('certificate_expired und certificate_not_yet_valid stehen in docs/fehlercodes.md', () => {
    assert.ok(DOCUMENTED.has('certificate_expired'));
    assert.ok(DOCUMENTED.has('certificate_not_yet_valid'));
  });
});
