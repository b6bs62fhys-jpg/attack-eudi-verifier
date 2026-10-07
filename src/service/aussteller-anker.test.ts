/**
 * Härtung 5: Vertrauensanker der Credential-Aussteller.
 *
 *   - TEST-Anker nur mit aktivem Entwicklungsschalter (Dienst und Demo)
 *   - Produktionsmodus ohne konfigurierte Anker: Start bricht ab
 *   - leere Ankerliste zur Laufzeit: jede Prüfung abgelehnt
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { BasicConstraintsExtension, X509Certificate, X509CertificateGenerator } from '@peculiar/x509';

import {
  ConfigError,
  ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM,
  ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM,
  ENV_ATTACK_VERIFIER_KEY_PEM,
  ENV_NODE_ENV,
} from '../config.ts';
import { buildSdJwtVc, generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { createWrprcIssuer, createWrprcLeaf } from '../onboarding/mock-pki.ts';
import { AuditLog } from './audit.ts';
import { bootstrapService } from './bootstrap.ts';
import { resolveIssuerAnchors } from './issuer-anchors.ts';
import { VerifierService } from './service.ts';
import { TenantStore } from './tenant.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';

const DEV = { devMode: true, isProduction: false };
const NO_DEV = { devMode: false, isProduction: false };
const PROD = { devMode: false, isProduction: true };

let tmpDir!: string;
let issuer!: TestKeyMaterial;
let other!: TestKeyMaterial;
let verifier!: TestKeyMaterial;
let holder!: TestKeyMaterial;
let identityEnv!: Record<string, string>;
const testFactory = async () => new Uint8Array([0xde, 0xad]);

function derToPem(der: Uint8Array, label: string): string {
  const lines = Buffer.from(der).toString('base64').match(/.{1,64}/g)?.join('\n') ?? '';
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

beforeAll(async () => {
  issuer = await generateTestKeyMaterial('Anker Issuer TEST');
  other = await generateTestKeyMaterial('Anker Anderer TEST');
  verifier = await generateTestKeyMaterial('Anker Verifier TEST');
  holder = await generateTestKeyMaterial('Anker Holder TEST');
  tmpDir = await mkdtemp(join(tmpdir(), 'attack-anker-test-'));
  await writeFile(join(tmpDir, 'one.pem'), derToPem(issuer.certDerBytes, 'CERTIFICATE'));
  await writeFile(join(tmpDir, 'two.pem'), derToPem(issuer.certDerBytes, 'CERTIFICATE') + derToPem(other.certDerBytes, 'CERTIFICATE'));
  await writeFile(join(tmpDir, 'empty.pem'), '# keine Zertifikate\n');
  await writeFile(join(tmpDir, 'broken.pem'), '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n');
  await writeFile(join(tmpDir, 'key.pem'), derToPem(new Uint8Array(await crypto.subtle.exportKey('pkcs8', verifier.privateKey)), 'PRIVATE KEY'));
  await writeFile(join(tmpDir, 'chain.pem'), derToPem(verifier.certDerBytes, 'CERTIFICATE'));
  identityEnv = {
    ATTACK_PUBLIC_BASE_URL: 'https://verifier.example',
    [ENV_ATTACK_VERIFIER_KEY_PEM]: join(tmpDir, 'key.pem'),
    [ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]: join(tmpDir, 'chain.pem'),
  };
});

afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

describe('resolveIssuerAnchors', () => {
  it('konfigurierte Anker werden geladen (ein und mehrere Zertifikate)', async () => {
    const one = await resolveIssuerAnchors(PROD, testFactory, { [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: join(tmpDir, 'one.pem') });
    assert.equal(one.anchors.length, 1);
    assert.equal(one.usedTestAnchor, false);
    assert.deepEqual(one.anchors[0], issuer.certDerBytes);
    const two = await resolveIssuerAnchors(PROD, testFactory, { [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: join(tmpDir, 'two.pem') });
    assert.equal(two.anchors.length, 2);
  });

  it('TEST-Anker nur mit Entwicklungsschalter', async () => {
    const dev = await resolveIssuerAnchors(DEV, testFactory, {});
    assert.equal(dev.usedTestAnchor, true);
    await assert.rejects(() => resolveIssuerAnchors(NO_DEV, testFactory, {}), ConfigError);
  });

  it('Produktionsmodus ohne konfigurierte Anker -> Abbruch', async () => {
    await assert.rejects(() => resolveIssuerAnchors(PROD, testFactory, {}), (e: unknown) => e instanceof ConfigError && /Produktionsmodus/.test(e.message));
  });

  it('konfigurierte Anker haben Vorrang vor TEST-Material, auch mit Entwicklungsschalter', async () => {
    const r = await resolveIssuerAnchors(DEV, testFactory, { [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: join(tmpDir, 'one.pem') });
    assert.equal(r.usedTestAnchor, false);
  });

  it('unlesbar, leer oder kaputt -> Abbruch ohne Zertifikatsinhalt in der Meldung', async () => {
    for (const file of ['fehlt.pem', 'empty.pem', 'broken.pem']) {
      await assert.rejects(
        () => resolveIssuerAnchors(PROD, testFactory, { [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: join(tmpDir, file) }),
        (e: unknown) => e instanceof ConfigError && !e.message.includes('BEGIN') && !e.message.includes('AAAA'),
        file,
      );
    }
  });
});

describe('bootstrapService: Anker im Produktionsmodus', () => {
  it('Produktion mit Identität, aber ohne Anker -> Start bricht ab', async () => {
    await assert.rejects(() => bootstrapService({ [ENV_NODE_ENV]: 'production', ...identityEnv }, () => undefined), ConfigError);
  });
  it('Produktion mit Identität und Ankern -> Start (Gegenprobe)', async () => {
    const boot = await bootstrapService({ [ENV_NODE_ENV]: 'production', ...identityEnv, [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: join(tmpDir, 'one.pem') }, () => undefined);
    assert.equal(boot.usedTestAnchor, false);
    assert.deepEqual(boot.issuerAnchors, [issuer.certDerBytes]);
  });
});

describe('Leere Ankerliste zur Laufzeit', () => {
  function build(anchors: () => readonly Uint8Array[]) {
    const tenants = new TenantStore();
    tenants.add({ id: 'tenant-a', name: 'Kunde A (TEST)', apiKey: 'test-api-key-anker-A', requestProfile: { id: 'test-given-name', claims: ['given_name'] } });
    const service = new VerifierService(
      tenants,
      new AuditLog(),
      { privateKey: verifier.privateKey, publicKey: verifier.publicKey, publicJwk: verifier.publicJwk, certificateChain: [verifier.certDerBytes] },
      anchors,
      undefined,
      undefined,
      undefined,
      undefined,
      true,
      DEV_TEST_OPTIONS,
    );
    service.baseUrl = 'http://127.0.0.1:9';
    return service;
  }

  async function presentation(service: VerifierService, issuerKey: TestKeyMaterial = issuer) {
    const created = await service.createRequest('tenant-a', {});
    const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
    const built = await buildSdJwtVc({ issuerKey, holderKey: holder, nonce: String(payload.nonce), audience: String(payload.client_id) });
    return { state: created.state, vpToken: { pid: [built.sdJwt] } };
  }

  it('Anker vorhanden -> gültig (Gegenprobe)', async () => {
    const service = build(() => [issuer.certDerBytes]);
    const p = await presentation(service);
    assert.equal((await service.handlePresentation(p.state, p.vpToken)).valid, true);
  });

  it('erkennt ein vom konfigurierten Root signiertes Blatt über den Trust Store', async () => {
    const ca = await createWrprcIssuer('Anker Credential Root TEST');
    const caLeaf = await createWrprcLeaf(ca, 'Anker Credential Leaf TEST');
    const caSignedIssuer: TestKeyMaterial = {
      privateKey: caLeaf.key.privateKey,
      publicKey: caLeaf.key.publicKey,
      publicJwk: (await crypto.subtle.exportKey('jwk', caLeaf.key.publicKey)) as JsonWebKey,
      x5cBase64: Buffer.from(caLeaf.certDer).toString('base64'),
      certDerBytes: caLeaf.certDer,
    };
    assert.notEqual(Buffer.compare(Buffer.from(caSignedIssuer.certDerBytes), Buffer.from(ca.certDer)), 0);
    const service = build(() => [ca.certDer]);
    const p = await presentation(service, caSignedIssuer);
    assert.equal((await service.handlePresentation(p.state, p.vpToken)).valid, true);
  });

  it('lehnt ein vom konfigurierten Root signiertes, aber abgelaufenes Blatt ab (abgelaufenes Zertifikat)', async () => {
    const ca = await createWrprcIssuer('Anker Credential Root TEST');
    const key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const issuerCert = new X509Certificate(new Uint8Array(ca.certDer));
    const cert = await X509CertificateGenerator.create({
      serialNumber: crypto.randomUUID().replace(/-/g, ''),
      subject: 'CN=Abgelaufenes Blatt, C=DE',
      issuer: issuerCert.subject,
      notBefore: new Date(Date.now() - 600_000),
      notAfter: new Date(Date.now() - 120_000),
      publicKey: key.publicKey,
      signingKey: ca.key.privateKey,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      extensions: [new BasicConstraintsExtension(false)],
    });
    const expiredIssuer: TestKeyMaterial = {
      privateKey: key.privateKey,
      publicKey: key.publicKey,
      publicJwk: (await crypto.subtle.exportKey('jwk', key.publicKey)) as JsonWebKey,
      x5cBase64: Buffer.from(cert.rawData).toString('base64'),
      certDerBytes: new Uint8Array(cert.rawData),
    };
    const service = build(() => [ca.certDer]);
    const p = await presentation(service, expiredIssuer);
    const outcome = await service.handlePresentation(p.state, p.vpToken);
    assert.equal(outcome.valid, false);
    assert.ok(outcome.error === 'certificate_expired' || outcome.error === 'issuer_chain_invalid');
  });

  it('lehnt ein von einer fremden Root signiertes Blatt ab (nicht vertrauter Anker)', async () => {
    const ca = await createWrprcIssuer('Anker Credential Root TEST');
    const foreignCa = await createWrprcIssuer('Fremde Root TEST');
    const foreignLeaf = await createWrprcLeaf(foreignCa, 'Fremdes Blatt TEST');
    const foreignSignedIssuer: TestKeyMaterial = {
      privateKey: foreignLeaf.key.privateKey,
      publicKey: foreignLeaf.key.publicKey,
      publicJwk: (await crypto.subtle.exportKey('jwk', foreignLeaf.key.publicKey)) as JsonWebKey,
      x5cBase64: Buffer.from(foreignLeaf.certDer).toString('base64'),
      certDerBytes: foreignLeaf.certDer,
    };
    const service = build(() => [ca.certDer]);
    const p = await presentation(service, foreignSignedIssuer);
    const outcome = await service.handlePresentation(p.state, p.vpToken);
    assert.equal(outcome.valid, false);
  });

  it('leere Liste -> abgelehnt (issuer_trust_anchors_empty), Sitzung nicht verbraucht', async () => {
    let anchors: Uint8Array[] = [];
    const service = build(() => anchors);
    const p = await presentation(service);
    assert.deepEqual(await service.handlePresentation(p.state, p.vpToken), { ok: true, valid: false, error: 'issuer_trust_anchors_empty' });
    anchors = [issuer.certDerBytes];
    assert.equal((await service.handlePresentation(p.state, p.vpToken)).valid, true, 'nach Wiederherstellung der Anker gilt dieselbe Sitzung');
  });

  it('Liste wird zur Laufzeit leer -> jede weitere Prüfung abgelehnt', async () => {
    let anchors: Uint8Array[] = [issuer.certDerBytes];
    const service = build(() => anchors);
    const first = await presentation(service);
    assert.equal((await service.handlePresentation(first.state, first.vpToken)).valid, true);
    anchors = [];
    for (let i = 0; i < 3; i += 1) {
      const p = await presentation(service);
      assert.equal((await service.handlePresentation(p.state, p.vpToken)).error, 'issuer_trust_anchors_empty');
    }
  });

  it('statisch leere Liste -> abgelehnt', async () => {
    const service = build(() => []);
    const p = await presentation(service);
    assert.equal((await service.handlePresentation(p.state, p.vpToken)).valid, false);
  });

  it('Anker eines anderen Ausstellers -> ungültig', async () => {
    const service = build(() => [other.certDerBytes]);
    const p = await presentation(service);
    assert.equal((await service.handlePresentation(p.state, p.vpToken)).valid, false);
  });
});

describe('Demo nur mit Entwicklungsschalter', () => {
  it('ohne ATTACK_DEV_MODE (auch mit echter Identität) -> Exit 1, klare Meldung', async () => {
    const r = await new Promise<{ code: number | null; stderr: string }>((resolve) => {
      const child = spawn(process.execPath, ['--experimental-strip-types', 'src/demo/demo.ts'], {
        cwd: process.cwd(),
        env: { PATH: process.env.PATH ?? '', ...identityEnv },
        stdio: ['ignore', 'ignore', 'pipe'],
      });
      let stderr = '';
      child.stderr.on('data', (d) => (stderr += d));
      child.on('exit', (code) => resolve({ code, stderr }));
    });
    assert.equal(r.code, 1);
    assert.match(r.stderr, /ATTACK_DEV_MODE=true/);
    assert.doesNotMatch(r.stderr, /\n\s+at\s/);
  });
});
