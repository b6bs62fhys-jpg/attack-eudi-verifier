/**
 * Tests für die Verifier-Identität (src/service/verifier-identity.ts).
 *
 * Fail-closed ist Absicht:
 *   - Ohne echte PEM-Werte und ohne Entwicklungsschalter bricht der Start ab.
 *   - Testmaterial ist NUR mit ATTACK_DEV_MODE=true außerhalb von Produktion
 *     erlaubt; der Fallback muss dabei lauter Test-Ursprung melden.
 *   - Fehlermeldungen enthalten niemals Schlüssel- oder Zertifikatsinhalt.
 */
import 'reflect-metadata';

import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, it } from 'vitest';

import { ConfigError, ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM, ENV_ATTACK_VERIFIER_KEY_PEM } from '../config.ts';
import { generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { loadVerifierIdentity, resolveVerifierIdentity } from './verifier-identity.ts';
import type { ServiceKeys } from './service.ts';

function derToPem(der: Uint8Array, label: string): string {
  const b64 = Buffer.from(der).toString('base64');
  const lines = b64.match(/.{1,64}/g)?.join('\n') ?? b64;
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

async function exportKeyPem(privateKey: CryptoKey): Promise<string> {
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
  return derToPem(new Uint8Array(pkcs8), 'PRIVATE KEY');
}

let tmpDir: string;
let realKeys: ServiceKeys;
let keyPem: string;
let chainPem: string;

beforeAll(async () => {
  const mk = await generateTestKeyMaterial('Identity TEST');
  realKeys = {
    privateKey: mk.privateKey,
    publicKey: mk.publicKey,
    publicJwk: mk.publicJwk,
    certificateChain: [mk.certDerBytes],
  };
  keyPem = await exportKeyPem(mk.privateKey);
  chainPem = derToPem(mk.certDerBytes, 'CERTIFICATE');
  tmpDir = await mkdtemp(join(tmpdir(), 'attack-identity-test-'));
  await writeFile(join(tmpDir, 'key.pem'), keyPem);
  await writeFile(join(tmpDir, 'chain.pem'), chainPem);
});

afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

// Die Identitätsauflösung braucht keine Ratenbegrenzung, AppConfig verlangt sie
// aber. Einmal zentral gesetzt, damit die drei Varianten nicht auseinanderlaufen.
const RATE_LIMITS = { publicPerWindow: 120, tenantPerWindow: 60, windowSeconds: 60 };
const devConfig = { isProduction: false, devMode: true, allowSelfSignedCertificate: true, nodeEnv: 'development', port: 8080, resultTtlSeconds: 60, clockSkewSeconds: 60, rateLimits: RATE_LIMITS };
const staleConfig = { isProduction: false, devMode: false, allowSelfSignedCertificate: false, nodeEnv: 'development', port: 8080, resultTtlSeconds: 60, clockSkewSeconds: 60, rateLimits: RATE_LIMITS };
const prodConfig = { isProduction: true, devMode: false, allowSelfSignedCertificate: false, nodeEnv: 'production', port: 8080, resultTtlSeconds: 60, clockSkewSeconds: 60, rateLimits: RATE_LIMITS };

const testKeysFactory = async (): Promise<ServiceKeys> => realKeys;

describe('loadVerifierIdentity – echte PEM-Werte', () => {
  it('lädt aus PEM-Dateien eine echte Identität', async () => {
    const keys = await loadVerifierIdentity({
      [ENV_ATTACK_VERIFIER_KEY_PEM]: join(tmpDir, 'key.pem'),
      [ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]: join(tmpDir, 'chain.pem'),
    });
    assert.ok(keys.privateKey);
    assert.equal(keys.certificateChain.length, 1);
  });

  it('bricht ab, wenn nur eine der beiden Variablen gesetzt ist', async () => {
    await assert.rejects(
      loadVerifierIdentity({ [ENV_ATTACK_VERIFIER_KEY_PEM]: join(tmpDir, 'key.pem') }),
      /beide oder keine/,
    );
    await assert.rejects(
      loadVerifierIdentity({ [ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]: join(tmpDir, 'chain.pem') }),
      /beide oder keine/,
    );
  });

  it('bricht mit klarer Meldung ab, wenn die Datei nicht lesbar ist', async () => {
    await assert.rejects(
      loadVerifierIdentity({
        [ENV_ATTACK_VERIFIER_KEY_PEM]: join(tmpDir, 'missing.pem'),
        [ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]: join(tmpDir, 'chain.pem'),
      }),
      /nicht lesbar/,
    );
  });

  it('gibt bei unbrauchbarem PEM keine Schlüssel-/Zertifikatsinhalte in der Meldung aus', async () => {
    await writeFile(join(tmpDir, 'bad-key.pem'), '-----BEGIN PRIVATE KEY-----\nQUJDREVGR0g=\n-----END PRIVATE KEY-----\n');
    await assert.rejects(
      loadVerifierIdentity({
        [ENV_ATTACK_VERIFIER_KEY_PEM]: join(tmpDir, 'bad-key.pem'),
        [ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]: join(tmpDir, 'chain.pem'),
      }),
      (e: unknown) => {
        const msg = e instanceof Error ? e.message : String(e);
        assert.match(msg, /Private-Key unbrauchbar/);
        assert.ok(!msg.includes('QUJDREVGR0g'), 'meldung darf keinen PEM-Inhalt enthalten');
        return true;
      },
    );
  });

  it('gibt bei unbrauchbarer Kette keine Zertifikatsinhalte in der Meldung aus', async () => {
    await writeFile(join(tmpDir, 'bad-chain.pem'), 'garbage');
    await assert.rejects(
      loadVerifierIdentity({
        [ENV_ATTACK_VERIFIER_KEY_PEM]: join(tmpDir, 'key.pem'),
        [ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]: join(tmpDir, 'bad-chain.pem'),
      }),
      (e: unknown) => {
        const msg = e instanceof Error ? e.message : String(e);
        assert.match(msg, /nicht lesbar|unbrauchbar/);
        return true;
      },
    );
  });
});

describe('resolveVerifierIdentity – alle Kombinationen', () => {
  it('ohne PEM-Werte und ohne Entwicklungsschalter bricht der Start ab (ConfigError)', async () => {
    await assert.rejects(resolveVerifierIdentity(staleConfig, testKeysFactory, {}), ConfigError);
  });

  it('ohne PEM-Werte und ohne Entwicklungsschalter enthält die Meldung keine Schlüsselinhalte', async () => {
    await assert.rejects(
      resolveVerifierIdentity(staleConfig, testKeysFactory, {}),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError);
        const msg = e.message;
        assert.match(msg, /ATTACK_DEV_MODE/);
        assert.match(msg, /ATTACK_VERIFIER_KEY_PEM/);
        assert.ok(!msg.includes(keyPem) && !msg.includes(chainPem), 'keine PEM-Inhalte in der Meldung');
        return true;
      },
    );
  });

  it('ohne PEM-Werte, aber mit Entwicklungsschalter, wird Testmaterial genutzt und gemeldet', async () => {
    const out = await resolveVerifierIdentity(devConfig, testKeysFactory, {});
    assert.equal(out.usedTestFallback, true);
    assert.ok(out.keys);
  });

  it('in Produktion ist der Test-Fallback verboten (ConfigError)', async () => {
    await assert.rejects(resolveVerifierIdentity(prodConfig, testKeysFactory, {}), ConfigError);
  });

  it('mit echten PEM-Werten gewinnt die echte Identität – auch mit Entwicklungsschalter', async () => {
    const out = await resolveVerifierIdentity(devConfig, testKeysFactory, {
      [ENV_ATTACK_VERIFIER_KEY_PEM]: join(tmpDir, 'key.pem'),
      [ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]: join(tmpDir, 'chain.pem'),
    });
    assert.equal(out.usedTestFallback, false);
    assert.equal(out.keys.certificateChain.length, 1);
  });
});