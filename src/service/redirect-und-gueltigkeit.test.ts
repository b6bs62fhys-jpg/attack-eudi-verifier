/**
 * Paket 5 b) und c).
 *
 * b) redirect_uri: standardmäßig aus. Nur mit ATTACK_REDIRECT_URI sendet der
 *    Dienst nach der Antwort der Wallet ein `redirect_uri`, und zwar nur, wenn
 *    die Präsentation verarbeitet wurde, mit Klartext und mit verschlüsselter
 *    Antwort (direct_post.jwt).
 * c) Gültigkeit des Request Objects: ATTACK_REQUEST_OBJECT_TTL_SECONDS,
 *    30 bis 600, Standard 120, ungültige Werte brechen den Start ab.
 * Nur Mock-Wallet und Test-Material.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import 'reflect-metadata';
import { CompactEncrypt, createLocalJWKSet, decodeJwt, jwtVerify } from 'jose';

import { ConfigError, DEFAULT_REQUEST_OBJECT_TTL_SECONDS, loadConfig } from '../config.ts';
import { buildSdJwtVc, generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { AuditLog } from './audit.ts';
import { VerifierService, type PresentationOutcome, type VerifierServiceOptions } from './service.ts';
import { TenantStore } from './tenant.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';

async function harness(options: Partial<VerifierServiceOptions> = {}) {
  const tenants = new TenantStore();
  tenants.add({ id: 'tenant-r', name: 'Kunde R (TEST)', apiKey: 'test-api-key-redirect', requestProfile: { id: 'test-given-name', claims: ['given_name'] } });
  const verifier = await generateTestKeyMaterial('Redirect Verifier TEST');
  const issuer = await generateTestKeyMaterial('Redirect Issuer TEST');
  const holder = await generateTestKeyMaterial('Redirect Holder TEST');
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
    { ...DEV_TEST_OPTIONS, ...options },
  );
  service.baseUrl = 'http://127.0.0.1:9';
  async function create() {
    const created = await service.createRequest('tenant-r', {});
    const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
    const jwk = (payload.client_metadata as { jwks: { keys: Array<JsonWebKey & { kid: string }> } }).jwks.keys[0] as JsonWebKey & { kid: string };
    return { created, payload, jwk };
  }
  async function sdJwt(payload: Record<string, unknown>, tamper = false) {
    return (
      await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: String(payload.nonce), audience: String(payload.client_id), tamperDisclosure: tamper })
    ).sdJwt;
  }
  return { service, create, sdJwt };
}

describe('b) redirect_uri', () => {
  const ZIEL = 'https://shop.example/fertig?quelle=wallet';

  it('ohne Konfiguration sendet der Dienst nichts (Standard aus)', async () => {
    const h = await harness();
    const { created, payload } = await h.create();
    const outcome = await h.service.handlePresentation(created.state, { pid: [await h.sdJwt(payload)] });
    assert.deepEqual(outcome, { ok: true, valid: true });
    assert.equal('redirect_uri' in outcome, false);
  });

  it('ohne Konfiguration auch nicht bei verschlüsselter Antwort', async () => {
    const h = await harness();
    const { created, payload, jwk } = await h.create();
    const jwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify({ vp_token: { pid: [await h.sdJwt(payload)] }, state: created.state })))
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid: jwk.kid })
      .encrypt(jwk);
    const outcome = await h.service.handleEncryptedPresentation(jwe);
    assert.deepEqual(outcome, { ok: true, valid: true });
  });

  it('mit Konfiguration: redirect_uri mit session_id nach gültiger Präsentation', async () => {
    const h = await harness({ redirectUri: ZIEL });
    const { created, payload } = await h.create();
    const outcome = await h.service.handlePresentation(created.state, { pid: [await h.sdJwt(payload)] });
    assert.equal(outcome.valid, true);
    assert.ok(outcome.redirect_uri);
    const url = new URL(outcome.redirect_uri as string);
    assert.equal(`${url.origin}${url.pathname}`, 'https://shop.example/fertig');
    assert.equal(url.searchParams.get('quelle'), 'wallet', 'vorhandene Query bleibt');
    assert.equal(url.searchParams.get('session_id'), created.sessionId);
  });

  it('mit Konfiguration und verschlüsselter Antwort: ebenfalls redirect_uri', async () => {
    const h = await harness({ redirectUri: ZIEL });
    const { created, payload, jwk } = await h.create();
    const jwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify({ vp_token: { pid: [await h.sdJwt(payload)] }, state: created.state })))
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid: jwk.kid })
      .encrypt(jwk);
    const outcome = await h.service.handleEncryptedPresentation(jwe);
    assert.equal(outcome.valid, true);
    assert.equal(new URL(outcome.redirect_uri as string).searchParams.get('session_id'), created.sessionId);
  });

  it('inhaltlich abgelehnte, aber verarbeitete Präsentation: redirect_uri kommt mit, valid bleibt false', async () => {
    const h = await harness({ redirectUri: ZIEL });
    const { created, payload } = await h.create();
    const outcome = await h.service.handlePresentation(created.state, { pid: [await h.sdJwt(payload, true)] });
    assert.equal(outcome.ok, true);
    assert.equal(outcome.valid, false);
    assert.ok(outcome.redirect_uri);
  });

  it('nicht verarbeitete Präsentation (unbekannter state, kaputtes JWE): kein redirect_uri', async () => {
    const h = await harness({ redirectUri: ZIEL });
    const unknown = await h.service.handlePresentation('unbekannt', { pid: ['x'] });
    assert.equal(unknown.ok, false);
    assert.equal('redirect_uri' in unknown, false);
    const jwe = await h.service.handleEncryptedPresentation('kein-jwe');
    assert.equal(jwe.ok, false);
    assert.equal('redirect_uri' in jwe, false);
  });

  it('Replay derselben Sitzung bekommt kein redirect_uri', async () => {
    const h = await harness({ redirectUri: ZIEL });
    const { created, payload } = await h.create();
    const token = await h.sdJwt(payload);
    await h.service.handlePresentation(created.state, { pid: [token] });
    const again = await h.service.handlePresentation(created.state, { pid: [token] });
    assert.equal('redirect_uri' in again, false, JSON.stringify(again));
  });

  describe('Konfiguration ATTACK_REDIRECT_URI', () => {
    it('Standard: nicht gesetzt', () => {
      assert.equal(loadConfig({}).redirectUri, undefined);
      assert.equal(loadConfig({ ATTACK_REDIRECT_URI: '  ' }).redirectUri, undefined);
    });
    it('https wird angenommen', () => {
      assert.equal(loadConfig({ ATTACK_REDIRECT_URI: ZIEL }).redirectUri, ZIEL);
    });
    for (const [titel, wert, muster] of [
      ['keine URL', 'shop.example', /keine gültige URL/],
      ['http ohne Entwicklungsschalter', 'http://shop.example/x', /https/],
      ['anderes Schema', 'javascript:alert(1)', /https/],
      ['mit Fragment', 'https://shop.example/x#a', /Fragment/],
      ['mit Zugangsdaten', 'https://u:p@shop.example/x', /Zugangsdaten/],
    ] as const) {
      it(`${titel} -> ConfigError`, () => {
        assert.throws(() => loadConfig({ ATTACK_REDIRECT_URI: wert }), (e: unknown) => e instanceof ConfigError && muster.test(e.message) && /Start abgebrochen/.test(e.message));
      });
    }
    it('http mit Entwicklungsschalter', () => {
      assert.equal(loadConfig({ ATTACK_DEV_MODE: 'true', ATTACK_REDIRECT_URI: 'http://127.0.0.1:3000/ok' }).redirectUri, 'http://127.0.0.1:3000/ok');
    });
  });
});

describe('c) Gültigkeit des Request Objects', () => {
  const lifetime = async (options: Partial<VerifierServiceOptions>) => {
    const h = await harness(options);
    const { created } = await h.create();
    const payload = decodeJwt(created.requestObject);
    return (payload.exp as number) - (payload.iat as number);
  };

  it('Standard bleibt 120 Sekunden', async () => {
    assert.equal(DEFAULT_REQUEST_OBJECT_TTL_SECONDS, 120);
    assert.equal(await lifetime({}), 120);
    assert.equal(loadConfig({}).requestObjectTtlSeconds, 120);
  });

  it('einstellbar: der Dienst signiert exp = iat + Wert', async () => {
    assert.equal(await lifetime({ requestObjectTtlSeconds: 300 }), 300);
    assert.equal(await lifetime({ requestObjectTtlSeconds: 600 }), 600);
    assert.equal(await lifetime({ requestObjectTtlSeconds: 30 }), 30);
  });

  it('ausdrücklich 120 ist dasselbe wie der Standard', async () => {
    assert.equal(await lifetime({ requestObjectTtlSeconds: 120 }), 120);
  });

  it('Konfiguration: Grenzen 30 und 600 gelten, außerhalb Abbruch mit Hinweis', () => {
    assert.equal(loadConfig({ ATTACK_REQUEST_OBJECT_TTL_SECONDS: '30' }).requestObjectTtlSeconds, 30);
    assert.equal(loadConfig({ ATTACK_REQUEST_OBJECT_TTL_SECONDS: '600' }).requestObjectTtlSeconds, 600);
    for (const wert of ['29', '601', '0', '-5', '1e3', '120.5', 'zwei Minuten']) {
      assert.throws(
        () => loadConfig({ ATTACK_REQUEST_OBJECT_TTL_SECONDS: wert }),
        (e: unknown) => e instanceof ConfigError && /ATTACK_REQUEST_OBJECT_TTL_SECONDS muss eine ganze Zahl zwischen 30 und 600 sein\. Start abgebrochen\./.test(e.message),
        wert,
      );
    }
  });

  it('leerer Wert gilt als nicht gesetzt', () => {
    assert.equal(loadConfig({ ATTACK_REQUEST_OBJECT_TTL_SECONDS: '' }).requestObjectTtlSeconds, 120);
  });
});

describe('Typ der Antwort', () => {
  it('PresentationOutcome ist die bisherige Form ohne Pflichtfeld redirect_uri', () => {
    const outcome: PresentationOutcome = { ok: true, valid: true };
    assert.deepEqual(Object.keys(outcome), ['ok', 'valid']);
  });
});
