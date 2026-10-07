/**
 * Nachweistests für die in phase1 adressierten Sicherheitslücken (Kunde 2,
 * TEIL 2): Jeder negative Fehlerpfad wird mit seinem positiven Gegenstück
 * gepaart, das dasselbe Material ohne die Manipulation akzeptiert. Läuft gegen
 * echte HTTP-Server auf 127.0.0.1 (ephemer). Nur TEST-Material im Speicher.
 *
 * Abgedeckt:
 *   - abgelaufene Sitzung: Präsentation nach TTL -> session_expired (Paar: vor TTL gültig)
 *   - state/Nonce-Mismatch (Cross-Session): Präsentation von Sitzung A auf
 *     Sitzung B wird nie akzeptiert (Paar: A auf A gültig)
 *   - Mandantenisolation auf Ergebnis-Endpunkten: fremder Mandant 404 nach
 *     completed, kein Zugriff auf Ergebnis ohne API-Schlüssel (401)
 *   - Ergebnis ist nicht „genau einmal“ abrufbar, aber nur authentisiert und
 *     binnen TTL; nach Ablauf/Löschung ist es weg (ehrliche IST-Doku)
 *   - JWE-Negativfälle (alg none, unbekannte alg, falscher enc, veränderter
 *     Chiffretext) -> jwe_decrypt_failed (Paar: korrektes JWE akzeptiert)
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import { afterAll, beforeAll, describe, it } from 'vitest';
import { CompactEncrypt, createLocalJWKSet, jwtVerify, type CompactJWEHeaderParameters } from 'jose';

import { createApp } from './app.ts';
import { VerifierService, type ServiceKeys } from './service.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';
import { AuditLog } from './audit.ts';
import { TenantStore } from './tenant.ts';
import { buildSdJwtVc, generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';

const KEY_A = 'test-api-key-nachweis-A';
const KEY_B = 'test-api-key-nachweis-B';

const b64u = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

type EncryptionJwk = JsonWebKey & { kid?: string };

async function encryptEnvelope(
  envelope: unknown,
  publicJwk: EncryptionJwk,
  header: { alg?: string; enc?: string; kid?: string | null } = {},
): Promise<string> {
  const kid = header.kid === undefined ? publicJwk.kid : header.kid;
  const protectedHeader: CompactJWEHeaderParameters = { alg: header.alg ?? 'ECDH-ES', enc: header.enc ?? 'A256GCM' };
  if (typeof kid === 'string') protectedHeader.kid = kid;
  return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(envelope))).setProtectedHeader(protectedHeader).encrypt(publicJwk);
}

/** Handgebautes Compact-JWE (z. B. alg=none), das jose so nicht erzeugen würde. */
function handJwe(header: Record<string, unknown>, iv: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): string {
  return [b64u(new TextEncoder().encode(JSON.stringify(header))), b64u(new Uint8Array(0)), b64u(iv), b64u(ciphertext), b64u(tag)].join('.');
}

interface Harness {
  base: string;
  app: http.Server;
  issuer: Awaited<ReturnType<typeof generateTestKeyMaterial>>;
  holder: Awaited<ReturnType<typeof generateTestKeyMaterial>>;
  verifierJwk: JsonWebKey;
  createSession(apiKey?: string): Promise<{ state: string; nonce: string; clientId: string; recipientJwk: EncryptionJwk }>;
  buildSdJwt(nonce: string, clientId: string): Promise<string>;
  resultGet(sessionId: string, apiKey?: string): Promise<Response>;
}

async function buildHarness(options: { ttlSeconds: number }): Promise<Harness> {
  const { ttlSeconds } = options;
  const tenants = new TenantStore();
  tenants.add({ id: 'tenant-a', name: 'Kunde A (TEST)', apiKey: KEY_A, requestTtlSeconds: ttlSeconds });
  tenants.add({ id: 'tenant-b', name: 'Kunde B (TEST)', apiKey: KEY_B, requestTtlSeconds: ttlSeconds });

  const verifierKey = await generateTestKeyMaterial('Nachweis Verifier TEST');
  const issuer = await generateTestKeyMaterial('Nachweis Issuer TEST');
  const holder = await generateTestKeyMaterial('Nachweis Holder TEST');
  const keys: ServiceKeys = {
    privateKey: verifierKey.privateKey,
    publicKey: verifierKey.publicKey,
    publicJwk: verifierKey.publicJwk,
    certificateChain: [verifierKey.certDerBytes],
  };

  const audit = new AuditLog();
  const service = new VerifierService(tenants, audit, keys, issuer.certDerBytes, undefined, undefined, undefined, undefined, true, DEV_TEST_OPTIONS);
  const app = createApp({ appLabel: 'nachweis-test', tenants, service });
  await new Promise<void>((resolve) => app.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${(app.address() as { port: number }).port}`;
  service.baseUrl = base;

  return {
    base,
    app,
    issuer,
    holder,
    verifierJwk: verifierKey.publicJwk,
    createSession: async (apiKey = KEY_A) => {
      const created = await fetch(`${base}/v1/verification-requests`, {
        method: 'POST',
        headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
        body: JSON.stringify({ claims: ['given_name'] }),
      });
      assert.equal(created.status, 201);
      const { state, requestObject } = (await created.json()) as { state: string; requestObject: string };
      const { payload } = await jwtVerify(requestObject, createLocalJWKSet({ keys: [verifierKey.publicJwk] }));
      const clientMetadata = payload.client_metadata as { jwks?: { keys?: EncryptionJwk[] } } | undefined;
      const recipientJwk = clientMetadata?.jwks?.keys?.[0];
      if (!recipientJwk) {
        throw new Error('Request Object enthält keinen öffentlichen Verschlüsselungsschlüssel');
      }
      return { state, nonce: payload.nonce as string, clientId: payload.client_id as string, recipientJwk };
    },
    buildSdJwt: async (nonce, clientId) => {
      const built = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce, audience: clientId });
      return built.sdJwt;
    },
    resultGet: (sessionId, apiKey?: string) =>
      fetch(`${base}/v1/verification-requests/${sessionId}`, { headers: apiKey ? { authorization: `Bearer ${apiKey}` } : {} }),
  };
}

async function present(hh: Harness, state: string, sdJwt: string): Promise<{ status: number; body: Record<string, unknown> }> {
  const post = await fetch(`${hh.base}/direct_post`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ vp_token: { pid: [sdJwt] }, state }),
  });
  return { status: post.status, body: (await post.json()) as Record<string, unknown> };
}

let h: Harness;
let hExp: Harness;

beforeAll(async () => {
  h = await buildHarness({ ttlSeconds: 300 });
  hExp = await buildHarness({ ttlSeconds: 1 });
});

afterAll(async () => {
  for (const hh of [h, hExp]) {
    if (hh?.app) {
      await new Promise<void>((resolve) => {
        hh.app.closeAllConnections();
        hh.app.close(() => resolve());
      });
    }
  }
});

describe('Sitzung: abgelaufene Sitzung (Negativ) vs. gültige Sitzung (Positiv)', () => {
  it('Positiv: Präsentation vor Ablauf wird akzeptiert', async () => {
    const s = await h.createSession();
    const sdJwt = await h.buildSdJwt(s.nonce, s.clientId);
    const { status, body } = await present(h, s.state, sdJwt);
    assert.equal(status, 200);
    assert.equal(body.valid, true, 'vor Ablauf muss dieselbe Präsentation akzeptiert werden');
  });

  it('Negativ: Präsentation nach TTL-Ablauf wird abgelehnt (session_expired)', async () => {
    const s = await hExp.createSession();
    const sdJwt = await hExp.buildSdJwt(s.nonce, s.clientId);
    await new Promise((r) => setTimeout(r, 1200));
    const { status, body } = await present(hExp, s.state, sdJwt);
    assert.equal(status, 422);
    assert.equal(body.error, 'session_expired', 'abgelaufene Sitzung hilft selbst eine kryptografisch gültige Präsentation nichts');
  });
});

describe('Sitzung: state/Nonce-Mismatch (Cross-Session)', () => {
  it('Negativ: Präsentation von Sitzung A auf Sitzung B wird nie akzeptiert', async () => {
    const a = await h.createSession();
    const b = await h.createSession();
    const sdForA = await h.buildSdJwt(a.nonce, a.clientId);

    // IST-Semantik des Dienstes: gegenüber der Bibliothek gültiges, aber zur
    // Ziel-Sitzung nicht passendes Material ergibt HTTP 200 mit valid=false
    // (entgegengenommen, aber nicht akzeptiert); Session-Probleme werden als 422
    // signalisiert, weil die Route öffentlich ist und es nichts zu
    // authentifizieren gab. Maßgebend ist valid===false.
    const { status, body } = await present(h, b.state, sdForA);
    assert.equal(body.valid, false, 'Tokengültigkeit für A verhilft auf B nicht zur Akzeptanz');
    assert.equal(status, 200);

    const bAgain = await present(h, b.state, await h.buildSdJwt(b.nonce, b.clientId));
    assert.equal(bAgain.body.error, 'session_reused', 'Ziel-Sitzung B wurde vom Fehlversuch verbraucht (ehrliche IST-Doku)');
  });

  it('Positiv: Präsentation von Sitzung A auf Sitzung A wird akzeptiert', async () => {
    const a = await h.createSession();
    const sdForA = await h.buildSdJwt(a.nonce, a.clientId);
    const { status, body } = await present(h, a.state, sdForA);
    assert.equal(status, 200);
    assert.equal(body.valid, true, 'eigene Sitzung wird mit eigenem Material akzeptiert');
  });
});

describe('Mandantenisolation auf Ergebnis-Endpunkten', () => {
  it('Negativ: fremder Mandant sieht das Ergebnis nach completed nicht (404)', async () => {
    const s = await h.createSession();
    await present(h, s.state, await h.buildSdJwt(s.nonce, s.clientId));
    const foreign = await h.resultGet(s.state, KEY_B);
    assert.equal(foreign.status, 404, 'fremder Mandant darf das Ergebnis nicht sehen');
  });

  it('Positiv: der eigene Mandant bekommt das Ergebnis nach completed (200)', async () => {
    const s = await h.createSession();
    await present(h, s.state, await h.buildSdJwt(s.nonce, s.clientId));
    const own = await h.resultGet(s.state, KEY_A);
    assert.equal(own.status, 200);
    const body = (await own.json()) as { status: string };
    assert.equal(body.status, 'completed', 'dieselbe Sitzung ist für den Eigentümer completed');
  });

  it('Negativ: Ergebnis ist ohne API-Schlüssel nicht abrufbar (401)', async () => {
    const s = await h.createSession();
    await present(h, s.state, await h.buildSdJwt(s.nonce, s.clientId));
    const anon = await h.resultGet(s.state, undefined);
    assert.equal(anon.status, 401, 'Ergebnis ist nie ohne Authentifizierung abrufbar');
  });

  it('Positiv: mit gültigem API-Schlüssel ist das Ergebnis genau einmal abrufbar (Haertung 2)', async () => {
    const s = await h.createSession();
    await present(h, s.state, await h.buildSdJwt(s.nonce, s.clientId));
    const first = await h.resultGet(s.state, KEY_A);
    const second = await h.resultGet(s.state, KEY_A);
    assert.equal(first.status, 200);
    const firstBody = (await first.json()) as { result?: { valid: boolean } };
    assert.equal(firstBody.result?.valid, true);
    assert.equal(second.status, 404, 'zweiter Abruf: Ergebnis ist verbraucht');
  });

  it('Negativ: nach TTL-Ablauf wird kein Ergebnis mehr geliefert (stale Result weg)', async () => {
    const s = await hExp.createSession();
    await present(hExp, s.state, await hExp.buildSdJwt(s.nonce, s.clientId));
    await new Promise((r) => setTimeout(r, 1200));
    const stale = await hExp.resultGet(s.state, KEY_A);
    assert.equal(stale.status, 200);
    assert.equal((await stale.json()).status, 'expired', 'nach Ablauf wird kein Ergebnis mehr geliefert');
  });

  it('Negativ: nach Löschung ist das Ergebnis nicht mehr abrufbar (404)', async () => {
    const s = await h.createSession();
    await present(h, s.state, await h.buildSdJwt(s.nonce, s.clientId));
    const del = await fetch(`${h.base}/v1/verification-requests/${s.state}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${KEY_A}` },
    });
    assert.equal(del.status, 204);
    const gone = await h.resultGet(s.state, KEY_A);
    assert.equal(gone.status, 404, 'nach Löschung existiert die Sitzung inkl. Ergebnis nicht mehr');
  });
});

describe('JWE: negative Fälle (Negativ) vs. korrektes JWE (Positiv)', () => {
  it('Positiv: korrekt verschlüsseltes JWE (ECDH-ES + A256GCM) wird akzeptiert', async () => {
    const s = await h.createSession();
    const sdJwt = await h.buildSdJwt(s.nonce, s.clientId);
    const jwe = await encryptEnvelope({ vp_token: { pid: [sdJwt] }, state: s.state }, s.recipientJwk);
    const res = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ response: jwe }).toString(),
    });
    assert.equal(res.status, 200);
    const outcome = (await res.json()) as { valid: boolean };
    assert.equal(outcome.valid, true, 'korrektes JWE muss akzeptiert werden');
  });

  it('Negativ: JWE nach Ablauf der Sitzung wird abgelehnt (session_expired)', async () => {
    const s = await hExp.createSession();
    const sdJwt = await hExp.buildSdJwt(s.nonce, s.clientId);
    const jwe = await encryptEnvelope({ vp_token: { pid: [sdJwt] }, state: s.state }, s.recipientJwk);
    await new Promise((resolve) => setTimeout(resolve, 1200));
    const res = await fetch(`${hExp.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ response: jwe }).toString(),
    });
    assert.equal(res.status, 422);
    assert.equal((await res.json()).error, 'session_expired');
  });

  it('Negativ: JWE mit alg=none wird abgelehnt (jwe_decrypt_failed)', async () => {
    const s = await h.createSession();
    const jwe = handJwe({ alg: 'none', enc: 'A256GCM', kid: s.state }, new Uint8Array(12), new TextEncoder().encode('ciphertext'), new Uint8Array(16));
    const res = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ response: jwe }).toString(),
    });
    assert.equal(res.status, 422);
    assert.equal((await res.json()).error, 'jwe_decrypt_failed');
  });

  it('Negativ: JWE mit unbekannter alg (A128KW) wird abgelehnt (jwe_decrypt_failed)', async () => {
    const s = await h.createSession();
    const oct = { kty: 'oct', k: b64u(crypto.getRandomValues(new Uint8Array(16))) } as unknown as JsonWebKey;
    const jwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify({ vp_token: { pid: [] }, state: s.state })))
      .setProtectedHeader({ alg: 'A128KW', enc: 'A256GCM', kid: s.state })
      .encrypt(oct);
    const res = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ response: jwe }).toString(),
    });
    assert.equal(res.status, 422);
    assert.equal((await res.json()).error, 'jwe_decrypt_failed');
  });

  it('Negativ: JWE mit nicht unterstütztem enc (A128CBC-HS256) wird abgelehnt', async () => {
    const s = await h.createSession();
    const jwe = await encryptEnvelope({ vp_token: { pid: [] }, state: s.state }, s.recipientJwk, { alg: 'ECDH-ES', enc: 'A128CBC-HS256', kid: s.state });
    const res = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ response: jwe }).toString(),
    });
    assert.equal(res.status, 422);
    assert.equal((await res.json()).error, 'jwe_decrypt_failed');
  });

  it('Negativ: veränderter Chiffretext wird abgelehnt (jwe_decrypt_failed)', async () => {
    const s = await h.createSession();
    const sdJwt = await h.buildSdJwt(s.nonce, s.clientId);
    const jwe = await encryptEnvelope({ vp_token: { pid: [sdJwt] }, state: s.state }, s.recipientJwk);
    const parts = jwe.split('.');
    const tamperedCt = Buffer.from(parts[3], 'base64url');
    tamperedCt[0] ^= 0x01;
    const tampered = [parts[0], parts[1], parts[2], b64u(tamperedCt), parts[4]].join('.');
    const res = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ response: tampered }).toString(),
    });
    assert.equal(res.status, 422);
    assert.equal((await res.json()).error, 'jwe_decrypt_failed');
  });
});