/**
 * Interop-Tests für /direct_post (Teil 1, Dokumentationspunkt 3 aus
 * docs/sicherheit.md). Der Verifier akzeptiert die Präsentation in drei
 * Eingabeformaten:
 *   1. application/json: DCQL-Envelope { vp_token: {…}, state }
 *   2. application/x-www-form-urlencoded: Envelope-Felder `vp_token`/`state`
 *      (vp_token als JSON-Objekt, JSON-Array oder roher SD-JWT-String)
 *   3. JWE-verschlüsselte Antwort (direct_post.jwt): `response=<JWE>` als
 *      Form-Post oder {"response": "<JWE>"} als JSON
 * Die Entschlüsselung übernimmt ausschließlich die Bibliothek
 * (decryptAuthorizationResponse: ECDH-ES + A128GCM/A256GCM, RFC 7516) — es wird
 * kein eigenes Krypto gebaut. Nur TEST-Material im Arbeitsspeicher.
 */
import assert from 'node:assert/strict';
import { afterAll, beforeAll, describe, it } from 'vitest';
import { CompactEncrypt, createLocalJWKSet, jwtVerify, type CompactJWEHeaderParameters } from 'jose';

import { createApp } from './app.ts';
import { VerifierService, type ServiceKeys } from './service.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';
import { AuditLog } from './audit.ts';
import { TenantStore } from './tenant.ts';
import { buildSdJwtVc, generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';

const KEY_A = 'test-api-key-interop-A';

async function generateEncryptionKey(): Promise<{ privateKey: CryptoKey; publicJwk: JsonWebKey }> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
  const jwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey;
  jwk.alg = 'ECDH-ES';
  jwk.use = 'enc';
  return { privateKey: pair.privateKey, publicJwk: jwk };
}

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

interface Harness {
  base: string;
  audit: AuditLog;
  issuerKey: Awaited<ReturnType<typeof generateTestKeyMaterial>>;
  holderKey: Awaited<ReturnType<typeof generateTestKeyMaterial>>;
  verifierJwk: JsonWebKey;
  server: Awaited<ReturnType<typeof import('node:http')['createServer']>>;
}

let h: Harness;

beforeAll(async () => {
  const tenantStore = new TenantStore();
  tenantStore.add({ id: 'tenant-a', name: 'Kunde A (TEST)', apiKey: KEY_A, requestTtlSeconds: 300 });

  const verifierKey = await generateTestKeyMaterial('Interop Verifier TEST');
  const issuerKey = await generateTestKeyMaterial('Interop Issuer TEST');
  const holderKey = await generateTestKeyMaterial('Interop Holder TEST');
  const keys: ServiceKeys = {
    privateKey: verifierKey.privateKey,
    publicKey: verifierKey.publicKey,
    publicJwk: verifierKey.publicJwk,
    certificateChain: [verifierKey.certDerBytes],
  };

  const audit = new AuditLog();
  const service = new VerifierService(tenantStore, audit, keys, issuerKey.certDerBytes, undefined, undefined, undefined, undefined, true, DEV_TEST_OPTIONS);
  const server = createApp({ appLabel: 'interop-test', tenants: tenantStore, service });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  const base = `http://127.0.0.1:${port}`;
  service.baseUrl = base;

  h = { base, audit, issuerKey, holderKey, verifierJwk: verifierKey.publicJwk, server };
});

afterAll(async () => {
  await new Promise<void>((resolve) => h.server.close(() => resolve()));
});

async function createSession(): Promise<{ state: string; nonce: string; clientId: string; uri: string; recipientJwk: EncryptionJwk }> {
  const created = await fetch(`${h.base}/v1/verification-requests`, {
    method: 'POST',
    headers: { authorization: `Bearer ${KEY_A}`, 'content-type': 'application/json' },
    body: JSON.stringify({ claims: ['given_name'] }),
  });
  assert.equal(created.status, 201, 'Request muss erzeugt werden');
  const { sessionId, requestObjectUri, requestObject } = (await created.json()) as {
    sessionId: string;
    requestObjectUri: string;
    requestObject: string;
  };
  const { payload } = await jwtVerify(requestObject, createLocalJWKSet({ keys: [h.verifierJwk] }));
  const clientMetadata = payload.client_metadata as { jwks?: { keys?: EncryptionJwk[] } } | undefined;
  const recipientJwk = clientMetadata?.jwks?.keys?.[0];
  if (!recipientJwk) {
    throw new Error('Request Object enthält keinen öffentlichen Verschlüsselungsschlüssel');
  }
  return { state: sessionId, nonce: payload.nonce as string, clientId: payload.client_id as string, uri: requestObjectUri, recipientJwk };
}

async function buildSdJwt(session: { nonce: string; clientId: string }): Promise<string> {
  const built = await buildSdJwtVc({
    issuerKey: h.issuerKey,
    holderKey: h.holderKey,
    nonce: session.nonce,
    audience: session.clientId,
  });
  return built.sdJwt;
}

function formEnvelopeParams(vpTokenParam: string, state: string): string {
  return new URLSearchParams({ vp_token: vpTokenParam, state }).toString();
}

describe('direct_post-Interop (Teil 1)', () => {
  it('Request Object nutzt bei konfigurierter Encryption direct_post.jwt', async () => {
    const session = await createSession();
    const ro = await fetch(session.uri);
    assert.equal(ro.status, 200);
    const { payload } = await jwtVerify(await ro.text(), createLocalJWKSet({ keys: [h.verifierJwk] }));
    assert.equal(payload.response_mode, 'direct_post.jwt');
    assert.ok(payload.client_metadata && typeof payload.client_metadata === 'object');
    const meta = payload.client_metadata as Record<string, unknown>;
    assert.ok(meta.jwks, 'client_metadata.jwks ist gesetzt');
    assert.deepEqual(meta.encrypted_response_enc_values_supported, ['A128GCM', 'A256GCM']);
  });

  it('Form-Post mit Json-Objekt (DCQL-Envelope) wird akzeptiert', async () => {
    const session = await createSession();
    const sdJwt = await buildSdJwt(session);
    const body = formEnvelopeParams(JSON.stringify({ pid: [sdJwt] }), session.state);
    const post = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    assert.equal(post.status, 200);
    const outcome = (await post.json()) as { valid: boolean };
    assert.equal(outcome.valid, true);
  });

  it('Form-Post mit rohem SD-JWT-String wird in den DCQL-Envelope gewickelt', async () => {
    const session = await createSession();
    const sdJwt = await buildSdJwt(session);
    const body = formEnvelopeParams(sdJwt, session.state);
    const post = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    assert.equal(post.status, 200);
    const outcome = (await post.json()) as { valid: boolean };
    assert.equal(outcome.valid, true);
  });

  it('Form-Post mit Json-Array wird in den DCQL-Envelope gewickelt', async () => {
    const session = await createSession();
    const sdJwt = await buildSdJwt(session);
    const body = formEnvelopeParams(JSON.stringify([sdJwt]), session.state);
    const post = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    assert.equal(post.status, 200);
    const outcome = (await post.json()) as { valid: boolean };
    assert.equal(outcome.valid, true);
  });

  it('JSON-Antwort (unverschlüsselt) funktioniert weiterhin', async () => {
    const session = await createSession();
    const sdJwt = await buildSdJwt(session);
    const post = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ vp_token: { pid: [sdJwt] }, state: session.state }),
    });
    assert.equal(post.status, 200);
    const outcome = (await post.json()) as { valid: boolean };
    assert.equal(outcome.valid, true);
  });

  it('JWE-Antwort als Form-Post (response=<JWE>) wird akzeptiert', async () => {
    const session = await createSession();
    const sdJwt = await buildSdJwt(session);
    const jwe = await encryptEnvelope({ vp_token: { pid: [sdJwt] }, state: session.state }, session.recipientJwk);
    const body = new URLSearchParams({ response: jwe }).toString();
    const post = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    assert.equal(post.status, 200);
    const outcome = (await post.json()) as { valid: boolean };
    assert.equal(outcome.valid, true);
  });

  it('JWE-Antwort als JSON ({"response": …}) wird akzeptiert', async () => {
    const session = await createSession();
    const sdJwt = await buildSdJwt(session);
    const jwe = await encryptEnvelope({ vp_token: { pid: [sdJwt] }, state: session.state }, session.recipientJwk);
    const post = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ response: jwe }),
    });
    assert.equal(post.status, 200);
    const outcome = (await post.json()) as { valid: boolean };
    assert.equal(outcome.valid, true);
  });

  it('JWE ohne kid wird abgelehnt (missing_kid)', async () => {
    const session = await createSession();
    const sdJwt = await buildSdJwt(session);
    const jwe = await encryptEnvelope({ vp_token: { pid: [sdJwt] }, state: session.state }, session.recipientJwk, { kid: null });
    const post = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ response: jwe }).toString(),
    });
    assert.equal(post.status, 422);
    assert.equal((await post.json()).error, 'missing_kid');
  });

  // Regressionstests zum `kid` aus dem JWE-Kopf. `kid` wird in service.ts
  // ungefiltert in Audit-Zeilen interpoliert (`session=${kid} reason=…`), die
  // Eingabeprüfung beschränkt aber nur auf String, nicht leer, höchstens 128
  // Zeichen. Ohne die Prüfung gegen `pendingByState` wäre das eine Log-Injection.
  // Diese Tests halten fest, dass der Wert eine existierende Session treffen
  // muss, bevor er protokolliert wird, und dass die Grenzen sauber abweisen.
  describe('kid aus dem JWE-Kopf', () => {
    /** Audit-Einträge seit einem Marker, damit parallele Läufe sich nicht stören. */
    function auditSince(mark: number): string[] {
      return h.audit.list().slice(mark).map((entry) => `${entry.event} ${entry.detail ?? ''}`);
    }

    async function postJweWithKid(kid: string): Promise<{ status: number; body: { error?: string; valid?: boolean } }> {
      const session = await createSession();
      const sdJwt = await buildSdJwt(session);
      const jwe = await encryptEnvelope({ vp_token: { pid: [sdJwt] }, state: session.state }, session.recipientJwk, { kid });
      const post = await fetch(`${h.base}/direct_post`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ response: jwe }).toString(),
      });
      return { status: post.status, body: (await post.json()) as { error?: string; valid?: boolean } };
    }

    it('kid mit Zeilenumbruch und Fälschungsversuch erreicht das Audit-Log nicht', async () => {
      const forged = 'x\n2026-01-01T00:00:00.000Z|evil|fake|reason=forged';
      const mark = h.audit.list().length;
      const { status, body } = await postJweWithKid(forged);
      assert.equal(status, 422);
      assert.equal(body.error, 'unknown_state');
      const entries = auditSince(mark);
      assert.ok(entries.includes('presentation_rejected reason=unknown_state'), `unexpected: ${JSON.stringify(entries)}`);
      for (const entry of entries) {
        assert.equal(entry.includes('forged'), false, `kid im Audit-Log: ${entry}`);
        assert.equal(entry.includes('evil'), false, `kid im Audit-Log: ${entry}`);
      }
    });

    it('kid mit genau 128 Zeichen wird abgewiesen (unknown_state)', async () => {
      const kid = 'a'.repeat(128);
      assert.equal(kid.length, 128);
      const mark = h.audit.list().length;
      const { status, body } = await postJweWithKid(kid);
      assert.equal(status, 422);
      assert.equal(body.error, 'unknown_state');
      for (const entry of auditSince(mark)) assert.equal(entry.includes(kid), false, `kid im Audit-Log: ${entry}`);
    });

    it('kid mit 129 Zeichen wird abgewiesen, ohne Absturz', async () => {
      const kid = 'b'.repeat(129);
      assert.equal(kid.length, 129);
      const mark = h.audit.list().length;
      const { status, body } = await postJweWithKid(kid);
      assert.equal(status, 422);
      // Die Längenprüfung in service.ts:636 greift vor der Session-Suche, der
      // Wert wird also als `missing_kid` abgewiesen, nicht als `unknown_state`.
      assert.equal(body.error, 'missing_kid');
      for (const entry of auditSince(mark)) assert.equal(entry.includes(kid), false, `kid im Audit-Log: ${entry}`);
    });

    it('kid mit fremdem Zeichensatz wird abgewiesen, ohne kid im Audit-Log', async () => {
      const mark = h.audit.list().length;
      for (const kid of ['ümläut-kid', 'emoji-🔑-kid', 'steuer\u0000-kid', 'tab\tkid', 'null\u0000kid', 'ctrl-\u0001-kid']) {
        const { status, body } = await postJweWithKid(kid);
        assert.equal(status, 422, `kid ${JSON.stringify(kid)}`);
        assert.equal(body.error, 'unknown_state', `kid ${JSON.stringify(kid)}`);
      }
      const entries = auditSince(mark);
      for (const entry of entries) {
        assert.equal(entry.includes('ümläut'), false, `kid im Audit-Log: ${entry}`);
        assert.equal(entry.includes('emoji'), false, `kid im Audit-Log: ${entry}`);
        assert.equal(entry.includes('steuer'), false, `kid im Audit-Log: ${entry}`);
        assert.equal(entry.includes('null'), false, `kid im Audit-Log: ${entry}`);
        assert.equal(entry.includes('ctrl-'), false, `kid im Audit-Log: ${entry}`);
      }
    });

    it('ein gültiger kid nach einem manipulierten bleibt nutzbar (kein DoS)', async () => {
      const session = await createSession();
      const sdJwt = await buildSdJwt(session);
      const bad = await encryptEnvelope({ vp_token: { pid: [sdJwt] }, state: session.state }, session.recipientJwk, { kid: 'x\nforged' });
      const attack = await fetch(`${h.base}/direct_post`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ response: bad }),
      });
      assert.equal(attack.status, 422);

      const good = await encryptEnvelope({ vp_token: { pid: [sdJwt] }, state: session.state }, session.recipientJwk);
      const post = await fetch(`${h.base}/direct_post`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ response: good }),
      });
      assert.equal(post.status, 200);
      assert.equal(((await post.json()) as { valid: boolean }).valid, true);
    });
  });

  it('JWE mit kid einer anderen Sitzung wird abgelehnt (state_mismatch)', async () => {
    const first = await createSession();
    const second = await createSession();
    const sdJwt = await buildSdJwt(second);
    const jwe = await encryptEnvelope({ vp_token: { pid: [sdJwt] }, state: second.state }, first.recipientJwk, { kid: first.state });
    const rejected = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ response: jwe }).toString(),
    });
    assert.equal(rejected.status, 422);
    assert.equal((await rejected.json()).error, 'state_mismatch');
    const retry = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ vp_token: { pid: [sdJwt] }, state: second.state }),
    });
    assert.equal((await retry.json()).valid, true);
  });

  it('Replay derselben JWE-Antwort wird abgelehnt (session_reused)', async () => {
    const session = await createSession();
    const sdJwt = await buildSdJwt(session);
    const jwe = await encryptEnvelope({ vp_token: { pid: [sdJwt] }, state: session.state }, session.recipientJwk);
    const body = new URLSearchParams({ response: jwe }).toString();
    const first = await fetch(`${h.base}/direct_post`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
    assert.equal((await first.json()).valid, true);
    const second = await fetch(`${h.base}/direct_post`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
    assert.equal(second.status, 422);
    assert.equal((await second.json()).error, 'session_reused');
  });

  it('jede Sitzung erhält einen eigenen Verschlüsselungsschlüssel mit kid = state', async () => {
    const first = await createSession();
    const second = await createSession();
    assert.equal(first.recipientJwk.kid, first.state);
    assert.equal(second.recipientJwk.kid, second.state);
    assert.notEqual(first.recipientJwk.x, second.recipientJwk.x);
    assert.notEqual(first.recipientJwk.y, second.recipientJwk.y);
  });

  it('JWE-Antwort mit falschem Empfängerschlüssel wird abgelehnt (jwe_decrypt_failed)', async () => {
    const session = await createSession();
    const sdJwt = await buildSdJwt(session);
    const wrong = await generateEncryptionKey();
    const jwe = await encryptEnvelope({ vp_token: { pid: [sdJwt] }, state: session.state }, wrong.publicJwk, { kid: session.state });
    const body = new URLSearchParams({ response: jwe }).toString();
    const post = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    assert.equal(post.status, 422);
    const outcome = (await post.json()) as { error?: string };
    assert.equal(outcome.error, 'jwe_decrypt_failed');
  });

  it('Fehlende Pflichtfelder im Form-Post werden mit 400 abgelehnt', async () => {
    const post = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'state=only-state',
    });
    assert.equal(post.status, 400);
    const body = (await post.json()) as { error: string };
    assert.equal(body.error, 'invalid_request');
  });
});