/**
 * Schritt 1: Basisentscheidungstest @openeudi/openid4vp v0.11.1.
 *
 * Ablauf wie im Plan (WP2-Kriterium): signierte Prüfanfrage mit DCQL erzeugen,
 * eine Test-Präsentation eines SD-JWT VC zu einer flüchtigen Sitzung prüfen und
 * akzeptieren. Negativtests (müssen alle abgelehnt werden):
 *   verfälschte Disclosure, abgelaufene Sitzung, falsche Zielgruppe,
 *   wiederverwendete Nonce, falscher Aussteller.
 *
 * Nur TEST-Material im Arbeitsspeicher, keine echten Schlüssel, kein Netzwerk.
 * Alle Signaturen verifiziert die Bibliothek (bzw. jose für den Request Object).
 */
import assert from 'node:assert/strict';
import {test} from 'vitest';
import {decodeProtectedHeader, jwtVerify, createLocalJWKSet} from 'jose';

import {buildHaipQuery, validateHaipQuery, createSignedAuthorizationRequest, verifyAuthorizationResponse, VERSION as OPENID4VP_VERSION} from '@openeudi/openid4vp';

import {VpSessionStore} from '../lib/session.ts';
import {buildSdJwtVc, generateTestKeyMaterial} from './mock-wallet.ts';

const PID_VCT = 'urn:eu.europa.ec.eudi:pid:1';

function describe(valid: boolean, error?: string): string {
  return valid ? 'AKZEPTIERT' : `ABGELEHNT${error ? ` (${error})` : ''}`;
}

test('Setup: Version und DCQL-Query sind konsistent', () => {
  assert.equal(OPENID4VP_VERSION, '0.11.1');
  const query = buildHaipQuery({ credentialId: 'pid', format: 'dc+sd-jwt', vctValues: [PID_VCT], claims: ['given_name'] });
  validateHaipQuery(query); // wirft bei Ungültigkeit
  assert.equal(query.credentials[0].id, 'pid');
});

test('Positiv 1: signierte Prüfanfrage mit DCQL wird erzeugt (Request Object)', async () => {
  const verifierKey = await generateTestKeyMaterial('Verifier');
  const sessionStore = new VpSessionStore();
  const session = sessionStore.create({ audience: 'x509_hash:placeholder', clientId: 'https://verifier.example', responseUri: 'https://verifier.example/response' });

  const signed = await createSignedAuthorizationRequest(
    {
      clientIdPrefix: 'x509_hash',
      requestUri: 'https://verifier.example/openid4vp/sd.jwt',
      responseUri: session.responseUri,
      nonce: session.nonce,
      state: 'TEST-state-1',
      responseMode: 'direct_post',
      signer: { privateKey: verifierKey.privateKey, publicKey: verifierKey.publicKey },
      signingAlgorithm: 'ES256',
      certificateChain: [verifierKey.certDerBytes],
      allowSelfSignedCertificate: true,
      vpFormatsSupported: { 'dc+sd-jwt': { sd_jwt_alg_values: ['ES256'], kb_jwt_alg_values: ['ES256'] } },
    },
    buildHaipQuery({ credentialId: 'pid', format: 'dc+sd-jwt', vctValues: [PID_VCT], claims: ['given_name'] }),
  );

  assert.ok(signed.requestObject);
  const { alg, x5c } = decodeProtectedHeader(signed.requestObject);
  assert.equal(alg, 'ES256');
  assert.ok(Array.isArray(x5c) && x5c.length >= 1, 'Request Object trägt die x5c-Kette (Verifier-Identität)');

  const keySet = createLocalJWKSet({ keys: [verifierKey.publicJwk] });
  const { payload } = await jwtVerify(signed.requestObject, keySet);
  const dcql = (payload as { dcql_query?: unknown }).dcql_query as { credentials?: Array<{ id: string; format: string }> };
  assert.ok(dcql && dcql.credentials, 'Request Object enthält dcql_query');
  assert.equal(dcql.credentials![0].id, 'pid');
  assert.equal(dcql.credentials![0].format, 'dc+sd-jwt');
  assert.equal((payload as { nonce?: string }).nonce, session.nonce, 'Nonce der Sitzung steckt im Request Object');
});

test('Positiv 2: Test-Präsentation eines SD-JWT VC wird validiert und akzeptiert', async () => {
  const issuerKey = await generateTestKeyMaterial('Test Issuer');
  const holderKey = await generateTestKeyMaterial('Test Holder');
  const sessionStore = new VpSessionStore();
  const session = sessionStore.create({ audience: 'https://verifier.example', clientId: 'https://verifier.example', responseUri: 'https://verifier.example/response' });

  const built = await buildSdJwtVc({ issuerKey, holderKey, nonce: session.nonce, audience: session.audience });

  const claimed = sessionStore.consume(session.id);
  assert.ok('session' in claimed);
  const result = await verifyAuthorizationResponse(
    { vp_token: { pid: [built.sdJwt] }, state: 'TEST-state-1' },
    buildHaipQuery({ credentialId: 'pid', format: 'dc+sd-jwt', vctValues: [PID_VCT], claims: ['given_name'] }),
    { trustedCertificates: [issuerKey.certDerBytes], nonce: claimed.session.nonce, audience: claimed.session.audience },
  );

  assert.equal(result.valid, true, 'gültige Präsentation muss akzeptiert werden');
  assert.equal(result.parsed.claims.given_name, 'Ada', 'freigegebener Claim ist lesbar');
  assert.equal(result.parsed.issuer.country, 'DE', 'Issuer-Land aus dem Zertifikat stammt');
  console.log('[Positiv] Präsentation:', describe(result.valid));
});

test('Negativ 1: verfälschte Disclosure wird abgelehnt', async () => {
  const issuerKey = await generateTestKeyMaterial('Test Issuer');
  const holderKey = await generateTestKeyMaterial('Test Holder');
  const sessionStore = new VpSessionStore();
  const session = sessionStore.create({ audience: 'https://verifier.example', clientId: 'https://verifier.example', responseUri: 'https://verifier.example/response' });

  const built = await buildSdJwtVc({ issuerKey, holderKey, nonce: session.nonce, audience: session.audience, tamperDisclosure: true });
  sessionStore.consume(session.id);

  // Ohne Initialwert: try und catch weisen beide zu. Ein Vorgabewert würde von
  // keinem Pfad gelesen und wäre toter Code.
  let rejected: boolean;
  let error: string;
  try {
    const r = await verifyAuthorizationResponse(
      { vp_token: { pid: [built.sdJwt] }, state: 'TEST-state-1' },
      buildHaipQuery({ credentialId: 'pid', format: 'dc+sd-jwt', vctValues: [PID_VCT], claims: ['given_name'] }),
      { trustedCertificates: [issuerKey.certDerBytes], nonce: session.nonce, audience: session.audience },
    );
    rejected = r.valid === false;
    error = r.parsed.error ?? '';
  } catch (e) {
    rejected = true;
    error = e instanceof Error ? e.message : String(e);
  }
  assert.equal(rejected, true, 'verfälschte Disclosure muss abgelehnt werden');
  console.log('[Negativ 1] verfälschte Disclosure:', describe(false, error));
});

test('Negativ 2a: abgelaufene Sitzung wird von der Sitzungsschicht abgelehnt', async () => {
  const store = new VpSessionStore(1); // TTL 1 s
  const session = store.create({ audience: 'https://verifier.example', clientId: 'https://verifier.example', responseUri: 'https://verifier.example/response' });
  session.expiresAt = Date.now() - 1; // abgelaufen

  const claimed = store.consume(session.id);
  assert.ok('reason' in claimed && claimed.reason === 'session_expired', 'abgelaufene Sitzung muss abgelehnt werden');
  console.log('[Negativ 2a] abgelaufene Sitzung:', 'ABGELEHNT (session_expired)');
});

test('Negativ 2b: abgelaufenes Credential wird von der Bibliothek abgelehnt', async () => {
  const issuerKey = await generateTestKeyMaterial('Test Issuer');
  const holderKey = await generateTestKeyMaterial('Test Holder');
  const sessionStore = new VpSessionStore();
  const session = sessionStore.create({ audience: 'https://verifier.example', clientId: 'https://verifier.example', responseUri: 'https://verifier.example/response' });

  const built = await buildSdJwtVc({ issuerKey, holderKey, nonce: session.nonce, audience: session.audience, expSeconds: -60 });
  sessionStore.consume(session.id);

  // Ohne Initialwert: try und catch weisen beide zu. Ein Vorgabewert würde von
  // keinem Pfad gelesen und wäre toter Code.
  let rejected: boolean;
  let error: string;
  try {
    const r = await verifyAuthorizationResponse(
      { vp_token: { pid: [built.sdJwt] }, state: 'TEST-state-1' },
      buildHaipQuery({ credentialId: 'pid', format: 'dc+sd-jwt', vctValues: [PID_VCT], claims: ['given_name'] }),
      { trustedCertificates: [issuerKey.certDerBytes], nonce: session.nonce, audience: session.audience },
    );
    rejected = r.valid === false;
    error = r.parsed.error ?? '';
  } catch (e) {
    rejected = true;
    error = e instanceof Error ? e.message : String(e);
  }
  assert.equal(rejected, true, 'abgelaufenes Credential muss abgelehnt werden');
  console.log('[Negativ 2b] abgelaufenes Credential:', describe(false, error));
});

test('Negativ 3: falsche Zielgruppe (Audience) wird von der Bibliothek abgelehnt', async () => {
  const issuerKey = await generateTestKeyMaterial('Test Issuer');
  const holderKey = await generateTestKeyMaterial('Test Holder');
  const sessionStore = new VpSessionStore();
  const session = sessionStore.create({ audience: 'https://verifier.example', clientId: 'https://verifier.example', responseUri: 'https://verifier.example/response' });

  // Inhaber bindet die Antwort an eine andere Zielgruppe (Angriff/Schnitzer)
  const built = await buildSdJwtVc({ issuerKey, holderKey, nonce: session.nonce, audience: 'https://evil.example' });
  sessionStore.consume(session.id);

  // Ohne Initialwert: try und catch weisen beide zu. Ein Vorgabewert würde von
  // keinem Pfad gelesen und wäre toter Code.
  let rejected: boolean;
  let error: string;
  try {
    const r = await verifyAuthorizationResponse(
      { vp_token: { pid: [built.sdJwt] }, state: 'TEST-state-1' },
      buildHaipQuery({ credentialId: 'pid', format: 'dc+sd-jwt', vctValues: [PID_VCT], claims: ['given_name'] }),
      { trustedCertificates: [issuerKey.certDerBytes], nonce: session.nonce, audience: session.audience },
    );
    rejected = r.valid === false;
    error = r.parsed.error ?? '';
  } catch (e) {
    rejected = true;
    error = e instanceof Error ? e.message : String(e);
  }
  assert.equal(rejected, true, 'falsche Zielgruppe muss abgelehnt werden');
  console.log('[Negativ 3] falsche Zielgruppe:', describe(false, error));
});

test('Negativ 4: wiederverwendete Nonce/Replay wird abgelehnt', async () => {
  const issuerKey = await generateTestKeyMaterial('Test Issuer');
  const holderKey = await generateTestKeyMaterial('Test Holder');
  const sessionStore = new VpSessionStore();
  const session = sessionStore.create({ audience: 'https://verifier.example', clientId: 'https://verifier.example', responseUri: 'https://verifier.example/response' });

  const built = await buildSdJwtVc({ issuerKey, holderKey, nonce: session.nonce, audience: session.audience });
  const query = buildHaipQuery({ credentialId: 'pid', format: 'dc+sd-jwt', vctValues: [PID_VCT], claims: ['given_name'] });

  // Erste Nutzung: Sitzung wird verbraucht und die Präsentation akzeptiert.
  const first = sessionStore.consume(session.id);
  assert.ok('session' in first);
  const r1 = await verifyAuthorizationResponse({ vp_token: { pid: [built.sdJwt] }, state: 'TEST-state-1' }, query, {
    trustedCertificates: [issuerKey.certDerBytes],
    nonce: first.session.nonce,
    audience: session.audience,
  });
  assert.equal(r1.valid, true, 'erste Präsentation der Sitzung muss gültig sein');

  // Replay mit identischer Nonce/Präsentation muss abgelehnt werden (Sitzung verbraucht).
  const second = sessionStore.consume(session.id);
  assert.ok('reason' in second && second.reason === 'session_reused', 'Replay auf verbrauchte Sitzung muss abgelehnt werden');
  console.log('[Negativ 4] wiederverwendete Nonce:', 'ABGELEHNT (session_reused)');
});

test('Negativ 4b: Nonce-Abweichung wird von der Bibliothek abgelehnt', async () => {
  const issuerKey = await generateTestKeyMaterial('Test Issuer');
  const holderKey = await generateTestKeyMaterial('Test Holder');
  const sessionStore = new VpSessionStore();
  const session = sessionStore.create({ audience: 'https://verifier.example', clientId: 'https://verifier.example', responseUri: 'https://verifier.example/response' });

  // Präsentation ist an session.nonce gebunden, Verifier erwartet eine andere
  const built = await buildSdJwtVc({ issuerKey, holderKey, nonce: session.nonce, audience: session.audience });
  sessionStore.consume(session.id);

  // Ohne Initialwert: try und catch weisen beide zu. Ein Vorgabewert würde von
  // keinem Pfad gelesen und wäre toter Code.
  let rejected: boolean;
  let error: string;
  try {
    const r = await verifyAuthorizationResponse(
      { vp_token: { pid: [built.sdJwt] }, state: 'TEST-state-1' },
      buildHaipQuery({ credentialId: 'pid', format: 'dc+sd-jwt', vctValues: [PID_VCT], claims: ['given_name'] }),
      { trustedCertificates: [issuerKey.certDerBytes], nonce: 'GANZ-ANDERE-NONCE', audience: session.audience },
    );
    rejected = r.valid === false;
    error = r.parsed.error ?? '';
  } catch (e) {
    rejected = true;
    error = e instanceof Error ? e.message : String(e);
  }
  assert.equal(rejected, true, 'Nonce-Abweichung muss abgelehnt werden');
  console.log('[Negativ 4b] Nonce-Abweichung:', describe(false, error));
});

test('Negativ 5: falscher Aussteller (nicht im Trust Store) wird abgelehnt', async () => {
  const issuerKey = await generateTestKeyMaterial('Test Issuer');
  const attackerKey = await generateTestKeyMaterial('Evil Issuer TEST');
  const holderKey = await generateTestKeyMaterial('Test Holder');
  const sessionStore = new VpSessionStore();
  const session = sessionStore.create({ audience: 'https://verifier.example', clientId: 'https://verifier.example', responseUri: 'https://verifier.example/response' });

  // Präsentation stammt von einem fremden TEST-Aussteller
  const built = await buildSdJwtVc({ issuerKey: attackerKey, holderKey, nonce: session.nonce, audience: session.audience });
  sessionStore.consume(session.id);

  // Ohne Initialwert: try und catch weisen beide zu. Ein Vorgabewert würde von
  // keinem Pfad gelesen und wäre toter Code.
  let rejected: boolean;
  let error: string;
  try {
    const r = await verifyAuthorizationResponse(
      { vp_token: { pid: [built.sdJwt] }, state: 'TEST-state-1' },
      buildHaipQuery({ credentialId: 'pid', format: 'dc+sd-jwt', vctValues: [PID_VCT], claims: ['given_name'] }),
      { trustedCertificates: [issuerKey.certDerBytes], nonce: session.nonce, audience: session.audience },
    );
    rejected = r.valid === false;
    error = r.parsed.error ?? '';
  } catch (e) {
    rejected = true;
    error = e instanceof Error ? e.message : String(e);
  }
  assert.equal(rejected, true, 'fremder Aussteller muss abgelehnt werden');
  console.log('[Negativ 5] falscher Aussteller:', describe(false, error));
});