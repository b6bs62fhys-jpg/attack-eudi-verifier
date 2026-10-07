/**
 * Äquivalenztest der beiden JAR-Pfade (Teil C): Die Basisbibliothek
 * `createSignedAuthorizationRequest` und die eigene minimale JAR-Erweiterung
 * `buildAuthorizationRequestJar` (src/onboarding/jar.ts) laufen mit
 * identischen Eingaben nebeneinander. Hintergrund: Die Bibliothek erlaubt
 * keine Zusatzclaims und exportiert ihren internen Signierer nicht, daher
 * signiert unser eigener Pfad bei `registration_ref` selbst. Damit kein
 * Drift entsteht, MÜSSEN header-Struktur (Keys + Reihenfolge + Werte),
 * Algorithmus und client_id-Format der beiden Pfade vollständig überein-
 * stimmen; alle gemeinsamen Payload-Felder haben identische Werte. Bewusste
 * Zusätze unseres Pfads sind ausschließlich `request_uri` (Payload) und
 * `registration_ref`.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { beforeAll, describe, it } from 'vitest';
import { decodeProtectedHeader } from 'jose';

import { buildHaipQuery, createSignedAuthorizationRequest } from '@openeudi/openid4vp';

import { buildAuthorizationRequestJar, VP_FORMATS_SUPPORTED } from '../onboarding/jar.ts';
import { generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';

const NOW_SECONDS = 1_800_000_000;
const PID_VCT = 'urn:eu.europa.ec.eudi:pid:1';

const COMMON = {
  requestUri: 'http://127.0.0.1:8123/v1/verification-requests/s1/request-object',
  responseUri: 'http://127.0.0.1:8123/direct_post',
  nonce: 'nonce-parity-test-1',
  state: 'session-parity-1',
};

function decodeSegment(compact: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(compact.split('.')[1], 'base64url').toString('utf8')) as Record<string, unknown>;
}

let verifier: Awaited<ReturnType<typeof generateTestKeyMaterial>>;
let chain: Uint8Array[];
let dcqlQuery: ReturnType<typeof buildHaipQuery>;

beforeAll(async () => {
  verifier = await generateTestKeyMaterial('JAR-Parity Verifier TEST');
  chain = [verifier.certDerBytes];
  dcqlQuery = buildHaipQuery({ credentialId: 'pid', format: 'dc+sd-jwt', vctValues: [PID_VCT], claims: ['given_name'] });
});

describe('JAR-Pfade: Bibliothek vs. eigene Erweiterung (registration_ref)', () => {
  it('Header-Struktur, Keys und Reihenfolge sind identisch', async () => {
    const lib = await createSignedAuthorizationRequest(
      {
        clientIdPrefix: 'x509_hash',
        requestUri: COMMON.requestUri,
        responseUri: COMMON.responseUri,
        nonce: COMMON.nonce,
        state: COMMON.state,
        responseMode: 'direct_post',
        signer: { privateKey: verifier.privateKey, publicKey: verifier.publicKey },
        signingAlgorithm: 'ES256',
        certificateChain: chain,
        allowSelfSignedCertificate: true,
        vpFormatsSupported: VP_FORMATS_SUPPORTED,
      },
      dcqlQuery,
    );

    const own = await buildAuthorizationRequestJar({
      requestUri: COMMON.requestUri,
      responseUri: COMMON.responseUri,
      nonce: COMMON.nonce,
      state: COMMON.state,
      dcqlQuery,
      registrationRef: {
        clientName: 'Test GmbH (TEST)',
        clientId: 'test-wrp-1',
        registryUri: 'https://TEST-registrar.example/api/v1',
        intendedUseId: 'https://uri.etsi.org/19475/Entitlement/Service_Provider',
      },
      privateKey: verifier.privateKey,
      publicKey: verifier.publicKey,
      allowSelfSignedCertificate: true,
      certificateChain: chain,
      vpFormatsSupported: VP_FORMATS_SUPPORTED,
      now: NOW_SECONDS,
    });

    const libHeader = decodeProtectedHeader(lib.requestObject);
    const ownHeader = decodeProtectedHeader(own.requestObject);

    assert.deepEqual(Object.keys(ownHeader), ['typ', 'alg', 'x5c'], 'Header-Keys + Reihenfolge');
    assert.deepEqual(ownHeader, libHeader, 'Header-Struktur und -Werte identisch');
    assert.equal(ownHeader.alg, 'ES256', 'Algorithmus');
    assert.equal(ownHeader.typ, 'oauth-authz-req+jwt');

    const libPayload = decodeSegment(lib.requestObject);
    const ownPayload = decodeSegment(own.requestObject);

    const expected = `x509_hash:${createHash('sha256').update(chain[0]).digest('base64url')}`;
    assert.equal(ownPayload.client_id, libPayload.client_id, 'client_id identisch');
    assert.equal(ownPayload.client_id, expected);
    assert.ok(/^x509_hash:[A-Za-z0-9_-]+$/.test(ownPayload.client_id as string), 'client_id-Format x509_hash:<base64url>');

    for (const key of ['response_uri', 'response_mode', 'nonce', 'state', 'iss', 'aud', 'response_type', 'dcql_query', 'client_metadata']) {
      assert.deepEqual(ownPayload[key], libPayload[key], `gemeinsames Feld ${key} identisch`);
    }
    assert.equal(ownPayload.iss, ownPayload.client_id);
    assert.equal(ownPayload.aud, 'https://self-issued.me/v2');
    assert.equal(ownPayload.response_type, 'vp_token');

    assert.equal(typeof libPayload.iat, 'number');
    assert.equal(typeof libPayload.exp, 'number');
    assert.equal((libPayload.exp as number) - (libPayload.iat as number), 120, 'Bibliotheks-Sitzungsfenster');
    assert.equal((ownPayload.exp as number) - (ownPayload.iat as number), 120, 'Eigenes Sitzungsfenster');

    assert.equal(libPayload.request_uri, undefined);
    assert.equal(libPayload.registration_ref, undefined);
    assert.equal(ownPayload.request_uri, COMMON.requestUri);
    assert.ok(ownPayload.registration_ref, 'registration_ref existiert nur im eigenen Pfad');
  });

  it('auch bei Response-Encryption (direct_post.jwt) sind beide Pfade identisch', async () => {
    const enc = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
    const encJwk = (await crypto.subtle.exportKey('jwk', enc.publicKey)) as JsonWebKey;
    encJwk.alg = 'ECDH-ES';
    encJwk.use = 'enc';

    const lib = await createSignedAuthorizationRequest(
      {
        clientIdPrefix: 'x509_hash',
        requestUri: COMMON.requestUri,
        responseUri: COMMON.responseUri,
        nonce: COMMON.nonce,
        state: COMMON.state,
        responseMode: 'direct_post.jwt',
        signer: { privateKey: verifier.privateKey, publicKey: verifier.publicKey },
        signingAlgorithm: 'ES256',
        certificateChain: chain,
        allowSelfSignedCertificate: true,
        vpFormatsSupported: VP_FORMATS_SUPPORTED,
        encryptionKey: { publicJwk: encJwk, supportedEncValues: ['A128GCM', 'A256GCM'] },
      },
      dcqlQuery,
    );

    const own = await buildAuthorizationRequestJar({
      requestUri: COMMON.requestUri,
      responseUri: COMMON.responseUri,
      nonce: COMMON.nonce,
      state: COMMON.state,
      dcqlQuery,
      registrationRef: {
        clientName: 'Test GmbH (TEST)',
        clientId: 'test-wrp-1',
        registryUri: 'https://TEST-registrar.example/api/v1',
        intendedUseId: 'https://uri.etsi.org/19475/Entitlement/Service_Provider',
      },
      privateKey: verifier.privateKey,
      publicKey: verifier.publicKey,
      allowSelfSignedCertificate: true,
      certificateChain: chain,
      vpFormatsSupported: VP_FORMATS_SUPPORTED,
      now: NOW_SECONDS,
      encryption: { publicJwk: encJwk, supportedEncValues: ['A128GCM', 'A256GCM'] },
    });

    const libHeader = decodeProtectedHeader(lib.requestObject);
    const ownHeader = decodeProtectedHeader(own.requestObject);
    assert.deepEqual(ownHeader, libHeader, 'Header identisch');

    const libPayload = decodeSegment(lib.requestObject);
    const ownPayload = decodeSegment(own.requestObject);
    assert.equal(ownPayload.client_id, libPayload.client_id);
    assert.equal(ownPayload.response_mode, 'direct_post.jwt');
    assert.equal(libPayload.response_mode, 'direct_post.jwt');
    assert.deepEqual(ownPayload.client_metadata, libPayload.client_metadata, 'client_metadata (jwks + enc-Werte) identisch');
    assert.deepEqual((ownPayload.client_metadata as Record<string, unknown>).jwks, {
      keys: [{ ...encJwk, use: 'enc' }],
    });
  });
});