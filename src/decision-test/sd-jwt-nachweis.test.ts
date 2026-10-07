/**
 * Nachweistests für die SD-JWT-Sicherheitslücken (Kunde 2, TEIL 2) auf dem
 * Bibliothekspfad (@openeudi/openid4vp verifyAuthorizationResponse). Jeder
 * negative Fehlerpfad wird mit dem positiven Gegenstück gepaart, das
 * dasselbe Material ohne die jeweilige Manipulation akzeptiert.
 *
 * Abgedeckt:
 *   - doppelte Disclosure bricht die Key-Binding-Bindung (sd_hash) -> abgelehnt
 *   - zusätzliche, nicht im Issuer-JWT verankerte Disclosure -> abgelehnt
 *   - fehlendes Key-Binding bei holder-gebundenem Credential -> abgelehnt
 *   - Issuer-JWT mit nbf in der Zukunft -> abgelehnt
 *
 * Nur TEST-Schlüssel im Arbeitsspeicher, kein Netzwerk.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import { SignJWT } from 'jose';

import { buildHaipQuery, verifyAuthorizationResponse } from '@openeudi/openid4vp';

import { buildSdJwtVc, generateTestKeyMaterial, type TestKeyMaterial } from './mock-wallet.ts';

const PID_VCT = 'urn:eu.europa.ec.eudi:pid:1';
const NONCE = 'nonce-nachweis-1';
const AUDIENCE = 'x509_hash:TEST-verifier';

const encodeB64url = (s: string) => Buffer.from(s, 'utf-8').toString('base64url');
const sha256B64url = async (s: string) => Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))).toString('base64url');

function query() {
  return buildHaipQuery({ credentialId: 'pid', format: 'dc+sd-jwt', vctValues: [PID_VCT], claims: ['given_name'] });
}

async function verifyOne(sdJwt: string, issuer: TestKeyMaterial): Promise<{ valid: boolean; error: string }> {
  try {
    const r = await verifyAuthorizationResponse(
      { vp_token: { pid: [sdJwt] }, state: 'nachweis-state' },
      query(),
      { trustedCertificates: [issuer.certDerBytes], nonce: NONCE, audience: AUDIENCE },
    );
    return { valid: r.valid, error: r.parsed.error ?? '' };
  } catch (e) {
    return { valid: false, error: e instanceof Error ? e.message : String(e) };
  }
}

async function material(): Promise<{ issuer: TestKeyMaterial; holder: TestKeyMaterial }> {
  return { issuer: await generateTestKeyMaterial('SD-JWT Nachweis Issuer TEST'), holder: await generateTestKeyMaterial('SD-JWT Nachweis Holder TEST') };
}

describe('SD-JWT: Disclosure-Integrität (Negativ vs. Positiv)', () => {
  it('Positiv: Präsentation mit der ursprünglich verankerten Disclosure wird akzeptiert', async () => {
    const { issuer, holder } = await material();
    const built = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: NONCE, audience: AUDIENCE });
    const { valid, error } = await verifyOne(built.sdJwt, issuer);
    assert.equal(valid, true, `unverändertes Material muss akzeptiert werden (${error})`);
  });

  it('Negativ: doppelt angehängte Disclosure bricht die Key-Binding-Bindung (sd_hash) und wird abgelehnt', async () => {
    const { issuer, holder } = await material();
    const built = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: NONCE, audience: AUDIENCE });
    const [jwt, disclosure, kb] = built.sdJwt.split('~');
    const dup = `${jwt}~${disclosure}~${disclosure}~${kb}`;
    const { valid, error } = await verifyOne(dup, issuer);
    assert.equal(valid, false, `doppelte Disclosure muss abgelehnt werden (${error})`);
  });

  it('Negativ: zusätzliche, nicht im Issuer-JWT verankerte Disclosure wird abgelehnt (Disclosure-Hash)', async () => {
    const { issuer, holder } = await material();
    const built = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: NONCE, audience: AUDIENCE });
    const [jwt, disclosure, kb] = built.sdJwt.split('~');
    const foreign = encodeB64url(JSON.stringify([crypto.randomUUID(), 'fremder_claim', 'geheim']));
    const smuggling = `${jwt}~${disclosure}~${foreign}~${kb}`;
    const { valid, error } = await verifyOne(smuggling, issuer);
    assert.equal(valid, false, `unverankerte Zusatz-Disclosure muss abgelehnt werden (${error})`);
  });
});

describe('SD-JWT: Key Binding (Negativ vs. Positiv)', () => {
  it('Positiv: Präsentation mit Key-Binding-JWT wird akzeptiert', async () => {
    const { issuer, holder } = await material();
    const built = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: NONCE, audience: AUDIENCE });
    assert.ok(built.kbJwt, 'KB-JWT muss erzeugt worden sein');
    const { valid, error } = await verifyOne(built.sdJwt, issuer);
    assert.equal(valid, true, `KB-gebundene Präsentation muss akzeptiert werden (${error})`);
  });

  it('Negativ: fehlendes Key-Binding-JWT wird bei holder-gebundenem Credential abgelehnt', async () => {
    const { issuer, holder } = await material();
    const built = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: NONCE, audience: AUDIENCE });
    assert.ok(built.kbJwt, 'Voraussetzung: KB-JWT ist Teil des Ausgangsmaterials');
    const withoutKb = built.sdJwt.slice(0, built.sdJwt.length - built.kbJwt.length);
    const { valid, error } = await verifyOne(withoutKb, issuer);
    assert.equal(valid, false, `fehlendes KB muss abgelehnt werden (${error})`);
  });
});

describe('SD-JWT: nbf (Negativ vs. Positiv)', () => {
  it('Positiv: Issuer-JWT ohne nbf wird akzeptiert', async () => {
    const { issuer, holder } = await material();
    const built = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: NONCE, audience: AUDIENCE });
    const { valid, error } = await verifyOne(built.sdJwt, issuer);
    assert.equal(valid, true, `JWT ohne nbf muss akzeptiert werden (${error})`);
  });

  it('Negativ: Issuer-JWT mit nbf in der Zukunft wird abgelehnt', async () => {
    const { issuer, holder } = await material();
    const { issuerJwt, disclosures } = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: NONCE, audience: AUDIENCE });

    const now = Math.floor(Date.now() / 1000);
    const originalPayload = JSON.parse(Buffer.from(issuerJwt.split('.')[1], 'base64url').toString('utf8')) as Record<string, unknown>;
    const futurePayload = { ...originalPayload, nbf: now + 120 };

    const futureIssuerJwt = await new SignJWT(futurePayload)
      .setProtectedHeader({ alg: 'ES256', typ: 'vc+sd-jwt', x5c: [issuer.x5cBase64] })
      .sign(issuer.privateKey);

    const futureBody = `${futureIssuerJwt}~${disclosures.join('~')}~`;
    const sdHash = await sha256B64url(futureBody);
    const futureKb = await new SignJWT({ iat: now, nonce: NONCE, sd_hash: sdHash, aud: AUDIENCE })
      .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
      .sign(holder.privateKey);

    const { valid, error } = await verifyOne(futureBody + futureKb, issuer);
    assert.equal(valid, false, `nbf in der Zukunft muss abgelehnt werden (${error})`);
  });
});