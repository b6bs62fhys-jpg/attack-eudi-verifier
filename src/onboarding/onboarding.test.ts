/**
 * Tests für RP-Onboarding (Baustein B): WRPAC, WRPRC, RegistrationRef,
 * Registrar-Client und JAR-Einbettung. Nur TEST-Schlüssel im Speicher,
 * Abrufe ausschließlich gegen lokale Mock-Server. Kein Netzwerk.
 */
import assert from 'node:assert/strict';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';
import { createLocalJWKSet, decodeJwt, jwtVerify } from 'jose';

import { generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import {
  TEST_ENTITLEMENT_MAP,
  TEST_NON_WRPA_POLICY,
  TEST_UNKNOWN_ENTITLEMENT_OID,
  createAccessCa,
  createWrprcIssuer,
  createWrprcLeaf,
  generateTestKeyPair,
  intendedUse,
  signWrprc,
  testWrp,
  toIntendedUseStatus,
} from './mock-pki.ts';
import { MockRegistrarServer } from './mock-registrar.ts';
import {
  ErrIntendedUseNotActive,
  ErrIntendedUseNotFound,
  ErrMalformed,
  ErrRegistrationRef,
  ErrRegistrarSignature,
  ErrRegistrarStale,
  ErrRegistrarTimeout,
  ErrTrustPath,
  ErrUnknownEntitlement,
  ErrWrprcEntitlement,
  ErrWrpacContactSan,
  ErrWrpacExtKeyUsage,
  ErrWrpacKeyUsage,
  ErrWrpacPolicy,
  ErrWrprcClaims,
  ErrWrprcExpired,
  ErrWrprcHeader,
  ErrWrprcNotYetValid,
  ErrWrprcPolicyId,
  ErrWrprcSignature,
  ErrWrprcType,
  ErrWrprcValidity,
  ErrWrpNotFound,
} from './errors.ts';
import { REGISTRATION_REF_CLAIM, isHttpUri, toRegistrationRefClaim, validateRegistrationRefRaw } from './registration-ref.ts';
import { buildAuthorizationRequestJar } from './jar.ts';
import { loadWrpac, validateWrpacChain } from './wrpac.ts';
import { NO_REVOCATION } from './revocation.ts';
import { WRPRC_JWT_TYPE, WRPRC_MAX_VALIDITY_SECONDS, verifyWrprc } from './wrprc.ts';
import { RegistrarClient, type RegistrarFetcher } from './registrar.ts';
import { ENTITLEMENTS_NS, OID_ANY_EXTENDED_KEY_USAGE, WRPRC_POLICY_OID } from './oid.ts';

const PID_URI = `${ENTITLEMENTS_NS}PID_Provider`;
const SERVICE_URI = `${ENTITLEMENTS_NS}Service_Provider`;

function toJwk(key: CryptoKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey('jwk', key) as Promise<JsonWebKey>;
}

function buildWrprcToken(options: {
  leafKey: CryptoKey;
  chain: Uint8Array[];
  sub?: string;
  iatOffset?: number;
  expOffset?: number;
  entitlements?: string[];
  policyId?: string[];
  registryUri?: string;
  typ?: string;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signWrprc(
    {
      sub: options.sub ?? 'test-wrp-1',
      iat: now + (options.iatOffset ?? 0),
      exp: now + (options.expOffset ?? 3600),
      registry_uri: options.registryUri ?? 'https://TEST-registrar.example/api/v1',
      entitlements: options.entitlements ?? [PID_URI],
      policy_id: options.policyId ?? [WRPRC_POLICY_OID],
    },
    options.leafKey,
    options.chain,
  );
}

/** Header-Typ verfaelschen, ohne die Signatur zu aendern. */
function retypedToken(token: string, typ: string): string {
  const head = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf-8')) as Record<string, unknown>;
  head.typ = typ;
  return [Buffer.from(JSON.stringify(head)).toString('base64url'), ...token.split('.').slice(1)].join('.');
}

/** x5c-Header entfernen (Header neu bauen). */
function tokenWithoutX5c(token: string): string {
  const head = { alg: 'ES256', typ: WRPRC_JWT_TYPE };
  void token.split('.')[0];
  return [Buffer.from(JSON.stringify(head)).toString('base64url'), ...token.split('.').slice(1)].join('.');
}

let authorityVerifierKey: TestKeyMaterial;
let accessCa: Awaited<ReturnType<typeof createAccessCa>>;
let wrpac: Awaited<ReturnType<typeof accessCa['issueWrpac']>>;
let registrarSigningKey: CryptoKeyPair;
let attackerKey: CryptoKeyPair;

beforeAll(async () => {
  authorityVerifierKey = await generateTestKeyMaterial('Onboarding Verifier TEST');
  accessCa = await createAccessCa();
  wrpac = await accessCa.issueWrpac({
    subjectCn: 'Test RP WRPAC TEST',
    entitlementOids: [Object.keys(TEST_ENTITLEMENT_MAP)[0]],
  });
  registrarSigningKey = await generateTestKeyPair();
  attackerKey = await generateTestKeyPair();
});

describe('RP-Onboarding (Baustein B)', () => {
  describe('RegistrationRef (RPRC_19a)', () => {
    it('validiert einen gueltigen Registrierungsnachweis und erzeugt den Claim', () => {
      const ref = validateRegistrationRefRaw({
        client_name: 'Test GmbH (TEST)',
        client_id: 'test-wrp-1',
        registry_uri: 'https://TEST-registrar.example/api/v1',
        intended_use_id: 'use-pid-1',
      });
      assert.equal(ref.clientName, 'Test GmbH (TEST)');
      assert.equal(ref.clientId, 'test-wrp-1');
      assert.deepEqual(toRegistrationRefClaim(ref)[REGISTRATION_REF_CLAIM], {
        client_name: 'Test GmbH (TEST)',
        client_id: 'test-wrp-1',
        registry_uri: 'https://TEST-registrar.example/api/v1',
        intended_use_id: 'use-pid-1',
      });
    });

    it('lehnt ungueltige Registrierungsnachweise ab', () => {
      const invalid = [
        {},
        { client_name: '', client_id: 'x', registry_uri: 'https://x', intended_use_id: 'y' },
        { client_name: 'Test', client_id: 'x', registry_uri: 'not-a-url', intended_use_id: 'y' },
        { client_name: 'Test', client_id: 'x', registry_uri: 'https://x', intended_use_id: '' },
        { client_name: 'Test', client_id: 'x', registry_uri: 'ftp://x', intended_use_id: 'y' },
      ] as unknown[];
      for (const bad of invalid) {
        assert.throws(() => validateRegistrationRefRaw(bad), ErrRegistrationRef);
      }
      assert.equal(isHttpUri('ftp://x'), false);
    });
  });

  describe('WRPAC', () => {
    it('laedt ein konformes Zugriffszertifikat und verifiziert die Kette zum Access-CA-Anker', async () => {
      const loaded = await loadWrpac(wrpac.certDer, { entitlementMap: TEST_ENTITLEMENT_MAP });
      assert.equal(loaded.subjectCommonName, 'Test RP WRPAC TEST');
      assert.deepEqual([...loaded.entitlements], [SERVICE_URI]);
      assert.ok(loaded.contactSanValues.length > 0, 'Kontakt-SAN muss vorhanden sein');
      await validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: NO_REVOCATION });
    });

    it('lehnt WRPAC ohne EUDIWRP-Policy ab', async () => {
      const bad = await accessCa.issueWrpac({ subjectCn: 'No Policy TEST', policyOids: [TEST_NON_WRPA_POLICY] });
      await assert.rejects(() => loadWrpac(bad.certDer, { entitlementMap: TEST_ENTITLEMENT_MAP }), ErrWrpacPolicy);
    });

    it('lehnt WRPAC mit unbekannter Entitlement-OID ab', async () => {
      const bad = await accessCa.issueWrpac({ subjectCn: 'Unknown Ent TEST', entitlementOids: [TEST_UNKNOWN_ENTITLEMENT_OID] });
      await assert.rejects(() => loadWrpac(bad.certDer, { entitlementMap: TEST_ENTITLEMENT_MAP }), ErrUnknownEntitlement);
    });

    it('lehnt WRPAC ohne Kontakt-SAN ab', async () => {
      const bad = await accessCa.issueWrpac({ subjectCn: 'No SAN TEST', contactSan: [] });
      await assert.rejects(() => loadWrpac(bad.certDer, { entitlementMap: TEST_ENTITLEMENT_MAP }), ErrWrpacContactSan);
    });

    it('lehnt WRPAC ohne digitalSignature ab', async () => {
      const bad = await accessCa.issueWrpac({ subjectCn: 'No KU TEST', keyUsageDigitalSignature: false });
      await assert.rejects(() => loadWrpac(bad.certDer, { entitlementMap: TEST_ENTITLEMENT_MAP }), ErrWrpacKeyUsage);
    });

    it('lehnt WRPAC mit unzulaessiger EKU ab', async () => {
      const bad = await accessCa.issueWrpac({ subjectCn: 'Wrong EKU TEST', extendedKeyUsages: ['1.3.6.1.5.5.7.3.1'] });
      await assert.rejects(() => loadWrpac(bad.certDer, { entitlementMap: TEST_ENTITLEMENT_MAP }), ErrWrpacExtKeyUsage);
    });

    it('akzeptiert WRPAC ohne EKU bzw. mit anyExtendedKeyUsage', async () => {
      const noEku = await accessCa.issueWrpac({ subjectCn: 'No EKU TEST', extendedKeyUsages: [] });
      await loadWrpac(noEku.certDer, { entitlementMap: TEST_ENTITLEMENT_MAP });
      const anyEku = await accessCa.issueWrpac({ subjectCn: 'Any EKU TEST', extendedKeyUsages: [OID_ANY_EXTENDED_KEY_USAGE] });
      await loadWrpac(anyEku.certDer, { entitlementMap: TEST_ENTITLEMENT_MAP });
    });

    it('lehnt WRPAC mit Kette zu fremdem Anker ab', async () => {
      const other = await createAccessCa('Other CA TEST');
      await assert.rejects(() => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [other.caCertDer], revocation: NO_REVOCATION }), ErrTrustPath);
    });
  });

  describe('WRPRC (JWT)', () => {
    let issuer: Awaited<ReturnType<typeof createWrprcIssuer>>;
    let leaf: Awaited<ReturnType<typeof createWrprcLeaf>>;
    let chain: Uint8Array[];

    beforeAll(async () => {
      issuer = await createWrprcIssuer();
      leaf = await createWrprcLeaf(issuer);
      chain = [leaf.certDer, issuer.certDer];
    });

    it('verifiziert ein gueltiges WRPRC gegen die Issuer-Anker', async () => {
      const token = await buildWrprcToken({ leafKey: leaf.key.privateKey, chain });
      const read = await verifyWrprc(token, { wrprcIssuerAnchors: [issuer.certDer], allowedEntitlements: [PID_URI], revocation: NO_REVOCATION });
      assert.equal(read.sub, 'test-wrp-1');
      assert.deepEqual([...read.entitlements], [PID_URI]);
      assert.ok(read.expiresAt.getTime() > read.issuedAt.getTime());
    });

    it('lehnt einen falschen Token-Typ ab', async () => {
      const token = await buildWrprcToken({ leafKey: leaf.key.privateKey, chain });
      await assert.rejects(() => verifyWrprc(retypedToken(token, 'jwt'), { wrprcIssuerAnchors: [issuer.certDer], allowedEntitlements: [PID_URI], revocation: NO_REVOCATION }), ErrWrprcType);
    });

    it('lehnt fehlende x5c-Kette ab', async () => {
      const token = await buildWrprcToken({ leafKey: leaf.key.privateKey, chain });
      await assert.rejects(() => verifyWrprc(tokenWithoutX5c(token), { wrprcIssuerAnchors: [issuer.certDer], allowedEntitlements: [PID_URI], revocation: NO_REVOCATION }), ErrWrprcHeader);
    });

    it('lehnt eine falsche Signatur ab', async () => {
      const otherKey = await generateTestKeyPair();
      const token = await signWrprc(
        {
          sub: 'test-wrp-1',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600,
          registry_uri: 'https://TEST-registrar.example/api/v1',
          entitlements: [PID_URI],
          policy_id: [WRPRC_POLICY_OID],
        },
        otherKey.privateKey,
        chain,
      );
      await assert.rejects(() => verifyWrprc(token, { wrprcIssuerAnchors: [issuer.certDer], allowedEntitlements: [PID_URI], revocation: NO_REVOCATION }), ErrWrprcSignature);
    });

    it('lehnt ein WRPRC ab, dessen Kette nicht zu den Ankern fuehrt', async () => {
      const otherIssuer = await createWrprcIssuer('Other WRPRC Issuer TEST');
      const token = await buildWrprcToken({ leafKey: leaf.key.privateKey, chain });
      await assert.rejects(() => verifyWrprc(token, { wrprcIssuerAnchors: [otherIssuer.certDer], allowedEntitlements: [PID_URI], revocation: NO_REVOCATION }), ErrTrustPath);
    });

    it('lehnt fehlende Pflicht-Claims ab', async () => {
      const token = await signWrprc(
        { sub: 'x', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 },
        leaf.key.privateKey,
        chain,
      );
      await assert.rejects(() => verifyWrprc(token, { wrprcIssuerAnchors: [issuer.certDer], allowedEntitlements: [PID_URI], revocation: NO_REVOCATION }), ErrWrprcClaims);
    });

    it('lehnt fehlende WRPRC-Policy in policy_id ab', async () => {
      const token = await buildWrprcToken({ leafKey: leaf.key.privateKey, chain, policyId: ['1.2.3.4'] });
      await assert.rejects(() => verifyWrprc(token, { wrprcIssuerAnchors: [issuer.certDer], allowedEntitlements: [PID_URI], revocation: NO_REVOCATION }), ErrWrprcPolicyId);
    });

    it('lehnt ab, wenn kein berechtigtes Entitlement vorhanden ist', async () => {
      const token = await buildWrprcToken({ leafKey: leaf.key.privateKey, chain, entitlements: [SERVICE_URI] });
      await assert.rejects(() => verifyWrprc(token, { wrprcIssuerAnchors: [issuer.certDer], allowedEntitlements: [PID_URI], revocation: NO_REVOCATION }), ErrWrprcEntitlement);
    });

    it('lehnt ein abgelaufenes WRPRC ab', async () => {
      const token = await buildWrprcToken({ leafKey: leaf.key.privateKey, chain, iatOffset: -7200, expOffset: -3600 });
      await assert.rejects(() => verifyWrprc(token, { wrprcIssuerAnchors: [issuer.certDer], allowedEntitlements: [PID_URI], revocation: NO_REVOCATION }), ErrWrprcExpired);
    });

    it('lehnt ein noch nicht gueltiges WRPRC ab', async () => {
      const token = await buildWrprcToken({ leafKey: leaf.key.privateKey, chain, iatOffset: 120, expOffset: 3600 });
      await assert.rejects(() => verifyWrprc(token, { wrprcIssuerAnchors: [issuer.certDer], allowedEntitlements: [PID_URI], revocation: NO_REVOCATION }), ErrWrprcNotYetValid);
    });

    it('lehnt ein Gueltigkeitsfenster ueber 12 Monate ab', async () => {
      const token = await buildWrprcToken({ leafKey: leaf.key.privateKey, chain, iatOffset: 0, expOffset: WRPRC_MAX_VALIDITY_SECONDS + 60 });
      await assert.rejects(() => verifyWrprc(token, { wrprcIssuerAnchors: [issuer.certDer], allowedEntitlements: [PID_URI], revocation: NO_REVOCATION }), ErrWrprcValidity);
    });

    it('lehnt malformed bearer (kein JWS) ab', async () => {
      await assert.rejects(() => verifyWrprc('kein-jws', { wrprcIssuerAnchors: [issuer.certDer], allowedEntitlements: [PID_URI], revocation: NO_REVOCATION }), ErrMalformed);
    });
  });

  describe('Registrar-Client (Mock)', () => {
    const servers: MockRegistrarServer[] = [];

    afterAll(async () => {
      for (const s of servers) await s.close();
    });

    function newServer(opts: ConstructorParameters<typeof MockRegistrarServer>[0]): MockRegistrarServer {
      const s = new MockRegistrarServer(opts);
      servers.push(s);
      return s;
    }

    let server: MockRegistrarServer;

    async function client(uri: string, opts: { maxResponseAgeSeconds?: number } = {}) {
      const jwk = await toJwk(registrarSigningKey.publicKey);
      return new RegistrarClient({ registryUri: uri, pinnedPublicJwk: jwk, maxResponseAgeSeconds: opts.maxResponseAgeSeconds });
    }

    it('ruft WRP-Verzeichnis, WRP-Eintrag und aktiven Intended Use ab (JWS, gepinnt)', async () => {
      const record = testWrp({ identifier: 'test-wrp-1' }, [intendedUse('use-pid-1')]);
      server = newServer({ signingKey: registrarSigningKey, corruptKey: attackerKey });
      const base = await server.start([record]);
      const c = await client(base);

      const list = await c.getWrpList();
      assert.equal(list.items.length, 1);
      assert.equal(list.items[0].identifier, 'test-wrp-1');

      const wrp = await c.getWrpByIdentifier('test-wrp-1');
      assert.equal(wrp.legalName, 'Test GmbH (TEST)');

      const use = await c.requireActiveIntendedUse('use-pid-1');
      assert.equal(use.active, true);
      assert.equal(use.status, 'active');
    });

    it('lehnt eine Registrar-Antwort mit falscher Signatur ab', async () => {
      const record = testWrp({ identifier: 'test-wrp-1' });
      server = newServer({ signingKey: registrarSigningKey, corruptKey: attackerKey });
      const base = await server.start([record]);
      server.setCorruptSignatures(true);
      const c = await client(base);
      await assert.rejects(() => c.getWrpList(), ErrRegistrarSignature);
    });

    it('kartiert 404 auf WRP-/Intended-Use-Fehler', async () => {
      const record = testWrp({ identifier: 'test-wrp-1' }, [intendedUse('use-pid-1')]);
      server = newServer({ signingKey: registrarSigningKey });
      const base = await server.start([record]);
      const c = await client(base);

      await assert.rejects(() => c.getWrpByIdentifier('unbekannt'), ErrWrpNotFound);
      await assert.rejects(() => c.checkIntendedUse('use-unbekannt'), ErrIntendedUseNotFound);
    });

    it('lehnt einen nicht aktiven Intended Use ab', async () => {
      const record = testWrp({ identifier: 'test-wrp-1' }, [intendedUse('use-pid-1', 'revoked')]);
      server = newServer({ signingKey: registrarSigningKey });
      const base = await server.start([record]);
      const c = await client(base);
      await assert.rejects(() => c.requireActiveIntendedUse('use-pid-1'), ErrIntendedUseNotActive);
      assert.equal(toIntendedUseStatus(record.item, 'use-pid-1').status, 'revoked');
    });

    it('lehnt eine zu alte Antwort ab (Replay-Schutz)', async () => {
      const record = testWrp({ identifier: 'test-wrp-1' });
      server = newServer({ signingKey: registrarSigningKey, iatOffsetSeconds: -10 });
      const base = await server.start([record]);
      const c = await client(base, { maxResponseAgeSeconds: 1 });
      await assert.rejects(() => c.getWrpList(), ErrRegistrarStale);
    });

    it('ordnet ein Timeout dem ErrRegistrarTimeout zu (nicht Unavailable)', async () => {
      const hanging: RegistrarFetcher = (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(Object.assign(new Error('abort'), { name: 'AbortError' })));
        });
      const jwk = await toJwk(registrarSigningKey.publicKey);
      const c = new RegistrarClient({
        registryUri: 'https://TEST-registrar.example/api/v1',
        pinnedPublicJwk: jwk,
        fetcher: hanging,
        timeoutMs: 30,
        minRequestIntervalMs: 0,
      });
      await assert.rejects(() => c.getWrpList(), ErrRegistrarTimeout);
    });

    it('pacet Anfragen auf minRequestIntervalMs (serialisiert)', async () => {
      const record = testWrp({ identifier: 'test-wrp-1' });
      server = newServer({ signingKey: registrarSigningKey });
      const base = await server.start([record]);
      const jwk = await toJwk(registrarSigningKey.publicKey);
      const sleeps: number[] = [];
      const t0 = Math.floor(Date.now() / 1000);
      let t = t0;
      const c = new RegistrarClient({
        registryUri: base,
        pinnedPublicJwk: jwk,
        minRequestIntervalMs: 1000,
        now: () => t,
        sleep: async (ms) => { sleeps.push(ms); },
      });

      await c.getWrpList();
      await c.getWrpList();
      assert.equal(sleeps.length, 1, 'der zweite Abruf wartet auf den Pacing-Slot');
      assert.equal(sleeps[0], 1000);

      t += 1;
      await c.getWrpList();
      assert.equal(sleeps.length, 1, 'nach Ablauf des Intervalls kein weiteres Warten');
      assert.equal(server.requestCount, 3);
    });
  });

  describe('JAR mit registration_ref (RPRC_19a)', () => {
    it('bettet den registration_ref in das signierte Request Object ein', async () => {
      const ref = validateRegistrationRefRaw({
        client_name: 'Test GmbH (TEST)',
        client_id: 'test-wrp-1',
        registry_uri: 'https://TEST-registrar.example/api/v1',
        intended_use_id: 'use-pid-1',
      });
      const jar = await buildAuthorizationRequestJar({
        requestUri: 'https://verifier.example.test/request',
        responseUri: 'https://verifier.example.test/direct_post',
        nonce: 'nonce-1',
        state: 'state-1',
        dcqlQuery: { query: [{ id: 'pid', format: 'dc+sd-jwt' }] },
        registrationRef: ref,
        privateKey: authorityVerifierKey.privateKey,
        certificateChain: [authorityVerifierKey.certDerBytes],
      });

      const claims = decodeJwt(jar.requestObject);
      const rr = claims.registration_ref as { client_name: string; client_id: string; intended_use_id: string };
      assert.equal(rr.client_name, 'Test GmbH (TEST)');
      assert.equal(rr.client_id, 'test-wrp-1');
      assert.equal(rr.intended_use_id, 'use-pid-1');

      const verified = await jwtVerify(jar.requestObject, createLocalJWKSet({ keys: [authorityVerifierKey.publicJwk] }));
      assert.equal(typeof verified.payload.client_id, 'string');
    });
  });
});