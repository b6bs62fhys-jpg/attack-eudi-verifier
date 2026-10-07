/**
 * Paket 3: Sandbox-Tauglichkeit.
 *
 * Geprüft wird, was die offizielle Developer-Doku und die
 * Referenzimplementierung EUDIPLO für eine Presentation Request an die
 * Sandbox-Wallet zeigen, und zwar am Request Object, das der Dienst im
 * Produktionsmodus tatsächlich ausliefert:
 *   a) verifier_info mit dem Registrierungszertifikat
 *   b) Request URI und Response URI aus ATTACK_PUBLIC_BASE_URL
 *   c) Wallet-Aufruf als openid4vp://-Link
 *   d) vct urn:eudi:pid:de:1 mit den Claim-Namen der deutschen PID
 *   e) sd-jwt_alg_values und kb-jwt_alg_values mit Bindestrich
 * Das Zugangszertifikat ist hier wie in der Sandbox von einer CA ausgestellt,
 * und im x5c-Kopf steht nur dieses eine Zertifikat.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import type http from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, exportJWK, jwtVerify, SignJWT } from 'jose';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';

import { ConfigError, ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM, ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM, ENV_ATTACK_VERIFIER_KEY_PEM, ENV_NODE_ENV, loadConfig } from '../config.ts';
import { buildSdJwtVc, generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { buildAuthorizationRequestJar, JarBuildError } from '../onboarding/jar.ts';
import { createAccessCa, type IssuedWrpac } from '../onboarding/mock-pki.ts';
import { createApp } from './app.ts';
import { AuditLog } from './audit.ts';
import { bootstrapService } from './bootstrap.ts';
import { PID_VCT_DE, PID_VCT_DEFAULT, REQUEST_PROFILE_TEMPLATES } from './profile.ts';
import { ENV_ATTACK_REGISTRATION_CERTIFICATE_FILE, loadRegistrationCertificate, parseRegistrationCertificate } from './registration-certificate.ts';
import { buildWalletUrl, VerifierService, type ServiceKeys } from './service.ts';
import { TenantStore } from './tenant.ts';
import { addTenantEntry, emptyTenantFile, ENV_ATTACK_TENANTS_FILE, writeTenantFile } from './tenant-file.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';

const BASE = 'https://verifier.example/attack';

let dir!: string;
let registrationJwt!: string;

function derToPem(der: Uint8Array, label: string): string {
  const lines = Buffer.from(der).toString('base64').match(/.{1,64}/g)?.join('\n') ?? '';
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

async function jwt(payload: Record<string, unknown>, header: Record<string, unknown> = { alg: 'ES256', typ: 'rc-wrp+jwt' }): Promise<string> {
  const key = await generateTestKeyMaterial('Registrar TEST');
  return new SignJWT(payload).setProtectedHeader(header as { alg: string }).sign(key.privateKey);
}

async function listen(server: http.Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

async function close(server: http.Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'attack-sandbox-'));
  registrationJwt = await jwt({ sub: 'attack', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 });
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('b) ATTACK_PUBLIC_BASE_URL', () => {
  const prod = { [ENV_NODE_ENV]: 'production' };

  it('im Produktionsmodus Pflicht', () => {
    assert.throws(() => loadConfig(prod), (e: unknown) => e instanceof ConfigError && /ATTACK_PUBLIC_BASE_URL ist im Produktionsmodus Pflicht/.test(e.message));
  });

  it('https wird angenommen, abschließender Schrägstrich fällt weg, ein Pfad bleibt', () => {
    assert.equal(loadConfig({ ...prod, ATTACK_PUBLIC_BASE_URL: 'https://verifier.example/' }).publicBaseUrl, 'https://verifier.example');
    assert.equal(loadConfig({ ...prod, ATTACK_PUBLIC_BASE_URL: ' https://verifier.example/attack// ' }).publicBaseUrl, 'https://verifier.example/attack');
  });

  it('ohne Produktionsmodus optional', () => {
    assert.equal(loadConfig({}).publicBaseUrl, undefined);
  });

  it('http nur mit Entwicklungsschalter', () => {
    assert.throws(() => loadConfig({ ATTACK_PUBLIC_BASE_URL: 'http://verifier.example' }), /muss mit https/);
    assert.equal(loadConfig({ ATTACK_DEV_MODE: 'true', ATTACK_PUBLIC_BASE_URL: 'http://127.0.0.1:8080' }).publicBaseUrl, 'http://127.0.0.1:8080');
  });

  for (const [titel, wert, muster] of [
    ['keine URL', 'verifier.example', /keine gültige URL/],
    ['anderes Schema', 'ftp://verifier.example', /muss mit https/],
    ['mit Query', 'https://verifier.example/?a=1', /Query/],
    ['mit Fragment', 'https://verifier.example/#x', /Fragment/],
    ['mit Zugangsdaten', 'https://nutzer:geheim@verifier.example', /Zugangsdaten/],
  ] as const) {
    it(`${titel} -> ConfigError`, () => {
      assert.throws(() => loadConfig({ ...prod, ATTACK_PUBLIC_BASE_URL: wert }), (e: unknown) => e instanceof ConfigError && muster.test(e.message));
    });
  }
});

describe('a) Registrierungszertifikat lesen', () => {
  it('das JWT selbst als Datei', () => {
    assert.equal(parseRegistrationCertificate(`${registrationJwt}\n`), registrationJwt);
  });

  it('JSON-Datei mit genau einem JWT, auch verschachtelt oder als JSON-String', () => {
    assert.equal(parseRegistrationCertificate(JSON.stringify({ jwt: registrationJwt })), registrationJwt);
    assert.equal(parseRegistrationCertificate(JSON.stringify({ data: { certificate: registrationJwt }, name: 'Attack' })), registrationJwt);
    assert.equal(parseRegistrationCertificate(JSON.stringify(registrationJwt)), registrationJwt);
    assert.equal(parseRegistrationCertificate(JSON.stringify({ a: registrationJwt, b: [registrationJwt] })), registrationJwt, 'dasselbe JWT zweimal ist eindeutig');
  });

  it('kein, mehrere oder unbrauchbare JWTs -> ConfigError ohne Inhalt in der Meldung', async () => {
    const zweites = await jwt({ sub: 'anderes' });
    const ohneAlg = await jwt({ sub: 'x' });
    const [, nutzlast, signatur] = ohneAlg.split('.');
    const algNone = `${Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url')}.${nutzlast}.${signatur}`;
    const abgelaufen = await jwt({ sub: 'x', exp: Math.floor(Date.now() / 1000) - 3600 });
    const faelle: Array<[string, RegExp]> = [
      ['kein json und kein jwt', /weder ein JWT noch gültiges JSON/],
      [JSON.stringify({ name: 'leer' }), /kein JWT/],
      [JSON.stringify({ a: registrationJwt, b: zweites }), /2 verschiedene JWTs/],
      [algNone, /"alg"/],
      ['e30.e30.e30', /"alg"/],
      [abgelaufen, /abgelaufen/],
      [`${Buffer.from('{"alg":"ES256"}').toString('base64url')}.${Buffer.from('[1]').toString('base64url')}.c2ln`, /Nutzdaten sind kein Objekt/],
    ];
    for (const [inhalt, muster] of faelle) {
      assert.throws(
        () => parseRegistrationCertificate(inhalt),
        (e: unknown) => {
          assert.ok(e instanceof ConfigError);
          assert.match(e.message, /^ATTACK_REGISTRATION_CERTIFICATE_FILE: /);
          assert.match(e.message, muster);
          assert.ok(!e.message.includes(registrationJwt.slice(0, 20)), 'kein Inhalt in der Meldung');
          return true;
        },
        String(muster),
      );
    }
  });

  it('Datei unlesbar -> ConfigError; lesbare Datei -> verifier_info-Eintrag', async () => {
    await assert.rejects(loadRegistrationCertificate(join(dir, 'fehlt.json')), /nicht lesbar/);
    const pfad = join(dir, 'registration-certificate.json');
    await writeFile(pfad, JSON.stringify({ jwt: registrationJwt }));
    assert.deepEqual(await loadRegistrationCertificate(pfad), { format: 'registration_cert', data: registrationJwt });
  });
});

describe('Request Object im Produktionsmodus, wie es an die Sandbox-Wallet geht', () => {
  let access!: IssuedWrpac;
  let env!: Record<string, string>;
  let apiKey!: string;
  let server!: http.Server;
  let local!: string;

  beforeAll(async () => {
    // Zugangszertifikat von einer CA ausgestellt (in der Sandbox: "German
    // Registrar"); in die Kettendatei kommt nur das Zugangszertifikat selbst.
    const ca = await createAccessCa('Registrar CA TEST');
    access = await ca.issueWrpac({ subjectCn: 'Attack Sandbox (TEST)' });
    const issuer = await generateTestKeyMaterial('Sandbox Issuer TEST');
    await writeFile(join(dir, 'access.key.pem'), derToPem(new Uint8Array(await crypto.subtle.exportKey('pkcs8', access.key.privateKey)), 'PRIVATE KEY'));
    await writeFile(join(dir, 'access.pem'), derToPem(access.certDer, 'CERTIFICATE'));
    await writeFile(join(dir, 'issuer-anchors.pem'), derToPem(issuer.certDerBytes, 'CERTIFICATE'));
    await writeFile(join(dir, 'registration-certificate.json'), JSON.stringify({ jwt: registrationJwt }));
    const added = addTenantEntry(emptyTenantFile(), { id: 'attack-sandbox', name: 'Attack Sandbox', requestProfile: 'pid_de' });
    await writeTenantFile(join(dir, 'tenants.json'), added.file);
    apiKey = added.apiKey;
    env = {
      [ENV_NODE_ENV]: 'production',
      ATTACK_PUBLIC_BASE_URL: `${BASE}/`,
      [ENV_ATTACK_VERIFIER_KEY_PEM]: join(dir, 'access.key.pem'),
      [ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]: join(dir, 'access.pem'),
      [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: join(dir, 'issuer-anchors.pem'),
      [ENV_ATTACK_TENANTS_FILE]: join(dir, 'tenants.json'),
      [ENV_ATTACK_REGISTRATION_CERTIFICATE_FILE]: join(dir, 'registration-certificate.json'),
    };
    const boot = await bootstrapService(env, () => {});
    assert.equal(boot.service.baseUrl, BASE, 'die Basis-URL kommt aus der Konfiguration, nicht vom Port');
    server = createApp({ appLabel: 'sandbox-test', tenants: boot.tenants, service: boot.service });
    local = await listen(server);
  });

  afterAll(async () => {
    await close(server);
  });

  async function create(): Promise<Record<string, string>> {
    const res = await fetch(`${local}/v1/verification-requests`, { method: 'POST', headers: { authorization: `Bearer ${apiKey}` } });
    assert.equal(res.status, 201, await res.clone().text());
    return (await res.json()) as Record<string, string>;
  }

  it('b) Request URI und Response URI kommen aus ATTACK_PUBLIC_BASE_URL', async () => {
    const out = await create();
    assert.equal(out.responseUri, `${BASE}/direct_post`);
    assert.equal(out.requestObjectUri, `${BASE}/v1/verification-requests/${out.sessionId}/request-object`);
    const payload = decodeJwt(out.requestObject as string);
    assert.equal(payload.response_uri, `${BASE}/direct_post`);
    assert.equal(payload.request_uri, out.requestObjectUri);
  });

  it('a) verifier_info trägt das Registrierungszertifikat, als Liste wie in OpenID4VP 1.0 und EUDIPLO', async () => {
    const payload = decodeJwt((await create()).requestObject as string);
    assert.deepEqual(payload.verifier_info, [{ format: 'registration_cert', data: registrationJwt }]);
  });

  it('Kopf: nur das Zugangszertifikat in x5c, client_id ist sein x509_hash, Signatur passt', async () => {
    const { requestObject } = await create();
    const header = decodeProtectedHeader(requestObject as string);
    assert.equal(header.typ, 'oauth-authz-req+jwt');
    assert.equal(header.alg, 'ES256');
    assert.deepEqual(header.x5c, [Buffer.from(access.certDer).toString('base64')]);
    const clientId = `x509_hash:${createHash('sha256').update(access.certDer).digest('base64url')}`;
    const jwk = await exportJWK(access.key.publicKey);
    const { payload } = await jwtVerify(requestObject as string, createLocalJWKSet({ keys: [{ ...jwk, alg: 'ES256' }] }));
    assert.equal(payload.client_id, clientId);
    assert.equal(payload.iss, clientId);
    assert.equal(payload.response_mode, 'direct_post.jwt');
    assert.equal(payload.aud, 'https://self-issued.me/v2');
  });

  it('c) walletUrl ist der openid4vp-Aufruf mit client_id, request_uri und request_uri_method=get', async () => {
    const out = await create();
    const payload = decodeJwt(out.requestObject as string);
    assert.equal(out.walletUrl, buildWalletUrl(payload.client_id as string, out.requestObjectUri as string));
    assert.match(out.walletUrl as string, /^openid4vp:\/\/\?client_id=x509_hash%3A[A-Za-z0-9_-]+&request_uri=https%3A%2F%2Fverifier\.example%2Fattack%2F/);
    const url = new URL(out.walletUrl as string);
    assert.equal(url.protocol, 'openid4vp:');
    assert.equal(url.searchParams.get('client_id'), payload.client_id);
    assert.equal(url.searchParams.get('request_uri'), out.requestObjectUri);
    assert.equal(url.searchParams.get('request_uri_method'), 'get');
  });

  it('der Dienst liefert das Request Object unter dem Pfad der Request URI aus', async () => {
    const out = await create();
    const pfad = new URL(out.requestObjectUri as string).pathname.replace(/^\/attack/, '');
    const res = await fetch(`${local}${pfad}`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'application/oauth-authz-req+jwt');
    assert.equal(await res.text(), out.requestObject);
  });

  it('d) Profil pid_de: vct urn:eudi:pid:de:1 mit given_name, family_name, birthdate', async () => {
    const payload = decodeJwt((await create()).requestObject as string);
    const query = payload.dcql_query as { credentials: Array<{ format: string; meta: { vct_values: string[] }; claims: Array<{ path: string[] }> }> };
    const credential = query.credentials[0];
    assert.equal(credential?.format, 'dc+sd-jwt');
    assert.deepEqual(credential?.meta.vct_values, [PID_VCT_DE]);
    assert.deepEqual(credential?.claims.map((c) => c.path), [['given_name'], ['family_name'], ['birthdate']]);
  });

  it('e) vp_formats_supported mit sd-jwt_alg_values und kb-jwt_alg_values', async () => {
    const payload = decodeJwt((await create()).requestObject as string);
    const formats = (payload.client_metadata as { vp_formats_supported: Record<string, Record<string, unknown>> }).vp_formats_supported;
    assert.deepEqual(formats['dc+sd-jwt'], { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] });
  });
});

describe('Bibliothekspfad ohne Registrierungszertifikat', () => {
  it('kein verifier_info, aber ebenfalls die korrigierten Feldnamen und ein walletUrl', async () => {
    const tenants = new TenantStore();
    tenants.add({ id: 'a', name: 'A', apiKey: 'schluessel-a-123' });
    const verifier = await generateTestKeyMaterial('Bibliothekspfad Verifier TEST');
    const keys: ServiceKeys = { privateKey: verifier.privateKey, publicKey: verifier.publicKey, publicJwk: verifier.publicJwk, certificateChain: [verifier.certDerBytes] };
    const service = new VerifierService(tenants, new AuditLog(), keys, verifier.certDerBytes, undefined, undefined, undefined, undefined, true, DEV_TEST_OPTIONS);
    service.baseUrl = 'http://127.0.0.1:9';
    const out = await service.createRequest('a', {});
    const payload = decodeJwt(out.requestObject);
    assert.equal(payload.verifier_info, undefined);
    const formats = (payload.client_metadata as { vp_formats_supported: Record<string, unknown> }).vp_formats_supported;
    assert.deepEqual(formats['dc+sd-jwt'], { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] });
    assert.equal(out.walletUrl, buildWalletUrl(payload.client_id as string, out.requestObjectUri));
  });
});

describe('eigener JAR-Pfad: dieselben Vorprüfungen wie die Bibliothek', () => {
  const basis = {
    requestUri: 'https://verifier.example/r',
    responseUri: 'https://verifier.example/direct_post',
    nonce: 'n',
    state: 's',
    dcqlQuery: {},
    verifierInfo: [{ format: 'registration_cert', data: 'a.b.c' }],
  };

  it('selbstsigniertes Blatt ohne Freigabe -> self_signed_leaf', async () => {
    const v = await generateTestKeyMaterial('Selbstsigniert TEST');
    await assert.rejects(
      buildAuthorizationRequestJar({ ...basis, privateKey: v.privateKey, publicKey: v.publicKey, certificateChain: [v.certDerBytes] }),
      (e: unknown) => e instanceof JarBuildError && e.code === 'self_signed_leaf',
    );
  });

  it('Schlüssel passt nicht zum Zertifikat -> signing_key_cert_mismatch', async () => {
    const v = await generateTestKeyMaterial('Zertifikat TEST');
    const fremd = await generateTestKeyMaterial('Fremder Schlüssel TEST');
    await assert.rejects(
      buildAuthorizationRequestJar({ ...basis, privateKey: fremd.privateKey, publicKey: fremd.publicKey, allowSelfSignedCertificate: true, certificateChain: [v.certDerBytes] }),
      (e: unknown) => e instanceof JarBuildError && e.code === 'signing_key_cert_mismatch',
    );
  });
});

describe('d) Durchlauf mit deutscher PID (urn:eudi:pid:de:1)', () => {
  let issuer!: TestKeyMaterial;
  let holder!: TestKeyMaterial;
  let server!: http.Server;
  let base!: string;
  let verifierJwk!: JsonWebKey;
  const KEY = 'schluessel-pid-de-123';

  beforeAll(async () => {
    const tenants = new TenantStore();
    tenants.add({ id: 'de', name: 'DE', apiKey: KEY, requestProfile: 'pid_de' });
    const verifier = await generateTestKeyMaterial('PID DE Verifier TEST');
    issuer = await generateTestKeyMaterial('PID DE Issuer TEST');
    holder = await generateTestKeyMaterial('PID DE Holder TEST');
    verifierJwk = verifier.publicJwk;
    const keys: ServiceKeys = { privateKey: verifier.privateKey, publicKey: verifier.publicKey, publicJwk: verifier.publicJwk, certificateChain: [verifier.certDerBytes] };
    const service = new VerifierService(tenants, new AuditLog(), keys, issuer.certDerBytes, undefined, undefined, undefined, undefined, true, DEV_TEST_OPTIONS);
    server = createApp({ appLabel: 'pid-de-test', tenants, service });
    base = await listen(server);
    service.baseUrl = base;
  });

  afterAll(async () => {
    await close(server);
  });

  async function vorlegen(vct: string): Promise<Record<string, unknown>> {
    const created = await fetch(`${base}/v1/verification-requests`, { method: 'POST', headers: { authorization: `Bearer ${KEY}` } });
    assert.equal(created.status, 201);
    const { state, sessionId, requestObject } = (await created.json()) as { state: string; sessionId: string; requestObject: string };
    const { payload } = await jwtVerify(requestObject, createLocalJWKSet({ keys: [verifierJwk] }));
    const built = await buildSdJwtVc({
      issuerKey: issuer,
      holderKey: holder,
      vct,
      claimName: 'given_name',
      claimValue: 'Erika',
      additionalDisclosures: { family_name: 'Mustermann', birthdate: '1984-01-26' },
      nonce: payload.nonce as string,
      audience: payload.client_id as string,
    });
    const post = await fetch(`${base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ vp_token: { pid: [built.sdJwt] }, state }),
    });
    const antwort = (await post.json()) as Record<string, unknown>;
    // Die Antwort an die Wallet enthält keine Claims; die bekommt nur der
    // Mandant über den Ergebnisabruf.
    assert.equal(antwort.claims, undefined);
    const ergebnis = await fetch(`${base}/v1/verification-requests/${sessionId}`, { headers: { authorization: `Bearer ${KEY}` } });
    const body = (await ergebnis.json()) as { result?: Record<string, unknown> };
    return { ...antwort, ...(body.result ?? {}) };
  }

  it('die Vorlage pid_de ist registriert', () => {
    assert.equal(REQUEST_PROFILE_TEMPLATES.pid_de?.vct, PID_VCT_DE);
  });

  it('eine deutsche PID wird angenommen, alle drei Claims kommen an', async () => {
    const body = await vorlegen(PID_VCT_DE);
    assert.equal(body.valid, true, JSON.stringify(body));
    assert.deepEqual(body.claims, { given_name: 'Erika', family_name: 'Mustermann', birthdate: '1984-01-26' });
  });

  it('ein Credential mit dem bisherigen vct wird für pid_de abgelehnt', async () => {
    const body = await vorlegen(PID_VCT_DEFAULT);
    assert.equal(body.valid, false, JSON.stringify(body));
  });
});
