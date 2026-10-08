/**
 * Paket 5 a): Der Unterzeichner einer Statusliste darf von einem Anker
 * signiert sein, nicht nur selbst Anker.
 *
 * Hintergrund: Die Sandbox-Vertrauensliste führt für Statuslisten eine CA
 * ("Deutschland PID-Status-List-Signer Test CA 1-26-2 2026"). Die
 * Statusliste selbst unterschreibt ein darunter ausgestelltes Zertifikat.
 *
 * Geprüft: Unterzeichner direkt als Anker, von CA signiert, von fremder CA
 * signiert, abgelaufene CA, abgelaufener Unterzeichner, falsche
 * Schlüsselverwendung, Zwischenzertifikat im x5c, pathLenConstraint,
 * Sperrung des Unterzeichners und fehlende Sperrquelle. Am Ende der Dienst:
 * eine Test PID mit Status wird mit CA-signiertem Unterzeichner angenommen.
 * Alles nur mit Test-Material und lokalem HTTP-Server.
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import { deflateSync } from 'node:zlib';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';
import { createLocalJWKSet, jwtVerify, SignJWT } from 'jose';
import {
  BasicConstraintsExtension,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509Certificate,
  X509CertificateGenerator,
  type Extension,
} from '@peculiar/x509';

import { buildSdJwtVc, generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { verifyChainToAnchor } from '../lib/cert-chain.ts';
import { MockRevocationList } from '../onboarding/mock-revocation.ts';
import { NO_REVOCATION, type RevocationChecker } from '../onboarding/revocation.ts';
import { AuditLog } from './audit.ts';
import { CredentialStatusError, STATUS_LIST_JWT_TYPE, TokenStatusListChecker } from './credential-status.ts';
import { VerifierService } from './service.ts';
import { TenantStore } from './tenant.ts';

const NO_DEV = { devMode: false, isProduction: false };
const DAY = 24 * 3600 * 1000;

interface Party {
  keys: CryptoKeyPair;
  cert: X509Certificate;
  der: Uint8Array;
  b64: string;
}

interface IssueOptions {
  issuer?: Party;
  ca?: boolean;
  pathLen?: number;
  usages?: KeyUsageFlags | null;
  notBefore?: Date;
  notAfter?: Date;
  extraExtensions?: Extension[];
  noBasicConstraints?: boolean;
}

async function issue(name: string, options: IssueOptions = {}): Promise<Party> {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const notBefore = options.notBefore ?? new Date(Date.now() - DAY);
  const notAfter = options.notAfter ?? new Date(Date.now() + 30 * DAY);
  const extensions: Extension[] = [];
  if (!options.noBasicConstraints) {
    extensions.push(new BasicConstraintsExtension(options.ca === true, options.pathLen, true));
  }
  if (options.usages !== null) {
    extensions.push(new KeyUsagesExtension(options.usages ?? (options.ca ? KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign : KeyUsageFlags.digitalSignature), true));
  }
  extensions.push(...(options.extraExtensions ?? []));
  const common = {
    serialNumber: crypto.randomUUID().replace(/-/g, ''),
    notBefore,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' } as const,
    extensions,
  };
  const cert = options.issuer
    ? await X509CertificateGenerator.create({
        ...common,
        subject: `CN=${name}, C=DE`,
        issuer: options.issuer.cert.subject,
        publicKey: keys.publicKey,
        signingKey: options.issuer.keys.privateKey,
      })
    : await X509CertificateGenerator.create({
        ...common,
        subject: `CN=${name}, C=DE`,
        issuer: `CN=${name}, C=DE`,
        publicKey: keys.publicKey,
        signingKey: keys.privateKey,
      });
  const der = new Uint8Array(cert.rawData);
  return { keys, cert, der, b64: Buffer.from(der).toString('base64') };
}

const ca = (name: string, options: IssueOptions = {}) => issue(name, { ca: true, ...options });
const signerOf = (name: string, issuer: Party, options: IssueOptions = {}) => issue(name, { issuer, ...options });

let server!: http.Server;
let base!: string;
const routes = new Map<string, string>();

function encodeStatusList(values: number[]): string {
  const bytes = new Uint8Array(Math.ceil((values.length * 2) / 8));
  values.forEach((value, idx) => {
    bytes[Math.floor((idx * 2) / 8)] |= value << ((idx * 2) % 8);
  });
  return deflateSync(bytes).toString('base64url');
}

/** Liefert eine Statusliste, signiert mit `signer`, x5c wie angegeben (Standard: nur der Unterzeichner). */
async function serveList(path: string, signer: Party, x5c: string[] = [signer.b64]): Promise<string> {
  const uri = `${base}${path}`;
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({ sub: uri, iat: now - 10, exp: now + 3600, status_list: { bits: 2, lst: encodeStatusList([0, 1, 2, 3]) } })
    .setProtectedHeader({ alg: 'ES256', typ: STATUS_LIST_JWT_TYPE, x5c })
    .sign(signer.keys.privateKey);
  routes.set(path, token);
  return uri;
}

const ref = (uri: string, idx: number) => ({ status: { status_list: { idx, uri } } });

function checker(anchors: Party[], revocation?: RevocationChecker): TokenStatusListChecker {
  return new TokenStatusListChecker({
    trustedSigners: () => anchors.map((a) => a.der),
    allowInsecureHttp: true,
    timeoutMs: 1_000,
    ...(revocation ? { revocation } : {}),
  });
}

async function rejectsWithCode(fn: () => Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(fn, (e: unknown) => {
    assert.ok(e instanceof CredentialStatusError, `kein CredentialStatusError: ${String(e)}`);
    assert.equal(e.code, code);
    return true;
  });
}

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const token = routes.get(req.url ?? '');
    if (!token) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/statuslist+jwt' });
    res.end(token);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('Statuslisten-Unterzeichner: Kette zum Anker', () => {
  it('Unterzeichner ist selbst der Anker -> akzeptiert, ohne Sperrquelle (wie bisher)', async () => {
    const signer = await issue('Anker-Unterzeichner TEST');
    const uri = await serveList('/k/direkt', signer);
    await checker([signer]).check(ref(uri, 0));
    await rejectsWithCode(() => checker([signer]).check(ref(uri, 1)), 'credential_revoked');
  });

  it('Unterzeichner von der CA signiert, CA ist Anker -> akzeptiert', async () => {
    const root = await ca('Status-CA TEST', { pathLen: 0 });
    const signer = await signerOf('Status-Signer TEST', root);
    const uri = await serveList('/k/ca', signer);
    await checker([root], NO_REVOCATION).check(ref(uri, 0));
    await rejectsWithCode(() => checker([root], NO_REVOCATION).check(ref(uri, 1)), 'credential_revoked');
  });

  it('Anker darf eine Liste mit mehreren Ankern sein, nur einer passt', async () => {
    const root = await ca('Status-CA TEST');
    const other = await ca('Andere CA TEST');
    const signer = await signerOf('Status-Signer TEST', root);
    const uri = await serveList('/k/mehrere', signer);
    await checker([other, root], NO_REVOCATION).check(ref(uri, 0));
  });

  it('Unterzeichner von fremder CA signiert -> status_list_signature_invalid', async () => {
    const trusted = await ca('Vertraute CA TEST');
    const foreign = await ca('Fremde CA TEST');
    const signer = await signerOf('Status-Signer TEST', foreign);
    const uri = await serveList('/k/fremd', signer);
    await rejectsWithCode(() => checker([trusted], NO_REVOCATION).check(ref(uri, 0)), 'status_list_signature_invalid');
  });

  it('gleicher Name wie die vertraute CA, aber anderer Schlüssel -> status_list_signature_invalid', async () => {
    const trusted = await ca('Status-CA TEST');
    const impostor = await ca('Status-CA TEST');
    const signer = await signerOf('Status-Signer TEST', impostor);
    const uri = await serveList('/k/doppelgaenger', signer, [signer.b64, impostor.b64]);
    await rejectsWithCode(() => checker([trusted], NO_REVOCATION).check(ref(uri, 0)), 'status_list_signature_invalid');
  });

  it('abgelaufene CA -> certificate_expired', async () => {
    const root = await ca('Abgelaufene CA TEST', { notBefore: new Date(Date.now() - 20 * DAY), notAfter: new Date(Date.now() - 10 * DAY) });
    const signer = await signerOf('Status-Signer TEST', root, { notBefore: new Date(Date.now() - 15 * DAY), notAfter: new Date(Date.now() + 5 * DAY) });
    const uri = await serveList('/k/ca-abgelaufen', signer);
    await rejectsWithCode(() => checker([root], NO_REVOCATION).check(ref(uri, 0)), 'certificate_expired');
  });

  it('abgelaufener Unterzeichner -> certificate_expired', async () => {
    const root = await ca('Status-CA TEST');
    const signer = await signerOf('Alter Signer TEST', root, { notBefore: new Date(Date.now() - 20 * DAY), notAfter: new Date(Date.now() - 10 * DAY) });
    const uri = await serveList('/k/signer-abgelaufen', signer);
    await rejectsWithCode(() => checker([root], NO_REVOCATION).check(ref(uri, 0)), 'certificate_expired');
  });

  it('Unterzeichner noch nicht gültig -> certificate_not_yet_valid', async () => {
    const root = await ca('Status-CA TEST');
    const signer = await signerOf('Neuer Signer TEST', root, { notBefore: new Date(Date.now() + 5 * DAY), notAfter: new Date(Date.now() + 10 * DAY) });
    const uri = await serveList('/k/signer-neu', signer);
    await rejectsWithCode(() => checker([root], NO_REVOCATION).check(ref(uri, 0)), 'certificate_not_yet_valid');
  });

  it('Unterzeichner mit Key Usage ohne digitalSignature -> status_list_signature_invalid', async () => {
    const root = await ca('Status-CA TEST');
    const signer = await signerOf('Signer ohne Signatur TEST', root, { usages: KeyUsageFlags.keyEncipherment });
    const uri = await serveList('/k/signer-usage', signer);
    await rejectsWithCode(() => checker([root], NO_REVOCATION).check(ref(uri, 0)), 'status_list_signature_invalid');
  });

  it('Aussteller ohne cA=true -> status_list_signature_invalid', async () => {
    const notCa = await issue('Kein CA TEST', { ca: false, usages: KeyUsageFlags.keyCertSign });
    const signer = await signerOf('Status-Signer TEST', notCa);
    const uri = await serveList('/k/kein-ca', signer);
    await rejectsWithCode(() => checker([notCa], NO_REVOCATION).check(ref(uri, 0)), 'status_list_signature_invalid');
  });

  it('Aussteller ganz ohne Basic Constraints -> status_list_signature_invalid', async () => {
    const bare = await issue('Ohne Constraints TEST', { noBasicConstraints: true, usages: KeyUsageFlags.keyCertSign });
    const signer = await signerOf('Status-Signer TEST', bare);
    const uri = await serveList('/k/ohne-constraints', signer);
    await rejectsWithCode(() => checker([bare], NO_REVOCATION).check(ref(uri, 0)), 'status_list_signature_invalid');
  });

  it('CA mit Key Usage ohne keyCertSign -> status_list_signature_invalid', async () => {
    const root = await ca('CA ohne keyCertSign TEST', { usages: KeyUsageFlags.digitalSignature });
    const signer = await signerOf('Status-Signer TEST', root);
    const uri = await serveList('/k/ca-usage', signer);
    await rejectsWithCode(() => checker([root], NO_REVOCATION).check(ref(uri, 0)), 'status_list_signature_invalid');
  });

  it('Zwischenzertifikat im x5c: Anker, Zwischen-CA, Unterzeichner -> akzeptiert', async () => {
    const root = await ca('Wurzel-CA TEST', { pathLen: 1 });
    const mid = await ca('Zwischen-CA TEST', { issuer: root, pathLen: 0 });
    const signer = await signerOf('Status-Signer TEST', mid);
    const uri = await serveList('/k/zwischen', signer, [signer.b64, mid.b64]);
    await checker([root], NO_REVOCATION).check(ref(uri, 0));
  });

  it('Zwischenzertifikat fehlt im x5c -> status_list_signature_invalid', async () => {
    const root = await ca('Wurzel-CA TEST', { pathLen: 1 });
    const mid = await ca('Zwischen-CA TEST', { issuer: root, pathLen: 0 });
    const signer = await signerOf('Status-Signer TEST', mid);
    const uri = await serveList('/k/zwischen-fehlt', signer);
    await rejectsWithCode(() => checker([root], NO_REVOCATION).check(ref(uri, 0)), 'status_list_signature_invalid');
  });

  it('pathLenConstraint 0 an der Wurzel verbietet eine Zwischen-CA -> status_list_signature_invalid', async () => {
    const root = await ca('Wurzel-CA TEST', { pathLen: 0 });
    const mid = await ca('Zwischen-CA TEST', { issuer: root });
    const signer = await signerOf('Status-Signer TEST', mid);
    const uri = await serveList('/k/pathlen', signer, [signer.b64, mid.b64]);
    await rejectsWithCode(() => checker([root], NO_REVOCATION).check(ref(uri, 0)), 'status_list_signature_invalid');
  });

  it('Zwischen-CA abgelaufen -> certificate_expired', async () => {
    const root = await ca('Wurzel-CA TEST');
    const mid = await ca('Zwischen-CA TEST', { issuer: root, notBefore: new Date(Date.now() - 20 * DAY), notAfter: new Date(Date.now() - 10 * DAY) });
    const signer = await signerOf('Status-Signer TEST', mid);
    const uri = await serveList('/k/zwischen-abgelaufen', signer, [signer.b64, mid.b64]);
    await rejectsWithCode(() => checker([root], NO_REVOCATION).check(ref(uri, 0)), 'certificate_expired');
  });

  it('Signatur des Unterzeichners passt nicht zum Aussteller (gefälschtes Zertifikat) -> status_list_signature_invalid', async () => {
    const root = await ca('Status-CA TEST');
    const real = await signerOf('Status-Signer TEST', root);
    const forgerKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    // Zertifikat mit dem Namen der CA als Aussteller, aber vom Angreifer signiert.
    const forged = await X509CertificateGenerator.create({
      serialNumber: '01',
      subject: real.cert.subject,
      issuer: root.cert.subject,
      notBefore: new Date(Date.now() - DAY),
      notAfter: new Date(Date.now() + DAY),
      publicKey: forgerKeys.publicKey,
      signingKey: forgerKeys.privateKey,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    });
    const der = new Uint8Array(forged.rawData);
    const result = await verifyChainToAnchor([der], [root.der], new Date());
    assert.deepEqual(result, { ok: false, failure: 'chain_untrusted' });
  });

  it('unlesbares x5c-Zertifikat -> chain_untrusted', async () => {
    const root = await ca('Status-CA TEST');
    assert.deepEqual(await verifyChainToAnchor([new Uint8Array([1, 2, 3])], [root.der], new Date()), { ok: false, failure: 'chain_untrusted' });
    assert.deepEqual(await verifyChainToAnchor([], [root.der], new Date()), { ok: false, failure: 'chain_untrusted' });
  });

  it('Kette tiefer als erlaubt -> chain_untrusted', async () => {
    const root = await ca('Wurzel TEST');
    let issuer = root;
    const mids: Party[] = [];
    for (let i = 0; i < 6; i += 1) {
      issuer = await ca(`Zwischen ${i} TEST`, { issuer });
      mids.push(issuer);
    }
    const signer = await signerOf('Tiefer Signer TEST', issuer);
    const chain = [signer.der, ...mids.reverse().map((m) => m.der)];
    assert.deepEqual(await verifyChainToAnchor(chain, [root.der], new Date()), { ok: false, failure: 'chain_untrusted' });
  });

  it('Pfad und Anker werden zurückgegeben', async () => {
    const root = await ca('Status-CA TEST');
    const signer = await signerOf('Status-Signer TEST', root);
    const result = await verifyChainToAnchor([signer.der], [root.der], new Date());
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.direct, false);
      assert.deepEqual(result.path.map((c) => c.subject), [signer.cert.subject, root.cert.subject]);
    }
  });

  it('zusätzliche Extended Key Usage stört nicht', async () => {
    const root = await ca('Status-CA TEST');
    const signer = await signerOf('Signer mit EKU TEST', root, { extraExtensions: [new ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.4'], false)] });
    const uri = await serveList('/k/eku', signer);
    await checker([root], NO_REVOCATION).check(ref(uri, 0));
  });
});

describe('Statuslisten-Unterzeichner: Sperrprüfung wie bei der Aussteller-Kette', () => {
  it('Unterzeichner gesperrt -> status_list_signer_revoked', async () => {
    const root = await ca('Status-CA TEST');
    const signer = await signerOf('Gesperrter Signer TEST', root);
    const revocation = new MockRevocationList();
    revocation.revoke(signer.der);
    const uri = await serveList('/r/gesperrt', signer);
    await rejectsWithCode(() => checker([root], revocation).check(ref(uri, 0)), 'status_list_signer_revoked');
  });

  it('Unterzeichner ausgesetzt -> status_list_signer_revoked', async () => {
    const root = await ca('Status-CA TEST');
    const signer = await signerOf('Ausgesetzter Signer TEST', root);
    const revocation = new MockRevocationList();
    revocation.suspend(signer.der);
    const uri = await serveList('/r/ausgesetzt', signer);
    await rejectsWithCode(() => checker([root], revocation).check(ref(uri, 0)), 'status_list_signer_revoked');
  });

  it('Zwischen-CA gesperrt -> status_list_signer_revoked', async () => {
    const root = await ca('Wurzel-CA TEST', { pathLen: 1 });
    const mid = await ca('Zwischen-CA TEST', { issuer: root, pathLen: 0 });
    const signer = await signerOf('Status-Signer TEST', mid);
    const revocation = new MockRevocationList();
    revocation.revoke(mid.der);
    const uri = await serveList('/r/zwischen', signer, [signer.b64, mid.b64]);
    await rejectsWithCode(() => checker([root], revocation).check(ref(uri, 0)), 'status_list_signer_revoked');
  });

  it('Sperrquelle nicht erreichbar -> status_list_signer_revocation_failed', async () => {
    const root = await ca('Status-CA TEST');
    const signer = await signerOf('Status-Signer TEST', root);
    const broken: RevocationChecker = {
      async checkRevoked() {
        throw new Error('ECONNREFUSED');
      },
    };
    const uri = await serveList('/r/weg', signer);
    await rejectsWithCode(() => checker([root], broken).check(ref(uri, 0)), 'status_list_signer_revocation_failed');
  });

  it('keine Sperrquelle konfiguriert und Unterzeichner nicht selbst Anker -> abgelehnt (fail closed)', async () => {
    const root = await ca('Status-CA TEST');
    const signer = await signerOf('Status-Signer TEST', root);
    const uri = await serveList('/r/ohne-quelle', signer);
    await rejectsWithCode(() => checker([root]).check(ref(uri, 0)), 'status_list_signer_revocation_failed');
  });

  it('Gegenprobe: nicht gesperrter Unterzeichner, aktive Sperrquelle -> akzeptiert', async () => {
    const root = await ca('Status-CA TEST');
    const signer = await signerOf('Status-Signer TEST', root);
    const uri = await serveList('/r/gut', signer);
    await checker([root], new MockRevocationList()).check(ref(uri, 0));
  });
});

describe('Dienst: Test PID mit Status, Unterzeichner von der CA signiert', () => {
  async function harness(anchors: Party[], revocation?: RevocationChecker) {
    const tenants = new TenantStore();
    tenants.add({ id: 'tenant-k', name: 'Kunde K (TEST)', apiKey: 'test-api-key-kette', requestProfile: { id: 'test-given-name', claims: ['given_name'] } });
    const verifier = await generateTestKeyMaterial('Kette Verifier TEST');
    const issuer = await generateTestKeyMaterial('Kette Issuer TEST');
    const holder = await generateTestKeyMaterial('Kette Holder TEST');
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
      { mode: NO_DEV, credentialStatus: checker(anchors, revocation), issuerRevocation: new MockRevocationList() },
    );
    service.baseUrl = 'http://127.0.0.1:9';
    return async (uri: string, idx: number) => {
      const created = await service.createRequest('tenant-k', {});
      const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
      const built = await buildSdJwtVc({
        issuerKey: issuer,
        holderKey: holder,
        nonce: String(payload.nonce),
        audience: String(payload.client_id),
        extraClaims: ref(uri, idx),
      });
      return service.handlePresentation(created.state, { pid: [built.sdJwt] });
    };
  }

  it('Test PID mit Status wird angenommen, wenn der Unterzeichner von einer Anker-CA signiert ist', async () => {
    const root = await ca('Status-List-Signer Test CA TEST', { pathLen: 0 });
    const signer = await signerOf('Status-Liste TEST', root);
    const uri = await serveList('/d/gut', signer);
    const present = await harness([root], new MockRevocationList());
    const outcome = await present(uri, 0);
    assert.equal(outcome.valid, true, JSON.stringify(outcome));
  });

  it('dieselbe Test PID wird abgelehnt, wenn die CA nicht Anker ist (vorher: jede CA-Kette)', async () => {
    const root = await ca('Status-List-Signer Test CA TEST');
    const other = await ca('Andere Test CA TEST');
    const signer = await signerOf('Status-Liste TEST', root);
    const uri = await serveList('/d/fremd', signer);
    const outcome = await (await harness([other], new MockRevocationList()))(uri, 0);
    assert.deepEqual(outcome, { ok: true, valid: false, error: 'status_list_signature_invalid' });
  });

  it('widerrufenes Credential bleibt abgelehnt, auch mit CA-Kette', async () => {
    const root = await ca('Status-List-Signer Test CA TEST');
    const signer = await signerOf('Status-Liste TEST', root);
    const uri = await serveList('/d/widerrufen', signer);
    const outcome = await (await harness([root], new MockRevocationList()))(uri, 1);
    assert.deepEqual(outcome, { ok: true, valid: false, error: 'credential_revoked' });
  });

  it('gesperrter Unterzeichner -> Präsentation abgelehnt mit status_list_signer_revoked', async () => {
    const root = await ca('Status-List-Signer Test CA TEST');
    const signer = await signerOf('Status-Liste TEST', root);
    const revocation = new MockRevocationList();
    revocation.revoke(signer.der);
    const uri = await serveList('/d/signer-gesperrt', signer);
    const outcome = await (await harness([root], revocation))(uri, 0);
    assert.deepEqual(outcome, { ok: true, valid: false, error: 'status_list_signer_revoked' });
  });
});
