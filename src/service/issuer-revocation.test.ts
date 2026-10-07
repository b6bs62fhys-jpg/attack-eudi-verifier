/**
 * Schritt 5 der OCSP-Umstellung: die Aussteller-Sperrprüfung im Dienst.
 *
 * Geprüft wird der Weg von der Präsentation bis zur Ablehnung, also die
 * Verdrahtung in `service.ts` plus `issuer-revocation.ts`. Der OCSP-Responder
 * ist ein lokaler HTTP-Server auf 127.0.0.1; es gibt keinen Aufruf ins Netz.
 */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import http from 'node:http';
import {afterAll, beforeAll, describe, it} from 'vitest';
import 'reflect-metadata';
import {AsnConvert, OctetString} from '@peculiar/asn1-schema';
import {BasicOCSPResponse, CertStatus, id_pkix_ocsp_basic, KeyHash, OCSPResponse, OCSPResponseStatus, ResponderID, ResponseBytes, ResponseData, RevokedInfo, SingleResponse} from '@peculiar/asn1-ocsp';
import {AlgorithmIdentifier, CRLReason} from '@peculiar/asn1-x509';
import {AuthorityInfoAccessExtension, BasicConstraintsExtension, X509Certificate, X509CertificateGenerator} from '@peculiar/x509';
import {createLocalJWKSet, jwtVerify} from 'jose';

import {ConfigError} from '../config.ts';
import {buildSdJwtVc, generateTestKeyMaterial, type TestKeyMaterial} from '../decision-test/mock-wallet.ts';
import {buildCertId, OcspRevocationChecker, responderKeyHash} from '../onboarding/ocsp-revocation.ts';
import {NO_REVOCATION, type RevocationChecker, type RevocationStatus} from '../onboarding/revocation.ts';
import {AuditLog} from './audit.ts';
import {installLibraryLogFilter} from '../lib/library-log-filter.ts';

import {VerifierService} from './service.ts';
import {DEV_TEST_OPTIONS} from './test-support.ts';
import {TenantStore} from './tenant.ts';

let server!: http.Server;
let base!: string;
const hits = new Map<string, number>();

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const path = (req.url ?? '/').split('?')[0];
    hits.set(path, (hits.get(path) ?? 0) + 1);
    void (async () => {
      for await (const chunk of req) void chunk;
      res.writeHead(200, { 'content-type': 'application/ocsp-response' });
      res.end(await antwortFuer(path));
    })();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  base = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

/** Pro Route hinterlegte Antwort: 'good', 'revoked' oder '503'. */
const antworten = new Map<string, 'good' | 'revoked' | '503'>();
/** Subject und Aussteller, fuer die der Responder antwortet. */
let antwortFuerPaar: { subject: X509Certificate; issuer: X509Certificate; key: CryptoKey } | undefined;

interface Ca {
  key: CryptoKeyPair;
  cert: X509Certificate;
}

/** TEST-Material aus einem Ca-Objekt (fuer buildSdJwtVc). */
async function toMaterial(ca: Ca): Promise<TestKeyMaterial> {
  return {
    privateKey: ca.key.privateKey,
    publicKey: ca.key.publicKey,
    publicJwk: (await crypto.subtle.exportKey('jwk', ca.key.publicKey)) as JsonWebKey,
    x5cBase64: Buffer.from(new Uint8Array(ca.cert.rawData)).toString('base64'),
    certDerBytes: new Uint8Array(ca.cert.rawData),
  };
}

async function antwortFuer(path: string): Promise<Uint8Array> {
  const modus = antworten.get(path) ?? 'good';
  if (modus === '503' || !antwortFuerPaar) return new Uint8Array([0x30, 0x03, 0x0a, 0x01, 0x00]);
  return buildResponse(antwortFuerPaar, modus);
}

function rawToEcdsaDer(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const integers = [raw.subarray(0, half), raw.subarray(half)].map((part) => {
    let start = 0;
    while (start < part.length - 1 && part[start] === 0) start += 1;
    let value = part.subarray(start);
    if ((value[0] as number) & 0x80) value = Uint8Array.from([0x00, ...value]);
    return [0x02, value.length, ...value];
  });
  const body = [...integers[0], ...integers[1]];
  return Uint8Array.from([0x30, body.length, ...body]);
}

async function buildResponse(paar: { subject: X509Certificate; issuer: X509Certificate; key: CryptoKey }, modus: 'good' | 'revoked'): Promise<Uint8Array> {
  const certId = await buildCertId(paar.subject, paar.issuer);
  const status =
    modus === 'good'
      ? new CertStatus({ good: null })
      : new CertStatus({ revoked: new RevokedInfo({ revocationTime: new Date(Date.now() - 60_000), revocationReason: new CRLReason(1) }) });
  const single = new SingleResponse({ certID: certId, certStatus: status, thisUpdate: new Date(Date.now() - 60_000), nextUpdate: new Date(Date.now() + 3600_000) });
  const tbs = new ResponseData({
    responderID: new ResponderID({ byKey: new KeyHash(responderKeyHash(paar.issuer)) }),
    producedAt: new Date(),
    responses: [single],
  });
  const tbsDer = AsnConvert.serialize(tbs);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, paar.key, tbsDer as unknown as BufferSource));
  const basic = new BasicOCSPResponse({
    tbsResponseData: tbs,
    signatureAlgorithm: new AlgorithmIdentifier({ algorithm: '1.2.840.10045.4.3.2' }),
    signature: rawToEcdsaDer(raw).buffer as ArrayBuffer,
  });
  return new Uint8Array(AsnConvert.serialize(new OCSPResponse({
    responseStatus: OCSPResponseStatus.successful,
    responseBytes: new ResponseBytes({ responseType: id_pkix_ocsp_basic, response: new OctetString(AsnConvert.serialize(basic)) }),
  })));
}

async function createIssuer(ocspUrl?: string): Promise<Ca> {
  const key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const cert = await X509CertificateGenerator.createSelfSigned({
    serialNumber: crypto.randomUUID().replace(/-/g, ''),
    name: 'CN=Dienst Issuer TEST, C=DE',
    notBefore: new Date(Date.now() - 3_600_000),
    notAfter: new Date(Date.now() + 30 * 86_400_000),
    keys: key,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [new BasicConstraintsExtension(true, 1, true), ...(ocspUrl ? [new AuthorityInfoAccessExtension({ ocsp: ocspUrl }, false)] : [])],
  });
  return { key, cert: new X509Certificate(new Uint8Array(cert.rawData)) };
}

interface Harness {
  present(): Promise<{ outcome: { valid: boolean; error?: string }; result: { status: string; result?: { valid: boolean } } }>;
}

/**
 * Baut einen Dienst, dessen Aussteller ein echtes, selbstsigniertes Zertifikat
 * ist. `asAnchor` entscheidet, ob dieses Zertifikat zugleich als Vertrauensanker
 * dient (dann entfaellt die Sperrfrage) oder als Blatt einer Kette, die von
 * einem getrennten Anker ausgestellt wurde (dann wird OCSP abgefragt).
 */
async function harness(opts: { blattMitAia: boolean; extra?: Record<string, unknown> }): Promise<Harness> {
  const tenants = new TenantStore();
  tenants.add({ id: 'tenant-ocsp', name: 'Kunde O (TEST)', apiKey: 'test-api-key-ocsp', requestProfile: { id: 'test-given-name', claims: ['given_name'] } });
  const verifier = await generateTestKeyMaterial('OCSP Verifier TEST');
  const holder = await generateTestKeyMaterial('OCSP Holder TEST');
  const ca = await createIssuer();
  const blatt = await (async () => {
    if (!opts.blattMitAia) return ca;
    const key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const cert = await X509CertificateGenerator.create({
      serialNumber: crypto.randomUUID().replace(/-/g, ''),
      subject: 'CN=Dienst Blatt TEST, C=DE',
      issuer: ca.cert.subject,
      notBefore: new Date(Date.now() - 3_600_000),
      notAfter: new Date(Date.now() + 30 * 86_400_000),
      publicKey: key.publicKey,
      signingKey: ca.key.privateKey,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      extensions: [new BasicConstraintsExtension(false), new AuthorityInfoAccessExtension({ ocsp: `${base}/ocsp` }, false)],
    });
    return { key, cert: new X509Certificate(new Uint8Array(cert.rawData)) };
  })();

  // Anker ist immer die CA; das Blatt wird nur dann geprueft, wenn es nicht
  // selbst der Anker ist.
  const material: TestKeyMaterial = {
    privateKey: blatt.key.privateKey,
    publicKey: blatt.key.publicKey,
    publicJwk: (await crypto.subtle.exportKey('jwk', blatt.key.publicKey)) as JsonWebKey,
    x5cBase64: Buffer.from(blatt.cert.rawData).toString('base64'),
    certDerBytes: new Uint8Array(blatt.cert.rawData),
  };
  // Der Responder beantwortet Anfragen zu diesem Paar und signiert mit dem
  // Schluessel des Ausstellers (so signiert auch ein echter OCSP-Responder).
  antwortFuerPaar = { subject: blatt.cert, issuer: blatt === ca ? ca.cert : ca.cert, key: (blatt === ca ? blatt.key : ca.key).privateKey };

  const service = new VerifierService(
    tenants,
    new AuditLog(),
    { privateKey: verifier.privateKey, publicKey: verifier.publicKey, publicJwk: verifier.publicJwk, certificateChain: [verifier.certDerBytes] },
    [new Uint8Array(ca.cert.rawData)],
    undefined,
    undefined,
    undefined,
    undefined,
    true,
    // Echter OCSP-Prüfer wie im Betrieb (allowInsecureHttp nur für den
    // lokalen Testserver auf 127.0.0.1).
    { ...DEV_TEST_OPTIONS, issuerRevocation: new OcspRevocationChecker({ allowInsecureHttp: true, clockSkewSeconds: 60 }), ...opts.extra },
  );
  service.baseUrl = 'http://127.0.0.1:9';

  return {
    present: async () => {
      const created = await service.createRequest('tenant-ocsp', {});
      const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
      const built = await buildSdJwtVc({ issuerKey: material, holderKey: holder, nonce: String(payload.nonce), audience: String(payload.client_id) });
      const outcome = await service.handlePresentation(created.state, { pid: [built.sdJwt] });
      return { outcome, result: service.getResult('tenant-ocsp', created.sessionId) };
    },
  };
}

describe('Dienst: Sperrprüfung der Aussteller-Kette (Schritt 5)', () => {
  it('Aussteller ist der Anker -> keine Sperrfrage, Präsentation gültig (Gegenprobe)', async () => {
    const h = await harness({ blattMitAia: false });
    const { outcome, result } = await h.present();
    assert.equal(outcome.valid, true, JSON.stringify(outcome));
    assert.equal(result.result?.valid, true);
  });

  it('gültiger OCSP-Status -> Präsentation gültig', async () => {
    antworten.set('/ocsp', 'good');
    const h = await harness({ blattMitAia: true });
    const { outcome, result } = await h.present();
    assert.equal(outcome.valid, true, JSON.stringify(outcome));
    assert.equal(result.result?.valid, true);
    assert.equal((hits.get('/ocsp') ?? 0) > 0, true, 'OCSP muss abgefragt worden sein');
  });

  it('gesperrtes Aussteller-Zertifikat -> Präsentation abgelehnt (issuer_certificate_revoked)', async () => {
    antworten.set('/ocsp', 'revoked');
    const h = await harness({ blattMitAia: true });
    const { outcome, result } = await h.present();
    assert.equal(outcome.valid, false);
    assert.equal(outcome.error, 'issuer_certificate_revoked');
    assert.equal(result.status, 'pending', 'kein Ergebnis bei gesperrtem Zertifikat');
  });

  it('Responder nicht erreichbar und keine Frist -> Ablehnung (issuer_revocation_check_failed)', async () => {
    antworten.set('/ocsp', '503');
    const h = await harness({ blattMitAia: true });
    const { outcome } = await h.present();
    assert.equal(outcome.valid, false);
    // Nach aussen der dokumentierte Sammelcode; der innere Code bleibt im Audit.
    assert.equal(outcome.error, 'issuer_revocation_check_failed');
  });

  it('Responder fällt aus, Zertifikat war nie geprüft -> keine Gnadenfrist', async () => {
    antworten.set('/ocsp', '503');
    const h = await harness({ blattMitAia: true });
    const { outcome } = await h.present();
    assert.equal(outcome.valid, false, 'ohne Vorabantwort wird nicht weich behandelt');
  });
});

/** Platzhalter, der die Credential-Statusprüfung passieren lässt. */
const ECHTE_STATUSPRUEFUNG = { async check(): Promise<void> { /* Teststub */ } };

describe('Dienst: Sperrprüfung ist Pflicht (kein stilles Abschalten)', () => {
  it('ohne issuerRevocation -> Startabbruch', () => {
    assert.throws(
      () => new VerifierService(new TenantStore(), new AuditLog(), {} as never, [], undefined, undefined, undefined, undefined, true, { mode: DEV_TEST_OPTIONS.mode, credentialStatus: ECHTE_STATUSPRUEFUNG }),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError);
        assert.match(e.message, /Sperrprüfung für Aussteller-Zertifikate konfiguriert/);
        return true;
      },
    );
  });

  it('NO_REVOCATION in Produktion -> Startabbruch', () => {
    assert.throws(
      () => new VerifierService(new TenantStore(), new AuditLog(), {} as never, [], undefined, undefined, undefined, undefined, true, { mode: { devMode: false, isProduction: true }, credentialStatus: ECHTE_STATUSPRUEFUNG, issuerRevocation: NO_REVOCATION }),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError);
        assert.match(e.message, /Sperrprüfung ist abgeschaltet/);
        return true;
      },
    );
  });

  it('NO_REVOCATION mit Entwicklungsschalter -> erlaubt (Gegenprobe)', () => {
    assert.doesNotThrow(() => new VerifierService(new TenantStore(), new AuditLog(), {} as never, [], undefined, undefined, undefined, undefined, true, { ...DEV_TEST_OPTIONS, issuerRevocation: NO_REVOCATION }));
  });
});

describe('Dienst: Vorrang des eigenen OCSP-Checkers vor der Bibliothek', () => {
  it('Bibliothek meldet good, eigener Checker revoked -> trotzdem Ablehnung', async () => {
    // Der eigene Checker wird direkt mit 'revoked' beliefert, waehrend die
    // Bibliothek im selben Lauf 'good' sieht: das ist mit einem einzigen
    // Responder nicht moeglich, daher wird der eigene Checker hier ersetzt.
    antworten.set('/ocsp', 'good');
    const tenants = new TenantStore();
    tenants.add({ id: 'tenant-ocsp', name: 'Kunde O (TEST)', apiKey: 'test-api-key-ocsp', requestProfile: { id: 'test-given-name', claims: ['given_name'] } });
    const verifier = await generateTestKeyMaterial('Vorrang Verifier TEST');
    const holder = await generateTestKeyMaterial('Vorrang Holder TEST');
    const ca = await createIssuer();
    const blattKey = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const blattCert = await X509CertificateGenerator.create({
      serialNumber: crypto.randomUUID().replace(/-/g, ''),
      subject: 'CN=Vorrang Blatt TEST, C=DE',
      issuer: ca.cert.subject,
      notBefore: new Date(Date.now() - 3_600_000),
      notAfter: new Date(Date.now() + 30 * 86_400_000),
      publicKey: blattKey.publicKey,
      signingKey: ca.key.privateKey,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      extensions: [new BasicConstraintsExtension(false), new AuthorityInfoAccessExtension({ ocsp: `${base}/ocsp` }, false)],
    });
    const blatt = new X509Certificate(new Uint8Array(blattCert.rawData));
    antwortFuerPaar = { subject: blatt, issuer: ca.cert, key: ca.key.privateKey };
    const material: TestKeyMaterial = {
      privateKey: blattKey.privateKey,
      publicKey: blattKey.publicKey,
      publicJwk: (await crypto.subtle.exportKey('jwk', blattKey.publicKey)) as JsonWebKey,
      x5cBase64: Buffer.from(blatt.rawData).toString('base64'),
      certDerBytes: new Uint8Array(blatt.rawData),
    };
    // Eigener Checker: liefert unabhängig von der Bibliothek 'revoked'.
    const eigenerChecker: RevocationChecker = { async checkRevoked(): Promise<RevocationStatus> { return 'revoked'; } };
    const service = new VerifierService(
      tenants,
      new AuditLog(),
      { privateKey: verifier.privateKey, publicKey: verifier.publicKey, publicJwk: verifier.publicJwk, certificateChain: [verifier.certDerBytes] },
      [new Uint8Array(ca.cert.rawData)],
      undefined,
      undefined,
      undefined,
      undefined,
      true,
      { ...DEV_TEST_OPTIONS, issuerRevocation: eigenerChecker },
    );
    service.baseUrl = 'http://127.0.0.1:9';
    const created = await service.createRequest('tenant-ocsp', {});
    const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
    const built = await buildSdJwtVc({ issuerKey: material, holderKey: holder, nonce: String(payload.nonce), audience: String(payload.client_id) });
    const outcome = await service.handlePresentation(created.state, { pid: [built.sdJwt] });
    assert.equal(outcome.valid, false, 'eigener Checker entscheidet unabhaengig');
    assert.equal(outcome.error, 'issuer_certificate_revoked');
  });
});

describe('Dienst: Bibliothekswarnungen landen ohne Filter im Log', () => {
  it('Gegenprobe: ohne Filter schreibt die Bibliothek bei OCSP-Ausfall nach console.warn', async () => {
    // Dieser Test dokumentiert die Notwendigkeit des Filters: die Bibliothek
    // meldet ihren eigenen OCSP-Fehlschlag selbst, mit Subject und Meldung.
    antworten.set('/ocsp', '503');
    const h = await harness({ blattMitAia: true });
    const original = console.warn;
    const gefangen: string[] = [];
    console.warn = (...args: unknown[]) => {
      gefangen.push(args.map(String).join(' '));
    };
    try {
      await h.present();
    } finally {
      console.warn = original;
    }
    const bibliothek = gefangen.filter((zeile) => zeile.startsWith('[openid4vp]'));
    assert.ok(bibliothek.length > 0, 'erwartet mindestens eine Bibliothekswarnung ohne Filter');
    assert.ok(
      bibliothek.some((zeile) => zeile.includes('Dienst Blatt TEST') || zeile.includes('CN=')),
      `die Warnung enthaelt den Zertifikat-Subject: ${JSON.stringify(bibliothek)}`,
    );
  });

  it('mit installiertem Filter bleibt von derselben Praesentation keine Bibliothekszeile im Log', async () => {
    antworten.set('/ocsp', '503');
    const h = await harness({ blattMitAia: true });
    const original = console.warn;
    const gefangen: string[] = [];
    const restore = installLibraryLogFilter({
      warn: (...args: unknown[]) => {
        gefangen.push(args.map(String).join(' '));
      },
    } as unknown as Console);
    console.warn = original;
    try {
      await h.present();
    } finally {
      restore();
    }
    assert.deepEqual(
      gefangen.filter((zeile) => zeile.startsWith('[openid4vp]')),
      [],
      'mit Filter darf keine Bibliothekszeile ankommen',
    );
  });
});

describe('Dienst: outward Fehlercodes der Sperrpruefung sind dokumentiert', () => {
  it('alle nach aussen moeglichen Sperrcodes stehen in docs/fehlercodes.md', () => {
    const dokumentiert = new Set(
      [...readFileSync(new URL('../../docs/fehlercodes.md', import.meta.url), 'utf8').matchAll(/`([a-z][a-z0-9_]*)`/g)].map((m) => m[1]),
    );
    // Diese Codes kann issuerRevocationErrorCode zurueckgeben.
    for (const code of ['issuer_certificate_revoked', 'issuer_certificate_suspended', 'issuer_revocation_check_failed', 'certificate_expired', 'certificate_not_yet_valid', 'issuer_chain_invalid', 'revocation_source_missing', 'revocation_status_unknown']) {
      assert.ok(dokumentiert.has(code), `${code} fehlt in docs/fehlercodes.md`);
    }
  });
});

describe('B8: Audit-Ereignis fuer die OCSP-Gnadenfrist', () => {
  it('Gnadenfrist wird verwendet -> Ereignis im Audit-Log, ohne Zertifikatsdaten', async () => {
    // Zähler wird vom OCSP-Beobachter erhöht, der Dienst wertet ihn aus.
    const gracePeriodSeen = { count: 0 };
    const checker: RevocationChecker = {
      async checkRevoked(): Promise<RevocationStatus> {
        // Simuliert genau das Verhalten des OCSP-Checkers in Zustand B.
        gracePeriodSeen.count += 1;
        return 'good';
      },
    };
    const tenants = new TenantStore();
    tenants.add({ id: 'tenant-gp', name: 'Kunde G (TEST)', apiKey: 'test-api-key-gp', requestProfile: { id: 'test-given-name', claims: ['given_name'] } });
    const verifier = await generateTestKeyMaterial('Grace Verifier TEST');
    const holder = await generateTestKeyMaterial('Grace Holder TEST');
    const ca = await createIssuer();
    const blattKey = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const blattCert = await X509CertificateGenerator.create({
      serialNumber: crypto.randomUUID().replace(/-/g, ''),
      subject: 'CN=Grace Blatt TEST, C=DE',
      issuer: ca.cert.subject,
      notBefore: new Date(Date.now() - 3_600_000),
      notAfter: new Date(Date.now() + 30 * 86_400_000),
      publicKey: blattKey.publicKey,
      signingKey: ca.key.privateKey,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      extensions: [new BasicConstraintsExtension(false)],
    });
    const blatt = new X509Certificate(new Uint8Array(blattCert.rawData));
    const material: TestKeyMaterial = {
      privateKey: blattKey.privateKey,
      publicKey: blattKey.publicKey,
      publicJwk: (await crypto.subtle.exportKey('jwk', blattKey.publicKey)) as JsonWebKey,
      x5cBase64: Buffer.from(blatt.rawData).toString('base64'),
      certDerBytes: new Uint8Array(blatt.rawData),
    };
    const audit = new AuditLog();
    const service = new VerifierService(
      tenants,
      audit,
      { privateKey: verifier.privateKey, publicKey: verifier.publicKey, publicJwk: verifier.publicJwk, certificateChain: [verifier.certDerBytes] },
      [new Uint8Array(ca.cert.rawData)],
      undefined,
      undefined,
      undefined,
      undefined,
      true,
      { ...DEV_TEST_OPTIONS, issuerRevocation: checker, gracePeriodSeen },
    );
    service.baseUrl = 'http://127.0.0.1:9';
    const created = await service.createRequest('tenant-gp', {});
    const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
    const built = await buildSdJwtVc({ issuerKey: material, holderKey: holder, nonce: String(payload.nonce), audience: String(payload.client_id) });
    const outcome = await service.handlePresentation(created.state, { pid: [built.sdJwt] });

    assert.equal(outcome.valid, true, 'die Gnadenfrist laesst die Praesentation durch');
    const eintraege = audit.list().filter((e) => e.event === 'issuer_revocation_grace_period');
    assert.equal(eintraege.length, 1, `genau ein Ereignis erwartet, war ${JSON.stringify(audit.list())}`);
    const eintrag = eintraege[0]!;
    assert.equal(eintrag.tenant, 'tenant-gp');
    // Format wie im uebrigen Dienst: session=<uuid> reason=<code>
    assert.match(eintrag.detail ?? '', /^session=[0-9a-f-]+ reason=stale_good_reused$/);
  });

  it('ohne Gnadenfrist-Verwendung -> kein Ereignis (Gegenprobe)', async () => {
    const gracePeriodSeen = { count: 0 };
    const checker: RevocationChecker = { async checkRevoked(): Promise<RevocationStatus> { return 'good'; } };
    const tenants = new TenantStore();
    tenants.add({ id: 'tenant-og', name: 'Kunde O (TEST)', apiKey: 'test-api-key-og', requestProfile: { id: 'test-given-name', claims: ['given_name'] } });
    const verifier = await generateTestKeyMaterial('OhneGrace Verifier TEST');
    const holder = await generateTestKeyMaterial('OhneGrace Holder TEST');
    const ca = await createIssuer();
    const audit = new AuditLog();
    const service = new VerifierService(
      tenants,
      audit,
      { privateKey: verifier.privateKey, publicKey: verifier.publicKey, publicJwk: verifier.publicJwk, certificateChain: [verifier.certDerBytes] },
      [new Uint8Array(ca.cert.rawData)],
      undefined,
      undefined,
      undefined,
      undefined,
      true,
      { ...DEV_TEST_OPTIONS, issuerRevocation: checker, gracePeriodSeen },
    );
    service.baseUrl = 'http://127.0.0.1:9';
    const created = await service.createRequest('tenant-og', {});
    const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
    // Blatt IST der Anker, daher wird die Kette gar nicht geprueft.
    const built = await buildSdJwtVc({ issuerKey: await toMaterial(ca), holderKey: holder, nonce: String(payload.nonce), audience: String(payload.client_id) });
    await service.handlePresentation(created.state, { pid: [built.sdJwt] });
    assert.equal(audit.list().filter((e) => e.event === 'issuer_revocation_grace_period').length, 0);
    assert.equal(gracePeriodSeen.count, 0, 'Zaehler bleibt unveraendert');
  });

  it('das Ereignis enthaelt keine Zertifikats-, Claim- oder Responder-Daten', () => {
    // Formale Pruefung des Detail-Formats, wie in fehlerbilder.test.ts gefordert.
    const erlaubt = /^session=[0-9a-f-]+ reason=[a-z_]+$/;
    const verboten = [/\bCN=/, /-----BEGIN/, /serial/i, /MII[A-Za-z0-9+/]/, /http:\/\//, /https:\/\//, /given_name/, /revokedAt/];
    for (const detail of ['session=0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d reason=stale_good_reused']) {
      assert.match(detail, erlaubt);
      for (const muster of verboten) assert.doesNotMatch(detail, muster);
    }
  });
});
