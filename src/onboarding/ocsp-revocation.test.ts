/**
 * Schritt 1/4/5 der OCSP-Umstellung: OCSP-Client (RFC 6960) fail closed.
 *
 * Der OCSP-Responder ist ein echter lokaler HTTP-Server auf 127.0.0.1, der
 * DER-kodierte, mit dem TEST-Ausstellerschlüssel signierte OCSP-Antworten
 * ausliefert. Es gibt keinen Aufruf ins Netz.
 *
 * Geprüft wird jeder Fehlerpfad einzeln (fester Code) und jeweils mit einer
 * positiven Gegenprobe, damit kein Test bloß "irgendetwas wirft" belegt.
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';

import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
  BasicOCSPResponse,
  CertID,
  CertStatus,
  KeyHash,
  id_pkix_ocsp_basic,
  id_pkix_ocsp_nonce,
  OCSPRequest,
  OCSPResponse,
  OCSPResponseStatus,
  ResponderID,
  ResponseBytes,
  ResponseData,
  RevokedInfo,
  SingleResponse,
} from '@peculiar/asn1-ocsp';
import { AlgorithmIdentifier, Certificate as AsnCertificate, CRLReason, Extension } from '@peculiar/asn1-x509';
import { AuthorityInfoAccessExtension, BasicConstraintsExtension, ExtendedKeyUsageExtension, X509Certificate, X509CertificateGenerator } from '@peculiar/x509';

import { OnboardingError } from './errors.ts';
import { buildCertId, buildOcspRequest, ecdsaDerToRaw, OcspRevocationChecker, responderKeyHash, subjectNameDer, type OcspRevocationCheckerOptions } from './ocsp-revocation.ts';
import { enforceRevocation } from './revocation.ts';

const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const ID_KP_OCSPSIGNING = '1.3.6.1.5.5.7.3.9';

let server!: http.Server;
let base!: string;
/** Anzahl der empfangenen OCSP-Anfragen pro Route. */
const hits = new Map<string, number>();

interface Ca {
  key: CryptoKeyPair;
  cert: X509Certificate;
}

interface ResponderOptions {
  status: 'good' | 'revoked' | 'hold' | 'unknown';
  subject: X509Certificate;
  issuer: Ca;
  thisUpdate: Date;
  nextUpdate?: Date;
  /** Nonce, die der Responder zurückgibt. `undefined` = keine Nonce beantworten. */
  echoNonce?: Uint8Array;
  /** Anstelle der Antwort nur einen responseStatus liefern. */
  responseStatus?: OCSPResponseStatus;
  /** Statt der echten Antwort beliebige Bytes liefern. */
  raw?: Uint8Array;
  /** Mit diesem Schlüssel signieren statt mit dem Ausstellerschlüssel. */
  signWith?: CryptoKey;
  /** Zertifikat, dessen Hash als responderID byKey gemeldet wird. */
  responderIdFrom?: X509Certificate;
  /** Delegiertes Responder-Zertifikat einbetten. */
  responderCert?: AsnCertificate;
}

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}

async function createCa(cn: string): Promise<Ca> {
  const key = await generateKeyPair();
  const cert = await X509CertificateGenerator.createSelfSigned({
    serialNumber: crypto.randomUUID().replace(/-/g, ''),
    name: `CN=${cn}, C=DE`,
    notBefore: new Date(Date.now() - 3_600_000),
    notAfter: new Date(Date.now() + 30 * 86_400_000),
    keys: key,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [new BasicConstraintsExtension(true, 1, true)],
  });
  return { key, cert: new X509Certificate(new Uint8Array(cert.rawData)) };
}

async function issueLeaf(ca: Ca, cn: string, aiaUrl?: string, serialNumber = crypto.randomUUID().replace(/-/g, '')): Promise<{ key: CryptoKeyPair; cert: X509Certificate }> {
  const key = await generateKeyPair();
  const cert = await X509CertificateGenerator.create({
    serialNumber,
    subject: `CN=${cn}, C=DE`,
    issuer: ca.cert.subject,
    notBefore: new Date(Date.now() - 3_600_000),
    notAfter: new Date(Date.now() + 30 * 86_400_000),
    publicKey: key.publicKey,
    signingKey: ca.key.privateKey,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [new BasicConstraintsExtension(false), ...(aiaUrl ? [new AuthorityInfoAccessExtension({ ocsp: aiaUrl }, false)] : [])],
  });
  return { key, cert: new X509Certificate(new Uint8Array(cert.rawData)) };
}

interface ResponderCert {
  asn: AsnCertificate;
  cert: X509Certificate;
  key: CryptoKeyPair;
}

async function issueResponderCert(ca: Ca, cn: string, withEku: boolean): Promise<ResponderCert> {
  const key = await generateKeyPair();
  const cert = await X509CertificateGenerator.create({
    serialNumber: crypto.randomUUID().replace(/-/g, ''),
    subject: `CN=${cn}, C=DE`,
    issuer: ca.cert.subject,
    notBefore: new Date(Date.now() - 3_600_000),
    notAfter: new Date(Date.now() + 10 * 86_400_000),
    publicKey: key.publicKey,
    signingKey: ca.key.privateKey,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [new BasicConstraintsExtension(false), ...(withEku ? [new ExtendedKeyUsageExtension([ID_KP_OCSPSIGNING], false)] : [])],
  });
  const parsed = new X509Certificate(new Uint8Array(cert.rawData));
  return { asn: AsnConvert.parse(new Uint8Array(cert.rawData), AsnCertificate) as AsnCertificate, cert: parsed, key };
}

/** Rohe WebCrypto-ECDSA-Signatur -> DER (SEQUENCE { r, s }) für den Responder. */
function rawToEcdsaDer(raw: Uint8Array): Uint8Array {
  const half = raw.length / 2;
  const integers = [raw.subarray(0, half), raw.subarray(half)].map((part) => {
    let start = 0;
    while (start < part.length - 1 && part[start] === 0x00) start += 1;
    let value = part.subarray(start);
    if (value[0] & 0x80) value = Uint8Array.from([0x00, ...value]);
    return [0x02, value.length, ...value];
  });
  const body = [...integers[0], ...integers[1]];
  return Uint8Array.from([0x30, body.length, ...body]);
}

async function buildResponse(options: ResponderOptions): Promise<Uint8Array> {
  if (options.raw) {
    return new Uint8Array([0x30, 0x03, 0x0a, 0x01, 0x00]);
  }
  const certId = await buildCertId(options.subject, options.issuer.cert);
  const certStatus =
    options.status === 'good'
      ? new CertStatus({ good: null })
      : options.status === 'unknown'
        ? new CertStatus({ unknown: null })
        : new CertStatus({ revoked: new RevokedInfo({ revocationTime: new Date(Date.now() - 60_000), ...(options.status === 'hold' ? { revocationReason: new CRLReason(6) } : {}) }) });

  const single = new SingleResponse({
    certID: certId,
    certStatus,
    thisUpdate: options.thisUpdate,
    ...(options.nextUpdate ? { nextUpdate: options.nextUpdate } : {}),
    ...(options.echoNonce ? { singleExtensions: [new Extension({ extnID: id_pkix_ocsp_nonce, extnValue: new OctetString(options.echoNonce), critical: false })] } : {}),
  });

  // responderID byKey: der Client vergleicht die Bytes mit dem erwarteten Signaturinhaber.
  const tbs = new ResponseData({ responderID: new ResponderID({ byKey: new KeyHash(responderKeyHash(options.responderIdFrom ?? options.issuer.cert)) }), producedAt: new Date(), responses: [single] });
  const tbsDer = AsnConvert.serialize(tbs);
  const signKey = options.signWith ?? options.issuer.key.privateKey;
  const rawSignature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signKey, tbsDer as unknown as BufferSource));
  const basic = new BasicOCSPResponse({
    tbsResponseData: tbs,
    signatureAlgorithm: new AlgorithmIdentifier({ algorithm: OID_ECDSA_SHA256 }),
    signature: rawToEcdsaDer(rawSignature).buffer as ArrayBuffer,
    ...(options.responderCert ? { certs: [options.responderCert] } : {}),
  });

  const response = new OCSPResponse({
    responseStatus: options.responseStatus ?? OCSPResponseStatus.successful,
    ...(options.responseStatus !== undefined && options.responseStatus !== OCSPResponseStatus.successful
      ? {}
      : { responseBytes: new ResponseBytes({ responseType: id_pkix_ocsp_basic, response: new OctetString(AsnConvert.serialize(basic)) }) }),
  });
  return new Uint8Array(AsnConvert.serialize(response));
}

/** Registriert eine Route, die genau einmal antwortet. */
function route(path: string, handler: (body: Uint8Array) => Promise<Uint8Array> | Uint8Array, delayMs = 0): void {
  hits.set(path, 0);
  routes.set(path, async (req, res) => {
    hits.set(path, (hits.get(path) ?? 0) + 1);
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const requestBody = new Uint8Array(Buffer.concat(chunks));
    if (delayMs > 0) await new Promise((resolve) => setTimeout(resolve, delayMs));
    let out: Uint8Array;
    try {
      out = await handler(requestBody);
    } catch {
      res.writeHead(500).end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/ocsp-response' });
    res.end(out);
  });
}

const routes = new Map<string, (req: http.IncomingMessage, res: http.ServerResponse) => Promise<void>>();

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const path = (req.url ?? '/').split('?')[0];
    const handler = routes.get(path);
    if (!handler) {
      res.writeHead(404).end();
      return;
    }
    void handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  base = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function checkerFor(overrides: OcspRevocationCheckerOptions = {}): OcspRevocationChecker {
  return new OcspRevocationChecker({ allowInsecureHttp: true, timeoutMs: 1_000, ...overrides });
}

async function rejectsWithCode(run: () => Promise<unknown>, code: string, hinweis?: string): Promise<void> {
  await assert.rejects(run, (e: unknown) => {
    assert.ok(e instanceof OnboardingError, `OnboardingError erwartet, war: ${String(e)}${hinweis ? ` (${hinweis})` : ''}`);
    assert.equal(e.code, code, hinweis);
    return true;
  });
}

describe('OCSP-Client: Grundpfad (fail closed)', () => {
  it('gültiges Zertifikat -> good', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Gueltig TEST', `${base}/good`);
    route('/good', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(Date.now() - 60_000), nextUpdate: new Date(Date.now() + 3600_000) }));
    const status = await checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData));
    assert.equal(status, 'good');
  });

  it('gesperrtes Zertifikat -> revoked', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Gesperrt TEST', `${base}/revoked`);
    route('/revoked', () => buildResponse({ status: 'revoked', subject: leaf.cert, issuer: ca, thisUpdate: new Date(Date.now() - 60_000), nextUpdate: new Date(Date.now() + 3600_000) }));
    const status = await checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData));
    assert.equal(status, 'revoked');
  });

  it('certificateHold -> suspended', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Ausgesetzt TEST', `${base}/hold`);
    route('/hold', () => buildResponse({ status: 'hold', subject: leaf.cert, issuer: ca, thisUpdate: new Date(Date.now() - 60_000), nextUpdate: new Date(Date.now() + 3600_000) }));
    const status = await checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData));
    assert.equal(status, 'suspended');
  });

  it('unbekannter Status -> revocation_status_unknown (fail closed)', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Unbekannt TEST', `${base}/unknown`);
    route('/unknown', () => buildResponse({ status: 'unknown', subject: leaf.cert, issuer: ca, thisUpdate: new Date(Date.now() - 60_000), nextUpdate: new Date(Date.now() + 3600_000) }));
    await rejectsWithCode(() => checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_status_unknown');
  });
});

describe('OCSP-Client: Zeitgrenze und Erreichbarkeit', () => {
  it('Responder nicht erreichbar -> revocation_unavailable', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Offline TEST', 'http://127.0.0.1:1/ocsp');
    await rejectsWithCode(() => checkerFor({ timeoutMs: 500 }).checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_unavailable');
  });

  it('Responder antwortet nicht (Zeitüberschreitung) -> revocation_timeout', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Hängend TEST', `${base}/hang`);
    route('/hang', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(), nextUpdate: new Date(Date.now() + 3600_000) }), 3_000);
    const started = Date.now();
    await rejectsWithCode(() => checkerFor({ timeoutMs: 300 }).checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_timeout');
    assert.ok(Date.now() - started < 2_500, 'Zeitgrenze muss greifen, nicht die Antwortzeit des Servers');
  });

  it('HTTP-Fehler des Responders -> revocation_unavailable', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'HTTP500 TEST', `${base}/kaputt`);
    hits.set('/kaputt', 0);
    routes.set('/kaputt', async (_req, res) => {
      hits.set('/kaputt', (hits.get('/kaputt') ?? 0) + 1);
      res.writeHead(500).end();
    });
    await rejectsWithCode(() => checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_unavailable');
  });

  it('Antwort zu groß -> revocation_list_too_large', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Riesig TEST', `${base}/gross`);
    route('/gross', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(), nextUpdate: new Date(Date.now() + 3600_000) }));
    await rejectsWithCode(() => checkerFor({ maxBytes: 32 }).checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_list_too_large');
  });

  it('ohne AIA-Adresse -> revocation_source_missing', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Ohne AIA TEST');
    await rejectsWithCode(() => checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_source_missing');
  });

  it('http-Adresse im Betrieb abgelehnt (nur mit allowInsecureHttp, z. B. Tests)', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Nur http TEST', `${base}/good2`);
    route('/good2', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(), nextUpdate: new Date(Date.now() + 3600_000) }));
    await rejectsWithCode(() => new OcspRevocationChecker().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_source_missing');
    assert.equal(await new OcspRevocationChecker({ allowInsecureHttp: true }).checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'good', 'Gegenprobe: mit Testschalter erlaubt');
  });

  it('responseStatus tryLater -> revocation_unavailable', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'TryLater TEST', `${base}/trylater`);
    route('/trylater', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(), responseStatus: OCSPResponseStatus.tryLater }));
    await rejectsWithCode(() => checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_unavailable');
  });

  it('Müllantwort -> revocation_list_malformed', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Müll TEST', `${base}/muell`);
    route('/muell', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(), raw: new Uint8Array([1, 2, 3]) }));
    await rejectsWithCode(() => checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_list_malformed');
  });
});

describe('OCSP-Client: Signatur der Antwort', () => {
  it('falsch signiert -> revocation_list_signature_invalid', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Falsch signiert TEST', `${base}/falsch`);
    const attacker = await generateKeyPair();
    route('/falsch', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(), nextUpdate: new Date(Date.now() + 3600_000), signWith: attacker.privateKey }));
    await rejectsWithCode(() => checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_list_signature_invalid');
  });

  it('Antwort einer fremden CA -> revocation_list_signature_invalid', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const other = await createCa('Fremde Ca TEST');
    const leaf = await issueLeaf(ca, 'Fremder Aussteller TEST', `${base}/fremd`);
    route('/fremd', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: other, thisUpdate: new Date(), nextUpdate: new Date(Date.now() + 3600_000) }));
    await rejectsWithCode(() => checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_list_signature_invalid');
  });

  it('delegierter Responder mit OCSPSigning-EKU -> good', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Delegiert TEST', `${base}/delegiert`);
    const responder = await issueResponderCert(ca, 'OCSP Responder delegiert TEST', true);
    route('/delegiert', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(), nextUpdate: new Date(Date.now() + 3600_000), responderCert: responder.asn, responderIdFrom: responder.cert, signWith: responder.key.privateKey }));
    assert.equal(await checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'good');
  });

  it('eingebettetes Zertifikat ohne OCSPSigning-EKU -> abgelehnt', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Delegiert ohne EKU TEST', `${base}/delegiert-ohne-eku`);
    const responder = await issueResponderCert(ca, 'OCSP Responder ohne EKU TEST', false);
    route('/delegiert-ohne-eku', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(), nextUpdate: new Date(Date.now() + 3600_000), responderCert: responder.asn, responderIdFrom: responder.cert, signWith: responder.key.privateKey }));
    await rejectsWithCode(() => checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_list_signature_invalid');
  });
});

describe('OCSP-Client: Nonce (Replay)', () => {
  it('die Anfrage trägt eine Nonce, die Antwort wird gegen sie geprüft', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Nonce TEST', `${base}/nonce`);
    let seenNonce: Uint8Array | undefined;
    route('/nonce', async (body) => {
      const request = AsnConvert.parse(body, OCSPRequest);
      const ext = request.tbsRequest.requestExtensions?.find((e) => e.extnID === id_pkix_ocsp_nonce);
      assert.ok(ext, 'Nonce-Erweiterung fehlt in der Anfrage');
      seenNonce = new Uint8Array(ext.extnValue.buffer, ext.extnValue.byteOffset, ext.extnValue.byteLength);
      return buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(), nextUpdate: new Date(Date.now() + 3600_000), echoNonce: seenNonce });
    });
    assert.equal(await checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'good');
    assert.equal(seenNonce?.length, 16, 'Nonce muss 16 Zufallsbytes sein');
  });

  it('falsche Nonce in der Antwort -> revocation_list_malformed (Replay abgewehrt)', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Replay TEST', `${base}/replay`);
    route('/replay', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(), nextUpdate: new Date(Date.now() + 3600_000), echoNonce: new Uint8Array(16).fill(7) }));
    await rejectsWithCode(() => checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_list_malformed');
  });

  it('Responder ohne Nonce -> akzeptiert, Zeitbindung gilt (Dokumentierte Ausnahme)', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Ohne Nonce TEST', `${base}/ohne-nonce`);
    route('/ohne-nonce', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(Date.now() - 60_000), nextUpdate: new Date(Date.now() + 3600_000) }));
    assert.equal(await checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'good');
  });

  it('Antwort ohne nextUpdate -> revocation_list_expired (Aktualität nicht beurteilbar)', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Ohne nextUpdate TEST', `${base}/ohne-nextupdate`);
    route('/ohne-nextupdate', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(Date.now() - 60_000) }));
    await rejectsWithCode(() => checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_list_expired');
  });
});

describe('OCSP-Client: Zeitbindung und Zuordnung', () => {
  it('thisUpdate in der Zukunft -> revocation_list_malformed', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Zukunft TEST', `${base}/zukunft`);
    route('/zukunft', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(Date.now() + 3_600_000), nextUpdate: new Date(Date.now() + 7200_000) }));
    await rejectsWithCode(() => checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_list_malformed');
  });

  it('nextUpdate überschritten -> revocation_list_expired', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Veraltet TEST', `${base}/veraltet`);
    route('/veraltet', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(Date.now() - 7_200_000), nextUpdate: new Date(Date.now() - 3_600_000) }));
    await rejectsWithCode(() => checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_list_expired');
  });

  it('Antwort passt zu einem anderen Zertifikat -> revocation_list_malformed', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Fremdes Ziel TEST', `${base}/fremdes-ziel`);
    const other = await issueLeaf(ca, 'Anderes TEST', `${base}/egal`);
    route('/fremdes-ziel', () => buildResponse({ status: 'good', subject: other.cert, issuer: ca, thisUpdate: new Date(), nextUpdate: new Date(Date.now() + 3600_000) }));
    await rejectsWithCode(() => checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_list_malformed');
  });

  it('Aussteller passt nicht zum Zertifikat -> revocation_list_malformed', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const other = await createCa('Andere Ca TEST');
    const leaf = await issueLeaf(ca, 'Falscher Aussteller TEST', `${base}/egal2`);
    await rejectsWithCode(() => checkerFor().checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(other.cert.rawData)), 'revocation_list_malformed');
  });
});

describe('OCSP-Client: Cache nach nextUpdate (Schritt 4)', () => {
  it('zwei Prüfungen innerhalb der Gültigkeit -> nur eine Anfrage', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Cache TEST', `${base}/cache`);
    route('/cache', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(Date.now() - 60_000), nextUpdate: new Date(Date.now() + 3600_000) }));
    const checker = checkerFor();
    const cert = new Uint8Array(leaf.cert.rawData);
    const issuer = new Uint8Array(ca.cert.rawData);
    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'good');
    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'good');
    assert.equal(hits.get('/cache'), 1, 'zweite Prüfung muss aus dem Cache kommen');
  });

  it('nach Ablauf von nextUpdate wird neu geholt', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Cache Ablauf TEST', `${base}/cache-ablauf`);
    let now = new Date('2026-09-25T10:00:00Z');
    route('/cache-ablauf', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: now, nextUpdate: new Date(now.getTime() + 120_000) }));
    const checker = checkerFor({ now: () => now });
    const cert = new Uint8Array(leaf.cert.rawData);
    const issuer = new Uint8Array(ca.cert.rawData);
    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'good');
    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'good');
    assert.equal(hits.get('/cache-ablauf'), 1);
    now = new Date(now.getTime() + 121_000);
    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'good', 'nach Ablauf wird neu geholt');
    assert.equal(hits.get('/cache-ablauf'), 2, 'zweite Anfrage nach Ablauf erwartet');
  });

  it('Cache-Gültigkeit endet spätestens nach der Obergrenze, auch bei fernem nextUpdate', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Cache Obergrenze TEST', `${base}/cache-grenze`);
    let now = new Date('2026-09-25T10:00:00Z');
    route('/cache-grenze', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: now, nextUpdate: new Date(now.getTime() + 365 * 86_400_000) }));
    const checker = checkerFor({ now: () => now, maxCacheTtlMs: 60_000 });
    const cert = new Uint8Array(leaf.cert.rawData);
    const issuer = new Uint8Array(ca.cert.rawData);
    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'good');
    now = new Date(now.getTime() + 60_001);
    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'good');
    assert.equal(hits.get('/cache-grenze'), 2, 'Obergrenze muss greifen');
  });

  it('Fehlerantworten werden nicht gecacht (zweiter Versuch fragt erneut)', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Cache Fehler TEST', `${base}/cache-fehler`);
    let antwort = 'kaputt';
    route('/cache-fehler', () => (antwort === 'kaputt' ? buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(), raw: new Uint8Array([9, 9, 9]) }) : buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(), nextUpdate: new Date(Date.now() + 3600_000) })));
    const checker = checkerFor();
    const cert = new Uint8Array(leaf.cert.rawData);
    const issuer = new Uint8Array(ca.cert.rawData);
    await rejectsWithCode(() => checker.checkRevoked(cert, 'leaf', issuer), 'revocation_list_malformed');
    antwort = 'gut';
    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'good');
    assert.equal(hits.get('/cache-fehler'), 2);
  });
});

describe('OCSP-Client: Anbindung an enforceRevocation', () => {
  it('good passiert, revoked wirft certificate_revoked', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Enforce TEST', `${base}/enforce`);
    route('/enforce', () => buildResponse({ status: 'good', subject: leaf.cert, issuer: ca, thisUpdate: new Date(), nextUpdate: new Date(Date.now() + 3600_000) }));
    const checker = checkerFor();
    await enforceRevocation(checker, new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData), 2_000);
  });

  it('revoked -> certificate_revoked über enforceRevocation', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Enforce gesperrt TEST', `${base}/enforce-gesperrt`);
    route('/enforce-gesperrt', () => buildResponse({ status: 'revoked', subject: leaf.cert, issuer: ca, thisUpdate: new Date(), nextUpdate: new Date(Date.now() + 3600_000) }));
    await rejectsWithCode(() => enforceRevocation(checkerFor(), new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData), 2_000), 'certificate_revoked');
  });
});

describe('Hilfsfunktion: ECDSA-Signatur DER -> roh', () => {
  it('konvertiert zwei INTEGER korrekt', () => {
    // r = 0x01, s = 0x02
    const der = Uint8Array.from([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
    const raw = ecdsaDerToRaw(der, 32);
    assert.equal(raw.length, 64);
    assert.equal(raw[31], 0x01);
    assert.equal(raw[63], 0x02);
  });

  it('führendes 0x00 wird entfernt, kurze Werte linksbündig', () => {
    const der = Uint8Array.from([0x30, 0x08, 0x02, 0x02, 0x00, 0x7f, 0x02, 0x02, 0x00, 0x80]);
    const raw = ecdsaDerToRaw(der, 32);
    assert.equal(raw[31], 0x7f);
    assert.equal(raw[63], 0x80);
  });

  it('lebnt unplausible Eingaben ab', () => {
    const faelle: Uint8Array[] = [
      Uint8Array.from([0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]), // falsches Tag
      Uint8Array.from([0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]), // Länge passt nicht
      Uint8Array.from([0x30, 0x08, 0x03, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00]), // kein INTEGER
      Uint8Array.from([0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x02]), // negativer Wert
      Uint8Array.from([0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00]), // Restbytes
      Uint8Array.from([0x30, 0x06, 0x02, 0x00, 0x02, 0x01, 0x02]), // leerer INTEGER
    ];
    for (const der of faelle) assert.throws(() => ecdsaDerToRaw(der, 32));
  });
});

describe('CertID- und Request-Bau', () => {
  it('buildOcspRequest erzeugt eine parsebare Anfrage mit CertID und Nonce', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'Request TEST');
    const certId = await buildCertId(leaf.cert, ca.cert);
    const nonce = new Uint8Array([1, 2, 3, 4]);
    const parsed = AsnConvert.parse(buildOcspRequest(certId, nonce), OCSPRequest);
    assert.equal(parsed.tbsRequest.requestList.length, 1);
    assert.equal(parsed.tbsRequest.requestList[0]?.reqCert.serialNumber.byteLength > 0, true);
    const ext = parsed.tbsRequest.requestExtensions?.find((e) => e.extnID === id_pkix_ocsp_nonce);
    assert.ok(ext);
    assert.deepEqual([...new Uint8Array(ext.extnValue.buffer, ext.extnValue.byteOffset, ext.extnValue.byteLength)], [1, 2, 3, 4]);
  });

  it('CertID enthält die Hashes nach RFC 6960 (SHA-1 über Name und Schlüssel)', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'CertID TEST');
    const certId: CertID = await buildCertId(leaf.cert, ca.cert);
    const nameHash = new Uint8Array(await crypto.subtle.digest('SHA-1', subjectNameDer(ca.cert) as unknown as BufferSource));
    assert.equal(certId.hashAlgorithm.algorithm, '1.3.14.3.2.26');
    assert.deepEqual([...new Uint8Array(certId.issuerNameHash.buffer, certId.issuerNameHash.byteOffset, certId.issuerNameHash.byteLength)], [...nameHash]);
    assert.equal(new Uint8Array(certId.issuerKeyHash.buffer, certId.issuerKeyHash.byteOffset, certId.issuerKeyHash.byteLength).length, 20);
  });
});

// ---------------------------------------------------------------------------
// Option B aus docs/entscheidung-ocsp-fail-modus.md: begrenzte Gnadenfrist
// fuer veraltete, zuvor verifizierte `good`-Antworten. Die Zeit wird ueber die
// Uhr des Checkers gesteuert (`now`), damit die Grenzen exakt getroffen werden.
// Der Ausfall des Responders wird als HTTP 503 simuliert; das ist fuer den
// Client ein normaler Sperrquellenausfall (kein Timeout, kein Formatfehler).
// ---------------------------------------------------------------------------
describe('OCSP-Client: Option B — drei Zustaende und Grenzfall 24 h', () => {
  const FRIST_24H = 24 * 60 * 60 * 1000;

  /** Route, die auf Zuruf mit HTTP 503 (Responder ausgefallen) antwortet. */
  function outageRoute(path: string): () => void {
    hits.set(path, 0);
    routes.set(path, async (_req, res) => {
      hits.set(path, (hits.get(path) ?? 0) + 1);
      for await (const chunk of _req) void chunk;
      res.writeHead(503).end();
    });
    return () => {
      routes.set(path, async (_req, res) => {
        hits.set(path, (hits.get(path) ?? 0) + 1);
        res.writeHead(503).end();
      });
    };
  }

  /**
   * Route, die eine `good`-Antwort mit fester thisUpdate/nextUpdate liefert und
   * auf Zuruf in den Ausfallzustand (HTTP 503) wechselt.
   */
  function goodRoute(path: string, ca: Ca, leaf: X509Certificate, thisUpdate: Date, nextUpdate: Date): void {
    hits.set(path, 0);
    routes.set(path, async (req, res) => {
      hits.set(path, (hits.get(path) ?? 0) + 1);
      for await (const chunk of req) void chunk;
      if (outageRoutes.get(path) === true) {
        res.writeHead(503).end();
        return;
      }
      res.writeHead(200, { 'content-type': 'application/ocsp-response' });
      res.end(await buildResponse({ status: 'good', subject: leaf, issuer: ca, thisUpdate, nextUpdate }));
    });
    outageRoutes.set(path, false);
    outageSwitch.set(path, () => {
      outageRoutes.set(path, true);
    });
  }

  const outageRoutes = new Map<string, boolean>();
  const outageSwitch = new Map<string, () => void>();

  it('Zustand A: innerhalb nextUpdate wird der Cache genutzt, keine zweite Anfrage', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'ZustandA TEST', `${base}/zustand-a`);
    const start = new Date('2026-09-25T08:00:00Z');
    let now = start;
    goodRoute('/zustand-a', ca, leaf.cert, start, new Date(start.getTime() + 3600_000));
    const checker = checkerFor({ now: () => now, unavailableMode: 'bounded-soft-fail' });
    const cert = new Uint8Array(leaf.cert.rawData);
    const issuer = new Uint8Array(ca.cert.rawData);

    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'good');
    // Responder faellt aus, 30 Minuten spaeter: noch innerhalb nextUpdate
    now = new Date(start.getTime() + 1800_000);
    outageSwitch.get('/zustand-a')?.();
    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'good', 'Zustand A trifft ohne Abfrage zu');
    assert.equal(hits.get('/zustand-a'), 1, 'innerhalb nextUpdate keine weitere Anfrage');
  });

  it('Zustand B: nach nextUpdate, aber innerhalb der Frist, wird die veraltete good-Antwort genutzt', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'ZustandB TEST', `${base}/zustand-b`);
    const start = new Date('2026-09-25T08:00:00Z');
    let now = start;
    goodRoute('/zustand-b', ca, leaf.cert, start, new Date(start.getTime() + 3600_000));
    const checker = checkerFor({ now: () => now, unavailableMode: 'bounded-soft-fail' });
    const cert = new Uint8Array(leaf.cert.rawData);
    const issuer = new Uint8Array(ca.cert.rawData);

    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'good', 'Vorabantwort holen');
    now = new Date(start.getTime() + 3601_000);
    outageSwitch.get('/zustand-b')?.();
    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'good', 'Zustand B: veraltete good-Antwort wird genutzt');
    assert.equal(hits.get('/zustand-b'), 2, 'im Zustand B wird neu gefragt und der Ausfall toleriert');
  });

  it('Zustand C: exakt am Ende der 24-Stunden-Frist noch good, 1 ms spaeter Ablehnung', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'ZustandC TEST', `${base}/zustand-c`);
    const start = new Date('2026-09-25T08:00:00Z');
    let now = start;
    goodRoute('/zustand-c', ca, leaf.cert, start, new Date(start.getTime() + 3600_000));
    const checker = checkerFor({ now: () => now, unavailableMode: 'bounded-soft-fail' });
    const cert = new Uint8Array(leaf.cert.rawData);
    const issuer = new Uint8Array(ca.cert.rawData);

    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'good', 'Vorabantwort holen');
    outageSwitch.get('/zustand-c')?.();
    // Genau am Fristende (nextUpdate + 24 h): noch innerhalb.
    now = new Date(start.getTime() + 3600_000 + FRIST_24H);
    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'good', 'exakt am Fristende gilt die Frist noch');
    // 1 ms später: Ablehnung.
    now = new Date(now.getTime() + 1);
    await assert.rejects(() => checker.checkRevoked(cert, 'leaf', issuer), (e: unknown) => {
      assert.ok(e instanceof OnboardingError);
      assert.equal(e.code, 'revocation_unavailable');
      return true;
    });
  });

  it('Zustand C: ohne Vorabantwort gibt es keine Gnadenfrist', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'OhneVorabantwort TEST', `${base}/ohne-vorabantwort`);
    outageRoute('/ohne-vorabantwort')();
    const checker = checkerFor({ unavailableMode: 'bounded-soft-fail' });
    await rejectsWithCode(() => checker.checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'revocation_unavailable');
  });

  it('Zustand C: revoked wird nie weich behandelt', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'RevokedFrist TEST', `${base}/revoked-mit-frist`);
    const start = new Date('2026-09-25T08:00:00Z');
    let now = start;
    route('/revoked-mit-frist', () => buildResponse({ status: 'revoked', subject: leaf.cert, issuer: ca, thisUpdate: start, nextUpdate: new Date(start.getTime() + 3600_000) }));
    const checker = checkerFor({ now: () => now, unavailableMode: 'bounded-soft-fail' });
    const cert = new Uint8Array(leaf.cert.rawData);
    const issuer = new Uint8Array(ca.cert.rawData);
    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'revoked');
    // Jetzt fällt der Responder aus und die Frist läuft ab: die gecachte
    // Sperrung darf unter keinen Umständen zu 'good' werden.
    outageRoute('/revoked-mit-frist')();
    now = new Date(start.getTime() + 3600_000 + FRIST_24H + 1);
    await rejectsWithCode(() => checker.checkRevoked(cert, 'leaf', issuer), 'revocation_unavailable', 'gecachtes revoked wird nie zu good');
  });

  it('Zustand C: suspended wird nie weich behandelt', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'SuspendedFrist TEST', `${base}/suspended-mit-frist`);
    const start = new Date('2026-09-25T08:00:00Z');
    route('/suspended-mit-frist', () => buildResponse({ status: 'hold', subject: leaf.cert, issuer: ca, thisUpdate: start, nextUpdate: new Date(start.getTime() + 3600_000) }));
    const checker = checkerFor({ now: () => start, unavailableMode: 'bounded-soft-fail' });
    assert.equal(await checker.checkRevoked(new Uint8Array(leaf.cert.rawData), 'leaf', new Uint8Array(ca.cert.rawData)), 'suspended');
  });

  it('fail-closed (Default) lehnt auch mit vorhandener Vorabantwort ab', async () => {
    const ca = await createCa('OCSP Ca TEST');
    const leaf = await issueLeaf(ca, 'FailclosedFrist TEST', `${base}/fail-closed-frist`);
    const start = new Date('2026-09-25T08:00:00Z');
    goodRoute('/fail-closed-frist', ca, leaf.cert, start, new Date(start.getTime() + 3600_000));
    let now = start;
    const checker = checkerFor({ now: () => now }); // Default: fail-closed
    const cert = new Uint8Array(leaf.cert.rawData);
    const issuer = new Uint8Array(ca.cert.rawData);
    assert.equal(await checker.checkRevoked(cert, 'leaf', issuer), 'good', 'Vorabantwort holen');
    // nextUpdate überschritten, Responder fällt aus: fail-closed lehnt ab,
    // obwohl ein Cache-Eintrag mit Status 'good' existiert.
    now = new Date(start.getTime() + 3601_000);
    outageSwitch.get('/fail-closed-frist')?.();
    await rejectsWithCode(() => checker.checkRevoked(cert, 'leaf', issuer), 'revocation_unavailable', 'fail-closed nutzt den alten Eintrag nicht');
  });
});

describe('OCSP-Client: paralleler Cache-Stresstest', () => {
  it('isoliert gleiche Seriennummern, Nonces und Status unter parallelen Refreshes', async () => {
    const caA = await createCa('OCSP Stress CA A TEST');
    const caB = await createCa('OCSP Stress CA B TEST');
    const sharedSerial = '4242424242424242';
    const leafA = await issueLeaf(caA, 'OCSP Stress A TEST', `${base}/stress`, sharedSerial);
    const leafB = await issueLeaf(caB, 'OCSP Stress B TEST', `${base}/stress`, sharedSerial);
    const entries = [
      { ca: caA, leaf: leafA, status: 'good' as const },
      { ca: caB, leaf: leafB, status: 'revoked' as const },
    ];
    const ids = await Promise.all(entries.map(({ ca, leaf }) => buildCertId(leaf.cert, ca.cert)));
    const idKey = (id: CertID): string => {
      const bytes = (value: ArrayBufferLike | { buffer: ArrayBufferLike; byteOffset: number; byteLength: number }): Uint8Array =>
        typeof value === 'object' && 'byteOffset' in value ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength) : new Uint8Array(value);
      return [id.hashAlgorithm.algorithm, bytes(id.issuerNameHash), bytes(id.issuerKeyHash), bytes(id.serialNumber)].map((part) => (typeof part === 'string' ? part : [...part].join(','))).join('|');
    };
    const expected = new Map(ids.map((id, index) => [idKey(id), entries[index]?.status]));
    let now = new Date('2026-09-27T12:00:00Z');
    let responseEpoch = 0;
    let nonceCounter = 0;
    let requests = 0;
    hits.set('/stress', 0);
    routes.set('/stress', async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const parsed = AsnConvert.parse(new Uint8Array(Buffer.concat(chunks)), OCSPRequest);
      const request = parsed.tbsRequest.requestList[0];
      assert.ok(request);
      const requestedId = request.reqCert;
      const selectedIndex = ids.findIndex((id) => idKey(id) === idKey(requestedId));
      assert.notEqual(selectedIndex, -1, 'Responder erhielt eine unbekannte CertID');
      const selected = entries[selectedIndex];
      assert.ok(selected);
      const nonceExtension = parsed.tbsRequest.requestExtensions?.find((extension) => extension.extnID === id_pkix_ocsp_nonce);
      assert.ok(nonceExtension, 'Jede Stress-Anfrage muss eine Nonce tragen');
      const nonce = new Uint8Array(nonceExtension.extnValue.buffer, nonceExtension.extnValue.byteOffset, nonceExtension.extnValue.byteLength);
      const ordinal = requests++;
      await new Promise((resolve) => setTimeout(resolve, (ordinal * 7) % 13));
      const response = await buildResponse({
        status: responseEpoch === 0 ? selected.status : selected.status === 'good' ? 'revoked' : 'good',
        subject: selected.leaf.cert,
        issuer: selected.ca,
        thisUpdate: new Date(now.getTime() - 1_000),
        nextUpdate: new Date(now.getTime() + 60 * 60_000),
        echoNonce: nonce,
      });
      res.writeHead(200, { 'content-type': 'application/ocsp-response' });
      res.end(response);
    });

    const checker = checkerFor({
      now: () => now,
      nonceFactory: () => {
        const nonce = new Uint8Array(16);
        new DataView(nonce.buffer).setUint32(12, nonceCounter++);
        return nonce;
      },
    });
    const query = async (index: number): Promise<string> => {
      const selected = entries[index % entries.length];
      return checker.checkRevoked(new Uint8Array(selected.leaf.cert.rawData), 'leaf', new Uint8Array(selected.ca.cert.rawData));
    };
    const assertExpected = (results: string[], indexes: number[], epoch: number): void => {
      results.forEach((result, index) => {
        const original = entries[indexes[index] % entries.length]?.status;
        const expectedStatus = epoch === 0 ? original : original === 'good' ? 'revoked' : 'good';
        assert.equal(result, expectedStatus);
      });
    };

    const firstIndexes = Array.from({ length: 64 }, (_, index) => index % 2);
    const firstResults = await Promise.all(firstIndexes.map(query));
    assertExpected(firstResults, firstIndexes, 0);
    assert.equal(expected.size, 2, 'Cache-Matrix muss Issuer-Name, Issuer-Key und Serial enthalten');
    assert.equal(requests, 2, 'Parallele Cache-Misses je CertID muessen auf einen OCSP-Request dedupliziert werden');

    // Beide Einträge sind jetzt gecacht. Gleiche Seriennummer, aber getrennte
    // Aussteller dürfen niemals den Status des jeweils anderen erhalten.
    const cacheHitsBefore = requests;
    const cachedIndexes = Array.from({ length: 64 }, (_, index) => (index * 3) % 2);
    assertExpected(await Promise.all(cachedIndexes.map(query)), cachedIndexes, 0);
    assert.equal(requests, cacheHitsBefore, 'Frische Cache-Einträge dürfen keinen Responder-Aufruf auslösen');

    // Nach nextUpdate werden alle Einträge parallel neu geladen. Die Antwort-
    // Reihenfolge ist absichtlich verzögert und wechselt deterministisch.
    now = new Date('2026-09-27T14:00:00Z');
    responseEpoch = 1;
    const refreshIndexes = Array.from({ length: 128 }, (_, index) => (index * 5 + 1) % 2);
    const refreshRequestsBefore = requests;
    const refreshResults = await Promise.all(refreshIndexes.map(query));
    assertExpected(refreshResults, refreshIndexes, 1);
    assert.equal(requests, refreshRequestsBefore + 2, 'Parallele Refreshes je CertID muessen ebenfalls dedupliziert werden');
    assert.ok(requests > cacheHitsBefore, 'Abgelaufene Cache-Einträge müssen neu geladen werden');
    assert.equal(nonceCounter, requests, 'Jeder OCSP-Request erhielt und validierte eine eigene Nonce');
  });
});
