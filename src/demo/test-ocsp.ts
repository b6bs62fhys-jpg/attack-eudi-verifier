/**
 * TEST-OCSP-Responder für die Demo (nur 127.0.0.1, ephemerer Port).
 *
 * Der Responder ist ein echter HTTP-Server, der DER-kodierte OCSP-Antworten
 * nach RFC 6960 ausliefert, signiert mit dem TEST-Schlüssel des jeweiligen
 * Aussteller-Zertifikats. Es ist kein eigener Protokollbau: Kodierung und
 * Prüfung übernehmen @peculiar/asn1-ocsp, @peculiar/x509 und der
 * OcspRevocationChecker aus src/onboarding/ocsp-revocation.ts. Das Muster
 * entspricht src/onboarding/ocsp-revocation.test.ts.
 *
 * Ein Responder bedient mehrere TEST-Aussteller, wie ein echter Responder
 * mehrere Zertifikate bedient: Der Sperrstatus wird über die Seriennummer aus
 * der CertID der Anfrage bestimmt. Dadurch unterscheidet sich das
 * Schlechtfall-Szenario `revoked_wrpac` vom Gutfall nur in der Identität des
 * TEST-Ausstellers, nicht in einem Sonderpfad des Codes.
 *
 * Es werden ausschließlich kurzlebige TEST-Schlüssel im Arbeitsspeicher
 * verwendet. Nichts wird persistiert, geloggt oder an einen externen Server
 * gesendet; der Responder hört ausschließlich auf der Loopback-Adresse.
 */
import http from 'node:http';

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
import { AlgorithmIdentifier, Extension } from '@peculiar/asn1-x509';
import { X509Certificate } from '@peculiar/x509';

import { responderKeyHash } from '../onboarding/ocsp-revocation.ts';
import type { TestKeyMaterial } from '../decision-test/mock-wallet.ts';

const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';

export type OcspStatus = 'good' | 'revoked';

/** Ein TEST-Aussteller, den der Responder bedienen kann. */
export interface OcspResponderIssuer {
  material: TestKeyMaterial;
  cert: X509Certificate;
  status: OcspStatus;
}

export interface TestOcspResponderOptions {
  issuers: OcspResponderIssuer[];
}

/** Seriennummern kommen aus @peculiar/asn1-x509 und @peculiar/x509 als Hex-String. */
function normalizeSerial(serial: string): string {
  return serial.toLowerCase().replace(/^0x/, '');
}

/** Rohe WebCrypto-ECDSA-Signatur -> DER (SEQUENCE { r, s }) für die Antwort. */
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

/** Liest die Nonce-Erweiterung aus der CertID-Anfrage, falls der Client eine sendet. */
function readRequestNonce(single: { singleRequestExtensions?: Extension[] }): Uint8Array | undefined {
  const nonce = single.singleRequestExtensions?.find((e) => e.extnID === id_pkix_ocsp_nonce);
  if (!nonce || typeof nonce.extnValue !== 'string') return undefined;
  try {
    const inner = AsnConvert.parse(Uint8Array.from(Buffer.from(nonce.extnValue, 'base64')), OctetString);
    return new Uint8Array(inner.buffer);
  } catch {
    return undefined;
  }
}

export class TestOcspResponder {
  private readonly issuers: OcspResponderIssuer[] = [];
  private server?: http.Server;
  private bySerial = new Map<string, OcspResponderIssuer>();
  baseUrl = '';
  requestCount = 0;

  constructor(options: TestOcspResponderOptions) {
    for (const issuer of options.issuers) this.addIssuer(issuer);
  }

  async start(): Promise<string> {
    this.server = http.createServer((req, res) => {
      void (async () => {
        if ((req.url ?? '').split('?')[0] !== '/ocsp') {
          res.writeHead(404).end();
          return;
        }
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(chunk as Buffer);
        this.requestCount += 1;
        const requestBody = new Uint8Array(Buffer.concat(chunks));
        try {
          const out = await this.buildResponse(requestBody);
          res.writeHead(200, { 'content-type': 'application/ocsp-response' });
          res.end(out);
        } catch {
          // Unlesbare Anfrage: RFC 6960 §4.2.1, malformedRequest.
          const failure = AsnConvert.serialize(
            new OCSPResponse({ responseStatus: OCSPResponseStatus.malformedRequest }),
          );
          res.writeHead(200, { 'content-type': 'application/ocsp-response' });
          res.end(Buffer.from(failure));
        }
      })();
    });
    await new Promise<void>((resolve) => this.server?.listen(0, '127.0.0.1', resolve));
    const address = this.server?.address() as { port: number };
    this.baseUrl = `http://127.0.0.1:${address.port}`;
    return this.baseUrl;
  }

  /**
   * Registriert einen TEST-Aussteller. Muss nach `start()` aufgerufen werden
   * werden, weil die Ausstellerzertifikate die OCSP-URL mit dem Port des
   * laufenden Responders erzeugen müssen.
   */
  addIssuer(issuer: OcspResponderIssuer): void {
    this.issuers.push(issuer);
    this.bySerial.set(normalizeSerial(issuer.cert.serialNumber), issuer);
  }

  /** Seriennummer eines TEST-Ausstellerzertifikats, hexkodiert. */
  static serialHex(material: TestKeyMaterial): string {
    return normalizeSerial(new X509Certificate(new Uint8Array(material.certDerBytes)).serialNumber);
  }

  private async buildResponse(requestBody: Uint8Array): Promise<Uint8Array> {
    const parsed = AsnConvert.parse(requestBody, OCSPRequest);
    const single = parsed.tbsRequest.requestList[0];
    if (!single) throw new Error('OCSP-Anfrage ohne CertID');
    const serial = normalizeSerial(Buffer.from(single.reqCert.serialNumber).toString('hex'));
    const issuer = this.bySerial.get(serial);
    if (!issuer) {
      // Unbekanntes Zertifikat: nicht "good" melden, sondern `unknown`. Der
      // Checker behandelt das fail closed.
      throw new Error(`TEST-Responder kennt die Seriennummer ${serial} nicht`);
    }

    const certId = new CertID({
      hashAlgorithm: parsed.tbsRequest.requestList[0].reqCert.hashAlgorithm,
      issuerNameHash: single.reqCert.issuerNameHash,
      issuerKeyHash: single.reqCert.issuerKeyHash,
      serialNumber: single.reqCert.serialNumber,
    });
    const certStatus =
      issuer.status === 'good' ? new CertStatus({ good: null }) : new CertStatus({ revoked: new RevokedInfo({ revocationTime: new Date(Date.now() - 60_000) }) });

    // Nonce der Anfrage beantworten (RFC 6960 §4.4.2). `extnValue` kommt aus
    // dem ASN-Schema base64-kodiert und enthält ein OCTET STRING; für die
    // Antwort wird derselbe OctetString wieder eingesetzt.
    const echoOctet = readRequestNonce(single);
    const echoNonce = echoOctet ? new OctetString(echoOctet) : undefined;

    const tbs = new ResponseData({
      responderID: new ResponderID({ byKey: new KeyHash(responderKeyHash(issuer.cert)) }),
      producedAt: new Date(),
      responses: [
        new SingleResponse({
          certID: certId,
          certStatus,
          thisUpdate: new Date(Date.now() - 60_000),
          nextUpdate: new Date(Date.now() + 3_600_000),
          ...(echoNonce ? { singleExtensions: [new Extension({ extnID: id_pkix_ocsp_nonce, extnValue: echoNonce, critical: false })] } : {}),
        }),
      ],
    });
    const tbsDer = AsnConvert.serialize(tbs);
    const rawSignature = new Uint8Array(
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, issuer.material.privateKey, tbsDer as unknown as BufferSource),
    );
    const basic = new BasicOCSPResponse({
      tbsResponseData: tbs,
      signatureAlgorithm: new AlgorithmIdentifier({ algorithm: OID_ECDSA_SHA256 }),
      signature: rawToEcdsaDer(rawSignature).buffer as ArrayBuffer,
    });
    const response = new OCSPResponse({
      responseStatus: OCSPResponseStatus.successful,
      responseBytes: new ResponseBytes({ responseType: id_pkix_ocsp_basic, response: new OctetString(AsnConvert.serialize(basic)) }),
    });
    return new Uint8Array(AsnConvert.serialize(response));
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      this.server.closeAllConnections();
      this.server.close(() => resolve());
      return undefined;
    });
  }
}
