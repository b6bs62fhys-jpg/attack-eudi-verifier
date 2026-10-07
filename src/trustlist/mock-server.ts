/**
 * Lokaler Mock-HTTP-Server für Trust Listen (Baustein A, Test).
 *
 * Liefert eine mit dem TEST-Trust-List-Authority-Schlüssel signierte JWS
 * (typ `trust-list+jwt.test`) unter GET /trustlist. Für Negativtests kann
 * die Signatur gezielt mit einem fremden TEST-Schlüssel erzeugt oder eine
 * status-Abweichung gesetzt werden. Nur 127.0.0.1, ephemerer Port.
 */
import { createServer, type Server } from 'node:http';
import { SignJWT, type JWTPayload } from 'jose';

import type { TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import type { TrustListDocument } from './types.ts';
import { TRUST_LIST_JWS_TYP } from './monitor.ts';

export interface TrustListBuilder {
  id: string;
  issuer: string;
  issuedAt: number;
  nextUpdate: number;
  version: string;
  entries: TrustListDocument['entries'];
}

export function buildTrustListDocument(builder: TrustListBuilder): TrustListDocument {
  return {
    id: builder.id,
    issuer: builder.issuer,
    issuedAt: builder.issuedAt,
    nextUpdate: builder.nextUpdate,
    version: builder.version,
    entries: builder.entries,
  };
}

export function trustListEntry(options: {
  providerName: string;
  country?: string;
  serviceType?: string;
  anchorFingerprintHex: string;
  subjectCommonName: string;
  validFrom?: number;
  validTo?: number;
}): TrustListDocument['entries'][number] {
  const nowSoon = Math.floor(Date.now() / 1000);
  return {
    providerName: options.providerName,
    country: options.country ?? 'DE',
    serviceType: options.serviceType ?? 'https://uri.etsi.org/TrstSvc/eSig/QES_Prov',
    trustAnchorX509Sha256: options.anchorFingerprintHex.toLowerCase(),
    subjectCommonName: options.subjectCommonName,
    validFrom: options.validFrom ?? nowSoon - 60,
    validTo: options.validTo ?? nowSoon + 7 * 24 * 3600,
  };
}

export async function signTrustListDocument(document: TrustListDocument, key: TestKeyMaterial): Promise<string> {
  return new SignJWT(document as unknown as JWTPayload)
    .setProtectedHeader({ alg: 'ES256', typ: TRUST_LIST_JWS_TYP })
    .sign(key.privateKey);
}

export interface TrustListServerOptions {
  authorityKey: TestKeyMaterial;
  /** Signatur mit fremdem TEST-Schlüssel erzeugen (Negativtest: falsche Signatur). */
  corruptKey?: TestKeyMaterial;
}

export class TrustListServer {
  private readonly authorityKey: TestKeyMaterial;
  private readonly corruptKey?: TestKeyMaterial;
  private server?: Server;
  private currentDoc?: TrustListDocument;
  private corrupt = false;
  private status = 200;
  requestCount = 0;
  baseUrl = '';

  constructor(options: TrustListServerOptions) {
    this.authorityKey = options.authorityKey;
    this.corruptKey = options.corruptKey;
  }

  async start(document: TrustListDocument): Promise<string> {
    this.currentDoc = document;
    this.server = createServer(async (req, res) => {
      this.requestCount += 1;
      if (req.url !== '/trustlist') {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'TEST: not found' }));
        return;
      }
      if (this.status !== 200) {
        res.writeHead(this.status, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: `TEST: http ${this.status}` }));
        return;
      }
      const key = this.corrupt ? (this.corruptKey as TestKeyMaterial) : this.authorityKey;
      const signed = await signTrustListDocument(this.currentDoc as TrustListDocument, key);
      res.writeHead(200, { 'content-type': `application/jose+json; profile="${TRUST_LIST_JWS_TYP}"` });
      res.end(signed);
    });
    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    const address = this.server.address() as { port: number };
    this.baseUrl = `http://127.0.0.1:${address.port}`;
    return this.baseUrl;
  }

  setDocument(document: TrustListDocument): void {
    this.currentDoc = document;
  }

  setCorruptSignature(corrupt: boolean): void {
    this.corrupt = corrupt;
  }

  setStatus(status: number): void {
    this.status = status;
  }

  close(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.server) return resolve();
      this.server.closeAllConnections();
      this.server.close((err) => (err ? reject(err) : resolve()));
    });
  }
}