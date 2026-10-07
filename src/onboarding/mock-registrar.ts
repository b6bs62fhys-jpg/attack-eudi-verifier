/**
 * Lokaler Mock-Registrar (Baustein B, Test) für CIR-(EU)-2025/848-API.
 *
 * Liefert JWS-signierte (JWT-)Antworten unter 127.0.0.1 (ephemerer Port):
 *   GET /api/v1/wrp
 *   GET /api/v1/wrp/{identifier}
 *   GET /api/v1/wrp/check-intended-use?identifier=...
 * Für Negativtests: falsche Signatur (fremder TEST-Schlüssel) oder
 * HTTP-Statusabweichung.
 */
import { createServer, type Server } from 'node:http';
import type { JWTPayload } from 'jose';

import { signRegistrarPayload, toIntendedUseStatus, type MockWrpRecord } from './mock-pki.ts';
import type { WrpItem, WrpListResponse } from './registrar.ts';

export interface MockRegistrarServerOptions {
  signingKey: CryptoKeyPair;
  corruptKey?: CryptoKeyPair;
  basePath?: string;
  /** iat-Abweichung für Replay-Tests (Negativ). */
  iatOffsetSeconds?: number;
}

export class MockRegistrarServer {
  private readonly signingKey: CryptoKeyPair;
  private readonly corruptKey?: CryptoKeyPair;
  private readonly basePath: string;
  private readonly iatOffsetSeconds: number;
  private server?: Server;
  private records: MockWrpRecord[] = [];
  private corrupt = false;
  private statusOverride = new Map<string, number>();
  requestCount = 0;
  baseUrl = '';

  constructor(options: MockRegistrarServerOptions) {
    this.signingKey = options.signingKey;
    this.corruptKey = options.corruptKey;
    this.basePath = (options.basePath ?? '/api/v1').replace(/\/+$/, '');
    this.iatOffsetSeconds = options.iatOffsetSeconds ?? 0;
  }

  async start(records: MockWrpRecord[]): Promise<string> {
    this.records = records;
    this.server = createServer(async (req, res) => {
      this.requestCount += 1;
      const url = new URL(req.url ?? '/', 'http://localhost');
      const status = this.statusOverride.get(url.pathname);
      if (status) {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: `TEST: http ${status}` }));
        return;
      }

      const listMatch = url.pathname === `${this.basePath}/wrp`;
      const checkMatch = url.pathname === `${this.basePath}/wrp/check-intended-use`;
      const itemMatch = url.pathname.startsWith(`${this.basePath}/wrp/`) ? /^\/api\/v1\/wrp\/([^/?]+)$/.exec(url.pathname) : null;

      if (req.method !== 'GET') {
        res.writeHead(405, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'TEST: nur GET' }));
        return;
      }
      if (listMatch) {
        const payload: WrpListResponse & { iat: number } = {
          iat: nowSeconds() + this.iatOffsetSeconds,
          items: this.records.map((r) => r.item),
        };
        res.writeHead(200, { 'content-type': 'application/jose+json' });
        res.end(await this.sign(payload as unknown as JWTPayload));
        return;
      }
      if (checkMatch) {
        const identifier = url.searchParams.get('identifier');
        const record = identifier ? this.records.find((r) => r.item.intendedUses.some((u) => u.identifier === identifier)) : undefined;
        if (!record) {
          res.writeHead(404, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'TEST: intended use unbekannt' }));
          return;
        }
        const statusPayload = toIntendedUseStatus(record.item, identifier as string);
        const payload = { ...statusPayload, iat: nowSeconds() + this.iatOffsetSeconds };
        res.writeHead(200, { 'content-type': 'application/jose+json' });
        res.end(await this.sign(payload));
        return;
      }
      if (itemMatch) {
        const identifier = decodeURIComponent(itemMatch[1]);
        const record = this.records.find((r) => r.item.identifier === identifier);
        if (!record) {
          res.writeHead(404, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'TEST: wrp unbekannt' }));
          return;
        }
        const payload = { ...record.item, iat: nowSeconds() + this.iatOffsetSeconds } as WrpItem & { iat: number };
        res.writeHead(200, { 'content-type': 'application/jose+json' });
        res.end(await this.sign(payload as unknown as JWTPayload));
        return;
      }

      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'TEST: unbekannte route' }));
    });

    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    const address = this.server.address() as { port: number };
    this.baseUrl = `http://127.0.0.1:${address.port}${this.basePath}`;
    return this.baseUrl;
  }

  setRecords(records: MockWrpRecord[]): void {
    this.records = records;
  }

  setCorruptSignatures(corrupt: boolean): void {
    this.corrupt = corrupt;
  }

  overrideStatus(path: string, status: number): void {
    if (status) this.statusOverride.set(path, status);
    else this.statusOverride.delete(path);
  }

  close(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.server) return resolve();
      this.server.closeAllConnections();
      this.server.close((err) => (err ? reject(err) : resolve()));
    });
  }

  private async sign(payload: JWTPayload): Promise<string> {
    const key = this.corrupt ? (this.corruptKey as CryptoKeyPair) : this.signingKey;
    return signRegistrarPayload(payload as Record<string, unknown>, key.privateKey);
  }
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}