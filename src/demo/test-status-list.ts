/**
 * Lokaler TEST-Status-List-Server für die Demo.
 *
 * Die Kodierung folgt dem Arbeitsstand IETF draft-ietf-oauth-status-list-21
 * (21.06.2026), Abschnitte 4.1, 4.2, 5.1 und 7.1: LSB-first gepackte
 * Statuswerte, ZLIB/DEFLATE, base64url in `status_list.lst`, JWT-Typ
 * `statuslist+jwt` und die Werte VALID=0x00, INVALID=0x01,
 * SUSPENDED=0x02. Das ist TEST-Infrastruktur, kein amtlicher Status Provider.
 *
 * Es werden nur kurzlebige TEST-Schlüssel im RAM benutzt. Der Server bindet
 * ausschließlich an 127.0.0.1 und wird von der Demo beim Schließen beendet.
 */
import http from 'node:http';
import { deflateSync } from 'node:zlib';

import { SignJWT } from 'jose';

import type { TestKeyMaterial } from '../decision-test/mock-wallet.ts';

export const TEST_STATUS_LIST_VALUES = [0x00, 0x01, 0x02] as const;

function encodeStatusList(values: readonly number[], bits: 1 | 2 | 4 | 8): string {
  const bytes = new Uint8Array(Math.ceil((values.length * bits) / 8));
  values.forEach((value, index) => {
    const offset = index * bits;
    bytes[Math.floor(offset / 8)] |= value << (offset % 8);
  });
  return deflateSync(bytes).toString('base64url');
}

export class TestStatusListServer {
  private server?: http.Server;
  private uri = '';

  async start(signer: TestKeyMaterial): Promise<string> {
    this.server = http.createServer((req, res) => {
      void this.respond(req, res, signer);
    });
    await new Promise<void>((resolve) => this.server?.listen(0, '127.0.0.1', resolve));
    const address = this.server.address() as { port: number };
    this.uri = `http://127.0.0.1:${address.port}/statuslists/demo`;
    return this.uri;
  }

  private async respond(req: http.IncomingMessage, res: http.ServerResponse, signer: TestKeyMaterial): Promise<void> {
    if (req.method !== 'GET' || req.url !== '/statuslists/demo') {
      res.writeHead(404).end();
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({
      sub: this.uri,
      iat: now - 60,
      exp: now + 3600,
      status_list: {
        bits: 2,
        lst: encodeStatusList(TEST_STATUS_LIST_VALUES, 2),
      },
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt', x5c: [signer.x5cBase64] })
      .sign(signer.privateKey);
    res.writeHead(200, { 'content-type': 'application/statuslist+jwt' });
    res.end(token);
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      this.server.closeAllConnections();
      this.server.close(() => resolve());
    });
  }
}
