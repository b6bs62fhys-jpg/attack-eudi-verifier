/**
 * QR-Code des Wallet-Aufrufs. Ein QR-Decoder ist keine Abhängigkeit des
 * Projekts; geprüft wird deshalb, dass ein gültiges SVG entsteht, dass es nur
 * von der Eingabe abhängt und dass ein längerer Aufruf ein größeres Raster
 * braucht, also wirklich in den Code eingeht.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'vitest';

import { WALLET_QR_PREFIX, walletQrDataUrl } from './wallet-qr.ts';

function svg(dataUrl: string): string {
  assert.ok(dataUrl.startsWith(WALLET_QR_PREFIX));
  return Buffer.from(dataUrl.slice(WALLET_QR_PREFIX.length), 'base64').toString('utf8');
}

function viewBoxSize(markup: string): number {
  const m = /viewBox="0 0 (\d+) (\d+)"/.exec(markup);
  assert.ok(m, 'viewBox fehlt');
  return Number(m[1]);
}

describe('walletQrDataUrl', () => {
  const kurz = 'openid4vp://?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Fv.example%2Fr&request_uri_method=get';
  const lang = `openid4vp://?client_id=x509_hash%3A${'a'.repeat(43)}&request_uri=${encodeURIComponent(`https://verifier.example/attack/v1/verification-requests/${'b'.repeat(36)}/request-object`)}&request_uri_method=get`;

  it('liefert ein SVG als data:-URL', () => {
    const markup = svg(walletQrDataUrl(kurz));
    assert.match(markup, /^<svg /);
    assert.match(markup, /<\/svg>$/);
    assert.match(markup, /<path /);
  });

  it('gleiche Eingabe, gleicher Code; andere Eingabe, anderer Code', () => {
    assert.equal(walletQrDataUrl(kurz), walletQrDataUrl(kurz));
    assert.notEqual(walletQrDataUrl(kurz), walletQrDataUrl(`${kurz}&x=1`));
  });

  it('ein längerer Aufruf braucht ein größeres Raster', () => {
    assert.ok(viewBoxSize(svg(walletQrDataUrl(lang))) > viewBoxSize(svg(walletQrDataUrl(kurz))));
  });
});
