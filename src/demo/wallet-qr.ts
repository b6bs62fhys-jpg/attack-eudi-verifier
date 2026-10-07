/**
 * QR-Code für den Wallet-Aufruf (openid4vp://...) auf der Flowseite.
 *
 * Erzeugt wird ein SVG über `qrcode-generator` (MIT, ohne weitere
 * Abhängigkeiten), ausgeliefert als `data:`-URL. Die Seite setzt sie nur als
 * `src` eines Bildes ein, nie als HTML, damit kein Markup aus der Antwort in
 * die Seite gelangt.
 *
 * Fehlerkorrektur M: Der Link enthält zwei URL-kodierte Adressen und wird
 * schnell lang; M hält das Raster kleiner als Q oder H und ist für das
 * Abscannen vom Bildschirm ausreichend.
 */
import qrcode from 'qrcode-generator';

export const WALLET_QR_PREFIX = 'data:image/svg+xml;base64,';

export function walletQrDataUrl(text: string): string {
  const qr = qrcode(0, 'M');
  qr.addData(text, 'Byte');
  qr.make();
  const svg = qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
  return `${WALLET_QR_PREFIX}${Buffer.from(svg, 'utf8').toString('base64')}`;
}
