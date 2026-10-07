/**
 * TEST-Sperrliste für WRPAC/WRPRC (Baustein B, Test).
 *
 * Fingerprint-basierte Mock-Sperrliste, die an den Erweiterungspunkt
 * `RevocationChecker` (src/onboarding/revocation.ts) andockt. Läuft nur im
 * Arbeitsspeicher, kein Netzwerk — reines TEST-Material. Die echte
 * Sperrquelle ist `CrlRevocationChecker`.
 */
import { sha256Hex } from '../trustlist/monitor.ts';
import type { RevocationChecker, RevocationStatus } from './revocation.ts';

export class MockRevocationList implements RevocationChecker {
  private readonly revoked = new Set<string>();
  private readonly suspended = new Set<string>();

  /** Ein Zertifikat (DER) als gesperrt markieren. */
  revoke(certDer: Uint8Array): void {
    this.revoked.add(sha256Hex(new Uint8Array(certDer)));
  }

  /** Ein Zertifikat (DER) als ausgesetzt markieren. */
  suspend(certDer: Uint8Array): void {
    this.suspended.add(sha256Hex(new Uint8Array(certDer)));
  }

  clear(): void {
    this.revoked.clear();
    this.suspended.clear();
  }

  // Die Parameter `role` und `issuerDer` werden nicht ausgewertet: dieser
  // Mock kennt keine Rolle und prüft nichts gegen einen Aussteller. Eine
  // Implementierung darf weniger Parameter haben als das Interface, deshalb
  // stehen sie hier gar nicht erst im Bild.
  async checkRevoked(certDer: Uint8Array): Promise<RevocationStatus> {
    const fingerprint = sha256Hex(new Uint8Array(certDer));
    if (this.revoked.has(fingerprint)) return 'revoked';
    if (this.suspended.has(fingerprint)) return 'suspended';
    return 'good';
  }
}
