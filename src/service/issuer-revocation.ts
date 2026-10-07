/**
 * Sperrprüfung der Issuer-Zertifikatskette eines vorgelegten Credentials.
 *
 * Zweck: Der Client liefert aus dem x5c-Header nur die Zertifikate, die die
 * Wallet mitgeschickt hat. Für die Sperrprüfung brauchen wir aber je Zertifikat
 * den zugehörigen Aussteller — für das oberste Zertifikat ist das der
 * konfigurierte Vertrauensanker, nicht das vorletzte `x5c`-Element. Dieses
 * Modul stellt die vollständige Kette zusammen und ruft für jedes Element
 * außer dem Anker `enforceRevocation` auf.
 *
 * Das ist bewusst derselbe Ablauf wie in der WRPAC-Prüfung
 * (`src/onboarding/wrpac.ts:138-141`): gleiche Schnittstelle
 * (`RevocationChecker`), gleiche festen Fehlercodes, gleiche Regel
 * "Anker werden nicht geprüft" (`src/onboarding/revocation.ts:40`).
 *
 * Vorrangregel (siehe docs/sicherheit.md, Abschnitt "Sperrprüfung"):
 * Diese Prüfung entscheidet allein über `good`/`revoked`. Die Prüfbibliothek
 * läuft zusätzlich mit `revocationPolicy: 'prefer'` und kann dadurch nur noch
 * ablehnen, nie annehmen.
 */
import { X509Certificate } from '@peculiar/x509';

import {
  ErrRevocationListMalformed,
  ErrRevocationSourceMissing,
} from '../onboarding/errors.ts';
import {
  DEFAULT_REVOCATION_TIMEOUT_MS,
  enforceRevocation,
  type RevocationChecker,
} from '../onboarding/revocation.ts';

/**
 * Prüft alle Zertifikate der dargestellten Kette außer dem Anker.
 *
 * @param certs        x5c-Zertifikate in Kettenrichtung (Blatt zuerst).
 * @param anchors      konfigurierte Vertrauensanker (DER).
 * @param timeoutMs    Zeitgrenze je Zertifikat.
 */
export async function enforceIssuerChainRevocation(
  checker: RevocationChecker,
  certs: readonly Uint8Array[],
  anchors: readonly Uint8Array[],
  timeoutMs = DEFAULT_REVOCATION_TIMEOUT_MS,
): Promise<void> {
  if (certs.length === 0) throw new ErrRevocationSourceMissing();

  const chain: X509Certificate[] = [];
  for (const der of certs) {
    try {
      chain.push(new X509Certificate(new Uint8Array(der)));
    } catch {
      throw new ErrRevocationListMalformed();
    }
  }

  // Ist das letzte dargestellte Zertifikat selbst ein Anker, ist die Kette
  // vollständig (selbstsigniertes Aussteller-Zertifikat als Anker).
  const presented = chain[chain.length - 1] as X509Certificate;
  if (anchorIndex(presented, anchors) >= 0) {
    chain.pop();
  } else {
    // Sonst wird der Anker aus den konfigurierten Ankern ergänzt, der das
    // oberste Zertifikat ausgestellt hat. Ohne diesen Aussteller ist die
    // CertID nicht bildbar -> fail closed.
    const issuer = anchors.map((der) => safeParse(der)).find((a) => a !== undefined && presented.issuer === a.subject);
    if (!issuer) throw new ErrRevocationSourceMissing();
    chain.push(issuer);
  }

  // Anker ist das letzte Element und wird nie geprüft (Vertrag von
  // RevocationChecker.checkRevoked). Jedes andere Element gegen seinen
  // Aussteller.
  for (let i = 0; i < chain.length - 1; i += 1) {
    const cert = chain[i] as X509Certificate;
    const issuer = chain[i + 1] as X509Certificate;
    const role = i === 0 ? 'leaf' : 'intermediate';
    await enforceRevocation(checker, new Uint8Array(cert.rawData), role, new Uint8Array(issuer.rawData), timeoutMs);
  }
}

function anchorIndex(cert: X509Certificate, anchors: readonly Uint8Array[]): number {
  return anchors.findIndex((der) => {
    const parsed = safeParse(der);
    return parsed !== undefined && equalBytes(new Uint8Array(parsed.rawData), new Uint8Array(cert.rawData));
  });
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

function safeParse(der: Uint8Array): X509Certificate | undefined {
  try {
    return new X509Certificate(new Uint8Array(der));
  } catch {
    return undefined;
  }
}
