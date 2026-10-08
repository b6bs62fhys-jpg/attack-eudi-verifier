/**
 * Kettenprüfung zu einem Vertrauensanker (fail closed), für Zertifikate, deren
 * Kette der Dienst selbst prüft: heute der Unterzeichner einer Statusliste.
 *
 * Warum es das gibt: Die Sandbox-Vertrauensliste führt für Statuslisten eine
 * CA ("Deutschland PID-Status-List-Signer Test CA 1-26-2 2026"), nicht das
 * Zertifikat, das die Liste tatsächlich unterschreibt. Ein Byte-Vergleich des
 * Unterzeichners mit den Ankern lehnt dann jede Liste ab.
 *
 * Geprüft wird, in dieser Reihenfolge:
 *   1. Pfad: Ist das Blatt selbst ein Anker (Byte-Gleichheit), ist der Pfad
 *      das Blatt allein. Sonst wird zum Aussteller weitergegangen, gesucht
 *      unter den übrigen x5c-Zertifikaten und den Ankern (Anker haben
 *      Vorrang). Ein Aussteller zählt nur, wenn Name (issuer = subject) und
 *      Signatur passen. Tiefe höchstens 5. Ohne Anker am Ende: untrusted.
 *   2. Gültigkeit: jedes Zertifikat im Pfad (mit Uhrabweichung).
 *   3. Schlüsselverwendung: das Blatt darf, wenn es eine Key-Usage-Erweiterung
 *      trägt, digitalSignature nicht ausschließen. Jeder Aussteller braucht
 *      Basic Constraints mit cA=true; trägt er Key Usage, muss keyCertSign
 *      gesetzt sein; ein pathLenConstraint begrenzt die Zahl der
 *      Zwischenzertifikate unter ihm.
 * Die Sperrprüfung der Zertifikate im Pfad bleibt Sache des Aufrufers
 * (`enforceIssuerChainRevocation`); die Anker selbst werden nie geprüft.
 */
import 'reflect-metadata';

import { BasicConstraintsExtension, KeyUsageFlags, KeyUsagesExtension, X509Certificate } from '@peculiar/x509';

import { certificateValidityFailure, DEFAULT_CLOCK_SKEW_SECONDS, type ValidityFailure } from './cert-validity.ts';

export type ChainFailure = 'chain_untrusted' | 'key_usage_invalid' | ValidityFailure;

export const MAX_CHAIN_DEPTH = 5;

export type ChainResult = { ok: true; path: X509Certificate[]; direct: boolean } | { ok: false; failure: ChainFailure };

function parse(der: Uint8Array): X509Certificate | undefined {
  try {
    return new X509Certificate(new Uint8Array(der));
  } catch {
    return undefined;
  }
}

function sameBytes(a: X509Certificate, b: X509Certificate): boolean {
  const x = new Uint8Array(a.rawData);
  const y = new Uint8Array(b.rawData);
  return x.length === y.length && x.every((byte, i) => byte === y[i]);
}

async function signedBy(cert: X509Certificate, issuer: X509Certificate): Promise<boolean> {
  if (cert.issuer !== issuer.subject) return false;
  try {
    return await cert.verify({ publicKey: issuer.publicKey, signatureOnly: true });
  } catch {
    return false;
  }
}

function usagesOf(cert: X509Certificate): KeyUsageFlags | undefined {
  return cert.getExtension(KeyUsagesExtension)?.usages;
}

/** Darf `issuer` Zertifikate ausstellen, mit höchstens `below` Zwischenzertifikaten darunter? */
function mayIssue(issuer: X509Certificate, below: number): boolean {
  const basic = issuer.getExtension(BasicConstraintsExtension);
  if (!basic || basic.ca !== true) return false;
  if (basic.pathLength !== undefined && below > basic.pathLength) return false;
  const usages = usagesOf(issuer);
  if (usages !== undefined && (usages & KeyUsageFlags.keyCertSign) === 0) return false;
  return true;
}

/**
 * Prüft `chain` (Blatt zuerst, wie im x5c-Header) gegen `anchors`.
 * Liefert den Pfad (Blatt bis Anker) oder den ersten Fehler.
 */
export async function verifyChainToAnchor(
  chain: readonly Uint8Array[],
  anchors: readonly Uint8Array[],
  now: Date,
  clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS,
): Promise<ChainResult> {
  const certs = chain.map(parse);
  const leaf = certs[0];
  if (!leaf || certs.some((c) => c === undefined)) return { ok: false, failure: 'chain_untrusted' };
  const intermediates = (certs.slice(1) as X509Certificate[]).filter((c) => !sameBytes(c, leaf));
  const anchorCerts = anchors.map(parse).filter((c): c is X509Certificate => c !== undefined);

  // 1. Pfad
  const path: X509Certificate[] = [leaf];
  let direct = false;
  if (anchorCerts.some((a) => sameBytes(a, leaf))) {
    direct = true;
  } else {
    let current = leaf;
    let reachedAnchor = false;
    for (let depth = 0; depth < MAX_CHAIN_DEPTH && !reachedAnchor; depth += 1) {
      let next: X509Certificate | undefined;
      for (const candidate of anchorCerts) {
        if (await signedBy(current, candidate)) {
          next = candidate;
          reachedAnchor = true;
          break;
        }
      }
      if (!next) {
        for (const candidate of intermediates) {
          if (path.includes(candidate)) continue;
          if (await signedBy(current, candidate)) {
            next = candidate;
            break;
          }
        }
      }
      if (!next) return { ok: false, failure: 'chain_untrusted' };
      path.push(next);
      current = next;
    }
    if (!reachedAnchor) return { ok: false, failure: 'chain_untrusted' };
  }

  // 2. Gültigkeit
  for (const cert of path) {
    const failure = certificateValidityFailure(cert, now, clockSkewSeconds);
    if (failure) return { ok: false, failure };
  }

  // 3. Schlüsselverwendung (bei einem direkten Anker prüft sich nichts weiter,
  // wie bisher: der Anker ist vom Betrieb ausdrücklich konfiguriert)
  if (!direct) {
    const usages = usagesOf(leaf);
    if (usages !== undefined && (usages & KeyUsageFlags.digitalSignature) === 0) return { ok: false, failure: 'key_usage_invalid' };
    for (let i = 1; i < path.length; i += 1) {
      // Zwischenzertifikate unter diesem Aussteller: Pfadelemente zwischen Blatt und ihm.
      if (!mayIssue(path[i] as X509Certificate, i - 1)) return { ok: false, failure: 'key_usage_invalid' };
    }
  }
  return { ok: true, path, direct };
}
