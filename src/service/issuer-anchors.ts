/**
 * Vertrauensanker für Credential-Aussteller (fail closed).
 *
 *   - ATTACK_ISSUER_TRUST_ANCHORS_PEM: Pfad zu einer PEM-Datei mit einem oder
 *     mehreren Aussteller-Zertifikaten.
 *   - Ohne diese Variable wird TEST-Material nur mit ATTACK_DEV_MODE=true
 *     außerhalb von Produktion erzeugt; sonst bricht der Start ab.
 * Meldungen nennen nie Zertifikatsinhalt.
 */
import { readFile } from 'node:fs/promises';

import { X509Certificate } from '@peculiar/x509';

import { certificateValidityFailure } from '../lib/cert-validity.ts';
import { ConfigError, ENV_ATTACK_DEV_MODE, ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM, type AppConfig } from '../config.ts';

export interface IssuerAnchors {
  anchors: Uint8Array[];
  /** true, wenn TEST-Material verwendet wird (nur mit Entwicklungsschalter). */
  usedTestAnchor: boolean;
}

export async function loadIssuerTrustAnchorsPem(path: string, now: Date = new Date(), clockSkewSeconds?: number): Promise<Uint8Array[]> {
  let pem: string;
  try {
    pem = await readFile(path, 'utf8');
  } catch {
    throw new ConfigError(`${ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM}: Datei nicht lesbar (Pfad prüfen). Start abgebrochen.`);
  }
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  if (blocks.length === 0) {
    throw new ConfigError(`${ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM}: keine Zertifikate gefunden. Start abgebrochen.`);
  }
  let anchors: Uint8Array[];
  try {
    anchors = blocks.map((block) => new Uint8Array(new X509Certificate(block).rawData));
  } catch {
    throw new ConfigError(`${ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM}: Zertifikat unbrauchbar. Start abgebrochen.`);
  }
  // Gültigkeitszeitraum jedes Ankers (Haertung 9). Zur Laufzeit filtert der
  // Dienst zusätzlich Anker, die inzwischen abgelaufen sind.
  anchors.forEach((der, index) => {
    const failure = certificateValidityFailure(der, now, clockSkewSeconds);
    if (failure) {
      const reason = failure === 'certificate_expired' ? 'abgelaufen' : 'noch nicht gültig';
      throw new ConfigError(`${ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM}: Zertifikat Nr. ${index + 1} ist ${reason} (${failure}). Start abgebrochen.`);
    }
  });
  return anchors;
}

/**
 * Entscheidet die Aussteller-Anker:
 *   1. ATTACK_ISSUER_TRUST_ANCHORS_PEM gesetzt -> laden (fail closed).
 *   2. Sonst nur mit Entwicklungsschalter außerhalb Produktion -> TEST-Anker.
 *   3. Sonst Abbruch.
 */
export async function resolveIssuerAnchors(
  config: Pick<AppConfig, 'devMode' | 'isProduction'> & Partial<Pick<AppConfig, 'clockSkewSeconds'>>,
  testFactory: () => Promise<Uint8Array>,
  env: Record<string, string | undefined> = process.env,
  now: () => Date = () => new Date(),
): Promise<IssuerAnchors> {
  const path = env[ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM];
  if (path) return { anchors: await loadIssuerTrustAnchorsPem(path, now(), config.clockSkewSeconds), usedTestAnchor: false };
  if (config.devMode && !config.isProduction) return { anchors: [await testFactory()], usedTestAnchor: true };
  throw new ConfigError(
    `Keine Aussteller-Vertrauensanker konfiguriert` +
      (config.isProduction ? ' (Produktionsmodus).' : '.') +
      ` ${ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM} setzen. TEST-Anker nur mit ${ENV_ATTACK_DEV_MODE}=true (niemals in Produktion). Start abgebrochen.`,
  );
}
