/**
 * Verifier-Identität der laufenden Instanz.
 *
 * Grundregel (fail closed): Der Dienst bricht den Start ab, wenn er weder
 * eine echte Verifier-Identität (PEM-Pfade) noch – ausschließlich mit
 * ausdrücklichem Entwicklungsschalter (ATTACK_DEV_MODE=true) außerhalb von
 * Produktion – Testmaterial verwenden darf. Es gibt keinen stillen Rückfall.
 *
 *   - ATTACK_VERIFIER_KEY_PEM        : PEM-PKCS#8-Private-Key (ECDSA P-256)
 *   - ATTACK_VERIFIER_CERT_CHAIN_PEM : PEM-Zertifikatskette (Blatt zuerst)
 *
 * Fehlermeldungen enthalten niemals Schlüssel- oder Zertifikatsinhalt; sie
 * nennen nur die zu setzenden Umgebungsvariablen.
 */
import 'reflect-metadata';

import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';

import { importJWK, importPKCS8 } from 'jose';
import { X509Certificate } from '@peculiar/x509';

import { ConfigError, ENV_ATTACK_DEV_MODE, ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM, ENV_ATTACK_VERIFIER_KEY_PEM, type AppConfig } from '../config.ts';
import { chainValidityFailure } from '../lib/cert-validity.ts';
import type { ServiceKeys } from './service.ts';

export interface VerifierIdentity {
  keys: ServiceKeys;
  /** true, wenn Testmaterial verwendet wird (nur mit Entwicklungsschalter). */
  usedTestFallback: boolean;
}

/** Eine PEM-Zertifikatskette (Blatt zuerst) in DER-Bytes zerlegen. */
function parsePemChain(pem: string): Uint8Array[] {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!blocks || blocks.length === 0) {
    throw new Error(`${ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM}: keine Zertifikate im PEM gefunden`);
  }
  return blocks.map((block) => new Uint8Array(new X509Certificate(block).rawData));
}

/**
 * Lädt die Verifier-Identität aus zwei PEM-Dateien (Pfade aus der Umgebung).
 * Wirft bei fehlerhaften Inhalten eine klare Meldung ohne Schlüsselinhalt
 * (fail closed). Wirft, wenn nur eine der beiden Variablen gesetzt ist.
 */
export interface ValidityOptions {
  /** Prüfzeitpunkt (injizierbare Uhr), Standard: jetzt. */
  now?: Date;
  /** Erlaubte Uhrabweichung in Sekunden, Standard 60. */
  clockSkewSeconds?: number;
}

/**
 * Bricht ab, wenn ein Zertifikat der Verifier-Kette abgelaufen oder noch nicht
 * gültig ist (Haertung 9). Die Meldung nennt nur den Grund, keinen Inhalt.
 */
export function assertVerifierChainValid(certificateChain: readonly Uint8Array[], options: ValidityOptions = {}): void {
  const failure = chainValidityFailure(certificateChain, options.now ?? new Date(), options.clockSkewSeconds);
  if (!failure) return;
  const reason = failure === 'certificate_expired' ? 'abgelaufen' : 'noch nicht gültig';
  throw new ConfigError(
    `Verifier-Zertifikatskette: ein Zertifikat ist ${reason} (${failure}). ` +
      `Gültige Kette über ${ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM} bereitstellen. Start abgebrochen.`,
  );
}

export async function loadVerifierIdentity(
  env: Record<string, string | undefined> = process.env,
  validity: ValidityOptions = {},
): Promise<ServiceKeys> {
  const keyFile = env[ENV_ATTACK_VERIFIER_KEY_PEM];
  const certChainFile = env[ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM];

  if (!keyFile && !certChainFile) {
    // Ueber den Dienst nicht erreichbar: resolveVerifierIdentity ruft diese
    // Funktion nur auf, wenn mindestens eine der beiden Variablen gesetzt ist
    // (Zeile 135), und bricht sonst mit der ConfigError-Meldung am Ende ab. Der
    // Typ wird trotzdem angeglichen, damit die exportierte Funktion bei jedem
    // Abbruch eine sprechende Meldung liefert statt "unerwarteter Fehler beim
    // Start (Error)".
    throw new ConfigError(
      `Weder ${ENV_ATTACK_VERIFIER_KEY_PEM} noch ${ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM} gesetzt. ` +
      `Beide Variablen müssen zusammen gesetzt sein (beide oder keine). Start abgebrochen.`,
    );
  }
  if (!keyFile || !certChainFile) {
    // Nur die eine der beiden gesetzten Variablen nennen. Der Betreiber soll
    // die fehlende beim Namen sehen, nicht "unerwarteter Fehler beim Start
    // (Error)". ConfigError, weil `startupFailureMessage` (src/config.ts:226)
    // genau dessen Meldung ausgibt; das Abbruchverhalten ändert sich dadurch
    // nicht (src/service/run.ts:34-38 bricht in jedem Fall mit Exit 1 ab).
    const fehlend = !keyFile ? ENV_ATTACK_VERIFIER_KEY_PEM : ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM;
    throw new ConfigError(
      `${fehlend}: nicht gesetzt. ${ENV_ATTACK_VERIFIER_KEY_PEM} und ${ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM} müssen zusammen gesetzt sein (beide oder keine). Start abgebrochen.`,
    );
  }

  let keyPem: string;
  let chainPem: string;
  try {
    keyPem = await readFile(keyFile, 'utf8');
    chainPem = await readFile(certChainFile, 'utf8');
  } catch {
    // Nur die Variablennamen, nie die Pfade aus der Umgebung: der Betreiber
    // sieht, welche Variable betroffen ist, und liest den Pfad dort nach, wo
    // er ihn gesetzt hat. ConfigError, damit startupFailureMessage die Meldung
    // ausgibt statt "(Error)".
    throw new ConfigError(
      `${ENV_ATTACK_VERIFIER_KEY_PEM} oder ${ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM}: PEM-Dateien nicht lesbar (Pfade prüfen). Start abgebrochen.`,
    );
  }

  let certificateChain: Uint8Array[];
  try {
    certificateChain = parsePemChain(chainPem);
  } catch {
    // Fängt auch den Fehler aus parsePemChain ab, dessen Meldung dadurch
    // nicht nach außen gelangt. Deshalb steht hier der Grund, nicht der
    // konkrete Parse-Fehler. Bewusst ohne das PEM-Marker-Literal: eine
    // Fehlermeldung soll kein Zertifikatsblock-Fragment enthalten, und der
    // Schutz "kein Schlüsselinhalt in der Meldung" bleibt streng.
    throw new ConfigError(
      `${ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM}: Zertifikatskette unbrauchbar (PEM mit mindestens einem Zertifikatsblock erwartet). Start abgebrochen.`,
    );
  }
  assertVerifierChainValid(certificateChain, validity);

  let privateKey: webcrypto.CryptoKey;
  let publicJwk: JsonWebKey;
  try {
    privateKey = await importPKCS8(keyPem, 'ES256', { extractable: true });
    publicJwk = (await webcrypto.subtle.exportKey('jwk', privateKey)) as Record<string, unknown> as JsonWebKey;
    delete publicJwk.d;
    publicJwk.key_ops = ['verify'];
  } catch {
    throw new ConfigError(
      `${ENV_ATTACK_VERIFIER_KEY_PEM}: Private-Key unbrauchbar (EC P-256 PKCS#8 erwartet). Start abgebrochen.`,
    );
  }

  const publicKey = (await importJWK(publicJwk, 'ES256', { extractable: true })) as webcrypto.CryptoKey;

  return { privateKey, publicKey, publicJwk, certificateChain };
}

/**
 * Entscheidet die laufende Verifier-Identität:
 *   1. Echte PEM-Pfade gesetzt → echte Identität laden (fail closed bei Fehlern).
 *   2. Keine echten Pfade, aber Entwicklungsschalter gesetzt UND nicht
 *      Produktion → Testmaterial (verursacht einen lauten Startblocker-Text).
 *   3. Sonst → Abbruch: klare Meldung, ohne Schlüsselinhalt.
 */
export async function resolveVerifierIdentity(
  config: AppConfig,
  testFactory: () => Promise<ServiceKeys>,
  env: Record<string, string | undefined> = process.env,
  now: () => Date = () => new Date(),
): Promise<VerifierIdentity> {
  const validity: ValidityOptions = { now: now(), clockSkewSeconds: config.clockSkewSeconds };
  if (env[ENV_ATTACK_VERIFIER_KEY_PEM] || env[ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]) {
    const keys = await loadVerifierIdentity(env, validity);
    return { keys, usedTestFallback: false };
  }

  if (config.devMode && !config.isProduction) {
    const keys = await testFactory();
    assertVerifierChainValid(keys.certificateChain, validity);
    return { keys, usedTestFallback: true };
  }

  throw new ConfigError(
    `Keine Verifier-Identität konfiguriert und kein Test-Rückfall erlaubt` +
      (config.isProduction ? ' (Produktionsmodus).' : '.') +
      ` Für eine echte Identität ${ENV_ATTACK_VERIFIER_KEY_PEM} und ${ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM} setzen. ` +
      `Für lokale Tests ${ENV_ATTACK_DEV_MODE}=true setzen (niemals in Produktion). Start abgebrochen.`,
  );
}