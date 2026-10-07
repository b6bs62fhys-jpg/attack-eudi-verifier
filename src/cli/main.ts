/**
 * Diagnose-CLI für den Betrieb des Verifier-Dienstes.
 *
 * Start:
 *   npm run cli -- status
 *   npm run cli -- anchors
 *   npm run cli -- ocsp
 *   npm run cli -- ratelimit
 *   npm run cli -- doctor
 *   npm run cli -- tenant add --id <id> --name <name> [--profile <vorlage>] [--ttl <s>] [--file <pfad>]
 *   npm run cli -- tenant list [--file <pfad>]
 *   npm run cli -- tenant revoke --id <id> [--file <pfad>]
 *
 * Die Diagnosebefehle lesen ausschließlich. Sie starten keinen Dienst, melden
 * sich nicht beim Dienst an, schreiben nichts und verändern keine
 * Konfiguration. Sie lesen dieselben Umgebungsvariablen und rufen dieselben
 * Funktionen auf wie der Dienst beim Start, damit die Auskunft dem entspricht,
 * was der Dienst tatsächlich tun würde, nicht dem, was in der Doku steht.
 *
 * Einzige Ausnahme ist `tenant`: Er schreibt genau eine Datei, die
 * Mandantendatei (ATTACK_TENANTS_FILE oder --file), und sonst nichts. Er lädt
 * keine Dienstkonfiguration und schaltet deshalb auch nie den
 * Entwicklungsschalter ein; er funktioniert mit NODE_ENV=production. Der
 * Klartext eines neuen API-Schlüssels erscheint genau einmal auf stdout und
 * wird nirgends gespeichert. Registrierung, Trust-List-Änderung und
 * Ankerpflege bleiben ein Betriebsprozess, keine CLI-Aktion.
 *
 * Ausgaben gehen nach stdout, Fehlermeldungen nach stderr. Rückgabewert 0
 * heißt "alles in Ordnung", 1 heißt "Befund", 2 heißt "Aufruf oder Konfiguration
 * unbrauchbar". So lässt sich der Befehl in eine Überwachung hängen.
 */

// @peculiar/x509 zieht tsyringe, das einen reflect-Polyfill verlangt. Der
// Dienst importiert ihn in src/service/run.ts, das CLI also genauso.
import 'reflect-metadata';

import { X509Certificate } from '@peculiar/x509';

import {
  ENV_ATTACK_ALLOW_SELF_SIGNED,
  ENV_ATTACK_CLOCK_SKEW_SECONDS,
  ENV_ATTACK_DEV_MODE,
  ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM,
  ENV_ATTACK_RATE_LIMIT_PUBLIC,
  ENV_ATTACK_RATE_LIMIT_TENANT,
  ENV_ATTACK_RATE_LIMIT_WINDOW,
  ENV_ATTACK_RESULT_TTL_SECONDS,
  loadConfig,
} from '../config.ts';
import { describeOnboardingState, loadAnchorsPem, resolveOnboardingGate } from '../onboarding/onboarding-wiring.ts';
import { OcspRevocationChecker } from '../onboarding/ocsp-revocation.ts';
import {
  describeRevocationSources,
  ENV_ATTACK_ISSUER_REVOCATION_SOURCES,
  ENV_ATTACK_ONBOARDING_REVOCATION_SOURCES,
  parseRevocationSources,
} from '../onboarding/revocation-source.ts';
import { resolveIssuerAnchors } from '../service/issuer-anchors.ts';
import { certificateValidityFailure } from '../lib/cert-validity.ts';
import { ROUTES } from '../service/app.ts';
import { TenantStore } from '../service/tenant.ts';
import { ENV_ATTACK_TENANTS_FILE } from '../service/tenant-file.ts';
import { runTenantCommand } from './tenant-command.ts';
import { REQUEST_PROFILE_TEMPLATES } from '../service/profile.ts';
import { generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { logger } from '../lib/logger.ts';

/** Variablennamen der Onboarding-Verdrahtung, dort definiert statt in config.ts. */
const ENV_ACCESS_CA_PEM = 'ATTACK_ONBOARDING_ACCESS_CA_PEM';
const ENV_WRPRC_ISSUER_PEM = 'ATTACK_ONBOARDING_WRPRC_ISSUER_PEM';

const OK = 0;
const FINDING = 1;
const UNBRAUCHBAR = 2;

const args = process.argv.slice(2);
const befehl = args[0] ?? 'help';

/** Alles Ausgegebene an einer Stelle, damit die Formatierung einheitlich bleibt. */
function out(text: string): void {
  process.stdout.write(`${text}\n`);
}

function fehler(text: string): void {
  process.stderr.write(`${text}\n`);
}

function kopf(titel: string): void {
  out('');
  out(titel);
  out('='.repeat(titel.length));
}

/** Basiskonfiguration, tolerant: fehlende Pflicht erzeugt keine Ausnahme. */
function basisConfig(env: Record<string, string | undefined>): ReturnType<typeof loadConfig> {
  return loadConfig({ ...env, [ENV_ATTACK_DEV_MODE]: env[ENV_ATTACK_DEV_MODE] ?? 'true' }, 8080);
}

/**
 * Zertifikat in lesbarer Kurzform. Zeigt bewusst Subject, Aussteller, Gültigkeit
 * und Seriennummer — keinen privaten Schlüssel, und aus einem Zertifikat lässt
 * sich ohnehin keiner ableiten.
 */
function beschreibeZertifikat(der: Uint8Array, jetzt: Date, clockSkewSeconds: number): string[] {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(new Uint8Array(der));
  } catch {
    return ['  unlesbares Zertifikat'];
  }
  const gueltig = certificateValidityFailure(der, jetzt, clockSkewSeconds);
  const zeilen = [
    `  Subject       ${cert.subject}`,
    `  Aussteller    ${cert.issuer}`,
    `  Seriennummer  ${cert.serialNumber}`,
    `  Gültig        ${cert.notBefore.toISOString()} bis ${cert.notAfter.toISOString()}`,
    `  Zustand       ${gueltig ?? 'gültig'}`,
  ];
  const ocsp = ocspUrlVon(cert);
  zeilen.push(`  OCSP (AIA)    ${ocsp ?? 'keine AIA-Erweiterung — Sperrprüfung nicht möglich'}`);
  return zeilen;
}

/** Liest die OCSP-Adresse aus der AIA-Erweiterung, sonst undefined. */
function ocspUrlVon(cert: X509Certificate): string | undefined {
  try {
    const aia = cert.getExtension('1.3.6.1.5.5.7.1.1');
    if (!aia) return undefined;
    const asn = aia as unknown as { [key: string]: unknown };
    const raw = JSON.stringify(asn);
    const treffer = /"ocsp"\s*:\s*"(https?:\/\/[^"]+)"/.exec(raw);
    return treffer?.[1];
  } catch {
    return undefined;
  }
}

/**
 * Liest die Anker einer PEM-Variablen mit demselben Lader wie der Dienst, damit
 * hier keine andere Fehlermeldung entsteht als beim Start.
 */
async function pemAusUmgebung(env: Record<string, string | undefined>, key: string): Promise<Uint8Array[]> {
  const pfad = env[key];
  if (!pfad) return [];
  return loadAnchorsPem(pfad, key);
}

async function cmdStatus(env: Record<string, string | undefined>): Promise<number> {
  const jetzt = new Date();
  const config = basisConfig(env);

  kopf('Onboarding-Gate');
  let befund = OK;
  // Das Gate wird genau so aufgelöst wie beim Start des Dienstes, mit derselben
  // Umgebung. Nur so ist die Auskunft belastbar; ein eigenes Nachbauen der
  // Prüfung würde genau die Abweichungen verdecken, die dieses Werkzeug sucht.
  //
  // resolveOnboardingGate gibt bei unlesbarem Material bewusst `undefined`
  // zurück, damit fehlende Konfiguration ein normaler Zustand bleibt. Damit
  // verschwindet aber der Grund, und der Betrieb kann einen Tippfehler im
  // Pfad nicht von "nicht konfiguriert" unterscheiden. Genau das prüft das CLI
  // zusätzlich nach.
  try {
    const gate = await resolveOnboardingGate({
      config,
      env,
      revocation: new OcspRevocationChecker({ clockSkewSeconds: config.clockSkewSeconds }),
      // Für die Materialauflösung braucht das Gate eine Mandantensicht. Eine
      // leere reicht: hier wird nur geprüft, ob aus der Umgebung ein Gate
      // entsteht, nicht wie es später je Mandant entscheidet.
      tenants: new TenantStore(),
      clockSkewSeconds: config.clockSkewSeconds,
    });
    out(describeOnboardingState({ gate }));
    if (!gate) {
      befund = FINDING;
      const gesetzt = [ENV_ACCESS_CA_PEM, ENV_WRPRC_ISSUER_PEM].filter((k) => env[k]);
      if (gesetzt.length === 0) {
        out('  Ursache           kein Onboarding konfiguriert (im Entwicklungsbetrieb normal)');
      } else {
        // Konfiguriert, aber kein Gate: das ist ein Konfigurationsfehler, kein
        // Normalzustand. Der Grund wird direkt ermittelt, weil der Dienst ihn
        // absichtlich verwirft.
        out(`  Ursache           ${gesetzt.join(' und ')} gesetzt, aber es entsteht kein Gate — Konfigurationsfehler.`);
        for (const schluessel of gesetzt) {
          try {
            await pemAusUmgebung(env, schluessel);
            out(`                    ${schluessel}: Datei lesbar, aber ohne verwendbare Anker`);
          } catch (e) {
            out(`                    ${schluessel}: ${(e as Error).message}`);
          }
        }
        out('                    In Produktion meldet /ready dafür "failed"; im Entwicklungsbetrieb "degraded".');
      }
    }
  } catch (e) {
    out(describeOnboardingState({ gate: undefined, error: e as Error }));
    fehler(`  Auflösung fehlgeschlagen: ${(e as Error).message}`);
    befund = FINDING;
  }
  out(`  Access-CA-PEM       ${env[ENV_ACCESS_CA_PEM] ?? 'nicht gesetzt'}`);
  out(`  WRPRC-Issuer-PEM    ${env[ENV_WRPRC_ISSUER_PEM] ?? 'nicht gesetzt'}`);

  kopf('Aussteller-Vertrauensanker');
  try {
    const aufgelöst = await resolveIssuerAnchors(config, async () => {
      const test = await generateTestKeyMaterial('CLI Test-Anker');
      return test.certDerBytes;
    }, env, () => jetzt);
    out(`  Quelle              ${aufgelöst.usedTestAnchor ? 'TEST-Anker (Entwicklungsschalter)' : env[ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]}`);
    out(`  Anzahl              ${aufgelöst.anchors.length}`);
  } catch (e) {
    fehler(`  ${(e as Error).message}`);
    befund = FINDING;
  }

  kopf('Laufzeit');
  out(`  Modus               ${config.isProduction ? 'Produktion' : 'Entwicklung'}`);
  out(`  Node_ENV            ${config.nodeEnv}`);
  out(`  Dev-Schalter        ${config.devMode ? `${ENV_ATTACK_DEV_MODE}=true` : 'aus'}`);
  out(`  Selbstsigniert      ${config.allowSelfSignedCertificate ? `${ENV_ATTACK_ALLOW_SELF_SIGNED}=true` : 'aus'}`);
  out(`  Port                ${config.port}`);
  out(`  Uhrabweichung       ${config.clockSkewSeconds} s (${ENV_ATTACK_CLOCK_SKEW_SECONDS})`);
  out(`  Ergebnis-TTL        ${config.resultTtlSeconds} s (${ENV_ATTACK_RESULT_TTL_SECONDS})`);
  for (const [titel, schluessel] of [
    ['Sperrung Aussteller', ENV_ATTACK_ISSUER_REVOCATION_SOURCES],
    ['Sperrung Onboarding', ENV_ATTACK_ONBOARDING_REVOCATION_SOURCES],
  ] as const) {
    try {
      out(`  ${titel.padEnd(19)} ${describeRevocationSources(parseRevocationSources(env, schluessel, config))} (${schluessel})`);
    } catch (e) {
      fehler(`  ${titel}: ${(e as Error).message}`);
      befund = FINDING;
    }
  }

  kopf('Routen');
  for (const route of ROUTES) {
    out(`  ${route.method.padEnd(6)} ${route.path.padEnd(46)} ${route.access}`);
  }
  out(`  ${ROUTES.length} Routen`);

  return befund;
}

async function cmdAnchors(env: Record<string, string | undefined>): Promise<number> {
  const jetzt = new Date();
  const config = basisConfig(env);
  kopf('Aussteller-Vertrauensanker');

  let anker: Uint8Array[];
  let quelle: string;
  try {
    const aufgelöst = await resolveIssuerAnchors(config, async () => {
      const test = await generateTestKeyMaterial('CLI Test-Anker');
      return test.certDerBytes;
    }, env, () => jetzt);
    anker = aufgelöst.anchors;
    quelle = aufgelöst.usedTestAnchor ? 'TEST-Anker (Entwicklungsschalter)' : String(env[ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]);
  } catch (e) {
    fehler(`  ${(e as Error).message}`);
    return FINDING;
  }
  out(`  Quelle  ${quelle}`);
  out(`  Anzahl  ${anker.length}`);

  let befund = OK;
  anker.forEach((der, index) => {
    out('');
    out(`  [${index + 1}]`);
    for (const zeile of beschreibeZertifikat(der, jetzt, config.clockSkewSeconds)) out(zeile);
    if (certificateValidityFailure(der, jetzt, config.clockSkewSeconds)) befund = FINDING;
  });

  kopf('Onboarding-Anker');
  for (const [titel, schluessel] of [
    ['Access CA', ENV_ACCESS_CA_PEM],
    ['WRPRC-Issuer', ENV_WRPRC_ISSUER_PEM],
  ] as const) {
    const pfad = env[schluessel];
    if (!pfad) {
      out(`  ${titel.padEnd(16)} nicht gesetzt (${schluessel})`);
      continue;
    }
    let zertifikate: Uint8Array[];
    try {
      zertifikate = await pemAusUmgebung(env, schluessel);
    } catch (e) {
      fehler(`  ${titel.padEnd(16)} nicht lesbar: ${(e as Error).message}`);
      befund = FINDING;
      continue;
    }
    out(`  ${titel.padEnd(16)} ${pfad} (${zertifikate.length} Zertifikat${zertifikate.length === 1 ? '' : 'e'})`);
    zertifikate.forEach((der, index) => {
      for (const zeile of beschreibeZertifikat(der, jetzt, config.clockSkewSeconds)) out(`    [${index + 1}]${zeile}`);
      if (certificateValidityFailure(der, jetzt, config.clockSkewSeconds)) befund = FINDING;
    });
  }

  return befund;
}

async function cmdOcsp(env: Record<string, string | undefined>): Promise<number> {
  const jetzt = new Date();
  const config = basisConfig(env);
  kopf('OCSP-Erreichbarkeit der konfigurierten Aussteller');

  let anker: Uint8Array[];
  try {
    const aufgelöst = await resolveIssuerAnchors(config, async () => {
      const test = await generateTestKeyMaterial('CLI Test-Anker');
      return test.certDerBytes;
    }, env, () => jetzt);
    anker = aufgelöst.anchors;
  } catch (e) {
    fehler(`  ${(e as Error).message}`);
    return FINDING;
  }

  if (anker.length === 0) {
    out('  Keine Anker konfiguriert, nichts zu prüfen.');
    return FINDING;
  }

  const checker = new OcspRevocationChecker({
    clockSkewSeconds: config.clockSkewSeconds,
    timeoutMs: 5_000,
    unavailableMode: 'bounded-soft-fail',
  });

  let befund = OK;
  for (const [index, der] of anker.entries()) {
    out('');
    let cert: X509Certificate;
    try {
      cert = new X509Certificate(new Uint8Array(der));
    } catch {
      fehler(`  [${index + 1}] unlesbares Zertifikat`);
      befund = FINDING;
      continue;
    }
    const ziel = ocspUrlVon(cert);
    out(`  [${index + 1}] ${cert.subject}`);
    if (!ziel) {
      out('      keine AIA-Erweiterung: der Dienst kann diesen Anker nicht prüfen');
      befund = FINDING;
      continue;
    }
    out(`      Responder  ${ziel}`);
    const start = performance.now();
    try {
      // Ein selbstsignierter Anker ist sein eigener Aussteller. Für ein
      // CA-signiertes Zertifikat müsste hier das CA-Zertifikat stehen; die
      // Kette prüft der Dienst ohnehin vor dieser Stelle.
      // 'anchor', weil hier der Vertrauensanker selbst geprüft wird, nicht ein
      // Blatt oder eine Zwischenzertifikatsstelle.
      const status = await checker.checkRevoked(der, 'anchor', der);
      const dauer = (performance.now() - start).toFixed(0);
      out(`      Antwort    ${status} in ${dauer} ms`);
      if (status === 'revoked' || status === 'suspended') {
        out('      Befund     der Anker ist gesperrt — der Dienst würde Präsentationen ablehnen');
        befund = FINDING;
      }
    } catch (e) {
      out(`      Antwort    FEHLER: ${(e as Error).message}`);
      befund = FINDING;
    }
  }

  if (befund === OK) out('');
  out('  Hinweis: geprüft wurde die Erreichbarkeit und Antwortgültigkeit, nicht die gesamte Dienstbereitschaft.');
  return befund;
}

function cmdRateLimit(env: Record<string, string | undefined>): number {
  kopf('Rate-Limit-Konfiguration');
  // Wirksame Werte, nicht die Konstanten: wenn die Variablen gesetzt sind,
  // zeigt das CLI die eingestellten Werte. Sonst würde es die Obergrenze
  // melden, die der Betrieb gerade abgeschaltet hat.
  const limits = basisConfig(env).rateLimits;
  const gesetzt = [
    ENV_ATTACK_RATE_LIMIT_PUBLIC,
    ENV_ATTACK_RATE_LIMIT_TENANT,
    ENV_ATTACK_RATE_LIMIT_WINDOW,
  ].filter((k) => env[k] !== undefined && env[k] !== '');
  out(gesetzt.length === 0 ? '  Quelle: eingebaute Voreinstellungen (keine Variable gesetzt)' : `  Quelle: ${gesetzt.join(', ')}`);
  out('');
  out(`  Fenster             ${limits.windowSeconds} s`);
  out(`  öffentliche Routen   ${limits.publicPerWindow} Anfragen je Fenster und IP-Adresse`);
  out(`  Mandantenrouten      ${limits.tenantPerWindow} Anfragen je Fenster und API-Schlüssel`);
  out('');
  out(`  Daraus folgt eine dauerhafte Grenze von rund ${(limits.tenantPerWindow / limits.windowSeconds).toFixed(2)} Anfragen`);
  out('  je Sekunde und Mandant. Für höheren Durchsatz die Mandantengrenze');
  out('  über die Umgebung erhöhen.');
  out('');
  out('  Ausgenommen vom Limit (jederzeit unbegrenzt):');
  for (const route of ROUTES.filter((r) => ['/live', '/health', '/ready', '/metrics'].includes(r.path))) {
    out(`    ${route.method.padEnd(6)} ${route.path}`);
  }
  out('');
  out('  Begrenzt:');
  for (const route of ROUTES.filter((r) => !['/live', '/health', '/ready', '/metrics'].includes(r.path))) {
    out(`    ${route.method.padEnd(6)} ${route.path.padEnd(46)} ${route.access === 'public' ? 'öffentlich' : 'Mandant'}`);
  }
  return OK;
}

async function cmdDoctor(env: Record<string, string | undefined>): Promise<number> {
  out('Diagnose in einem Durchlauf. Jeder Abschnitt prüft einen Teil, am Ende steht das Gesamturteil.');
  const einzel = [await cmdStatus(env), await cmdAnchors(env), await cmdOcsp(env), cmdRateLimit(env)];
  const befund = einzel.includes(UNBRAUCHBAR) ? UNBRAUCHBAR : einzel.some((r) => r === FINDING) ? FINDING : OK;
  kopf('Urteil');
  if (befund === OK) out('  Keine Beanstandung.');
  else out('  Beanstandung, siehe die Abschnitte oben. Der Dienst würde in diesem Zustand starten, aber mit Lücken.');
  return befund;
}

async function main(): Promise<number> {
  const env = process.env;
  switch (befehl) {
    case 'tenant':
      return runTenantCommand(args.slice(1), env, { out, err: fehler });
    case 'status':
      return cmdStatus(env);
    case 'anchors':
      return cmdAnchors(env);
    case 'ocsp':
      return cmdOcsp(env);
    case 'ratelimit':
      return cmdRateLimit(env);
    case 'doctor':
      return cmdDoctor(env);
    case 'help':
    case '--help':
    case '-h':
      out(
        [
          'CLI für den Verifier-Dienst. Die Diagnosebefehle sind lesend.',
          '',
          '  status      Onboarding-Gate, Anker, Laufzeit und Routenübersicht',
          '  anchors     Zertifikate der Aussteller- und Onboarding-Anker im Detail',
          '  ocsp        Erreichbarkeit und Antwortgültigkeit der OCSP-Responder',
          '  ratelimit   aktuelle Rate-Limit-Werte und welche Routen betroffen sind',
          '  doctor      alle Prüfungen nacheinander, am Ende das Gesamturteil',
          '',
          'Mandantenpflege (schreibt nur die Mandantendatei, nie etwas anderes):',
          '',
          '  tenant add --id <id> --name <name> [--profile <vorlage>] [--ttl <sekunden>] [--file <pfad>]',
          '  tenant list [--file <pfad>]',
          '  tenant revoke --id <id> [--file <pfad>]',
          '',
          `  Ohne --file gilt ${ENV_ATTACK_TENANTS_FILE}. Profilvorlagen: ${Object.keys(REQUEST_PROFILE_TEMPLATES).join(', ')}.`,
          '  Der API-Schlüssel erscheint nur bei "add" und nur einmal. Gespeichert wird nur sein SHA-256-Hash.',
          '',
          'Rückgabewert: 0 in Ordnung, 1 Beanstandung, 2 Aufruf unbrauchbar.',
        ].join('\n'),
      );
      return OK;
    default:
      fehler(`Unbekannter Befehl "${befehl}". Siehe "npm run cli -- help".`);
      return UNBRAUCHBAR;
  }
}

process.exitCode = await main().catch((e: unknown) => {
  logger.error('cli_failed', { message: (e as Error).message });
  fehler(`CLI abgebrochen: ${(e as Error).message}`);
  return UNBRAUCHBAR;
});
