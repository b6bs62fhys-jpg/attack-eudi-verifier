/**
 * Härtung 4: Produktionsschalter vollständig.
 *
 * Alle Kombinationen aus NODE_ENV (development/production),
 * ATTACK_DEV_MODE, ATTACK_ALLOW_SELF_SIGNED und echter Verifier-Identität
 * (PEM) werden gegen `bootstrapService` geprüft. Zusätzlich startet der echte
 * Einstiegspunkt run.ts als Prozess: Abbruch mit Exit-Code 1, klarer Meldung,
 * ohne Stacktrace und ohne Schlüsselinhalt; mit Entwicklungsschalter eine
 * deutliche Warnung.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';

import {
  ConfigError,
  ENV_ATTACK_ALLOW_SELF_SIGNED,
  ENV_ATTACK_DEV_MODE,
  ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM,
  ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM,
  ENV_ATTACK_VERIFIER_KEY_PEM,
  ENV_NODE_ENV,
  ENV_PORT,
} from '../config.ts';
import { generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { bootstrapService } from './bootstrap.ts';
import { NO_CREDENTIAL_STATUS } from './credential-status.ts';
import { ENV_ATTACK_ENTITLEMENT_MAP_JSON } from '../onboarding/entitlement-source.ts';

let tmpDir!: string;
let keyPem!: string;
let identityEnv!: Record<string, string>;

function derToPem(der: Uint8Array, label: string): string {
  const lines = Buffer.from(der).toString('base64').match(/.{1,64}/g)?.join('\n') ?? '';
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

beforeAll(async () => {
  const mk = await generateTestKeyMaterial('Schalter Identity TEST');
  keyPem = derToPem(new Uint8Array(await crypto.subtle.exportKey('pkcs8', mk.privateKey)), 'PRIVATE KEY');
  tmpDir = await mkdtemp(join(tmpdir(), 'attack-schalter-test-'));
  await writeFile(join(tmpDir, 'key.pem'), keyPem);
  await writeFile(join(tmpDir, 'chain.pem'), derToPem(mk.certDerBytes, 'CERTIFICATE'));
  const issuer = await generateTestKeyMaterial('Schalter Issuer TEST');
  await writeFile(join(tmpDir, 'anchors.pem'), derToPem(issuer.certDerBytes, 'CERTIFICATE'));
  // „Echte Konfiguration": Verifier-Identität UND Aussteller-Anker (Haertung 5).
  identityEnv = {
    [ENV_ATTACK_VERIFIER_KEY_PEM]: join(tmpDir, 'key.pem'),
    [ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]: join(tmpDir, 'chain.pem'),
    [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: join(tmpDir, 'anchors.pem'),
  };
});

afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

interface Combo {
  production: boolean;
  dev: boolean;
  selfSigned: boolean;
  keys: boolean;
}

/** Erwartung nach Grundsatz „im Zweifel ablehnen". */
function expectedAbort(c: Combo): string | undefined {
  if (c.production && c.dev) return 'Entwicklungsschalter in Produktion';
  if (c.production && c.selfSigned) return 'selbstsigniert in Produktion';
  if (c.selfSigned && !c.dev) return 'selbstsigniert ohne Entwicklungsschalter';
  if (!c.keys && !c.dev) return 'keine Verifier-Identität/Anker ohne Entwicklungsschalter';
  return undefined;
}

function envFor(c: Combo): Record<string, string> {
  const env: Record<string, string> = { [ENV_NODE_ENV]: c.production ? 'production' : 'development' };
  if (c.dev) env[ENV_ATTACK_DEV_MODE] = 'true';
  if (c.selfSigned) env[ENV_ATTACK_ALLOW_SELF_SIGNED] = 'true';
  if (c.keys) Object.assign(env, identityEnv);
  return env;
}

const combos: Combo[] = [];
for (const production of [false, true]) for (const dev of [false, true]) for (const selfSigned of [false, true]) for (const keys of [false, true]) combos.push({ production, dev, selfSigned, keys });

describe('bootstrapService: alle Kombinationen der Produktionsschalter', () => {
  for (const c of combos) {
    const label = `NODE_ENV=${c.production ? 'production' : 'development'} DEV=${c.dev} SELF_SIGNED=${c.selfSigned} PEM=${c.keys}`;
    const reason = expectedAbort(c);
    it(`${label} -> ${reason ? `Abbruch (${reason})` : 'Start'}`, async () => {
      const warnings: string[] = [];
      const run = () => bootstrapService(envFor(c), (m) => warnings.push(m));
      if (reason) {
        await assert.rejects(run, (e: unknown) => {
          assert.ok(e instanceof ConfigError, `ConfigError erwartet, erhalten: ${String(e)}`);
          assert.ok(!e.message.includes('PRIVATE KEY') && !e.message.includes(keyPem.split('\n')[1]), 'Meldung ohne Schlüsselinhalt');
          assert.match(e.message, /Start abgebrochen/);
          return true;
        });
      } else {
        const boot = await run();
        assert.equal(boot.usedTestIdentity, !c.keys);
        assert.equal(boot.usedTestAnchor, !c.keys, 'TEST-Anker nur ohne konfigurierte Anker (und nur mit Entwicklungsschalter)');
        assert.equal(boot.credentialStatus === NO_CREDENTIAL_STATUS, c.dev, 'Statusprüfung nur mit Entwicklungsschalter abgeschaltet');
        assert.equal(boot.testTenants.length > 0, c.dev, 'Test-Mandanten nur mit Entwicklungsschalter');
      }
    });
  }
});

describe('Warnungen beim Start', () => {
  it('Entwicklungsschalter aktiv -> deutliche Warnung', async () => {
    const warnings: string[] = [];
    await bootstrapService({ [ENV_ATTACK_DEV_MODE]: 'true' }, (m) => warnings.push(m));
    assert.ok(warnings.some((w) => w.includes('ATTACK_DEV_MODE=true ist AKTIV')));
    assert.ok(warnings.some((w) => w.includes('TEST-MATERIAL')));
    assert.ok(warnings.some((w) => w.includes('ABGESCHALTET')));
  });
  it('selbstsigniert aktiv -> eigene Warnung', async () => {
    const warnings: string[] = [];
    await bootstrapService({ [ENV_ATTACK_DEV_MODE]: 'true', [ENV_ATTACK_ALLOW_SELF_SIGNED]: 'true' }, (m) => warnings.push(m));
    assert.ok(warnings.some((w) => w.includes('ATTACK_ALLOW_SELF_SIGNED=true ist AKTIV')));
  });
  it('ohne Lockerung -> keine Lockerungswarnung; nur der Onboarding-Hinweis', async () => {
    // B3: Das Onboarding-Gate meldet seinen Zustand beim Start. Das ist keine
    // Lockerung, sondern eine Zustandsmeldung, und sie erscheint auch im
    // strengen Betrieb. Geprüft wird deshalb getrennt: keine der
    // Lockerungswarnungen, aber genau eine Zustandsmeldung zum Gate.
    const warnings: string[] = [];
    await bootstrapService({ ...identityEnv }, (m) => warnings.push(m));
    const lockerungen = warnings.filter((w) => w.includes('ist AKTIV') || w.includes('ABGESCHALTET') || w.includes('!!!'));
    assert.deepEqual(lockerungen, [], `erwartet keine Lockerungswarnung, war ${JSON.stringify(warnings)}`);
    const gate = warnings.filter((w) => w.startsWith('Onboarding-Gate:'));
    assert.equal(gate.length, 1, `erwartet genau eine Onboarding-Meldung, war ${JSON.stringify(gate)}`);
    assert.match(gate[0] ?? '', /NICHT aktiv/);
  });
});

function runService(env: Record<string, string>, waitFor?: RegExp): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--experimental-strip-types', 'src/service/run.ts'], {
      cwd: process.cwd(),
      env: { PATH: process.env.PATH ?? '', ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`Zeitüberschreitung, stdout=${stdout} stderr=${stderr}`));
    }, 20_000);
    const check = () => {
      if (waitFor && waitFor.test(stdout)) child.kill('SIGTERM');
    };
    child.stdout.on('data', (d) => {
      stdout += d;
      check();
    });
    child.stderr.on('data', (d) => (stderr += d));
    child.on('exit', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

async function freePort(): Promise<number> {
  const probe = http.createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const port = (probe.address() as { port: number }).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

function assertCleanAbort(r: { code: number | null; stderr: string; stdout: string }): void {
  assert.equal(r.code, 1);
  assert.match(r.stderr, /Start abgebrochen/);
  assert.doesNotMatch(r.stderr, /\n\s+at\s/, 'kein Stacktrace');
  assert.doesNotMatch(r.stderr + r.stdout, /PRIVATE KEY|BEGIN CERTIFICATE/, 'kein Schlüsselinhalt');
}

describe('Einstiegspunkt run.ts als Prozess', () => {
  it('Produktion ohne echte Identität -> Exit 1, klare Meldung', async () => {
    assertCleanAbort(await runService({ [ENV_NODE_ENV]: 'production' }));
  });
  it('Produktion mit Entwicklungsschalter -> Exit 1', async () => {
    assertCleanAbort(await runService({ [ENV_NODE_ENV]: 'production', [ENV_ATTACK_DEV_MODE]: 'true' }));
  });
  it('Produktion mit selbstsigniert -> Exit 1', async () => {
    assertCleanAbort(await runService({ [ENV_NODE_ENV]: 'production', [ENV_ATTACK_ALLOW_SELF_SIGNED]: 'true', ...identityEnv }));
  });
  it('ohne alles (keine Identität, kein Schalter) -> Exit 1', async () => {
    assertCleanAbort(await runService({}));
  });
  it('Entwicklungsschalter -> startet mit deutlicher Warnung', async () => {
    const port = await freePort();
    const r = await runService({ [ENV_ATTACK_DEV_MODE]: 'true', [ENV_PORT]: String(port) }, /läuft auf/);
    assert.match(r.stdout, /läuft auf http:\/\/127\.0\.0\.1:/);
    assert.match(r.stderr, /ATTACK_DEV_MODE=true ist AKTIV/);
  });
});

/**
 * B4: Die Entitlement-Quelle ist fail closed. Eine konfigurierte, aber kaputte
 * JSON-Datei bricht den Start ab — auch dann, wenn sonst alles konfiguriert ist
 * und kein Entwicklungsschalter gesetzt wurde. Geprueft wird ueber den echten
 * Prozess, weil genau der Startabbruch die Zusage ist.
 */
describe('Entitlement-Quelle: konfiguriert und kaputt -> Exit 1', () => {
  /**
   * Wie `assertCleanAbort`, aber ohne die feste Zusage „Start abgebrochen": die
   * ConfigError-Meldung der Entitlement-Quelle wird vom Einstiegspunkt bewusst
   * roh ausgegeben (`startupFailureMessage` gibt bei `ConfigError` `e.message`
   * zurück), damit der Betrieb genau die Variablen- und Dateiangabe sieht.
   * Geprueft werden die Eigenschaften, die zaehlen: Exit-Code 1, kein
   * Stacktrace, kein Schluesselinhalt.
   */
  function assertEntitlementAbort(r: { code: number | null; stderr: string; stdout: string }): void {
    assert.equal(r.code, 1, 'Start muss abbrechen');
    assert.doesNotMatch(r.stderr, /\n\s+at\s/, 'kein Stacktrace');
    assert.doesNotMatch(r.stderr + r.stdout, /PRIVATE KEY|BEGIN CERTIFICATE/, 'kein Schluesselinhalt');
  }
  async function withKaputteDatei(inhalt: string, name: string): Promise<string> {
    const pfad = join(tmpDir, name);
    await writeFile(pfad, inhalt);
    return pfad;
  }

  it('Datei fehlt auf der Platte -> Exit 1, Meldung nennt die Variable', async () => {
    const r = await runService({ [ENV_NODE_ENV]: 'production', ...identityEnv, [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: join(tmpDir, 'gibt-es-nicht.json') });
    assertEntitlementAbort(r);
    assert.match(r.stderr, new RegExp(ENV_ATTACK_ENTITLEMENT_MAP_JSON));
    assert.match(r.stderr, /Datei nicht lesbar/);
  });

  it('kein gueltiges JSON -> Exit 1', async () => {
    const pfad = await withKaputteDatei('{"version": 1, "entitlements":', 'kaputt-1.json');
    const r = await runService({ [ENV_NODE_ENV]: 'production', ...identityEnv, [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: pfad });
    assertEntitlementAbort(r);
    assert.match(r.stderr, /kein gültiges JSON/);
  });

  it('falsche version -> Exit 1', async () => {
    const pfad = await withKaputteDatei('{"version": 2, "entitlements": {"0.4.0.19475.1.11": "https://example.invalid/r"}}', 'version-2.json');
    const r = await runService({ [ENV_NODE_ENV]: 'production', ...identityEnv, [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: pfad });
    assertEntitlementAbort(r);
    assert.match(r.stderr, /"version" muss die Zahl 1 sein/);
  });

  it('leere entitlements -> Exit 1, weil die Datei sonst wirkungslos waere', async () => {
    const pfad = await withKaputteDatei('{"version": 1, "entitlements": {}}', 'leer.json');
    const r = await runService({ [ENV_NODE_ENV]: 'production', ...identityEnv, [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: pfad });
    assertEntitlementAbort(r);
    assert.match(r.stderr, /"entitlements" ist leer/);
  });

  it('Ueberschreiben einer normativen A.2-OID -> Exit 1', async () => {
    const pfad = await withKaputteDatei('{"version": 1, "entitlements": {"0.4.0.19475.1.1": "https://example.invalid/selbstgewaehlt"}}', 'ueberschreiben.json');
    const r = await runService({ [ENV_NODE_ENV]: 'production', ...identityEnv, [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: pfad });
    assertEntitlementAbort(r);
    assert.match(r.stderr, /normativ festgelegt/);
  });

  it('auch im Entwicklungsbetrieb -> Exit 1, keine stille Teilkarte', async () => {
    const pfad = await withKaputteDatei('{"version": 1, "entitlements": []}', 'dev-kaputt.json');
    const r = await runService({ [ENV_ATTACK_DEV_MODE]: 'true', [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: pfad });
    assertEntitlementAbort(r);
    assert.match(r.stderr, /"entitlements" muss ein Objekt/);
  });

  it('eine gueltige Datei startet und meldet Basis plus Datei', async () => {
    const port = await freePort();
    const pfad = await withKaputteDatei('{"version": 1, "entitlements": {"0.4.0.19475.1.11": "https://example.invalid/19475/SubEntitlement/EigeneRolle"}}', 'gut.json');
    const r = await runService({ [ENV_ATTACK_DEV_MODE]: 'true', [ENV_PORT]: String(port), [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: pfad }, /läuft auf/);
    assert.match(r.stdout, /läuft auf http:\/\/127\.0\.0\.1:/);
    // Im Entwicklungsbetrieb ist die Basis die TEST-Karte, die Datei kommt dazu.
    assert.match(r.stderr, /Entitlement-Quelle: TEST-Karte .* \+ JSON-Datei/, 'Startmeldung nennt TEST-Basis und Datei');
    assert.match(r.stderr, /5 Einträge/, 'vier TEST-Eintraege plus einer aus der Datei');
  });

  it('im Normalbetrieb ohne die Variable nennt die Startmeldung die normative Basis aus A.2', async () => {
    // Produktionsstart mit echter Identität: hier greift die normative Basis,
    // und sie hat zehn Eintraege. Genau dieser Pfad war vorher eine leere Karte.
    const port = await freePort();
    const r = await runService({ [ENV_NODE_ENV]: 'production', [ENV_PORT]: String(port), ...identityEnv }, /läuft auf/);
    assert.match(r.stderr, /Entitlement-Quelle: ETSI TS 119 475 V1\.2\.1 Anhang A\.2/);
    assert.match(r.stderr, /10 Einträge/);
  });
});

/**
 * Paket F: Fehlt beim Produktionsstart genau EINE der beiden Verifier-Identitäts-
 * variablen, brach der Dienst mit "Start abgebrochen: unerwarteter Fehler beim
 * Start (Error)." ab, weil src/service/verifier-identity.ts einen einfachen
 * `Error` warf und `startupFailureMessage` (src/config.ts:226) nur `ConfigError`
 * mit sprechender Meldung behandelt.
 *
 * Geprüft werden die vier Kombinationen ueber den echten Prozess, weil genau
 * der Startabbruch bzw. das Starten die Zusage ist. Der Aufrufer ist in jedem
 * Fall derselbe: `run.ts:34-38` faengt bedingungslos ab und beendet mit
 * Exit 1. Der Fix aendert deshalb nur den Meldungstext, nicht das Verhalten.
 */
describe('Fehlende Verifier-Identitaet: Meldung nennt die fehlende Variable', () => {
  /** Genau eine der beiden Variablen gesetzt, alles andere wie im echten Betrieb. */
  async function mitGenauEiner(gesetzt: string): Promise<{ code: number | null; stdout: string; stderr: string }> {
    const env: Record<string, string> = {
      [ENV_NODE_ENV]: 'production',
      [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: join(tmpDir, 'anchors.pem'),
    };
    // Aus 'identityEnv' genau den einen Eintrag herausgreifen.
    for (const k of [ENV_ATTACK_VERIFIER_KEY_PEM, ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]) {
      if (k === gesetzt) env[k] = identityEnv[k] as string;
    }
    return runService(env);
  }

  it('nur ATTACK_VERIFIER_KEY_PEM gesetzt -> Exit 1, nennt die fehlende Kette', async () => {
    const r = await mitGenauEiner(ENV_ATTACK_VERIFIER_KEY_PEM);
    assert.equal(r.code, 1, 'Start muss abbrechen wie vorher');
    assert.doesNotMatch(r.stderr, /\n\s+at\s/, 'kein Stacktrace');
    assert.doesNotMatch(r.stderr + r.stdout, /PRIVATE KEY|BEGIN CERTIFICATE/, 'kein Schluesselinhalt');
    assert.match(r.stderr, new RegExp(ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM), 'fehlende Variable muss beim Namen genannt werden');
    assert.doesNotMatch(r.stderr, /unerwarteter Fehler beim Start/, 'nicht mehr die generische Meldung');
  });

  it('nur ATTACK_VERIFIER_CERT_CHAIN_PEM gesetzt -> Exit 1, nennt den fehlenden Key', async () => {
    const r = await mitGenauEiner(ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM);
    assert.equal(r.code, 1, 'Start muss abbrechen wie vorher');
    assert.doesNotMatch(r.stderr, /\n\s+at\s/, 'kein Stacktrace');
    assert.doesNotMatch(r.stderr + r.stdout, /PRIVATE KEY|BEGIN CERTIFICATE/, 'kein Schluesselinhalt');
    assert.match(r.stderr, new RegExp(ENV_ATTACK_VERIFIER_KEY_PEM), 'fehlende Variable muss beim Namen genannt werden');
    assert.doesNotMatch(r.stderr, /unerwarteter Fehler beim Start/, 'nicht mehr die generische Meldung');
  });

  it('beide fehlen -> Exit 1, Meldung bleibt die bereits brauchbare', async () => {
    // Dieser Fall wird nicht angefasst: hier greift eine eigene ConfigError-
    // Meldung aus resolveVerifierIdentity, die beide Variablen nennt.
    const r = await runService({ [ENV_NODE_ENV]: 'production', [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: join(tmpDir, 'anchors.pem') });
    assert.equal(r.code, 1, 'Start muss abbrechen wie vorher');
    assert.match(r.stderr, new RegExp(ENV_ATTACK_VERIFIER_KEY_PEM));
    assert.match(r.stderr, new RegExp(ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM));
    assert.doesNotMatch(r.stderr, /unerwarteter Fehler beim Start/, 'diese Meldung war schon brauchbar');
  });

  it('beide gesetzt -> Dienst startet, kein Unterschied zum Vorher-Verhalten', async () => {
    const port = await freePort();
    const r = await runService({ [ENV_NODE_ENV]: 'production', [ENV_PORT]: String(port), ...identityEnv }, /läuft auf/);
    assert.match(r.stdout, /läuft auf http:\/\/127\.0\.0\.1:/, 'Dienst muss starten');
    assert.doesNotMatch(r.stderr, /Start abgebrochen/, 'kein Abbruch');
  });
});

/**
 * Paket G: dieselbe Fehlertyp-Ursache an den übrigen Abbruchstellen von
 * `loadVerifierIdentity`. Diese Stellen warfen einen einfachen `Error`;
 * `startupFailureMessage` (src/config.ts:226) gibt nur bei `ConfigError` die
 * eigene Meldung aus, sonst `Start abgebrochen: unerwarteter Fehler beim Start
 * (Error).` — die sprechende Meldung existierte, war aber unerreichbar.
 *
 * Geprüft wird über den echten Prozess, weil genau die Ausgabe entscheidet: ein
 * Test auf `loadVerifierIdentity` allein hätte den Fehler nicht gesehen, weil
 * genau diese Umleitung ihn ausmacht. Das Abbruchverhalten ist vor und nach dem
 * Fix Exit 1.
 */
describe('Unbrauchbare Verifier-PEM: Meldung nennt den Grund', () => {
  /** Schlechte Dateien im bereits vorhandenen tmpDir anlegen. */
  async function kaputteDateien(): Promise<{ key: string; chain: string }> {
    const key = join(tmpDir, 'paket-g-key.pem');
    const chain = join(tmpDir, 'paket-g-chain.pem');
    await writeFile(key, '-----BEGIN PRIVATE KEY-----\nQUJDREVGR0g=\n-----END PRIVATE KEY-----\n');
    await writeFile(chain, 'garbage\n');
    return { key, chain };
  }

  /** Abbruch prüfen und zusätzlich: keine generische Meldung, kein Schlüsselinhalt. */
  function assertAbbruchMitGrund(r: { code: number | null; stderr: string; stdout: string }, Grund: RegExp): void {
    assert.equal(r.code, 1, 'Start muss abbrechen wie vorher');
    assert.doesNotMatch(r.stderr, /\n\s+at\s/, 'kein Stacktrace');
    assert.doesNotMatch(r.stderr + r.stdout, /PRIVATE KEY|BEGIN CERTIFICATE/, 'kein Schlüsselinhalt');
    assert.match(r.stderr, Grund, 'Meldung muss den eigentlichen Grund nennen');
    assert.doesNotMatch(r.stderr, /unerwarteter Fehler beim Start/, 'nicht mehr die generische Meldung');
  }

  it('PEM-Datei nicht lesbar -> nennt die betroffene Variable', async () => {
    const { chain } = await kaputteDateien();
    const r = await runService({
      [ENV_NODE_ENV]: 'production',
      [ENV_ATTACK_VERIFIER_KEY_PEM]: join(tmpDir, 'paket-g-gibt-es-nicht.pem'),
      [ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]: chain,
      [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: join(tmpDir, 'anchors.pem'),
    });
    assertAbbruchMitGrund(r, /nicht lesbar/);
    assert.match(r.stderr, new RegExp(ENV_ATTACK_VERIFIER_KEY_PEM), 'betroffene Variable muss benannt sein');
  });

  it('Zertifikatskette ohne CERTIFICATE-Block -> nennt die Kette', async () => {
    const { key, chain } = await kaputteDateien();
    const r = await runService({
      [ENV_NODE_ENV]: 'production',
      [ENV_ATTACK_VERIFIER_KEY_PEM]: key,
      [ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]: chain,
      [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: join(tmpDir, 'anchors.pem'),
    });
    assertAbbruchMitGrund(r, /Zertifikatskette unbrauchbar/);
    assert.match(r.stderr, new RegExp(ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM), 'betroffene Variable muss benannt sein');
  });

  it('Private-Key unbrauchbar -> nennt den Key', async () => {
    // Nur der Key ist hier kaputt, die Kette ist die gueltige aus dem tmpDir.
    const { key } = await kaputteDateien();
    const r = await runService({
      [ENV_NODE_ENV]: 'production',
      [ENV_ATTACK_VERIFIER_KEY_PEM]: key,
      [ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]: join(tmpDir, 'chain.pem'),
      [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: join(tmpDir, 'anchors.pem'),
    });
    assertAbbruchMitGrund(r, /Private-Key unbrauchbar/);
    assert.match(r.stderr, new RegExp(ENV_ATTACK_VERIFIER_KEY_PEM), 'betroffene Variable muss benannt sein');
  });
});
