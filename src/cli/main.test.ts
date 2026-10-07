/**
 * Das CLI wird getestet, weil seine Zusage sonst ungeprüft wäre: Die
 * Diagnosebefehle lesen nur und sagen, was der Dienst tun würde, statt was die
 * Doku behauptet. Der einzige Schreibbefehl `tenant` schreibt nur die
 * Mandantendatei, läuft ohne Entwicklungsschalter und zeigt den Klartext eines
 * Schlüssels genau einmal.
 *
 * Getestet wird der Prozess, nicht die Funktionen: entscheidend ist, was auf
 * stdout und stderr landet und welcher Exit-Code zurückkommt, weil genau das
 * eine Überwachung auswertet.
 */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, it } from 'vitest';

import { hashApiKey } from '../service/tenant.ts';

const CLI = fileURLToPath(new URL('main.ts', import.meta.url));

interface Lauf {
  code: number;
  stdout: string;
  stderr: string;
}

function lauf(befehl: string, env: Record<string, string> = {}): Promise<Lauf> {
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      ['--experimental-strip-types', CLI, befehl],
      {
        // Bewusst eine minimale Umgebung: ohne ATTACK_DEV_MODE wäre die
        // Ankerauflösung fail closed, was die Befehle mit einem Fehler statt
        // mit einer Diagnose enden ließe.
        env: { PATH: process.env.PATH ?? '', ATTACK_DEV_MODE: 'true', ...env },
        timeout: 30_000,
      },
      (error, stdout, stderr) => {
        if (error && typeof error.code !== 'number') {
          reject(error);
          return;
        }
        resolve({ code: typeof error?.code === 'number' ? error.code : 0, stdout, stderr });
      },
    );
  });
}

/** Lauf mit beliebigen Argumenten und ohne vorgegebenen Entwicklungsschalter. */
function laufArgs(argumente: string[], env: Record<string, string> = {}): Promise<Lauf> {
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      ['--experimental-strip-types', CLI, ...argumente],
      { env: { PATH: process.env.PATH ?? '', ...env }, timeout: 30_000 },
      (error, stdout, stderr) => {
        if (error && typeof error.code !== 'number') {
          reject(error);
          return;
        }
        resolve({ code: typeof error?.code === 'number' ? error.code : 0, stdout, stderr });
      },
    );
  });
}

describe('Diagnose-CLI', () => {
  it('help listet die lesenden Befehle und als einzigen Schreibbefehl tenant', async () => {
    const r = await lauf('help');
    assert.equal(r.code, 0);
    for (const befehl of ['status', 'anchors', 'ocsp', 'ratelimit', 'doctor']) {
      assert.match(r.stdout, new RegExp(`\\b${befehl}\\b`), `${befehl} muss angeboten werden`);
    }
    // Die Zusage "Diagnose ist lesend" wird geprüft, nicht nur behauptet: kein
    // Befehl mit Schreibwirkung darf auf oberster Ebene im Angebot stehen.
    // Schreiben darf nur `tenant`, und zwar nur seine drei Unterbefehle.
    for (const verb of ['add', 'create', 'set', 'delete', 'remove', 'register', 'import', 'write', 'rotate', 'revoke']) {
      assert.doesNotMatch(
        r.stdout,
        new RegExp(`^\\s+${verb}\\b`, 'm'),
        `das CLI darf außer tenant keinen Schreibbefehl anbieten, gefunden: ${verb}`,
      );
    }
    const schreibend = r.stdout.split('\n').filter((z) => /^\s+tenant\b/.test(z)).map((z) => z.trim().split(/\s+/)[1]);
    assert.deepEqual(schreibend, ['add', 'list', 'revoke']);
    assert.match(r.stdout, /lesend/i);
    assert.match(r.stdout, /schreibt nur die Mandantendatei/);
  });

  it('ein unbekannter Befehl bricht mit Code 2 ab', async () => {
    const r = await lauf('gibtsnicht');
    assert.equal(r.code, 2, `erwartet 2, stdout: ${r.stdout}`);
    assert.match(r.stderr, /Unbekannter Befehl/);
  });

  it('status meldet ohne Onboarding-Material eine Beanstandung mit Code 1', async () => {
    const r = await lauf('status');
    // Ohne die beiden PEM-Variablen entsteht kein Gate, das ist ein Befund
    // und kein Fehler.
    assert.equal(r.code, 1, `erwartet 1, stdout: ${r.stdout}`);
    assert.match(r.stdout, /Onboarding-Gate: NICHT aktiv/);
    assert.match(r.stdout, /ATTACK_ONBOARDING_ACCESS_CA_PEM/);
    assert.match(r.stdout, /ATTACK_ONBOARDING_WRPRC_ISSUER_PEM/);
  });

  it('status unterscheidet "nicht konfiguriert" von "Pfad gesetzt, aber unlesbar"', async () => {
    const ohne = await lauf('status');
    assert.match(ohne.stdout, /kein Onboarding konfiguriert/, 'ohne Variablen ist das ein Normalzustand');

    const mit = await lauf('status', {
      ATTACK_ONBOARDING_ACCESS_CA_PEM: '/tmp/gibt-es-nicht-access-ca.pem',
      ATTACK_ONBOARDING_WRPRC_ISSUER_PEM: '/tmp/gibt-es-nicht-wrprc.pem',
    });
    // Der Dienst wirft den Grund bei unlesbarem Material absichtlich weg. Ohne
    // eigene Prüfung sähe ein Tippfehler im Pfad hier wie "nicht konfiguriert"
    // aus — das ist genau der Fall, den das CLI auffinden soll.
    assert.doesNotMatch(mit.stdout, /kein Onboarding konfiguriert/);
    assert.match(mit.stdout, /Konfigurationsfehler/);
    assert.match(mit.stdout, /gibt-es-nicht/);
    assert.equal(mit.code, 1);
  });

  it('anchors zeigt Subject, Gültigkeit und Sperrzustand der Anker', async () => {
    const r = await lauf('anchors');
    assert.match(r.stdout, /Aussteller-Vertrauensanker/);
    assert.match(r.stdout, /Subject\s+\S+/);
    assert.match(r.stdout, /Seriennummer/);
    assert.match(r.stdout, /Gültig/);
    // Der Test-Anker trägt keine AIA, genau das muss das CLI sagen, weil der
    // Dienst an diesem Anker keine Sperrprüfung vornehmen kann.
    assert.match(r.stdout, /keine AIA-Erweiterung/);
  });

  it('ocsp sagt, wenn ein Anker keine Sperrprüfung erlaubt', async () => {
    const r = await lauf('ocsp');
    assert.match(r.stdout, /OCSP-Erreichbarkeit/);
    assert.match(r.stdout, /keine AIA-Erweiterung/);
    // Ohne prüfbaren Anker ist das ein Befund.
    assert.equal(r.code, 1);
  });

  it('ratelimit nennt die wirksamen Werte und deren Grenze', async () => {
    const r = await lauf('ratelimit');
    assert.equal(r.code, 0);
    assert.match(r.stdout, /120 Anfragen je Fenster und IP-Adresse/);
    assert.match(r.stdout, /60 Anfragen je Fenster und API-Schlüssel/);
    // Die Folge der Voreinstellung muss genannt werden, sonst liest sich die
    // Zahl wie eine Kapazitätsaussage.
    assert.match(r.stdout, /1\.00 Anfragen\s+je Sekunde und Mandant/);
    // Und es muss benannt sein, woher die Werte kommen.
    assert.match(r.stdout, /eingebaute Voreinstellungen/);
  });

  it('ratelimit zeigt eingestellte Werte statt der Voreinstellung', async () => {
    // Genau der Fehler, den ein Diagnosewerkzeug nicht machen darf: die
    // Obergrenze melden, die der Betrieb gerade abgeschaltet hat.
    const r = await lauf('ratelimit', { ATTACK_RATE_LIMIT_TENANT_PER_WINDOW: '6000' });
    assert.equal(r.code, 0);
    assert.match(r.stdout, /6000 Anfragen je Fenster und API-Schlüssel/);
    assert.match(r.stdout, /ATTACK_RATE_LIMIT_TENANT_PER_WINDOW/);
    assert.match(r.stdout, /100\.00 Anfragen\s+je Sekunde/);
    assert.doesNotMatch(r.stdout, /60 Anfragen je Fenster und API-Schlüssel/);
  });

  it('doctor fasst alle Prüfungen zusammen und endet mit einem Urteil', async () => {
    const r = await lauf('doctor');
    assert.match(r.stdout, /Urteil/);
    // Ohne Onboarding-Material und ohne prüfbaren Anker gibt es Beanstandung.
    assert.equal(r.code, 1);
    assert.match(r.stdout, /Beanstandung|Keine Beanstandung/);
  });

  it('raten die Betriebsrouten aus, begrenzt die Fachrouten', async () => {
    const r = await lauf('ratelimit');
    const ausgenommen = r.stdout.split('Ausgenommen vom Limit')[1] ?? '';
    for (const pfad of ['/live', '/health', '/ready', '/metrics']) {
      assert.match(ausgenommen, new RegExp(pfad.replace('/', '\\/')), `${pfad} muss ausgenommen sein`);
    }
    const begrenzt = r.stdout.split('Begrenzt:')[1] ?? '';
    for (const pfad of ['/direct_post', '/v1/verification-requests']) {
      assert.match(begrenzt, new RegExp(pfad.replace('/', '\\/')), `${pfad} muss begrenzt sein`);
    }
  });
});

describe('CLI tenant: Mandantenpflege ohne Entwicklungsschalter', () => {
  let dir!: string;
  const prod = (pfad: string): Record<string, string> => ({ NODE_ENV: 'production', ATTACK_TENANTS_FILE: pfad });

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'attack-cli-tenant-'));
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('add im Produktionsmodus: Schlüssel einmal auf stdout, in der Datei nur der Hash, Rechte 0600', async () => {
    const pfad = join(dir, 'add.json');
    const r = await laufArgs(['tenant', 'add', '--id', 'kunde-a', '--name', 'Kunde A GmbH', '--profile', 'age_over_18'], prod(pfad));
    assert.equal(r.code, 0, r.stderr);
    const schluessel = r.stdout.match(/atk_[A-Za-z0-9_-]{43}/g) ?? [];
    assert.equal(schluessel.length, 1, 'der Schlüssel erscheint genau einmal');
    const key = schluessel[0] as string;
    const inhalt = await readFile(pfad, 'utf8');
    assert.ok(!inhalt.includes(key), 'Klartext nicht in der Datei');
    assert.ok(inhalt.includes(hashApiKey(key)), 'Hash in der Datei');
    assert.equal((await stat(pfad)).mode & 0o777, 0o600);
    // Kein Entwicklungsschalter, keine Lockerungswarnung.
    assert.doesNotMatch(r.stdout + r.stderr, /ATTACK_DEV_MODE|TEST-MATERIAL|Test-Mandanten/);
    assert.ok(!r.stderr.includes(key), 'Schlüssel nicht auf stderr');
  });

  it('list zeigt Mandanten und Status, aber weder Schlüssel noch Hash', async () => {
    const pfad = join(dir, 'list.json');
    const add = await laufArgs(['tenant', 'add', '--id', 'kunde-a', '--name', 'Kunde A'], prod(pfad));
    const key = (add.stdout.match(/atk_[A-Za-z0-9_-]{43}/) ?? [''])[0];
    const r = await laufArgs(['tenant', 'list'], prod(pfad));
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /kunde-a\s+aktiv/);
    assert.ok(!r.stdout.includes(key), 'kein Schlüssel');
    assert.ok(!r.stdout.includes(hashApiKey(key)), 'kein Hash');
  });

  it('revoke sperrt, ist wiederholbar, und eine erneute Vergabe der ID scheitert', async () => {
    const pfad = join(dir, 'revoke.json');
    await laufArgs(['tenant', 'add', '--id', 'kunde-a', '--name', 'Kunde A'], prod(pfad));
    const r = await laufArgs(['tenant', 'revoke', '--id', 'kunde-a'], prod(pfad));
    assert.equal(r.code, 0, r.stderr);
    assert.match(r.stdout, /gesperrt/);
    const datei = JSON.parse(await readFile(pfad, 'utf8')) as { tenants: Array<{ status: string; revokedAt?: string }> };
    assert.equal(datei.tenants[0]?.status, 'revoked');
    assert.ok(datei.tenants[0]?.revokedAt);
    const nochmal = await laufArgs(['tenant', 'revoke', '--id', 'kunde-a'], prod(pfad));
    assert.equal(nochmal.code, 0);
    assert.match(nochmal.stdout, /bereits gesperrt/);
    const neu = await laufArgs(['tenant', 'add', '--id', 'kunde-a', '--name', 'Kunde A neu'], prod(pfad));
    assert.equal(neu.code, 2);
    assert.match(neu.stderr, /existiert bereits/);
  });

  it('eine kaputte Datei wird nicht überschrieben', async () => {
    const pfad = join(dir, 'kaputt.json');
    await writeFile(pfad, '{ "version": 1, "tenants": [ ');
    const r = await laufArgs(['tenant', 'add', '--id', 'kunde-b', '--name', 'B'], prod(pfad));
    assert.equal(r.code, 2);
    assert.match(r.stderr, /kein gültiges JSON/);
    assert.equal(await readFile(pfad, 'utf8'), '{ "version": 1, "tenants": [ ');
  });

  it('Fehlaufrufe enden mit Code 2', async () => {
    const pfad = join(dir, 'fehl.json');
    assert.equal((await laufArgs(['tenant', 'add', '--id', 'x'], prod(pfad))).code, 2, 'ohne --name');
    assert.equal((await laufArgs(['tenant', 'add', '--id', 'x', '--name', 'X', '--profile', 'gibtsnicht'], prod(pfad))).code, 2);
    assert.equal((await laufArgs(['tenant', 'add', '--id', 'x', '--name', 'X', '--ttl', 'lang'], prod(pfad))).code, 2);
    assert.equal((await laufArgs(['tenant', 'add', '--id', 'x', '--name', 'X', '--unbekannt', '1'], prod(pfad))).code, 2);
    assert.equal((await laufArgs(['tenant', 'loeschen', '--id', 'x'], prod(pfad))).code, 2);
    assert.equal((await laufArgs(['tenant', 'revoke', '--id', 'x'], prod(join(dir, 'gibtsnicht.json')))).code, 2);
    const ohneDatei = await laufArgs(['tenant', 'list'], { NODE_ENV: 'production' });
    assert.equal(ohneDatei.code, 2);
    assert.match(ohneDatei.stderr, /ATTACK_TENANTS_FILE/);
  });
});
