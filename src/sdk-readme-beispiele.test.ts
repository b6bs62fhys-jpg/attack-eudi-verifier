/**
 * Führt die Beispielblöcke aus sdk/typescript/README.md aus, statt sie nur zu
 * beschreiben. Muster nach src/quickstart-beispiele.test.ts: der Testdienst
 * läuft im selben Prozess, die Blöcke laufen als Kindprozess dagegen.
 *
 * Wird ein Beispiel so verändert, dass es nicht mehr startet, nicht mehr gegen
 * die echten Feldnamen des Clients geht oder eine Methode aufruft, die es nicht
 * gibt, schlägt dieser Test fehl.
 *
 * Geprüft wird nicht der Wortlaut, sondern: laufen die Blöcke, und stimmen die
 * Feldnamen, die sie benutzen, mit src/generated.ts überein.
 */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, it } from 'vitest';

import { createApp } from './service/app.ts';
import { VerifierService, type ServiceKeys } from './service/service.ts';
import { AuditLog } from './service/audit.ts';
import { TenantStore } from './service/tenant.ts';
import { generateTestKeyMaterial } from './decision-test/mock-wallet.ts';
import { DEV_TEST_OPTIONS } from './service/test-support.ts';

const execFileAsync = promisify(execFile);

const WURZEL = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const README = resolve(WURZEL, 'sdk/typescript/README.md');
const SDK_INDEX = resolve(WURZEL, 'sdk/typescript/src/index.ts');
const GENERATED = resolve(WURZEL, 'sdk/typescript/src/generated.ts');
const KEY_A = 'test-api-key-sdk-readme';

interface Harness {
  base: string;
  server: Awaited<ReturnType<typeof createApp>>;
}

let h: Harness;
const tempDirs: string[] = [];

/** Die ts-Blöcke der README in Dokumentreihenfolge. */
function tsBloecke(): string[] {
  const inhalt = readFileSync(README, 'utf8');
  return [...inhalt.matchAll(/```ts\n([\s\S]*?)```/g)].map((m) => m[1] ?? '');
}

/**
 * Die Blöcke, die etwas mit dem Client aufrufen. Der Installationsblock und
 * die Generierungsbefehle sind bash, sie laufen nicht hier.
 */
function clientBloecke(): string[] {
  return tsBloecke().filter((b) => b.includes('attack.'));
}

/**
 * Schreibt die Blöcke als ein zusammenhaengendes Skript.
 *
 * Die Blöcke der README bauen aufeinander auf: der erste legt `attack` und
 * `request` an, die folgenden benutzen sie. Sie werden deshalb in
 * Dokumentreihenfolge in eine Datei geschrieben und als Ganzes ausgeführt.
 * `walletJwe` steht in keinem Block, es kommt aus der Wallet, und wird als
 * Platzhalter gesetzt.
 */
function skriptSchreiben(bloecke: string[], basis: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'sdk-readme-'));
  tempDirs.push(dir);
  const datei = join(dir, 'beispiel.ts');
  const kopf = `import { AttackClient } from ${JSON.stringify(SDK_INDEX)};\n`;
  // Der erste Block legt `attack` und `request` an und bleibt auf oberster
  // Ebene. Die uebrigen kommen in eine Klammer: sie sehen die Namen des ersten
  // Blocks, aber ihre eigenen const-Deklarationen kollidieren nicht untereinander.
  // Ohne die Klammer bricht das Skript, weil die README `outcome` zweimal
  // deklariert.
  const koerper = bloecke
    .map((block, i) => (i === 0 ? block : `{\n${block}\n}`))
    .join('\n')
    // Der Import steht schon im Kopf, sonst waere AttackClient zweimal
    // deklariert und das Skript startet nicht.
    .replace(/^import .*AttackClient.*$/gm, '')
    .replaceAll("process.env.ATTACK_URL ?? 'http://127.0.0.1:8080'", JSON.stringify(basis))
    .replaceAll('process.env.ATTACK_API_KEY', JSON.stringify(KEY_A))
    .replaceAll('walletJwe', JSON.stringify('nicht-ein-jwe'));
  writeFileSync(datei, `${kopf}\n${koerper}\n`, 'utf8');
  return datei;
}

beforeAll(async () => {
  const tenants = new TenantStore();
  // Das Beispiel der README fordert age_over_18. Das gehoert zum Profil
  // age_over_18, der Standard ist pid_basis mit given_name und birth_date.
  // Ohne diese Zeile antwortet der Dienst mit claims_invalid.
  tenants.add({
    id: 'tenant-sdk',
    name: 'SDK TEST',
    apiKey: KEY_A,
    requestTtlSeconds: 300,
    requestProfile: 'age_over_18',
  });

  const verifierKey = await generateTestKeyMaterial('SDK README Verifier TEST');
  const issuerKey = await generateTestKeyMaterial('SDK README Issuer TEST');
  const keys: ServiceKeys = {
    privateKey: verifierKey.privateKey,
    publicKey: verifierKey.publicKey,
    publicJwk: verifierKey.publicJwk,
    certificateChain: [verifierKey.certDerBytes],
  };

  const audit = new AuditLog();
  const service = new VerifierService(
    tenants,
    audit,
    keys,
    issuerKey.certDerBytes,
    undefined,
    undefined,
    undefined,
    undefined,
    true,
    DEV_TEST_OPTIONS,
  );
  const server = createApp({ appLabel: 'attack-service', tenants, service });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  service.baseUrl = base;
  h = { base, server };
}, 60_000);

afterAll(async () => {
  // Ist beforeAll gescheitert, gibt es keinen Server. Dann nur die
  // temporaeren Verzeichnisse aufraeumen und den Fehler nicht ueberdecken.
  if (h?.server) await new Promise<void>((r) => h.server.close(() => r()));
  for (const d of tempDirs) rmSync(d, { recursive: true, force: true });
});

describe('SDK TypeScript: die Beispiele der README laufen', () => {
  it('die README hat überhaupt ts-Blöcke, die den Client benutzen', () => {
    assert.ok(clientBloecke().length >= 4, `nur ${clientBloecke().length} Client-Blöcke in der README`);
  });

  it('die README importiert den Client aus dem Paketnamen', () => {
    const importiert = tsBloecke().find((b) => b.includes('import'));
    assert.ok(importiert, 'kein Importblock in der README');
    assert.match(importiert, /@eudi-verify-sdk\/typescript/);
  });

  it('alle Blöcke laufen als Skript gegen den Testdienst', async () => {
    const datei = skriptSchreiben(clientBloecke(), h.base);
    const { stdout, stderr } = await execFileAsync(
      process.execPath,
      ['--experimental-strip-types', datei],
      { encoding: 'utf8', timeout: 60_000, cwd: WURZEL },
    );
    // Der erste Block legt eine Sitzung an und gibt ihre URIs aus. Ohne diese
    // Zeile laeuft der Block nicht, sondern wirft.
    assert.match(stdout, /https?:\/\//, 'der Block createPresentationRequest hat keine URI ausgegeben');
    // Ein falscher Feldname liefert undefined, kein Fehler. Deshalb wird nicht
    // nur auf einen Fehler geprueft, sondern darauf, dass in der Ausgabe
    // nichts undefined steht.
    assert.ok(
      !/undefined/.test(stdout),
      `im Beispiel steht ein undefined, ein Feldname ist falsch:\n${stdout}`,
    );
    assert.ok(
      !/ReferenceError|TypeError|SyntaxError|is not a function/.test(stdout + stderr),
      `das Skript meldet einen Fehler:\n${stdout}\n${stderr}`,
    );
  }, 90_000);

  it('jede Methode, die die README aufruft, gibt es im Client', () => {
    const index = readFileSync(SDK_INDEX, 'utf8');
    const aufrufe = new Set<string>();
    for (const block of clientBloecke()) {
      for (const m of block.matchAll(/attack\.([a-zA-Z]+)\(/g)) {
        if (m[1]) aufrufe.add(m[1]);
      }
    }
    assert.ok(aufrufe.size >= 5, `nur ${aufrufe.size} verschiedene Clientmethoden in der README`);
    for (const methode of aufrufe) {
      assert.ok(
        new RegExp(`\\b${methode}\\s*\\(`).test(index),
        `die README ruft attack.${methode}(), die gibt es im Client nicht`,
      );
    }
  });

  it('jedes Feld, das die README liest, steht in den erzeugten Typen', () => {
    const generated = readFileSync(GENERATED, 'utf8');
    // requestObjectUri, responseUri und sessionId aus dem Anlageblock,
    // result.claims aus dem Ergebnisblock, error aus den Ablehnungsbloecken.
    const muster: [string, RegExp][] = [
      ['requestObjectUri', /requestObjectUri: string/],
      ['responseUri', /responseUri: string/],
      ['sessionId', /sessionId: string/],
      ['claims', /claims/],
      ['error', /error:/],
    ];
    for (const [feld, rx] of muster) {
      assert.ok(rx.test(generated), `die README liest ${feld}, in src/generated.ts gibt es das Feld nicht`);
    }
  });

  it('die Statuswerte der README stehen in ResultStatus', () => {
    const generated = readFileSync(GENERATED, 'utf8');
    // Der Status ist eine Vereinigung aus mehreren Zeichenketten, kein einzelner
    // Wert, deshalb bis zum Semikolon greifen.
    const block = /ResultStatus: \{[\s\S]*?status: ([^;]+);/.exec(generated);
    assert.ok(block && block[1], 'Statuswerte in ResultStatus nicht gefunden');
    const erlaubt = block[1] ?? '';
    assert.ok(tsBloecke().every((b) => !b.includes("status === 'unknown")), 'unbekannter Status im Beispiel');
    // completed wird im Ergebnisblock geprueft, es muss ein erlaubter Wert sein.
    assert.match(erlaubt, /completed/);
    assert.match(erlaubt, /pending/);
  });

  it('die README nennt die drei Betriebsrouten, die es im Client gibt', () => {
    const readme = readFileSync(README, 'utf8');
    for (const [methode, pfad] of [
      ['liveness', '/live'],
      ['readiness', '/ready'],
      ['metrics', '/metrics'],
    ] as const) {
      assert.ok(readme.includes(`attack.${methode}()`), `die README ruft attack.${methode}() nicht`);
      assert.ok(readme.includes(pfad), `die README nennt ${pfad} nicht`);
    }
  });
});
