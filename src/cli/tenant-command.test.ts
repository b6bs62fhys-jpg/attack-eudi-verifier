/**
 * `tenant` im Prozess. Der Prozesstest in main.test.ts prüft Exit-Code und
 * Ausgabekanäle; dieser Test prüft dieselben Wege ohne Unterprozess, damit die
 * Logik auch in der Abdeckung sichtbar ist, und deckt die Fehlerpfade ab.
 */
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, it } from 'vitest';

import { hashApiKey } from '../service/tenant.ts';
import { loadTenantFile } from '../service/tenant-file.ts';
import { runTenantCommand } from './tenant-command.ts';

let dir!: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'attack-tenant-command-'));
});
afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function run(argv: string[], env: Record<string, string | undefined> = {}): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await runTenantCommand(argv, env, { out: (t) => out.push(t), err: (t) => err.push(t) });
  return { code, out: out.join('\n'), err: err.join('\n') };
}

describe('tenant im Prozess', () => {
  it('add, list, revoke über --file', async () => {
    const pfad = join(dir, 'ablauf.json');
    const add = await run(['add', '--id', 'kunde-a', '--name', 'Kunde A', '--ttl', '600', '--file', pfad]);
    assert.equal(add.code, 0, add.err);
    const key = (add.out.match(/atk_[A-Za-z0-9_-]{43}/) ?? [''])[0];
    assert.ok(key);
    const datei = await loadTenantFile(pfad);
    assert.equal(datei.tenants[0]?.apiKeySha256, hashApiKey(key));
    assert.equal(datei.tenants[0]?.requestTtlSeconds, 600);

    const list = await run(['list', '--file', pfad]);
    assert.equal(list.code, 0);
    assert.match(list.out, /kunde-a\s+aktiv/);
    assert.match(list.out, /1 aktiv, 0 gesperrt/);
    assert.ok(!list.out.includes(key) && !list.out.includes(hashApiKey(key)));

    const revoke = await run(['revoke', '--id', 'kunde-a', '--file', pfad]);
    assert.equal(revoke.code, 0);
    assert.match((await run(['list', '--file', pfad])).out, /kunde-a\s+gesperrt.*\n.*gesperrt seit/);
    assert.match((await run(['revoke', '--id', 'kunde-a', '--file', pfad])).out, /bereits gesperrt/);
  });

  it('die Umgebungsvariable gilt, wenn --file fehlt; --file hat Vorrang', async () => {
    const ausEnv = join(dir, 'env.json');
    const ausArg = join(dir, 'arg.json');
    assert.equal((await run(['add', '--id', 'a', '--name', 'A'], { ATTACK_TENANTS_FILE: ausEnv })).code, 0);
    assert.equal((await run(['add', '--id', 'b', '--name', 'B', '--file', ausArg], { ATTACK_TENANTS_FILE: ausEnv })).code, 0);
    assert.deepEqual((await loadTenantFile(ausEnv)).tenants.map((t) => t.id), ['a']);
    assert.deepEqual((await loadTenantFile(ausArg)).tenants.map((t) => t.id), ['b']);
  });

  it('list ohne Datei und mit leerer Datei', async () => {
    const fehlt = await run(['list', '--file', join(dir, 'fehlt.json')]);
    assert.equal(fehlt.code, 0);
    assert.match(fehlt.out, /existiert noch nicht/);
    const leer = join(dir, 'leer.json');
    await writeFile(leer, JSON.stringify({ version: 1, tenants: [] }));
    assert.match((await run(['list', '--file', leer])).out, /keine Einträge/);
  });

  it('eigenes Profil wird in der Liste benannt', async () => {
    const pfad = join(dir, 'eigen.json');
    const eintrag = {
      id: 'eigen',
      name: 'Eigen',
      apiKeySha256: hashApiKey('x'),
      requestProfile: { id: 'mein-profil', claims: ['given_name'] },
      requestTtlSeconds: 300,
      status: 'active',
      createdAt: '2026-10-07T10:00:00.000Z',
    };
    await writeFile(pfad, JSON.stringify({ version: 1, tenants: [eintrag] }));
    assert.match((await run(['list', '--file', pfad])).out, /eigenes Profil \(mein-profil\)/);
  });

  const fehler: Array<[string, string[], RegExp]> = [
    ['ohne Datei', ['list'], /ATTACK_TENANTS_FILE/],
    ['unbekannte Option', ['add', '--wer', 'x', '--file', 'f.json'], /tenant:/],
    ['ohne Unterbefehl', ['--file', 'f.json'], /add, list oder revoke/],
    ['add ohne --name', ['add', '--id', 'x', '--file', 'f.json'], /--id und --name/],
    ['add mit unbekanntem Profil', ['add', '--id', 'x', '--name', 'X', '--profile', 'nein', '--file', 'f.json'], /unbekannte Profilvorlage/],
    ['add mit unbrauchbarer TTL', ['add', '--id', 'x', '--name', 'X', '--ttl', '5', '--file', 'f.json'], /requestTtlSeconds/],
    ['add mit ungültiger ID', ['add', '--id', 'Gross', '--name', 'X', '--file', 'f.json'], /"id"/],
    ['revoke ohne --id', ['revoke', '--file', 'f.json'], /--id ist Pflicht/],
    ['revoke ohne Datei', ['revoke', '--id', 'x', '--file', 'f.json'], /existiert nicht/],
  ];
  for (const [titel, argv, muster] of fehler) {
    it(`${titel} -> Code 2`, async () => {
      const argvMitPfad = argv.map((a) => (a === 'f.json' ? join(dir, `fehl-${titel.replace(/\W+/g, '-')}.json`) : a));
      const r = await run(argvMitPfad);
      assert.equal(r.code, 2);
      assert.match(r.err, muster);
    });
  }

  it('revoke mit unbekannter ID scheitert, die Datei bleibt unverändert', async () => {
    const pfad = join(dir, 'unbekannt.json');
    await run(['add', '--id', 'a', '--name', 'A', '--file', pfad]);
    const vorher = await readFile(pfad, 'utf8');
    const r = await run(['revoke', '--id', 'b', '--file', pfad]);
    assert.equal(r.code, 2);
    assert.match(r.err, /nicht vorhanden/);
    assert.equal(await readFile(pfad, 'utf8'), vorher);
  });

  it('eine ungültige Datei wird weder gelesen noch überschrieben', async () => {
    const pfad = join(dir, 'ungueltig.json');
    await writeFile(pfad, JSON.stringify({ version: 1, tenants: [{ id: 'a' }] }));
    const r = await run(['add', '--id', 'b', '--name', 'B', '--file', pfad]);
    assert.equal(r.code, 2);
    assert.match(r.err, /"name"/);
    assert.equal(await readFile(pfad, 'utf8'), JSON.stringify({ version: 1, tenants: [{ id: 'a' }] }));
  });
});
