/**
 * Mandantendatei: Prüfung (fail closed), Schreiben, Anlegen, Sperren und der
 * Dienststart im Produktionsmodus.
 *
 * Der Kern der Zusage wird am Dienst selbst geprüft, nicht nur an den
 * Hilfsfunktionen: Mit NODE_ENV=production und ohne Entwicklungsschalter muss
 * ein Mandant aus der Datei sich mit seinem Schlüssel anmelden können, ein
 * gesperrter nicht, und eine kaputte Datei muss den Start abbrechen.
 */
import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';

import {
  ConfigError,
  ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM,
  ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM,
  ENV_ATTACK_VERIFIER_KEY_PEM,
  ENV_NODE_ENV,
} from '../config.ts';
import { generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { createApp } from './app.ts';
import { bootstrapService } from './bootstrap.ts';
import { hashApiKey, TenantStore } from './tenant.ts';
import {
  addTenantEntry,
  applyTenantFile,
  emptyTenantFile,
  ENV_ATTACK_TENANTS_FILE,
  loadTenantFile,
  parseTenantFile,
  revokeTenantEntry,
  TENANT_FILE_MAX_BYTES,
  writeTenantFile,
  type TenantFile,
} from './tenant-file.ts';

let dir!: string;
let identityEnv!: Record<string, string>;

function derToPem(der: Uint8Array, label: string): string {
  const lines = Buffer.from(der).toString('base64').match(/.{1,64}/g)?.join('\n') ?? '';
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'attack-tenant-file-'));
  const verifier = await generateTestKeyMaterial('Mandantendatei Verifier TEST');
  const issuer = await generateTestKeyMaterial('Mandantendatei Issuer TEST');
  await writeFile(join(dir, 'key.pem'), derToPem(new Uint8Array(await crypto.subtle.exportKey('pkcs8', verifier.privateKey)), 'PRIVATE KEY'));
  await writeFile(join(dir, 'chain.pem'), derToPem(verifier.certDerBytes, 'CERTIFICATE'));
  await writeFile(join(dir, 'anchors.pem'), derToPem(issuer.certDerBytes, 'CERTIFICATE'));
  identityEnv = {
    [ENV_NODE_ENV]: 'production',
    ATTACK_PUBLIC_BASE_URL: 'https://verifier.example',
    [ENV_ATTACK_VERIFIER_KEY_PEM]: join(dir, 'key.pem'),
    [ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]: join(dir, 'chain.pem'),
    [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: join(dir, 'anchors.pem'),
  };
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

function entry(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'kunde-a',
    name: 'Kunde A GmbH',
    apiKeySha256: hashApiKey('schluessel-kunde-a'),
    requestProfile: 'pid_basis',
    requestTtlSeconds: 300,
    status: 'active',
    createdAt: '2026-10-07T10:00:00.000Z',
    ...overrides,
  };
}

function rejects(raw: unknown, pattern: RegExp): void {
  assert.throws(
    () => parseTenantFile(raw, 'TESTDATEI'),
    (e: unknown) => {
      assert.ok(e instanceof ConfigError, `ConfigError erwartet, war ${String(e)}`);
      assert.match(e.message, /^TESTDATEI: /);
      assert.match(e.message, pattern);
      // Der Hash ist kein Geheimnis, gehört aber trotzdem nicht in eine Meldung.
      assert.ok(!e.message.includes(hashApiKey('schluessel-kunde-a')), 'Meldung ohne Hash');
      return true;
    },
  );
}

describe('Mandantendatei: Prüfung fail closed', () => {
  it('eine gültige Datei mit aktivem und gesperrtem Mandanten wird gelesen', () => {
    const file = parseTenantFile(
      {
        version: 1,
        tenants: [
          entry(),
          entry({ id: 'kunde-b', apiKeySha256: hashApiKey('b'), status: 'revoked', revokedAt: '2026-10-07T11:00:00.000Z' }),
          entry({ id: 'kunde-c', apiKeySha256: hashApiKey('c'), requestProfile: { id: 'eigen', claims: ['given_name'] } }),
        ],
      },
      'TESTDATEI',
    );
    assert.equal(file.tenants.length, 3);
    assert.equal(file.tenants[1]?.revokedAt, '2026-10-07T11:00:00.000Z');
  });

  const faelle: Array<[string, unknown, RegExp]> = [
    ['kein Objekt', [], /JSON-Objekt/],
    ['unbekanntes Feld oben', { version: 1, tenants: [], extra: true }, /Unbekanntes Feld "extra"/],
    ['falsche Version', { version: 2, tenants: [] }, /version/],
    ['tenants keine Liste', { version: 1, tenants: {} }, /tenants/],
    ['Eintrag kein Objekt', { version: 1, tenants: ['x'] }, /Eintrag 1 muss ein Objekt/],
    ['unbekanntes Feld im Eintrag', { version: 1, tenants: [entry({ apiKey: 'klartext' })] }, /unbekanntes Feld "apiKey"/],
    ['ID mit Großbuchstaben', { version: 1, tenants: [entry({ id: 'Kunde' })] }, /"id"/],
    ['doppelte ID', { version: 1, tenants: [entry(), entry({ apiKeySha256: hashApiKey('x') })] }, /doppelt/],
    ['leerer Name', { version: 1, tenants: [entry({ name: '  ' })] }, /"name"/],
    ['Name mit Steuerzeichen', { version: 1, tenants: [entry({ name: 'a\nb' })] }, /"name"/],
    ['Hash kein Hex', { version: 1, tenants: [entry({ apiKeySha256: 'klartext-schluessel' })] }, /apiKeySha256/],
    ['Hash in Großbuchstaben', { version: 1, tenants: [entry({ apiKeySha256: hashApiKey('schluessel-kunde-a').toUpperCase() })] }, /apiKeySha256/],
    ['doppelter Hash', { version: 1, tenants: [entry(), entry({ id: 'kunde-b' })] }, /anderen Mandanten/],
    ['unbekannte Profilvorlage', { version: 1, tenants: [entry({ requestProfile: 'gibtsnicht' })] }, /Unbekannte Vorlage/],
    ['Profil als Liste', { version: 1, tenants: [entry({ requestProfile: ['pid_basis'] })] }, /requestProfile/],
    ['TTL zu klein', { version: 1, tenants: [entry({ requestTtlSeconds: 5 })] }, /requestTtlSeconds/],
    ['TTL keine ganze Zahl', { version: 1, tenants: [entry({ requestTtlSeconds: 30.5 })] }, /requestTtlSeconds/],
    ['unbekannter Status', { version: 1, tenants: [entry({ status: 'paused' })] }, /status/],
    ['createdAt kein Zeitpunkt', { version: 1, tenants: [entry({ createdAt: 'gestern' })] }, /createdAt/],
    ['gesperrt ohne revokedAt', { version: 1, tenants: [entry({ status: 'revoked' })] }, /revokedAt/],
    ['aktiv mit revokedAt', { version: 1, tenants: [entry({ revokedAt: '2026-10-07T11:00:00.000Z' })] }, /revokedAt/],
  ];
  for (const [titel, raw, muster] of faelle) {
    it(`${titel} -> ConfigError`, () => rejects(raw, muster));
  }

  it('unlesbare Datei, kaputtes JSON und Übergröße brechen ab', async () => {
    await assert.rejects(loadTenantFile(join(dir, 'gibtsnicht.json')), /Datei nicht lesbar/);
    const kaputt = join(dir, 'kaputt.json');
    await writeFile(kaputt, '{ "version": 1, ');
    await assert.rejects(loadTenantFile(kaputt), /kein gültiges JSON/);
    const gross = join(dir, 'gross.json');
    await writeFile(gross, ' '.repeat(TENANT_FILE_MAX_BYTES + 1));
    await assert.rejects(loadTenantFile(gross), /größer als/);
  });
});

describe('Mandantendatei: anlegen, sperren, schreiben', () => {
  it('add liefert den Klartext nur zurück, in der Datei steht nur der Hash', () => {
    const { file, apiKey } = addTenantEntry(emptyTenantFile(), { id: 'kunde-a', name: 'Kunde A', now: new Date('2026-10-07T10:00:00Z') });
    assert.match(apiKey, /^atk_[A-Za-z0-9_-]{43}$/);
    const text = JSON.stringify(file);
    assert.ok(!text.includes(apiKey), 'Klartext darf nicht in der Datei stehen');
    assert.equal(file.tenants[0]?.apiKeySha256, hashApiKey(apiKey));
    assert.equal(file.tenants[0]?.status, 'active');
    assert.equal(file.tenants[0]?.createdAt, '2026-10-07T10:00:00.000Z');
  });

  it('zwei Schlüssel sind verschieden', () => {
    const a = addTenantEntry(emptyTenantFile(), { id: 'a', name: 'A' });
    const b = addTenantEntry(a.file, { id: 'b', name: 'B' });
    assert.notEqual(a.apiKey, b.apiKey);
  });

  it('eine vergebene ID wird nicht erneut vergeben, auch nicht nach Sperrung', () => {
    const { file } = addTenantEntry(emptyTenantFile(), { id: 'kunde-a', name: 'A' });
    const gesperrt = revokeTenantEntry(file, 'kunde-a').file;
    assert.throws(() => addTenantEntry(gesperrt, { id: 'kunde-a', name: 'A neu' }), /existiert bereits/);
  });

  it('add mit unbrauchbarer TTL wird vor dem Schreiben abgelehnt', () => {
    assert.throws(() => addTenantEntry(emptyTenantFile(), { id: 'a', name: 'A', requestTtlSeconds: Number.NaN }), /requestTtlSeconds/);
  });

  it('revoke sperrt, ist wiederholbar und kennt keine fremden IDs', () => {
    const { file } = addTenantEntry(emptyTenantFile(), { id: 'kunde-a', name: 'A' });
    const erst = revokeTenantEntry(file, 'kunde-a', new Date('2026-10-07T12:00:00Z'));
    assert.equal(erst.alreadyRevoked, false);
    assert.equal(erst.file.tenants[0]?.status, 'revoked');
    assert.equal(erst.file.tenants[0]?.revokedAt, '2026-10-07T12:00:00.000Z');
    assert.equal(revokeTenantEntry(erst.file, 'kunde-a').alreadyRevoked, true);
    assert.throws(() => revokeTenantEntry(file, 'fremd'), /nicht vorhanden/);
  });

  it('write schreibt mit Rechten 0600, ohne Reste, und liest sich zurück', async () => {
    const pfad = join(dir, 'schreiben.json');
    const { file } = addTenantEntry(emptyTenantFile(), { id: 'kunde-a', name: 'A' });
    await writeTenantFile(pfad, file);
    const modus = (await stat(pfad)).mode & 0o777;
    assert.equal(modus, 0o600);
    assert.deepEqual(await loadTenantFile(pfad), file);
    const reste = (await readdir(dir)).filter((n) => n.endsWith('.tmp'));
    assert.deepEqual(reste, []);
  });

  it('write lehnt ungültigen Inhalt ab und lässt die vorhandene Datei unverändert', async () => {
    const pfad = join(dir, 'unveraendert.json');
    const { file } = addTenantEntry(emptyTenantFile(), { id: 'kunde-a', name: 'A' });
    await writeTenantFile(pfad, file);
    const vorher = await readFile(pfad, 'utf8');
    const kaputt = { version: 1, tenants: [{ ...file.tenants[0], apiKeySha256: 'x' }] } as unknown as TenantFile;
    await assert.rejects(writeTenantFile(pfad, kaputt), /apiKeySha256/);
    assert.equal(await readFile(pfad, 'utf8'), vorher);
  });

  it('applyTenantFile lädt nur aktive Mandanten, über den Hash', () => {
    const a = addTenantEntry(emptyTenantFile(), { id: 'kunde-a', name: 'A' });
    const b = addTenantEntry(a.file, { id: 'kunde-b', name: 'B' });
    const file = revokeTenantEntry(b.file, 'kunde-b').file;
    const store = new TenantStore();
    assert.deepEqual(applyTenantFile(store, file), { active: 1, revoked: 1 });
    assert.equal(store.byApiKey(a.apiKey)?.id, 'kunde-a');
    assert.equal(store.byApiKey(b.apiKey), undefined);
  });

  it('applyTenantFile bricht bei Kollision mit einem vorhandenen Mandanten ab', () => {
    const store = new TenantStore();
    store.add({ id: 'kunde-a', name: 'schon da', apiKey: 'vorhandener-schluessel' });
    const { file } = addTenantEntry(emptyTenantFile(), { id: 'kunde-a', name: 'A' });
    assert.throws(() => applyTenantFile(store, file), (e: unknown) => e instanceof ConfigError && /kunde-a/.test(e.message));
  });
});

describe('TenantStore.addHashed', () => {
  it('lehnt einen Hash ab, der kein SHA-256-Hex ist', () => {
    assert.throws(() => new TenantStore().addHashed({ id: 'a', name: 'A', apiKeyHash: 'nicht-hex' }), /SHA-256-Hex/);
  });
  it('lehnt einen Schlüssel ab, der schon einem anderen Mandanten gehört', () => {
    const store = new TenantStore();
    store.add({ id: 'a', name: 'A', apiKey: 'gleicher-schluessel' });
    assert.throws(() => store.add({ id: 'b', name: 'B', apiKey: 'gleicher-schluessel' }), /anderen Mandanten/);
  });
});

describe('Dienststart im Produktionsmodus mit Mandantendatei', () => {
  async function dateiMit(name: string): Promise<{ pfad: string; aktiv: string; gesperrt: string }> {
    const pfad = join(dir, name);
    const a = addTenantEntry(emptyTenantFile(), { id: 'kunde-a', name: 'Kunde A' });
    const b = addTenantEntry(a.file, { id: 'kunde-b', name: 'Kunde B' });
    await writeTenantFile(pfad, revokeTenantEntry(b.file, 'kunde-b').file);
    return { pfad, aktiv: a.apiKey, gesperrt: b.apiKey };
  }

  it('lädt aktive Mandanten ohne Entwicklungsschalter, gesperrte nicht', async () => {
    const { pfad, aktiv, gesperrt } = await dateiMit('start.json');
    const warnungen: string[] = [];
    const boot = await bootstrapService({ ...identityEnv, [ENV_ATTACK_TENANTS_FILE]: pfad }, (m) => warnungen.push(m));
    assert.equal(boot.config.isProduction, true);
    assert.equal(boot.config.devMode, false);
    assert.deepEqual(boot.testTenants, []);
    assert.deepEqual(boot.tenantFile, { active: 1, revoked: 1 });
    assert.equal(boot.tenants.byApiKey(aktiv)?.id, 'kunde-a');
    assert.equal(boot.tenants.byApiKey(gesperrt), undefined);
    assert.ok(warnungen.some((w) => w.startsWith('Mandantendatei: 1 aktiv, 1 gesperrt')));
    assert.ok(!warnungen.some((w) => w.includes(aktiv)), 'Schlüssel nie im Log');
  });

  it('Anmeldung am HTTP-Dienst: aktiver Schlüssel kommt durch, gesperrter und fremder bekommen 401', async () => {
    const { pfad, aktiv, gesperrt } = await dateiMit('http.json');
    const boot = await bootstrapService({ ...identityEnv, [ENV_ATTACK_TENANTS_FILE]: pfad }, () => {});
    const server = createApp({ appLabel: 'tenant-file-test', tenants: boot.tenants, service: boot.service });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    boot.service.baseUrl = `http://127.0.0.1:${port}`;
    const status = (key: string) =>
      new Promise<number>((resolve, reject) => {
        const req = http.request(
          { host: '127.0.0.1', port, path: '/v1/verification-requests/unbekannt', method: 'GET', headers: { authorization: `Bearer ${key}` } },
          (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
          },
        );
        req.on('error', reject);
        req.end();
      });
    try {
      // Unbekannte Sitzung: 404 heißt, die Anmeldung war erfolgreich.
      assert.equal(await status(aktiv), 404);
      assert.equal(await status(gesperrt), 401);
      assert.equal(await status('atk_fremd'), 401);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('kaputte Datei bricht den Start ab', async () => {
    const pfad = join(dir, 'start-kaputt.json');
    await writeFile(pfad, JSON.stringify({ version: 1, tenants: [entry({ status: 'paused' })] }));
    await assert.rejects(bootstrapService({ ...identityEnv, [ENV_ATTACK_TENANTS_FILE]: pfad }, () => {}), (e: unknown) => {
      assert.ok(e instanceof ConfigError);
      assert.match(e.message, /status/);
      assert.match(e.message, /Start abgebrochen/);
      return true;
    });
  });

  it('gesetzte, aber fehlende Datei bricht den Start ab', async () => {
    await assert.rejects(
      bootstrapService({ ...identityEnv, [ENV_ATTACK_TENANTS_FILE]: join(dir, 'fehlt.json') }, () => {}),
      /ATTACK_TENANTS_FILE: Datei nicht lesbar.*Start abgebrochen/,
    );
  });

  it('ohne Datei startet der Dienst, meldet aber laut, dass er keine Mandanten hat', async () => {
    const warnungen: string[] = [];
    const boot = await bootstrapService({ ...identityEnv }, (m) => warnungen.push(m));
    assert.equal(boot.tenants.list().length, 0);
    assert.equal(boot.tenantFile, undefined);
    assert.ok(warnungen.some((w) => w.includes('Keine Mandantendatei konfiguriert') && w.includes('401')));
  });
});
