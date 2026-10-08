/**
 * Paket 6 b): X-Forwarded-For nur von vertrauenswürdigen Proxys.
 *
 * Einheitentests für die Auflösung und Konfiguration, danach echtes HTTP gegen
 * die Ratenbegrenzung der öffentlichen Route /direct_post mit einem Header, den
 * ein Client von außen mitschickt.
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import { describe, it } from 'vitest';
import 'reflect-metadata';

import { ConfigError } from '../config.ts';
import { bootstrapService } from '../service/bootstrap.ts';
import { RateLimiter } from '../service/rate-limit.ts';
import { createApp } from '../service/app.ts';
import { TenantStore } from '../service/tenant.ts';
import { normalizeAddress, parseTrustedProxies, resolveClientAddress } from './client-ip.ts';

const trust = (raw: string) => parseTrustedProxies(raw);

describe('parseTrustedProxies', () => {
  it('nicht gesetzt oder leer: keine Liste', () => {
    assert.equal(parseTrustedProxies(undefined), undefined);
    assert.equal(parseTrustedProxies('  '), undefined);
  });

  it('Adressen und Netze, IPv4 und IPv6, mit Leerzeichen', () => {
    const t = trust(' 127.0.0.1, 10.0.0.0/8 ,::1, 2001:db8::/32 ');
    assert.deepEqual(t?.entries, ['127.0.0.1', '10.0.0.0/8', '::1', '2001:db8::/32']);
    assert.equal(t?.contains('127.0.0.1'), true);
    assert.equal(t?.contains('10.20.30.40'), true);
    assert.equal(t?.contains('11.0.0.1'), false);
    assert.equal(t?.contains('::1'), true);
    assert.equal(t?.contains('2001:db8:1::5'), true);
    assert.equal(t?.contains('2001:db9::1'), false);
    assert.equal(t?.contains('kein-ip'), false);
  });

  it('IPv4 in IPv6-Schreibweise (::ffff:) zählt als dieselbe Adresse', () => {
    assert.equal(normalizeAddress('::ffff:127.0.0.1'), '127.0.0.1');
    assert.equal(trust('127.0.0.1')?.contains('::ffff:127.0.0.1'), true);
    assert.equal(trust('10.0.0.0/8')?.contains('::ffff:10.1.2.3'), true);
  });

  for (const [titel, wert, muster] of [
    ['kein IP-Wert', 'proxy.example', /weder eine IP-Adresse/],
    ['leerer Eintrag in der Liste', '127.0.0.1,,10.0.0.1', /weder eine IP-Adresse/],
    ['Präfix zu groß (IPv4)', '10.0.0.0/33', /zwischen 0 und 32/],
    ['Präfix zu groß (IPv6)', '::1/129', /zwischen 0 und 128/],
    ['Präfix keine Zahl', '10.0.0.0/acht', /zwischen 0 und 32/],
    ['negatives Präfix', '10.0.0.0/-1', /zwischen 0 und 32/],
    ['zwei Schrägstriche', '10.0.0.0/8/9', /weder eine IP-Adresse/],
    ['alles vertrauen, IPv4', '0.0.0.0/0', /jeder Adresse vertrauen/],
    ['alles vertrauen, IPv6', '::/0', /jeder Adresse vertrauen/],
  ] as const) {
    it(`${titel} -> ConfigError mit Start abgebrochen`, () => {
      assert.throws(() => trust(wert), (e: unknown) => e instanceof ConfigError && muster.test(e.message) && /Start abgebrochen/.test(e.message) && e.message.startsWith('ATTACK_TRUSTED_PROXIES'));
    });
  }
});

describe('resolveClientAddress', () => {
  const t = trust('10.0.0.0/8,127.0.0.1');

  it('ohne Liste zählt immer die Gegenstelle, der Header wird ignoriert', () => {
    assert.equal(resolveClientAddress('203.0.113.9', '198.51.100.1', undefined), '203.0.113.9');
  });

  it('Gegenstelle nicht vertraut: gefälschter Header wird ignoriert', () => {
    assert.equal(resolveClientAddress('203.0.113.9', '198.51.100.1', t), '203.0.113.9');
    assert.equal(resolveClientAddress('203.0.113.9', '10.0.0.5', t), '203.0.113.9');
  });

  it('Gegenstelle vertraut: letzter Eintrag, der kein Proxy ist', () => {
    assert.equal(resolveClientAddress('10.0.0.2', '198.51.100.1', t), '198.51.100.1');
    assert.equal(resolveClientAddress('127.0.0.1', '198.51.100.1', t), '198.51.100.1');
  });

  it('mehrere Proxys: von rechts, eigene Proxys werden übersprungen', () => {
    assert.equal(resolveClientAddress('10.0.0.2', '198.51.100.1, 10.0.0.9', t), '198.51.100.1');
    assert.equal(resolveClientAddress('10.0.0.2', '198.51.100.1,10.0.0.9,10.0.0.8', t), '198.51.100.1');
  });

  it('vom Client vorangestellte Fälschung wird nie verwendet', () => {
    // Der Client schickt "X-Forwarded-For: 1.1.1.1", der Proxy hängt die echte Adresse an.
    assert.equal(resolveClientAddress('10.0.0.2', '1.1.1.1, 198.51.100.7', t), '198.51.100.7');
    assert.equal(resolveClientAddress('10.0.0.2', '6.6.6.6, 1.1.1.1, 198.51.100.7, 10.0.0.9', t), '198.51.100.7');
  });

  it('Header fehlt, leer oder alle Einträge sind Proxys: Gegenstelle', () => {
    assert.equal(resolveClientAddress('10.0.0.2', undefined, t), '10.0.0.2');
    assert.equal(resolveClientAddress('10.0.0.2', '', t), '10.0.0.2');
    assert.equal(resolveClientAddress('10.0.0.2', '10.0.0.3, 10.0.0.4', t), '10.0.0.2');
  });

  it('unbrauchbarer Header: Gegenstelle (fail closed)', () => {
    for (const header of ['kein-ip', '198.51.100.1, kein-ip', '198.51.100.1:4711', ',,', '198.51.100.1,', 'x'.repeat(2000), Array.from({ length: 25 }, () => '198.51.100.1').join(',')]) {
      assert.equal(resolveClientAddress('10.0.0.2', header, t), '10.0.0.2', header.slice(0, 30));
    }
  });

  it('IPv6-Client und ::ffff:-Gegenstelle', () => {
    assert.equal(resolveClientAddress('::ffff:10.0.0.2', '2001:db8::7', t), '2001:db8::7');
    assert.equal(resolveClientAddress('::ffff:203.0.113.9', '198.51.100.1', t), '203.0.113.9');
  });

  it('keine Gegenstelle bekannt: unknown', () => {
    assert.equal(resolveClientAddress(undefined, '198.51.100.1', t), 'unknown');
  });
});

describe('Ratenbegrenzung über HTTP mit X-Forwarded-For', () => {
  async function run(trustedProxies: string | undefined, scenario: (post: (forwarded?: string) => Promise<number>) => Promise<void>): Promise<void> {
    const server = createApp({
      appLabel: 'proxy-test',
      tenants: new TenantStore(),
      service: {} as never,
      rateLimiter: new RateLimiter({ windowMs: 60_000 }),
      rateLimits: { publicPerWindow: 2 },
      ...(trustedProxies ? { trustedProxies: trust(trustedProxies) } : {}),
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;
    // Die Gegenstelle ist in diesem Test immer 127.0.0.1.
    const post = (forwarded?: string) =>
      new Promise<number>((resolve, reject) => {
        const req = http.request(
          { host: '127.0.0.1', port, path: '/direct_post', method: 'POST', headers: { 'content-length': '2', ...(forwarded ? { 'x-forwarded-for': forwarded } : {}) } },
          (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
          },
        );
        req.on('error', reject);
        req.end('{}');
      });
    try {
      await scenario(post);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }

  it('ohne Liste: alle Wallets teilen sich die Gegenstelle, ein Header ändert nichts', async () => {
    await run(undefined, async (post) => {
      assert.equal(await post('198.51.100.1'), 400);
      assert.equal(await post('198.51.100.2'), 400);
      assert.equal(await post('198.51.100.3'), 429, 'dritte Anfrage trotz anderer Header-Adresse begrenzt');
    });
  });

  it('Gegenstelle nicht in der Liste: gefälschter Header umgeht die Begrenzung nicht', async () => {
    await run('10.0.0.0/8', async (post) => {
      assert.equal(await post('198.51.100.1'), 400);
      assert.equal(await post('198.51.100.2'), 400);
      assert.equal(await post('198.51.100.3'), 429);
      assert.equal(await post('198.51.100.4'), 429);
    });
  });

  it('Gegenstelle in der Liste: jede Wallet bekommt ihr eigenes Budget', async () => {
    await run('127.0.0.1', async (post) => {
      assert.equal(await post('198.51.100.1'), 400);
      assert.equal(await post('198.51.100.1'), 400);
      assert.equal(await post('198.51.100.1'), 429, 'dieselbe Wallet ist begrenzt');
      assert.equal(await post('198.51.100.2'), 400, 'eine andere Wallet nicht');
      assert.equal(await post('198.51.100.2'), 400);
      assert.equal(await post('198.51.100.2'), 429);
    });
  });

  it('Gegenstelle in der Liste: vorangestellte Fälschung des Clients bringt kein frisches Budget', async () => {
    await run('127.0.0.1', async (post) => {
      // Der Proxy hängt die echte Adresse rechts an; links steht, was der Client behauptet.
      assert.equal(await post('9.9.9.1, 198.51.100.7'), 400);
      assert.equal(await post('9.9.9.2, 198.51.100.7'), 400);
      assert.equal(await post('9.9.9.3, 198.51.100.7'), 429);
    });
  });

  it('Gegenstelle in der Liste, aber kein Header: Gegenstelle zählt', async () => {
    await run('127.0.0.1', async (post) => {
      assert.equal(await post(), 400);
      assert.equal(await post(), 400);
      assert.equal(await post(), 429);
    });
  });
});

describe('Dienststart mit ATTACK_TRUSTED_PROXIES', () => {
  it('gültige Liste wird übernommen und laut gemeldet', async () => {
    const warnings: string[] = [];
    const boot = await bootstrapService({ ATTACK_DEV_MODE: 'true', ATTACK_TRUSTED_PROXIES: '172.28.0.0/24' }, (m) => warnings.push(m));
    assert.deepEqual(boot.trustedProxies?.entries, ['172.28.0.0/24']);
    assert.ok(warnings.some((w) => w.startsWith('Vertrauenswürdige Proxys: 172.28.0.0/24')));
  });

  it('ohne die Variable: keine Liste, keine Meldung', async () => {
    const warnings: string[] = [];
    const boot = await bootstrapService({ ATTACK_DEV_MODE: 'true' }, (m) => warnings.push(m));
    assert.equal(boot.trustedProxies, undefined);
    assert.ok(!warnings.some((w) => w.includes('Vertrauenswürdige Proxys')));
  });

  it('ungültiger Eintrag bricht den Start ab', async () => {
    await assert.rejects(bootstrapService({ ATTACK_DEV_MODE: 'true', ATTACK_TRUSTED_PROXIES: '0.0.0.0/0' }, () => {}), (e: unknown) => e instanceof ConfigError);
  });
});
