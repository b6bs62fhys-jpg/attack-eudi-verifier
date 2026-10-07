import assert from 'node:assert/strict';
import { describe, it } from 'vitest';

import { createApp } from './app.ts';
import { loadConfig, ENV_ATTACK_RATE_LIMIT_TENANT, ENV_ATTACK_RATE_LIMIT_WINDOW } from '../config.ts';
import { RateLimiter } from './rate-limit.ts';
import { TenantStore } from './tenant.ts';

describe('RateLimiter', () => {
  it('rejects at the limit and resets at the next window', () => {
    let now = 1_000;
    const limiter = new RateLimiter({ windowMs: 1_000, now: () => now });
    assert.equal(limiter.consume('client-a', 2).allowed, true);
    assert.equal(limiter.consume('client-a', 2).allowed, true);
    const rejected = limiter.consume('client-a', 2);
    assert.equal(rejected.allowed, false);
    assert.equal(rejected.remaining, 0);
    assert.equal(rejected.retryAfterSeconds, 1);
    now = 2_000;
    assert.equal(limiter.consume('client-a', 2).allowed, true);
  });

  it('keeps distributed client identities independent', () => {
    const limiter = new RateLimiter({ windowMs: 60_000, now: () => 1_000 });
    assert.equal(limiter.consume('api:tenant-a', 1).allowed, true);
    assert.equal(limiter.consume('api:tenant-a', 1).allowed, false);
    assert.equal(limiter.consume('api:tenant-b', 1).allowed, true);
    assert.equal(limiter.consume('ip:192.0.2.10', 1).allowed, true);
  });

  it('protects the public direct_post endpoint and resets the window', async () => {
    let now = 1_000;
    const limiter = new RateLimiter({ windowMs: 1_000, now: () => now });
    const server = createApp({
      appLabel: 'rate-test',
      tenants: new TenantStore(),
      service: {} as never,
      rateLimiter: limiter,
      rateLimits: { publicPerWindow: 2 },
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;
    try {
      const request = () => fetch(`http://127.0.0.1:${port}/direct_post`, { method: 'POST', body: '{}' });
      assert.equal((await request()).status, 400);
      assert.equal((await request()).status, 400);
      const limited = await request();
      assert.equal(limited.status, 429);
      assert.equal(limited.headers.get('retry-after'), '1');
      now = 2_000;
      assert.equal((await request()).status, 400);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});


/**
 * Die Verdrahtung von der Umgebung bis zum laufenden Dienst. Ohne diesen
 * Abschnitt wäre offen, ob die Konfiguration nur in loadConfig landet oder
 * tatsächlich das Verhalten ändert — das ist der Fehler, den ein
 * Konfigurationsfeature am häufigsten hat.
 */
describe('Rate-Limit aus der Umgebung', () => {
  it('die eingestellte Mandantengrenze wirkt auf die echte Route', async () => {
    const config = loadConfig(
      { [ENV_ATTACK_RATE_LIMIT_TENANT]: '3', [ENV_ATTACK_RATE_LIMIT_WINDOW]: '60' },
      8080,
    );
    assert.equal(config.rateLimits.tenantPerWindow, 3);

    const tenants = new TenantStore();
    tenants.add({ id: 't', name: 'Kunde T (TEST)', apiKey: 'rate-env-test-key' });
    const limiter = new RateLimiter({ windowMs: config.rateLimits.windowSeconds * 1000 });
    const server = createApp({
      appLabel: 'rate-env-test',
      tenants,
      // Der Handler wird gar nicht erreicht: die Begrenzung greift davor. Das
      // ist beabsichtigt, sonst müsste hier ein vollständiger Dienst stehen.
      service: {} as never,
      rateLimiter: limiter,
      rateLimits: config.rateLimits,
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    try {
      const status: number[] = [];
      let limitHeader: string | null = null;
      for (let i = 0; i < 4; i += 1) {
        const res = await fetch(`${base}/v1/verification-requests/irgendwas`, {
          headers: { authorization: 'Bearer rate-env-test-key' },
        });
        await res.arrayBuffer();
        status.push(res.status);
        if (res.status === 429) limitHeader = res.headers.get('x-ratelimit-limit');
      }
      // Die ersten drei passieren die Grenze (und scheitern danach im leeren
      // Handler), die vierte wird abgewiesen. Genau das ist der Nachweis, dass
      // die Umgebung am laufenden Dienst ankommt.
      assert.equal(limitHeader, '3', 'die Antwort muss den eingestellten Wert nennen');
      assert.equal(status[3], 429, `die vierte Anfrage muss greifen, war ${status.join(',')}`);
    } finally {
      await new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      });
    }
  });

  it('ohne eingestellte Werte gilt weiterhin 60, nicht der Testwert', async () => {
    // Gegenprobe: die Voreinstellung darf nicht durch das Verdrahten von
    // rateLimits versehentlich wegfallen.
    const config = loadConfig({}, 8080);
    const tenants = new TenantStore();
    tenants.add({ id: 't', name: 'Kunde T (TEST)', apiKey: 'rate-default-test-key' });
    const limiter = new RateLimiter({ windowMs: config.rateLimits.windowSeconds * 1000 });
    const server = createApp({
      appLabel: 'rate-default-test',
      tenants,
      service: {} as never,
      rateLimiter: limiter,
      rateLimits: config.rateLimits,
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    try {
      let gesperrtBeimAufruf: number | null = null;
      for (let i = 1; i <= 61; i += 1) {
        const res = await fetch(`${base}/v1/verification-requests/x`, { headers: { authorization: 'Bearer rate-default-test-key' } });
        await res.arrayBuffer();
        if (res.status === 429) {
          gesperrtBeimAufruf = i;
          break;
        }
      }
      assert.equal(gesperrtBeimAufruf, 61, 'der 61. Aufruf muss greifen (60 erlaubt)');
    } finally {
      await new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      });
    }
  });

  it('das Fenster aus der Umgebung bestimmt die Dauer der Sperre', async () => {
    let now = 0;
    const config = loadConfig({ [ENV_ATTACK_RATE_LIMIT_WINDOW]: '5' }, 8080);
    assert.equal(config.rateLimits.windowSeconds, 5);
    const limiter = new RateLimiter({ windowMs: config.rateLimits.windowSeconds * 1000, now: () => now });
    limiter.consume('k', 1);
    assert.equal(limiter.consume('k', 1).allowed, false);
    now = 4_999;
    assert.equal(limiter.consume('k', 1).allowed, false, 'vor Fensterende weiterhin gesperrt');
    now = 5_000;
    assert.equal(limiter.consume('k', 1).allowed, true, 'nach Fensterende wieder frei');
  });
});
