/**
 * Tests für die zentrale Konfiguration (src/config.ts).
 * Deckt alle Kombinationen des Produktionsschalters ab (fail closed):
 * Entwicklungsschalter und selbstsignierte Zertifikate sind in Produktion
 * verboten; ohne Explizit-Setzung bleibt alles aus.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'vitest';

import {
  ConfigError,
  DEFAULT_RATE_LIMIT_PUBLIC,
  DEFAULT_RATE_LIMIT_TENANT,
  DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
  ENV_ATTACK_ALLOW_SELF_SIGNED,
  ENV_ATTACK_DEV_MODE,
  ENV_ATTACK_RATE_LIMIT_PUBLIC,
  ENV_ATTACK_RATE_LIMIT_TENANT,
  ENV_ATTACK_RATE_LIMIT_WINDOW,
  ENV_NODE_ENV,
  ENV_PORT,
  loadConfig,
} from '../config.ts';

describe('loadConfig – Defaults (leere Umgebung)', () => {
  it('schaltet nichts ein und nutzt den übergebenen Default-Port', () => {
    const c = loadConfig({}, 8080);
    assert.equal(c.isProduction, false);
    assert.equal(c.devMode, false);
    assert.equal(c.allowSelfSignedCertificate, false);
    assert.equal(c.nodeEnv, 'development');
    assert.equal(c.port, 8080);
  });

  it('Default-Port 8080 für den Dienst, 3000 für die Demo', () => {
    assert.equal(loadConfig({}).port, 8080);
    assert.equal(loadConfig({}, 3000).port, 3000);
  });

  it('PORT liest eine gültige ganze Zahl', () => {
    assert.equal(loadConfig({ [ENV_PORT]: '9443' }).port, 9443);
  });

  it('PORT außerhalb 1..65535 bricht ab', () => {
    assert.throws(() => loadConfig({ [ENV_PORT]: '0' }), ConfigError);
    assert.throws(() => loadConfig({ [ENV_PORT]: '-1' }), ConfigError);
    assert.throws(() => loadConfig({ [ENV_PORT]: '65536' }), ConfigError);
    assert.throws(() => loadConfig({ [ENV_PORT]: 'abc' }), ConfigError);
  });
});

describe('loadConfig – Produktionserkennung', () => {
  it('NODE_ENV=production aktiviert isProduction', () => {
    const c = loadConfig({ [ENV_NODE_ENV]: 'production' });
    assert.equal(c.isProduction, true);
    assert.equal(c.devMode, false);
    assert.equal(c.allowSelfSignedCertificate, false);
  });
});

describe('loadConfig – Entwicklungsschalter', () => {
  it('ATTACK_DEV_MODE=true außerhalb Produktion wird akzeptiert', () => {
    const c = loadConfig({ [ENV_ATTACK_DEV_MODE]: 'true' });
    assert.equal(c.devMode, true);
    assert.equal(c.isProduction, false);
  });

  it('ATTACK_DEV_MODE=true in Produktion bricht ab', () => {
    assert.throws(
      () => loadConfig({ [ENV_NODE_ENV]: 'production', [ENV_ATTACK_DEV_MODE]: 'true' }),
      ConfigError,
    );
  });
});

describe('loadConfig – selbstsignierte Zertifikate', () => {
  it('ATTACK_ALLOW_SELF_SIGNED=true mit Entwicklungsschalter außerhalb Produktion wird akzeptiert', () => {
    const c = loadConfig({ [ENV_ATTACK_ALLOW_SELF_SIGNED]: 'true', [ENV_ATTACK_DEV_MODE]: 'true' });
    assert.equal(c.allowSelfSignedCertificate, true);
  });

  it('ATTACK_ALLOW_SELF_SIGNED=true ohne Entwicklungsschalter bricht ab (Haertung 4)', () => {
    assert.throws(() => loadConfig({ [ENV_ATTACK_ALLOW_SELF_SIGNED]: 'true' }), ConfigError);
  });

  it('ATTACK_ALLOW_SELF_SIGNED=true in Produktion bricht ab', () => {
    assert.throws(
      () => loadConfig({ [ENV_NODE_ENV]: 'production', [ENV_ATTACK_ALLOW_SELF_SIGNED]: 'true' }),
      ConfigError,
    );
  });

  it('jeder Wert außer exakt "true" bleibt aus', () => {
    for (const v of ['1', 'yes', 'TRUE', '', undefined]) {
      const c = loadConfig({ [ENV_ATTACK_ALLOW_SELF_SIGNED]: v });
      assert.equal(c.allowSelfSignedCertificate, false, `Wert ${JSON.stringify(v)} muss aus bleiben`);
    }
  });
});

describe('loadConfig – Ratenbegrenzung', () => {
  it('ohne Variablen gelten die bisher fest verdrahteten Werte', () => {
    const config = loadConfig({}, 8080);
    // Die Voreinstellung darf sich nicht unbemerkt ändern: sie ist in
    // docs/fehlercodes.md und docs/lasttest.md als Vertrag genannt.
    assert.deepEqual(config.rateLimits, {
      publicPerWindow: 120,
      tenantPerWindow: 60,
      windowSeconds: 60,
    });
    assert.equal(DEFAULT_RATE_LIMIT_PUBLIC, 120);
    assert.equal(DEFAULT_RATE_LIMIT_TENANT, 60);
    assert.equal(DEFAULT_RATE_LIMIT_WINDOW_SECONDS, 60);
  });

  it('jede Grenze ist einzeln über die Umgebung stellbar', () => {
    const config = loadConfig(
      {
        [ENV_ATTACK_RATE_LIMIT_PUBLIC]: '5000',
        [ENV_ATTACK_RATE_LIMIT_TENANT]: '3000',
        [ENV_ATTACK_RATE_LIMIT_WINDOW]: '10',
      },
      8080,
    );
    assert.deepEqual(config.rateLimits, { publicPerWindow: 5000, tenantPerWindow: 3000, windowSeconds: 10 });
  });

  it('ein Leerwert ist wie nicht gesetzt, kein Fehler', () => {
    const config = loadConfig({ [ENV_ATTACK_RATE_LIMIT_TENANT]: '' }, 8080);
    assert.equal(config.rateLimits.tenantPerWindow, 60);
  });

  it('ein unbrauchbarer Wert bricht den Start ab, statt still zu fallen', () => {
    // Fail closed wie bei den übrigen Schaltern: ein Tippfehler darf nicht dazu
    // führen, dass der Dienst unbegrenzt Anfragen annimmt.
    //
    // "1e3" steht hier bewusst nicht auf der Liste: Number("1e3") ergibt 1000,
    // ein gültiger Ganzzahlwert im Bereich. Die Variablen werden genauso
    // gelesen wie PORT und ATTACK_RESULT_TTL_SECONDS, und eine Sonderbehandlung
    // nur für diese drei wäre eine Inkonsistenz ohne Gewinn.
    for (const wert of ['0', '-1', '1,5', 'abc', ' ']) {
      assert.throws(
        () => loadConfig({ [ENV_ATTACK_RATE_LIMIT_TENANT]: wert }, 8080),
        (e: unknown) => e instanceof ConfigError && e.message.includes(ENV_ATTACK_RATE_LIMIT_TENANT),
        `Wert ${JSON.stringify(wert)} muss den Start abbrechen`,
      );
    }
  });

  it('die Obergrenze ist eine Fehlkonfigurationsbremse, kein Schutz', () => {
    assert.throws(() => loadConfig({ [ENV_ATTACK_RATE_LIMIT_TENANT]: '1000001' }, 8080), ConfigError);
    assert.equal(loadConfig({ [ENV_ATTACK_RATE_LIMIT_TENANT]: '1000000' }, 8080).rateLimits.tenantPerWindow, 1_000_000);
  });

  it('das Fenster wird begrenzt, damit eine Einstellung nicht sinnlos wird', () => {
    assert.throws(() => loadConfig({ [ENV_ATTACK_RATE_LIMIT_WINDOW]: '0' }, 8080), ConfigError);
    assert.throws(() => loadConfig({ [ENV_ATTACK_RATE_LIMIT_WINDOW]: '3601' }, 8080), ConfigError);
  });

  it('die Fehlermeldung nennt die Variable und die Grenzen, aber keinen Wert', () => {
    try {
      loadConfig({ [ENV_ATTACK_RATE_LIMIT_PUBLIC]: 'nope' }, 8080);
      assert.fail('muss abbrechen');
    } catch (e) {
      const msg = (e as Error).message;
      assert.ok(msg.includes(ENV_ATTACK_RATE_LIMIT_PUBLIC));
      assert.ok(msg.includes('1') && msg.includes('1000000'));
    }
  });
});
