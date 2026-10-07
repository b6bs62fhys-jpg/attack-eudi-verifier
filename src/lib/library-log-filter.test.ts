/**
 * Logfilter der Prüfbibliothek (`src/lib/library-log-filter.ts`).
 *
 * Zwei Eigenschaften sind zu beweisen:
 *   1. Zeilen mit dem Präfix `[openid4vp]` werden unterdrückt.
 *   2. Alle anderen Warnungen kommen unverändert durch — insbesondere die
 *      eigenen Dev-Modus-Warnungen aus `src/config.ts`, die im Betrieb
 *      sichtbar sein müssen.
 *
 * Der Test arbeitet mit einer eigenen Console-Attrappe, damit weder der
 * Testbericht noch andere Tests etwas mitbekommen. Die
 * Produktionsinstallation in `src/service/run.ts` wird zusätzlich geprüft.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'vitest';

import { announceDevMode, announceSelfSignedCertificate, type AppConfig } from '../config.ts';
import { installLibraryLogFilter, LIBRARY_WARN_PREFIX } from './library-log-filter.ts';

/** Eigene Console-Attrappe, die nur `warn` auffängt. */
function fakeConsole(): { console: Console; lines: string[][]; logs: string[]; errors: string[] } {
  const lines: string[][] = [];
  const logs: string[] = [];
  const errors: string[] = [];
  const target = {
    warn: (...args: unknown[]) => {
      lines.push(args.map(String));
    },
    log: (...args: unknown[]) => {
      logs.push(args.map(String).join(' '));
    },
    error: (...args: unknown[]) => {
      errors.push(args.map(String).join(' '));
    },
  } as unknown as Console;
  return { console: target, lines, logs, errors };
}

const DEV_CONFIG = { devMode: true, isProduction: false, allowSelfSignedCertificate: true } as AppConfig;
const PROD_CONFIG = { devMode: false, isProduction: true, allowSelfSignedCertificate: false } as AppConfig;

describe('Logfilter: Unterdrückung der Bibliothekswarnungen', () => {
  it('eine Zeile mit dem Präfix [openid4vp] wird unterdrückt', () => {
    const { console: target, lines } = fakeConsole();
    const restore = installLibraryLogFilter(target);
    target.warn(`${LIBRARY_WARN_PREFIX} OCSP check failed for CN=Max Mustermann GmbH, C=DE via https://ocsp.example/ocsp, falling back to CRL: timeout`);
    assert.deepEqual(lines, [], 'die Bibliothekszeile darf nicht ankommen');
    restore();
  });

  it('die realistische Meldung mit Seriennummer bleibt ebenfalls unterdrückt', () => {
    const { console: target, lines } = fakeConsole();
    const restore = installLibraryLogFilter(target);
    target.warn(`${LIBRARY_WARN_PREFIX} OCSP response does not contain an entry for subject serial 4A1F2C00D3`);
    assert.deepEqual(lines, []);
    restore();
  });

  it('mehrere Bibliothekszeilen hintereinander werden alle unterdrückt', () => {
    const { console: target, lines } = fakeConsole();
    const restore = installLibraryLogFilter(target);
    target.warn(`${LIBRARY_WARN_PREFIX} OCSP check failed ...`);
    target.warn(`${LIBRARY_WARN_PREFIX} CRL check failed ...`);
    target.warn(`${LIBRARY_WARN_PREFIX} provenance lookup failed ...`);
    assert.deepEqual(lines, []);
    restore();
  });
});

describe('Logfilter: eigene Warnungen kommen durch', () => {
  it('eine eigene Warnung wird unverändert ausgegeben', () => {
    const { console: target, lines } = fakeConsole();
    const restore = installLibraryLogFilter(target);
    target.warn('!!! WARNUNG: ATTACK_DEV_MODE=true ist AKTIV !!!');
    assert.deepEqual(lines, [['!!! WARNUNG: ATTACK_DEV_MODE=true ist AKTIV !!!']]);
    restore();
  });

  it('alle Argumente einer eigenen Warnung bleiben erhalten', () => {
    const { console: target, lines } = fakeConsole();
    const restore = installLibraryLogFilter(target);
    target.warn('Wert:', 42, { a: 1 });
    assert.deepEqual(lines, [['Wert:', '42', '[object Object]']]);
    restore();
  });

  it('eine Meldung, die das Präfix nur enthält, nicht beginnt, kommt durch', () => {
    const { console: target, lines } = fakeConsole();
    const restore = installLibraryLogFilter(target);
    target.warn(`eigene Meldung mit ${LIBRARY_WARN_PREFIX} im Text`);
    assert.equal(lines.length, 1, 'Prüfung ist ein Präfix-, kein Inhaltsvergleich');
    restore();
  });

  it('ein nicht-stringförmiges erstes Argument kommt durch', () => {
    const { console: target, lines } = fakeConsole();
    const restore = installLibraryLogFilter(target);
    target.warn({ code: 'x' });
    assert.equal(lines.length, 1);
    restore();
  });

  it('die Dev-Modus-Warnungen aus config.ts erreichen das Log weiterhin', () => {
    const { console: target, lines } = fakeConsole();
    const restore = installLibraryLogFilter(target);
    announceDevMode(DEV_CONFIG, target.warn);
    announceSelfSignedCertificate(DEV_CONFIG, target.warn);
    restore();

    const texte = lines.map((zeile) => zeile.join(' '));
    // announceDevMode: 4 Zeilen, announceSelfSignedCertificate: 3 Zeilen.
    assert.equal(texte.length, 7, `erwartet 7 eigene Warnungen, war ${JSON.stringify(texte)}`);
    assert.ok(texte.every((t) => t.startsWith('!!!')), 'nur eigene Warnungen, keine Bibliothekszeile');
    assert.ok(texte.some((t) => t.includes('ATTACK_DEV_MODE')));
    assert.ok(texte.some((t) => t.includes('ATTACK_ALLOW_SELF_SIGNED')));
    assert.equal(texte.some((t) => t.startsWith(LIBRARY_WARN_PREFIX)), false);
  });

  it('im Produktivmodus gibt es keine eigene Warnung (Gegenprobe)', () => {
    const { console: target, lines } = fakeConsole();
    const restore = installLibraryLogFilter(target);
    announceDevMode(PROD_CONFIG, target.warn);
    announceSelfSignedCertificate(PROD_CONFIG, target.warn);
    restore();
    assert.deepEqual(lines, []);
  });
});

describe('Logfilter: Eingriffsbreite', () => {
  it('console.error und console.log werden nicht verändert', () => {
    const { console: target, logs, errors } = fakeConsole();
    const restore = installLibraryLogFilter(target);
    target.error('Fehler bleibt sichtbar');
    target.log('Log bleibt sichtbar');
    restore();
    assert.deepEqual(errors, ['Fehler bleibt sichtbar']);
    assert.deepEqual(logs, ['Log bleibt sichtbar']);
  });

  it('restore stellt den ursprünglichen Zustand wieder her', () => {
    const { console: target, lines } = fakeConsole();
    const original = target.warn;
    const restore = installLibraryLogFilter(target);
    assert.notEqual(target.warn, original, 'der Filter muss console.warn ersetzen');
    restore();
    assert.equal(target.warn, original);
    target.warn(`${LIBRARY_WARN_PREFIX} nach dem Restore sichtbar`);
    assert.equal(lines.length, 1);
  });

  it('zweites Installieren umhüllt nicht erneut, liefert aber die echte Restore-Funktion', () => {
    const { console: target, lines } = fakeConsole();
    const restoreErste = installLibraryLogFilter(target);
    const nachErsterInstallation = target.warn;
    const restoreZweite = installLibraryLogFilter(target);
    assert.equal(target.warn, nachErsterInstallation, 'kein zweiter Wrapper');
    target.warn(`${LIBRARY_WARN_PREFIX} unterdrückt`);
    assert.deepEqual(lines, []);
    // B12-Nebenlücke behoben: die zweite Rückgabe ist keine No-op-Funktion,
    // sondern die laufende Restore-Funktion.
    restoreZweite();
    assert.notEqual(target.warn, nachErsterInstallation, 'die zweite Rückgabe muss zurücksetzen');
    restoreErste(); // idempotent, darf nichts überschreiben
  });

  it('B12: vergessenes restore() blockiert ein späteres install() nicht', () => {
    const { console: target, lines } = fakeConsole();
    installLibraryLogFilter(target); // Rückgabe absichtlich ignoriert (Absturzfall)
    const restoreZweite = installLibraryLogFilter(target);

    target.warn(`${LIBRARY_WARN_PREFIX} unterdrückt`);
    assert.deepEqual(lines, [], 'der zweite Versuch filtert wieder');

    restoreZweite();
    target.warn(`${LIBRARY_WARN_PREFIX} nach restore sichtbar`);
    assert.equal(lines.length, 1, 'Filter muss wieder abschaltbar sein');
    const erste: string = lines.flat().join(' ');
    assert.ok(erste.startsWith(LIBRARY_WARN_PREFIX), `erwartet Präfix, war ${JSON.stringify(erste)}`);
  });

  it('B12: restore() überschreibt kein Fremd-Update von console.warn', () => {
    const { console: target } = fakeConsole();
    const restore = installLibraryLogFilter(target);
    const fremd = (): void => undefined;
    target.warn = fremd; // Fremdcode war schneller
    restore();
    assert.equal(target.warn, fremd, 'Fremdänderung bleibt stehen');
  });

  it('B12: der Default-Pfad (globales console) filtert wirklich und ist rückgängig machbar', () => {
    // Dieser Pfad wird in src/service/run.ts:28 ohne Argument verwendet und war
    // vorher nur indirekt getestet. Geprüft wird die Wirkung, nicht nur die
    // Referenz.
    const ausgangsfkt = console.warn;
    const geschrieben: string[] = [];
    const fremd = (...args: unknown[]): void => {
      geschrieben.push(args.map(String).join(' '));
    };
    console.warn = fremd;
    try {
      const restore = installLibraryLogFilter();
      console.warn(`${LIBRARY_WARN_PREFIX} muss unterdrückt werden`);
      console.warn('eigene Warnung muss sichtbar bleiben');
      assert.deepEqual(geschrieben, ['eigene Warnung muss sichtbar bleiben'], 'nur die Bibliothekszeile wird geschluckt');
      restore();
    } finally {
      console.warn = ausgangsfkt;
    }
    assert.equal(console.warn, ausgangsfkt, 'globales console ist wieder im Ausgangszustand');
  });

  it('der Filter ist im Prozesseinstieg installiert', async () => {
    const { readFileSync } = await import('node:fs');
    const quelle = readFileSync(new URL('../service/run.ts', import.meta.url), 'utf8');
    assert.match(quelle, /installLibraryLogFilter\(\);/);
  });
});
