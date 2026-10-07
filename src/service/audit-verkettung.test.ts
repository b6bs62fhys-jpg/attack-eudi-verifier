/**
 * Hash-Verkettung des Audit-Logs.
 *
 * Geprueft werden drei Angriffe auf eine Kette: ein Eintrag wird nach dem
 * Aufzeichnen geaendert, ein Eintrag in der Mitte wird geloescht, zwei
 * Eintraege werden vertauscht. Jeder Fall muss mit Index erkannt werden.
 *
 * Alle drei melden denselben Grund `abweichung`. Das ist Absicht und keine
 * Vereinfachung: der Pruefer sieht nur Eintrag und erwarteten Vorgaengerhash, und
 * alle drei Angriffe erzeugen dasselbe Muster. Unterscheidbar waere es nur mit
 * einer aeusseren Referenz.
 *
 * Der bestehende Test src/service/audit-inhalt.test.ts prueft, dass kein
 * Praesentationsinhalt im Log landet. Diese Datei prueft die Verkettung und
 * laesst die Inhaltspruefung unangetastet.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'vitest';

import { AuditLog, verifyChain, hashEintrag, type AuditEntry } from './audit.ts';

/** Baut eine Kette von n Einträgen über das echte AuditLog. */
function kette(n: number): AuditEntry[] {
  const log = new AuditLog();
  for (let i = 0; i < n; i += 1) {
    log.record('tenant-a', i % 2 === 0 ? 'request_created' : 'result_read', `runde=${i}`);
  }
  return [...log.list()];
}

describe('Audit-Log: Hash-Verkettung', () => {
  it('jeder Eintrag traegt einen Hash', () => {
    for (const eintrag of kette(5)) {
      assert.equal(typeof eintrag.hash, 'string');
      assert.equal(eintrag.hash?.length, 64, 'SHA-256 ist 64 Hex-Zeichen');
    }
  });

  it('unversehrte Kette ist gültig', () => {
    const log = new AuditLog();
    log.record('tenant-a', 'request_created');
    log.record('tenant-a', 'result_read', 'gelesen');
    const pruefung = log.verify();
    assert.equal(pruefung.gueltig, true);
    assert.equal(pruefung.index, -1);
    assert.equal(pruefung.geprueft, 2);
    assert.equal(pruefung.ungekettet, 0);
  });

  it('leeres Log ist gültig', () => {
    const pruefung = new AuditLog().verify();
    assert.equal(pruefung.gueltig, true);
    assert.equal(pruefung.geprueft, 0);
  });

  it('GEÄNDERTER Eintrag wird mit Index erkannt', () => {
    const log = new AuditLog();
    log.record('tenant-a', 'request_created');
    log.record('tenant-a', 'result_read');
    log.record('tenant-a', 'result_expired');
    const manipuliert = [...log.list()];
    manipuliert[1] = { ...manipuliert[1], detail: 'manipuliert' };
    const pruefung = verifyChain(manipuliert);
    assert.equal(pruefung.gueltig, false);
    assert.equal(pruefung.index, 1);
    assert.equal(pruefung.grund, 'abweichung');
  });

  it('GELÖSCHTER Eintrag in der Mitte wird mit Index erkannt', () => {
    const log = new AuditLog();
    log.record('tenant-a', 'request_created');
    log.record('tenant-a', 'result_read');
    log.record('tenant-a', 'result_expired');
    log.record('tenant-a', 'session_expired');
    const manipuliert = [...log.list()];
    manipuliert.splice(1, 1);
    const pruefung = verifyChain(manipuliert);
    assert.equal(pruefung.gueltig, false);
    // Index 1 ist der Nachfolger des geloeschten Eintrags, er passt nicht mehr.
    assert.equal(pruefung.index, 1);
    assert.equal(pruefung.grund, 'abweichung');
  });

  it('VERTAUSCHTER Eintrag wird mit Index erkannt', () => {
    const log = new AuditLog();
    log.record('tenant-a', 'request_created');
    log.record('tenant-a', 'result_read', 'a');
    log.record('tenant-a', 'result_read', 'b');
    const manipuliert = [...log.list()];
    [manipuliert[1], manipuliert[2]] = [manipuliert[2]!, manipuliert[1]!];
    const pruefung = verifyChain(manipuliert);
    assert.equal(pruefung.gueltig, false);
    assert.equal(pruefung.index, 1);
    assert.equal(pruefung.grund, 'abweichung');
  });

  it('ein eigener chain-Hash bricht die Kette am Index danach', () => {
    const log = new AuditLog();
    log.record('tenant-a', 'request_created');
    log.record('tenant-a', 'result_read');
    const manipuliert = [...log.list()];
    manipuliert[1] = { ...manipuliert[1], hash: 'f'.repeat(64) };
    const pruefung = verifyChain(manipuliert);
    assert.equal(pruefung.gueltig, false);
    assert.equal(pruefung.index, 1);
  });

  it('clear() setzt auch die Kette zurück', () => {
    const log = new AuditLog();
    log.record('tenant-a', 'request_created');
    log.record('tenant-a', 'result_read');
    log.clear();
    assert.equal(log.verify().gueltig, true);
    log.record('tenant-a', 'request_created');
    assert.equal(log.verify().gueltig, true, 'nach clear beginnt eine saubere Kette');
  });

  it('Einträge ohne Hash gelten als ungekettet', () => {
    // Von Hand gebauter Eintrag, wie ihn Altbestand oder ein Test erzeugt.
    const alt: AuditEntry[] = [{ at: '2026-01-01T00:00:00.000Z', tenant: 't', event: 'request_created' }];
    const pruefung = verifyChain(alt);
    assert.equal(pruefung.ungekettet, 1);
    assert.equal(pruefung.gueltig, false);
    assert.equal(pruefung.grund, 'verkettung-unvollstaendig');
  });

  it('der Hash bindet Zeitstempel, Mandant, Ereignis und Detail', () => {
    const basis: AuditEntry = { at: '2026-01-01T00:00:00.000Z', tenant: 't', event: 'request_created', detail: 'x' };
    const startwert = '0'.repeat(64);
    const original = hashEintrag(startwert, basis);
    for (const geaendert of [
      { ...basis, at: '2026-01-01T00:00:00.001Z' },
      { ...basis, tenant: 'u' },
      { ...basis, event: 'result_read' as const },
      { ...basis, detail: 'y' },
    ]) {
      assert.notEqual(hashEintrag(startwert, geaendert), original, 'Hash muss sich unterscheiden');
    }
  });

  it('der Vorgänger-Hash fließt ein', () => {
    const basis: AuditEntry = { at: '2026-01-01T00:00:00.000Z', tenant: 't', event: 'request_created' };
    assert.notEqual(hashEintrag('0'.repeat(64), basis), hashEintrag('1'.repeat(64), basis));
  });
});
