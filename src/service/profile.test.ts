import assert from 'node:assert/strict';
import { describe, it } from 'vitest';

import { PID_VCT_DEFAULT, REQUEST_PROFILE_TEMPLATES, nurAngefragteClaims, parseRequestProfile, resolveRequestProfile } from './profile.ts';

describe('Anfrageprofile', () => {
  it('stellt pid_basis und age_over_18 bereit', () => {
    const pid = resolveRequestProfile('pid_basis');
    assert.equal(pid.id, 'pid_basis');
    assert.equal(pid.vct, PID_VCT_DEFAULT);
    assert.deepEqual(pid.claims, ['given_name', 'birth_date']);
    assert.equal(pid.credentialId, 'pid');

    const age = resolveRequestProfile('age_over_18');
    assert.deepEqual(age.claims, ['age_over_18']);
    assert.equal(age.credentialId, 'pid');
  });

  it('age_over_18 fragt keine personenbezogenen Zusatzclaims ab', () => {
    const age = resolveRequestProfile('age_over_18');
    for (const claim of ['given_name', 'family_name', 'birth_date', 'resident_address']) assert.equal(age.claims.includes(claim), false);
  });

  it('lehnt unbekannte Vorlagen und Konfigurationen ab', () => {
    assert.throws(() => resolveRequestProfile('existiert_nicht'), /Unbekannte Vorlage/);
    assert.throws(() => resolveRequestProfile({ id: 'custom', claims: ['given_name'], irgendwas: true }), /unbekanntes Feld/);
    assert.throws(() => resolveRequestProfile({ id: 'custom', claims: 'given_name' }), /claims muss eine Liste sein/);
    assert.throws(() => resolveRequestProfile({ id: 'custom', claims: [] }), /mindestens ein Claim/);
    assert.throws(() => resolveRequestProfile({ id: 'custom', claims: ['unbekannt'] }), /unbekannter Claim/);
    assert.throws(() => resolveRequestProfile({ id: 'custom', claims: ['given_name'], credentialId: 'other' }), /nicht unterstützt/);
  });

  it('liefert Kopien und verhindert stilles Mutieren der Vorlagen', () => {
    const first = resolveRequestProfile('pid_basis');
    const second = resolveRequestProfile('pid_basis');
    first.claims.push('extra');
    assert.equal(second.claims.includes('extra'), false);
    assert.deepEqual(REQUEST_PROFILE_TEMPLATES.pid_basis.claims, ['given_name', 'birth_date']);
    assert.deepEqual(parseRequestProfile({ id: 'custom', claims: ['given_name'] }, 'custom').claims, ['given_name']);
  });
});

describe('nurAngefragteClaims', () => {
  it('laesst nur die angefragten Claims durch', () => {
    const gefiltert = nurAngefragteClaims({ given_name: 'Ada', age_over_18: true }, ['given_name']);
    assert.deepEqual(gefiltert, { given_name: 'Ada' });
  });

  it('verwirft Klartext-Angaben aus dem Issuer-JWT, auch unbekannte', () => {
    // Das ist der Fehler aus Paket 3: die Bibliothek gab Klartext-Angaben aus
    // dem Aussteller-JWT mit heraus, der Dienst reichte sie ungefiltert durch.
    const gefiltert = nurAngefragteClaims(
      {
        given_name: 'Ada',
        status: { status_list: { idx: 0, uri: 'https://example/status' } },
        _internes_merkmal: 42,
        fachlicher_zusatz: 'intern',
      },
      ['given_name'],
    );
    assert.deepEqual(Object.keys(gefiltert), ['given_name']);
    assert.ok(!Object.prototype.hasOwnProperty.call(gefiltert, 'status'));
    assert.ok(!Object.prototype.hasOwnProperty.call(gefiltert, '_internes_merkmal'));
    assert.ok(!Object.prototype.hasOwnProperty.call(gefiltert, 'fachlicher_zusatz'));
  });

  it('behandelt Hash und Klartext gleich: nicht angefragt heisst draussen', () => {
    // Die Herkunft der Angabe darf keine Rolle spielen. Gehashte Angaben ohne
    // Offenlegung kann die Bibliothek ohnehin nicht ausgeben, deshalb blieb der
    // Fehler lange unbemerkt.
    const mitHash = nurAngefragteClaims({ given_name: 'Ada', birth_date: '_hashwert' }, ['given_name']);
    const mitKlartext = nurAngefragteClaims({ given_name: 'Ada', birth_date: '1990-01-01' }, ['given_name']);
    assert.deepEqual(mitHash, mitKlartext);
    assert.ok(!Object.prototype.hasOwnProperty.call(mitHash, 'birth_date'));
  });

  it('behaelt die Reihenfolge der Anfrageliste nicht fuer relevant, aber den Inhalt', () => {
    const gefiltert = nurAngefragteClaims({ age_over_18: true, given_name: 'Ada' }, ['given_name', 'age_over_18']);
    assert.deepEqual(gefiltert, { given_name: 'Ada', age_over_18: true });
  });

  it('leere Anfrageliste ergibt ein leeres Ergebnis', () => {
    assert.deepEqual(nurAngefragteClaims({ given_name: 'Ada' }, []), {});
  });

  it('aendert das uebergebene Objekt nicht', () => {
    const parsed = { given_name: 'Ada', intern: 'x' };
    nurAngefragteClaims(parsed, ['given_name']);
    assert.deepEqual(parsed, { given_name: 'Ada', intern: 'x' }, 'die Bibliothekdaten bleiben unveraendert');
  });

  it('behaelt verschachtelte Werte unveraendert bei, wenn sie angefragt sind', () => {
    const wert = { nested: { deep: [1, 2, 3] } };
    const gefiltert = nurAngefragteClaims({ wert, uebrig: 1 }, ['wert']);
    assert.deepEqual(gefiltert, { wert });
    assert.equal(gefiltert.wert, wert, 'der Wert wird uebergeben, nicht kopiert');
  });

  it('laesst einen Namen nicht durch, der nur aehnlich heisst', () => {
    const gefiltert = nurAngefragteClaims({ given_name: 'Ada', given_names: 'x', Given_Name: 'y' }, ['given_name']);
    assert.deepEqual(Object.keys(gefiltert), ['given_name']);
  });
});
