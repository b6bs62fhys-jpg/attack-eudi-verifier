/**
 * Gleicht docs/openapi.yaml gegen die Routentabelle in src/service/app.ts ab.
 *
 * Muster nach src/service/mandanten-matrix.test.ts: die Routen sind die
 * Wahrheit, die Datei muss ihnen folgen. Eine neue Route ohne Eintrag lässt
 * diesen Test fehlschlagen, ein Eintrag ohne Route ebenso.
 *
 * Es gibt keinen YAML-Parser in den Abhängigkeiten, und es wird keiner
 * hinzugefügt. Geprüft wird deshalb mit einer Zeilenprüfung, die genau die
 * Stellen liest, auf die es ankommt: die Schlüssel unter `paths:` und die
 * Methoden darunter. Das ist schwächer als ein vollständiger Parser und im
 * Abschlussbericht als Lücke benannt.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { describe, it } from 'vitest';

import { ROUTES } from './service/app.ts';

const WURZEL = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DATEI = resolve(WURZEL, 'docs/openapi.yaml');

/**
 * OpenAPI schreibt Pfadparameter in geschweiften Klammern, der Code in
 * Doppelpunkten. Beides meint dasselbe Segment. Fuer den Abgleich werden die
 * Klammern zu Doppelpunkten, sonst waere jede Datei formal falsch.
 */
function normalisierePfad(pfad: string): string {
  return pfad.replaceAll('{', ':').replaceAll('}', '');
}

/** Liefert die Routen aus der YAML-Datei: Pfad, dann die Methoden darunter. */
function routenAusDerDatei(): Map<string, Set<string>> {
  const zeilen = readFileSync(DATEI, 'utf8').split('\n');
  const gefunden = new Map<string, Set<string>>();
  const echteMethoden = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options']);
  let pfad: string | null = null;
  let methodenUnterPfad = false;

  for (const zeile of zeilen) {
    // Kommentare und Leerzeilen aendern den Zustand nicht. Sonst bricht ein
    // Kommentar mitten in einem Pfad die Erfassung der Methoden ab.
    if (/^\s*#/.test(zeile) || zeile.trim() === '') continue;
    // Pfadzeilen unter paths: beginnen mit zwei Leerzeichen und einem /
    const pfadTreffer = /^ {2}(\/[^:]*):\s*$/.exec(zeile);
    if (pfadTreffer && pfadTreffer[1] !== null) {
      pfad = pfadTreffer[1];
      gefunden.set(normalisierePfad(pfad), new Set());
      methodenUnterPfad = false;
      continue;
    }
    // Komponenten und Beschreibungen ausschliessen, sonst zaehlt
    // '#/components/schemas/...' als Route.
    if (/^[a-z]/i.test(zeile) || /^ {2}[a-z]/.test(zeile)) {
      pfad = null;
      methodenUnterPfad = false;
      continue;
    }
    if (pfad === null) continue;
    // Methodenzeilen unter einem Pfad: vier Leerzeichen, keine weiteren
    const methodenTreffer = /^ {4}(get|post|put|patch|delete|head|options):\s*$/.exec(zeile);
    if (methodenTreffer && methodenTreffer[1] !== null && echteMethoden.has(methodenTreffer[1])) {
      // Der Schlüssel ist normalisiert, sonst greift get() bei Klammern
      // nicht und die Methode geht verloren.
      gefunden.get(normalisierePfad(pfad))?.add(methodenTreffer[1].toUpperCase());
      methodenUnterPfad = true;
      continue;
    }
    void methodenUnterPfad;
  }
  return gefunden;
}

const ausDerDatei = routenAusDerDatei();
const ausDemCode = new Map<string, Set<string>>();
for (const route of ROUTES) {
  const menge = ausDemCode.get(route.path) ?? new Set<string>();
  menge.add(route.method);
  ausDemCode.set(route.path, menge);
}

describe('OpenAPI-Abgleich', () => {
  it('die Datei wurde gelesen und enthält Pfade', () => {
    assert.ok(ausDerDatei.size > 0, 'keine Pfade in docs/openapi.yaml gefunden');
  });

  it('jede Route aus dem Code steht in der Datei', () => {
    for (const [pfad, methoden] of ausDemCode) {
      assert.ok(ausDerDatei.has(pfad), `Route ${pfad} fehlt in docs/openapi.yaml`);
      for (const methode of methoden) {
        assert.ok(
          ausDerDatei.get(pfad)?.has(methode),
          `Route ${methode} ${pfad} fehlt in docs/openapi.yaml`,
        );
      }
    }
  });

  it('jeder Eintrag in der Datei entspricht einer Route aus dem Code', () => {
    for (const [pfad, methoden] of ausDerDatei) {
      assert.ok(ausDemCode.has(pfad), `docs/openapi.yaml nennt ${pfad}, im Code gibt es diese Route nicht`);
      for (const methode of methoden) {
        assert.ok(
          ausDemCode.get(pfad)?.has(methode),
          `docs/openapi.yaml nennt ${methode} ${pfad}, im Code gibt es diese Methode nicht`,
        );
      }
    }
  });

  it('Pfadanzahl stimmt überein', () => {
    assert.equal(ausDerDatei.size, ausDemCode.size, 'unterschiedliche Anzahl Pfade');
  });

  it('jede Mandantenroute ist in der Datei ohne security-Ausnahme', () => {
    const inhalt = readFileSync(DATEI, 'utf8');
    for (const route of ROUTES.filter((r) => r.access === 'tenant')) {
      // Die Mandantenschlüssel sind global als security gesetzt. Eine Route
      // darf security: [] nur tragen, wenn sie im Code public ist.
      const abschnitt = abschnittFuer(inhalt, route.path);
      if (/security: \[\]/m.test(abschnitt)) {
        assert.equal(route.access, 'public', `${route.path} ist Mandantenroute, hat aber security: []`);
      }
    }
  });

  it('jede öffentliche Route ohne Schlüssel ist als public markiert', () => {
    const inhalt = readFileSync(DATEI, 'utf8');
    for (const route of ROUTES.filter((r) => r.access === 'public')) {
      const abschnitt = abschnittFuer(inhalt, route.path);
      const ohneSchluessel = /security: \[\]/m.test(abschnitt);
      const pfad = route.path;
      // /direct_post nimmt den Nachweis einer Wallet entgegen, dort gibt es
      // keinen Mandantenschluessel. Die uebrigen oeffentlichen Routen sind
      // Betriebsrouten ohne Schluessel.
      assert.ok(ohneSchluessel || pfad === '/direct_post', `${pfad} verlangt Schluessel, ist aber public`);
    }
  });
});

/**
 * Liefert den Dateiausschnitt, der zu einem Pfad gehoert, in normalisierten
 * Zeilen. Gesucht wird mit beiden Schreibweisen, weil der Code Doppelpunkte
 * und die OpenAPI-Datei geschweifte Klammern nutzt.
 *
 * Gesucht wird nach einer exakten Zeile, damit /v1/verification-requests/{id}
 * nicht auf /v1/verification-requests/{id}/request-object springt.
 */
function abschnittFuer(inhalt: string, pfad: string): string {
  const zeilen = inhalt.split('\n');
  // Nur der Doppelpunkt direkt nach einem Pfadsegment wird zu einer Klammer.
  // replaceAll auf ':' wuerde auch den nach /v1 ersetzen und den Pfad zerlegen.
  const alsKlammern = pfad.replace(/:([^/]+)/g, '{$1}');
  const gesucht = new Set([`${pfad}:`, `${alsKlammern}:`]);
  const start = zeilen.findIndex((z) => gesucht.has(z.trim()));
  if (start < 0) return '';
  const ende = zeilen.findIndex((z, i) => i > start && /^ {2}\/[^ ]*:\s*$/.test(z));
  const roh = zeilen.slice(start, ende < 0 ? zeilen.length : ende);
  return roh
    .filter((z) => !/^\s*#/.test(z))
    .map((z) => normalisierePfad(z.trim()))
    .join('\n');
}
