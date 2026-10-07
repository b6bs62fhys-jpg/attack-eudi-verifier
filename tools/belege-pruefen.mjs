#!/usr/bin/env node
/**
 * Prueft die Datei-und-Zeilen-Belege in einem Markdown-Dokument.
 *
 * Ein Beleg sieht aus wie `src/service/audit.ts:140` oder
 * `src/service/service.ts:272-276`. Fuer jeden Beleg wird geprueft:
 *   - die Datei existiert
 *   - die Zeile liegt in der Datei
 *   - die Zeile ist nicht leer
 *
 * Bei einem Bereich zaehlt die erste Zeile als Anker, sie muss Inhalt haben.
 * Ein Bereich darf Leerzeilen enthalten, das ist normal fuer Code.
 *
 * Aufruf: node tools/belege-pruefen.mjs [interne Notiz, nicht veröffentlicht]
 * Rueckgabe: 0 wenn alle Belege stimmen, 1 sonst. Die Fehler gehen nach stderr.
 */
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const WURZEL = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Holt alle Belege der Form `datei.ts:12` oder `datei.ts:12-20` aus einem Text. */
export function belege(text) {
  const rx = /`([A-Za-z0-9_./-]+\.(?:ts|tsx|js|mjs|md|yaml|yml|json|mts|cts))(?::(\d+)(?:-(\d+))?)?`/g;
  const gefundene = [];
  for (const m of text.matchAll(rx)) {
    const [, datei, von, bis] = m;
    if (!von) continue; // ohne Zeilenangabe ist der Beleg nur ein Dateiname
    gefundene.push({ datei, von: Number(von), bis: bis ? Number(bis) : Number(von) });
  }
  return gefundene;
}

/** Prueft einen Beleg. Gibt null zurueck, wenn er stimmt, sonst einen Text. */
export function pruefeBeleg(beleg) {
  const pfad = resolve(WURZEL, beleg.datei);
  if (!existsSync(pfad)) return `Datei ${beleg.datei} gibt es nicht`;
  const zeilen = readFileSync(pfad, 'utf8').split('\n');
  if (beleg.von > zeilen.length) return `${beleg.datei}:${beleg.von} liegt hinter dem Dateiende (${zeilen.length} Zeilen)`;
  if (beleg.bis > zeilen.length) return `${beleg.datei}:${beleg.bis} liegt hinter dem Dateiende (${zeilen.length} Zeilen)`;
  if (beleg.bis < beleg.von) return `${beleg.datei}: Bereich ${beleg.von}-${beleg.bis} laeuft rueckwaerts`;
  if (zeilen[beleg.von - 1].trim() === '') return `${beleg.datei}:${beleg.von} ist eine Leerzeile`;
  return null;
}

function main() {
  const ziel = process.argv[2];
  if (!ziel) {
    process.stderr.write('Aufruf: node tools/belege-pruefen.mjs <dokument.md>\n');
    return 2;
  }
  const pfad = resolve(WURZEL, ziel);
  if (!existsSync(pfad)) {
    process.stderr.write(`Dokument ${ziel} gibt es nicht\n`);
    return 2;
  }
  const liste = belege(readFileSync(pfad, 'utf8'));
  const fehler = [];
  for (const beleg of liste) {
    const meldung = pruefeBeleg(beleg);
    if (meldung) fehler.push(meldung);
  }
  const eigentuemer = new Set(liste.map((b) => b.datei));
  process.stdout.write(`${ziel}: ${liste.length} Belege in ${eigentuemer.size} Dateien, ${fehler.length} Fehler\n`);
  for (const f of fehler) process.stderr.write(`  ${f}\n`);
  return fehler.length === 0 ? 0 : 1;
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/^.*[/\\]/, ''))) {
  process.exit(main());
}
