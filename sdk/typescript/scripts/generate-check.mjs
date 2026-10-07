/**
 * Drift-Wächter für `src/generated.ts`.
 *
 * Die Datei ist aus `openapi.yaml` im Repo-Root erzeugt. Ohne Prüfung kann sie
 * still veralten — das war der Zustand, in dem sie sich befand: `/live`,
 * `/ready`, `/metrics` und das durchgängige 429 fehlten, während die Spec sie
 * längst kannte. Ein solcher Drift fällt erst auf, wenn ein Aufrufer genau die
 * fehlende Route braucht.
 *
 * Statt die erzeugte Datei zu vergleichen, wird neu erzeugt und byteweise
 * verglichen. Das ist gegenüber einem Strukturvergleich robuster: es meldet
 * auch, wenn nur die Formatierung oder die Reihenfolge kippt, und es braucht
 * keinen geparsten Spec im Test.
 *
 * Aufruf: `npm run generate:check` (Exit 0 = aktuell, 1 = Drift)
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HIER = dirname(fileURLToPath(import.meta.url));
const SDK_ROOT = resolve(HIER, '..');
const REPO_ROOT = resolve(SDK_ROOT, '..', '..');
const SPEC = join(REPO_ROOT, 'openapi.yaml');
const ZIEL = join(SDK_ROOT, 'src', 'generated.ts');

const BEFEHL = 'openapi-typescript';
const ARGUMENTE = [SPEC, '-o'];

/** Bekannte Abweichungen zwischen erzeugter und eingecheckter Datei. */
const ERLAUBTE_ABWEICHUNGEN = [
  // openapi-typescript schreibt einen Hinweiskopf, den die eingecheckte Datei
  // nicht hatte. Kein semantischer Unterschied.
  { beschreibung: 'Kopfkommentar', pruefe: (a, b) => !a.startsWith('/*') && b.startsWith('/*') },
];

function lies(pfad) {
  return readFileSync(pfad, 'utf8');
}

/** Erzeugt die Datei frisch in ein temporaeres Verzeichnis. */
function erzeuge() {
  const ziel = mkdtempSync(join(tmpdir(), 'attack-generated-'));
  const datei = join(ziel, 'generated.ts');
  try {
    execFileSync(process.execPath, [join(SDK_ROOT, 'node_modules', '.bin', BEFEHL), ...ARGUMENTE, datei], {
      cwd: SDK_ROOT,
      stdio: 'pipe',
    });
    return lies(datei);
  } finally {
    rmSync(ziel, { recursive: true, force: true });
  }
}

function main() {
  if (!existsSync(SPEC)) {
    process.stderr.write(`Drift: ${SPEC} nicht gefunden.\n`);
    return 1;
  }
  if (!existsSync(ZIEL)) {
    process.stderr.write(`Drift: ${ZIEL} nicht gefunden. Erst "npm run generate" ausführen.\n`);
    return 1;
  }

  let frisch;
  try {
    frisch = erzeuge();
  } catch (e) {
    process.stderr.write(`Drift: Erzeugung fehlgeschlagen: ${e.message}\n`);
    return 1;
  }

  const eingecheckt = lies(ZIEL);
  if (eingecheckt === frisch) {
    process.stdout.write('generated.ts entspricht openapi.yaml.\n');
    return 0;
  }
  for (const ausnahme of ERLAUBTE_ABWEICHUNGEN) {
    if (ausnahme.pruefe(eingecheckt.trimStart(), frisch.trimStart())) {
      process.stdout.write(`generated.ts entspricht openapi.yaml (${ausnahme.beschreibung}).\n`);
      return 0;
    }
  }

  process.stderr.write(
    [
      'Drift: src/generated.ts passt nicht zu openapi.yaml.',
      'Die Datei ist erzeugt. Bitte "npm run generate" im Verzeichnis',
      'sdk/typescript ausführen und die Änderung mit committen.',
      '',
    ].join('\n'),
  );
  // Ein paar Zeilen Kontext, damit man nicht raten muss.
  const alt = eingecheckt.split('\n');
  const neu = frisch.split('\n');
  const unterschiede = [];
  for (let i = 0; i < Math.max(alt.length, neu.length); i += 1) {
    if (alt[i] !== neu[i]) unterschiede.push(i + 1);
    if (unterschiede.length === 10) break;
  }
  if (unterschiede.length > 0) {
    process.stderr.write(`Erste abweichende Zeilen: ${unterschiede.join(', ')}\n`);
  }
  process.stderr.write(`eingecheckt: ${alt.length} Zeilen, erzeugt: ${neu.length} Zeilen\n`);
  return 1;
}

process.exitCode = main();
