/**
 * Die Dateiliste im Dockerfile gegen die Importe von src/service/run.ts.
 *
 * Das Produktionsimage kopiert die Laufzeitdateien einzeln. Eine neue Datei, die
 * run.ts transitiv importiert, aber nicht in der Liste steht, bricht den Start
 * mit "Cannot find module" ab; eine Datei in der Liste, die niemand importiert,
 * ist Ballast im Image. Beides ist in dieser Woche vorgekommen (cert-chain.ts
 * fehlte, und die CI hätte es erst im Docker-Job gezeigt). Dieser Test findet es
 * ohne Docker.
 *
 * Aufgelöst werden relative Importe (`import ... from './x.ts'`, `export ... from`,
 * `import './x.ts'`) ab src/service/run.ts, transitiv.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'vitest';

const WURZEL = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const IMPORT = /(?:import|export)\s[^'"]*?from\s+['"](\.[^'"]+)['"]|import\s+['"](\.[^'"]+)['"]/g;

function erreichbar(): string[] {
  const gesehen = new Set<string>();
  const stapel = [resolve(WURZEL, 'src/service/run.ts')];
  while (stapel.length > 0) {
    const datei = stapel.pop() as string;
    if (gesehen.has(datei)) continue;
    gesehen.add(datei);
    for (const m of readFileSync(datei, 'utf8').matchAll(IMPORT)) {
      stapel.push(resolve(dirname(datei), (m[1] ?? m[2]) as string));
    }
  }
  return [...gesehen].map((d) => relative(WURZEL, d)).sort();
}

function kopiert(): string[] {
  const dockerfile = readFileSync(resolve(WURZEL, 'Dockerfile'), 'utf8');
  return [...dockerfile.matchAll(/COPY --from=build \/app\/(src\/\S+)/g)].map((m) => m[1] as string).sort();
}

describe('Dockerfile: Laufzeitdateien', () => {
  it('jede von run.ts erreichbare Datei steht im Dockerfile', () => {
    const kopiertSet = new Set(kopiert());
    const fehlt = erreichbar().filter((d) => !kopiertSet.has(d));
    assert.deepEqual(fehlt, [], `fehlt im Image (Start bricht mit "Cannot find module" ab): ${fehlt.join(', ')}`);
  });

  it('keine Datei im Dockerfile, die run.ts nicht erreicht', () => {
    const erreichbarSet = new Set(erreichbar());
    const ballast = kopiert().filter((d) => !erreichbarSet.has(d));
    assert.deepEqual(ballast, [], `Ballast im Image: ${ballast.join(', ')}`);
  });

  it('keine Testdatei in der Liste', () => {
    assert.deepEqual(kopiert().filter((d) => d.endsWith('.test.ts')), []);
  });

  it('die Liste ist nicht leer und enthält den Einstiegspunkt', () => {
    assert.ok(kopiert().length > 20);
    assert.ok(kopiert().includes('src/service/run.ts'));
  });

  it('die Prüfung erkennt eine fehlende Datei (Gegenprobe)', () => {
    const ohne = new Set(kopiert().filter((d) => d !== 'src/lib/cert-chain.ts'));
    assert.ok(erreichbar().some((d) => !ohne.has(d)), 'cert-chain.ts muss erreichbar sein, sonst prüft der Test nichts');
  });
});
