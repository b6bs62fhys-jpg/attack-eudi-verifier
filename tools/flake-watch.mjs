/**
 * Flake-Wächter: wiederholt die zeitabhängigen Testdateien mehrfach.
 *
 * Zweck: Ein Test, der nur durch Zeit oder Last kippt, ist in einer CI ein
 * rotes Signal, dessen Ursache niemand zuordnen kann. `src/onboarding/gueltigkeit.test.ts`
 * war so ein Fall — ungefähr jeder neunte Lauf des vollen Laufs. Der Test ist
 * inzwischen an der Wurzel behoben, dieser Wächter soll verhindern, dass ein
 * ähnlicher Fall unbemerkt zurückkommt.
 *
 * Warum eine Schleife und nicht `vitest --repeats`:
 * `--repeats` führt die Wiederholungen im selben Prozess aus. Die HTTP-Tests
 * unter sich teilen dann einen Dienst, und nach 60 Anfragen je Minute
 * greift das Ratenlimit — der Lauf meldet 429 statt 201. Das ist keine
 * Flake, sondern das korrekt arbeitende Ratenlimit; `--repeats` erzeugt hier
 * also systematisch Fehlschläge. Jeder Aufruf in dieser Schleife ist ein
 * eigener Prozess mit frischem Zustand, was die Wiederholung überhaupt erst
 * aussagekräftig macht.
 *
 * Aufruf: `npm run test:flake` (Exit 0 = alle Wiederholungen grün)
 */

import { execFileSync } from 'node:child_process';

/** Dateien, deren Verhalten von Uhrzeit, Ablauf oder Cache-Gültigkeit abhängt. */
const ZEITABHAENGIG = [
  'src/onboarding/gueltigkeit.test.ts',
  'src/service/gueltigkeit-dienst.test.ts',
  'src/service/ergebnis-einmal.test.ts',
  'src/service/nachweis.test.ts',
  'src/demo/demo-szenarien.test.ts',
  'src/onboarding/ocsp-revocation.test.ts',
  'src/service/credential-status.test.ts',
  'src/trustlist/trustlist.test.ts',
  'src/service/issuer-revocation.test.ts',
  // Paket 6. Beide lesen keine echte Uhr, der Nachweis laeuft ueber 5
  // Wiederholungen (gruen). Sie stehen trotzdem hier, weil beide Zeitkanten
  // pruefen — `sicherheitsluecken.test.ts` die Zertifikatskante bei Abweichung 0
  // und die Fenstersperre des Rate Limiters, `praesentations-fuzz.test.ts` die
  // Grenzen des Parsers. Faellt eine davon, ist der Wächter die billigste Stelle,
  // es zu sehen. Wer sie entfernt, verliert den Nachweis der Stabilitaet.
  'src/service/sicherheitsluecken.test.ts',
  'src/service/praesentations-fuzz.test.ts',
  // Paket C. Liest keine echte Uhr, steht aber hier, weil der Test eine
  // whole-Session-Kette faehrt: Sitzung anlegen, praesentieren, Ergebnis
  // holen, Replay pruefen. Faellt eine der Uebergaenge aus, ist der Waelchter
  // die billigste Stelle, es zu sehen. 5 von 5 Wiederholungen gruen.
  'src/service/praesentation-422-e2e.test.ts',
];

const WIEDERHOLUNGEN = Number(process.env.FLAKE_REPEATS ?? 10);

/** Harte Obergrenze, damit der Wächter die CI nicht aufhalten kann. */
const ZEIT_BUDGET_MS = Number(process.env.FLAKE_BUDGET_MS ?? 8 * 60 * 1000);

const start = Date.now();
const roteLaeufe = [];

for (let i = 1; i <= WIEDERHOLUNGEN; i += 1) {
  if (Date.now() - start > ZEIT_BUDGET_MS) {
    process.stdout.write(`Zeitbudget nach ${i - 1} von ${WIEDERHOLUNGEN} Wiederholungen erreicht.\n`);
    break;
  }
  const laufStart = Date.now();
  try {
    execFileSync('npx', ['vitest', 'run', ...ZEITABHAENGIG], { stdio: 'pipe' });
    process.stdout.write(`Wiederholung ${i}/${WIEDERHOLUNGEN} grün (${((Date.now() - laufStart) / 1000).toFixed(1)} s)\n`);
  } catch {
    // Im Fehlerfall die Ausgabe des Laufs ausgeben, sonst ist die Ursache nicht
    // sichtbar und der Wächter ist wertlos.
    process.stdout.write(`Wiederholung ${i}/${WIEDERHOLUNGEN} ROT\n`);
    roteLaeufe.push(i);
  }
}

const gedauer = ((Date.now() - start) / 1000).toFixed(1);
if (roteLaeufe.length === 0) {
  process.stdout.write(`Flake-Wächter: ${WIEDERHOLUNGEN} Wiederholungen der ${ZEITABHAENGIG.length} zeitabhängigen Dateien, alle grün (${gedauer} s).\n`);
  process.exitCode = 0;
} else {
  process.stdout.write(`Flake-Wächter: rot in Wiederholung ${roteLaeufe.join(', ')}. Ein einzelner roter Lauf reicht.\n`);
  process.exitCode = 1;
}
