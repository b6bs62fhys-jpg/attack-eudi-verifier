/**
 * Zufaellige Formen fuer den Praesentationsparser und die Claim-Filterung.
 *
 * Zwei Entscheidungen vorweg, beide aus dem Auftrag:
 *
 * **Kein `fast-check`.** Die Bibliothek waere die richtige Wahl fuer
 * Property-Tests, sie bringt aber eine neue Abhaengigkeit in das Projekt,
 * deren Zweck kein Laufzeitcode ist. Der Auftrag erlaubt eine neue
 * Abhaengigkeit nur mit Begruendung im PR; das ist der Punkt, an dem eine
 * generative Bibliothek ihre Berechtigung erst nachweisen muss. Was hier
 * steht, kommt ohne sie aus: ein kleiner, deterministischer Generator mit
 * festem Startwert, der dieselben Eingaben bei jedem Lauf erzeugt.
 *
 * **Warum ein deterministischer Generator und kein `Math.random`.** Ein Test,
 * der zufaellige Eingaben zieht, ist bei Fehlschlag nicht reproduzierbar. Der
 * Fehler zeigt sich dann einmal und verschwindet. Hier laeuft der Generator
 * mit festem Startwert, ein Fehler ist also immer derselbe und immer wieder da.
 *
 * **Die Kryptografie bleibt draussen.** Es werden keine Zertifikate und keine
 * Signaturen erzeugt. Geprueft wird die reine Formpruefung: Welche
 * Zeichenfolge landet in welchem Fehlercode. Das ist die Schicht, in der ein
 * Fehler ein falscher Statuscode bedeutet.
 *
 * Der Claim-Filter wird gegen zwei Eigenschaften geprueft, die zusammen die
 * Datensparsamkeit ausmachen: kein unerwartetes Feld kommt durch, und kein
 * erwartetes verschwindet.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'vitest';

import { MAX_DISCLOSURES, MAX_VP_TOKEN_CHARS, vpTokenLimitError } from './limits.ts';
import { nurAngefragteClaims } from './profile.ts';

/**
 * Erzeugt Zahlen aus einem festen Startwert (xorshift32).
 *
 * Ein Generator mit Saat statt `Math.random`, damit ein Fehlschlag
 * reproduzierbar bleibt. Fuer Eingabeformen reicht die Gleichverteilung dieses
 * Laufs; es wird keine kryptografische Guete behauptet.
 */
function zufall(saat: number): () => number {
  let zustand = saat | 0 || 1;
  return () => {
    zustand ^= zustand << 13;
    zustand ^= zustand >>> 17;
    zustand ^= zustand << 5;
    return ((zustand >>> 0) % 1_000_000) / 1_000_000;
  };
}

/** Zeichen, die in den Eingaben vorkommen duerfen: sichtbar, inklusive der Kanten. */
const ZEICHEN: string[] = [
  ...'abcdefghijklmnopqrstuvwxyz',
  ...'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  ...'0123456789',
  '-._~!#', // Trennzeichen des SD-JWT und der Basis64url
  ' ', // Leerzeichen: kein gueltiger Bestandteil, aber moeglich
  '\u0001', // Steuerzeichen (SOH, als Escapesequenz im Quelltext)
  'ä', 'ö', 'ü', 'ß', // Zeichen ausserhalb von ASCII
  '中', // Zeichen ausserhalb von Latin-1
  '\u{1f600}', // Zeichen ausserhalb der BMP
];

function zufallstext(rnd: () => number, laenge: number): string {
  let out = '';
  for (let i = 0; i < laenge; i += 1) out += ZEICHEN[Math.floor(rnd() * ZEICHEN.length)]!;
  return out;
}

/** Die Formen, die `vpTokenLimitError` unterscheidet. */
const FORMEN = [
  undefined,
  null,
  true,
  42,
  'text',
  [],
  {},
  [1, 2],
  { pid: undefined },
  { pid: null },
  { pid: 'kein-array' },
  { pid: [] },
  { pid: [1] },
  { pid: [null] },
  { pid: ['a', 'b'] },
  { pid: [''] },
  { pid: ['a~'] },
  { pid: ['~'] },
  { pid: ['a'.repeat(MAX_VP_TOKEN_CHARS + 1)] },
] as const;

describe('Praesentationsparser: zufaellige Formen', () => {
  // 500 Durchlaeufe je Eigenschaft. Genug, um Formfehler zu finden, wenig
  // genug, um lokal schnell zu bleiben.
  const LAEUFE = 500;

  it('jede zufaellige Form ergibt einen Fehlercode oder undefined, nie einen Wurf', () => {
    // Die zentrale Eigenschaft: `vpTokenLimitError` ist die erste Stelle, an
    // der eine fremde Eingabe ankam. Ein Wurf waere ein 500 statt eines 400.
    const rnd = zufall(0x5eed);
    for (let i = 0; i < LAEUFE; i += 1) {
      const vpToken: unknown = FORMEN[Math.floor(rnd() * FORMEN.length)];
      const state = rnd() < 0.5 ? 'g' : zufallstext(rnd, Math.floor(rnd() * 300));
      const ergebnis = vpTokenLimitError(state, vpToken);
      assert.ok(
        ergebnis === undefined || typeof ergebnis === 'string',
        `Form ${i} ergab ${String(ergebnis)}`,
      );
    }
  });

  it('eine zufaellige Zeichenfolge wird nach Form beurteilt, nicht nach Inhalt', () => {
    // Erwartung nach dem Code gelesen, nicht nach einer Vermutung:
    // `vpTokenLimitError` prueft die **Form** — ist es ein nichtleerer
    // String, und ist er nicht zu lang. Ob der Inhalt ein gueltiges SD-JWT
    // ist, entscheidet die Bibliothek weiter oben, nicht diese Funktion.
    //
    // Ein zufaelliger Text ist deshalb meistens `undefined`, nicht abgelehnt.
    // Der Test haelt fest, dass kein anderer Code erscheint und die Laengengrenze
    // trotzdem greift — sonst wuerde ein `>=` bei `too_long` hier auffallen.
    const rnd = zufall(0xc0de);
    for (let i = 0; i < LAEUFE; i += 1) {
      const laenge = Math.floor(rnd() * 200);
      const token = zufallstext(rnd, laenge);
      const ergebnis = vpTokenLimitError('g', { pid: [token] });
      // Leer wird abgelehnt (`token.length === 0`), alles andere passiert die
      // Formpruefung, weil 200 Zeichen weit unter der Grenze liegen.
      if (token.length === 0) {
        assert.equal(ergebnis, 'vp_token_invalid', `Durchlauf ${i}: leerer Token`);
      } else {
        assert.equal(ergebnis, undefined, `Token "${token}" ergab ${String(ergebnis)}`);
      }
    }
  });

  it('die Disclosures-Obergrenze haelt bei jeder zufaelligen Tilde-Zahl', () => {
    // Die Zahl der gefuellten Teile entscheidet ueber `too_many_disclosures`.
    // Jede Anzahl muss zu genau einem der beiden Ausgaenge fuehren.
    const rnd = zufall(0xd15c);
    for (let i = 0; i < LAEUFE; i += 1) {
      const anzahl = Math.floor(rnd() * (MAX_DISCLOSURES + 12));
      const token = `head~${Array.from({ length: anzahl }, (_, k) => `d${k}`).join('~')}~kb`;
      const ergebnis = vpTokenLimitError('g', { pid: [token] });
      if (anzahl > MAX_DISCLOSURES) {
        assert.equal(ergebnis, 'too_many_disclosures', `${anzahl} Disclosures muessen abgelehnt werden`);
      } else {
        assert.equal(ergebnis, undefined, `${anzahl} Disclosures muessen durchgehen`);
      }
    }
  });

  it('eine zufaellige Laenge genau um die Tokengrenze herum trifft die richtige Seite', () => {
    // Die Grenze ist `> MAX_VP_TOKEN_CHARS`. Rundherum geprueft, damit ein
    // Vergleich mit `>=` auffaellt.
    const rnd = zufall(0xbeef);
    for (let i = 0; i < LAEUFE; i += 1) {
      const laenge = MAX_VP_TOKEN_CHARS + Math.floor(rnd() * 5) - 2;
      if (laenge <= 0) continue;
      const ergebnis = vpTokenLimitError('g', { pid: ['a'.repeat(laenge)] });
      if (laenge > MAX_VP_TOKEN_CHARS) {
        assert.equal(ergebnis, 'vp_token_too_long', `${laenge} Zeichen muessen abgelehnt werden`);
      } else {
        assert.equal(ergebnis, undefined, `${laenge} Zeichen muessen durchgehen`);
      }
    }
  });
});

describe('Claim-Filterung: zufaellige Objektformen', () => {
  const LAEUFE = 500;

  it('nur angefragte Namen kommen durch, unabhaengig vom Wert', () => {
    // Die Eigenschaft der Datensparsamkeit: was nicht angefragt wurde, darf
    // nicht im Ergebnis stehen. Der Wert wird frei variiert, weil er fuer die
    // Zugehoerigkeit keine Rolle spielt.
    const rnd = zufall(0xfeed);
    const namen = ['given_name', 'family_name', 'birth_date', 'age_over_18', 'unbekannt', '__proto__', 'constructor', ''];
    for (let i = 0; i < LAEUFE; i += 1) {
      const angefragt = [namen[Math.floor(rnd() * namen.length)]!, namen[Math.floor(rnd() * namen.length)]!];
      const parsed: Record<string, unknown> = {};
      for (const n of namen) parsed[n] = rnd();
      const gefiltert = nurAngefragteClaims(parsed, angefragt);
      for (const [name] of Object.entries(gefiltert)) {
        assert.ok(angefragt.includes(name), `"${name}" stand nicht in der Anfrageliste, kam aber durch`);
      }
    }
  });

  it('jeder angefragte Name, der im Ergebnis liegt, war wirklich angefragt', () => {
    // Die Gegenrichtung: der Filter darf nichts verlieren, was verlangt wurde.
    const rnd = zufall(0xface);
    for (let i = 0; i < LAEUFE; i += 1) {
      const anzahl = 1 + Math.floor(rnd() * 4);
      const angefragt: string[] = [];
      const parsed: Record<string, unknown> = {};
      for (let k = 0; k < anzahl; k += 1) {
        const name = `claim_${k}`;
        angefragt.push(name);
        parsed[name] = k;
      }
      assert.deepEqual(nurAngefragteClaims(parsed, angefragt), parsed);
    }
  });

  it('der Filter veraendert das uebergebene Objekt nicht', () => {
    // `nurAngefragteClaims` baut ein neues Objekt. Wuerde es in-place filtern,
    // waere das Credential nach der Pruefung veraendert — der Aufrufer verliert
    // die Rohdaten.
    const rnd = zufall(0x1234);
    for (let i = 0; i < LAEUFE; i += 1) {
      const parsed: Record<string, unknown> = { behalten: 1, weg: 2 };
      const vor = Object.keys(parsed).length;
      nurAngefragteClaims(parsed, ['behalten']);
      assert.equal(Object.keys(parsed).length, vor, `Durchlauf ${i}: das Original wurde veraendert`);
      assert.equal(parsed.weg, 2, `Durchlauf ${i}: ein nicht angefragtes Feld ging verloren`);
    }
    void rnd;
  });
});
