/**
 * Lücken, die die Coverage-Messung vom 28.09.2026 gezeigt hat.
 *
 * Die Messung (Basis `a5f89b3`) ergab für `src/service` und `src/onboarding`
 * diese unbedeckten Stellen. Die hier geschlossenen sind die, an denen ein
 * Fehler sicherheitsrelevant wäre: das Verhalten an einer Grenze, ein
 * Konfigurationsfehler, oder ein Fehlercode, der nach außen geht.
 *
 * Nicht geschlossen und warum:
 *
 *   - `src/service/run.ts` (0 %) ist der Prozesseinstieg. Er ist ein
 *     Entry-Point ohne testbare Zweige; eine Testdatei dafür wäre eine
 *     Scheinabdeckung. Bleibt offen.
 *   - `src/cli/main.ts` (0 %) ebenso Kommandozeile. Der `release-dryrun`-Job
 *     aus Paket 4 ruft den CLI-Pfad auf, das ist ein echter Beleg, aber kein
 *     Test.
 *   - `src/service/audit.ts:44` ist `clear()`. Wird der Pfad je gebraucht,
 *     gehört er in den Test der Stelle, die ihn braucht, nicht hierher.
 *
 * Alle Zeitpunkte kommen aus injizierten Uhren. Kein Test liest die echte Uhr.
 */
import assert from 'node:assert/strict';
import { beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';

import { DEFAULT_CLOCK_SKEW_SECONDS, certificateValidityFailure } from '../lib/cert-validity.ts';
import { CLOCK_SKEW_SECONDS_MAX, ConfigError, DEFAULT_CLOCK_SKEW_SECONDS_CONFIG, ENV_ATTACK_CLOCK_SKEW_SECONDS, ENV_ATTACK_RATE_LIMIT_PUBLIC, ENV_ATTACK_RATE_LIMIT_TENANT, ENV_ATTACK_RATE_LIMIT_WINDOW, ENV_ATTACK_RESULT_TTL_SECONDS, loadConfig } from '../config.ts';
import { RateLimiter } from './rate-limit.ts';
import { MAX_CLAIMS, MAX_DISCLOSURES, MAX_STATE_CHARS, MAX_VP_TOKEN_CHARS, ServiceInputError, validateClaims, validateVct, vpTokenLimitError } from './limits.ts';
import { nurAngefragteClaims, parseRequestProfile } from './profile.ts';
import { TenantStore } from './tenant.ts';
import { generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';

describe('Eine Wahrheit für die Uhrabweichung', () => {
  it('Zertifikatsprüfung und Konfiguration nennen denselben Standard', () => {
    // Zwei Konstanten mit derselben Bedeutung an zwei Orten: `cert-validity.ts`
    // (der Standard der Prüfung) und `config.ts` (der Standard der
    // Konfiguration). Sie sind unabhängig definiert, also kann eine geändert
    // werden, ohne dass die andere es merkt. Genau dieser Fall ist in Paket 5
    // bei vier anderen Stellen passiert.
    assert.equal(
      DEFAULT_CLOCK_SKEW_SECONDS_CONFIG,
      DEFAULT_CLOCK_SKEW_SECONDS,
      'Zwei Standardwerte fuer dieselbe Groesse: sie muessen zusammenfallen',
    );
  });

  it('die Standardgrenze der Konfiguration ist die Obergrenze, die geprueft wird', () => {
    // Nur als Widerspruchsschutz: `zahlAusUmgebung` wird mit
    // `CLOCK_SKEW_SECONDS_MAX` gerufen, und 300 muss dort auch die Grenze
    // sein. Sonst waere die dokumentierte Obergrenze falsch.
    assert.equal(CLOCK_SKEW_SECONDS_MAX, 300);
    assert.throws(() => loadConfig({ [ENV_ATTACK_CLOCK_SKEW_SECONDS]: String(CLOCK_SKEW_SECONDS_MAX + 1) }), ConfigError);
    assert.equal(loadConfig({ [ENV_ATTACK_CLOCK_SKEW_SECONDS]: String(CLOCK_SKEW_SECONDS_MAX) }).clockSkewSeconds, CLOCK_SKEW_SECONDS_MAX);
  });
});

describe('Konfigurationsfehler an der Grenze', () => {
  it('jede Obergrenze ist die letzte erlaubte Zahl', () => {
    // Ein Wert genau auf der Grenze ist erlaubt, einer darüber bricht den Start
    // ab. `zahlAusUmgebung` gilt fuer alle drei, deshalb werden sie
    // gemeinsam geprueft statt einzeln.
    const paare: Array<[string, number]> = [
      [ENV_ATTACK_RESULT_TTL_SECONDS, 3600],
      [ENV_ATTACK_RATE_LIMIT_WINDOW, 3600],
      [ENV_ATTACK_RATE_LIMIT_PUBLIC, 1_000_000],
      [ENV_ATTACK_RATE_LIMIT_TENANT, 1_000_000],
    ];
    for (const [name, grenze] of paare) {
      assert.equal(loadConfig({ [name]: String(grenze) }) && true, true, `${name} auf der Grenze muss erlaubt sein`);
      assert.throws(
        () => loadConfig({ [name]: String(grenze + 1) }),
        (f: unknown) => f instanceof ConfigError,
        `${name} bei ${grenze + 1} muss abgelehnt werden`,
      );
    }
  });

  it('die Mindestgrenze ist 1, 0 wird abgelehnt', () => {
    // Bei den Ratenbegrenzungen und der Ergebnis-Aufbewahrung ist 0 unsinnig:
    // kein Fenster heisst sofortige Sperre, keine Aufbewahrung heisst das
    // Ergebnis ist sofort weg. Beides wird abgelehnt statt still akzeptiert.
    for (const name of [ENV_ATTACK_RESULT_TTL_SECONDS, ENV_ATTACK_RATE_LIMIT_WINDOW, ENV_ATTACK_RATE_LIMIT_PUBLIC, ENV_ATTACK_RATE_LIMIT_TENANT]) {
      assert.throws(() => loadConfig({ [name]: '0' }), ConfigError, `${name}=0 muss abgelehnt werden`);
    }
  });

  it('eine Nachkommastelle ist keine ganze Zahl und wird abgelehnt', () => {
    for (const name of [ENV_ATTACK_RESULT_TTL_SECONDS, ENV_ATTACK_RATE_LIMIT_WINDOW, ENV_ATTACK_CLOCK_SKEW_SECONDS]) {
      assert.throws(() => loadConfig({ [name]: '2.5' }), ConfigError, `${name}=2.5 muss abgelehnt werden`);
    }
  });

  it('eine Nachkommastelle bei der Uhrabweichung heisst: keine Toleranz', () => {
    // `0.5` waere als Sekundenbruchteil lesbar. Der Code fordert eine ganze
    // Zahl, damit der Wert in der Zertifikatspruefung als Millisekunden
    // aufgeht. Diese Pruefung ist genau der Punkt, an dem eine Nachkommastelle
    // zu einer unerwarteten Toleranz fuehren wuerde.
    assert.throws(() => loadConfig({ [ENV_ATTACK_CLOCK_SKEW_SECONDS]: '0.5' }), ConfigError);
    assert.equal(loadConfig({ [ENV_ATTACK_CLOCK_SKEW_SECONDS]: '0' }).clockSkewSeconds, 0);
  });
});

describe('Zertifikatskante bei Abweichung 0', () => {
  // Abgedeckt ist die Kante in `src/onboarding/gueltigkeit.test.ts`. Hier steht
  // nur, was dort fehlt: dass der Standardpfad **ohne** injizierte Abweichung
  // dieselbe strenge Kante hat wie ein explizit gesetzter Wert 0.
  //
  // Ein echtes Zertifikat, kein Attrappen-Objekt: `certificateValidityFailure`
  // baut daraus einen `X509Certificate` und liefert bei einem unlesbaren
  // Zertifikat `certificate_expired`. Eine Attrappe wuerde also immer
  // abgelehnt und der Test waere gruen, ohne die Kante zu pruefen.
  const now = new Date(1_700_000_000_000);
  // Zwei Zertifikate, weil beide Kanten sonst nicht gleichzeitig pruefbar sind:
  // ein Zertifikat, dessen notAfter auf dem Pruefzeitpunkt liegt, ist an der
  // notBefore-Grenze nicht mehr pruefbar, weil es dann zwingend abgelaufen ist.
  let amEnde!: TestKeyMaterial;
  let amAnfang!: TestKeyMaterial;

  beforeAll(async () => {
    amEnde = await generateTestKeyMaterial('Kante notAfter TEST', { notBefore: new Date(now.getTime() - 60_000), notAfter: now });
    amAnfang = await generateTestKeyMaterial('Kante notBefore TEST', { notBefore: now, notAfter: new Date(now.getTime() + 3_600_000) });
  });

  it('genau notAfter ist gueltig, eine Sekunde spaeter nicht', () => {
    assert.equal(certificateValidityFailure(amEnde.certDerBytes, now, 0), undefined, 'genau notAfter muss gueltig sein');
    assert.equal(certificateValidityFailure(amEnde.certDerBytes, new Date(now.getTime() + 1000), 0), 'certificate_expired');
  });

  it('genau notBefore ist gueltig, eine Sekunde vorher nicht', () => {
    assert.equal(certificateValidityFailure(amAnfang.certDerBytes, now, 0), undefined, 'genau notBefore muss gueltig sein');
    assert.equal(certificateValidityFailure(amAnfang.certDerBytes, new Date(now.getTime() - 1000), 0), 'certificate_not_yet_valid');
  });
});

describe('Rate-Limit-Kanten, bisher unbedeckt', () => {
  it('clear() leert die Fenster wirklich', () => {
    // `clear()` war unbedeckt (Zeile 47). Der Fehler waere still: nach clear
    // bleibt der Schluessel mit seinem Zaehler stehen, und die Sperre haelt
    // länger als gedacht.
    const now = 1_000;
    const limiter = new RateLimiter({ windowMs: 1_000, now: () => now });
    assert.equal(limiter.consume('k', 1).allowed, true);
    assert.equal(limiter.consume('k', 1).allowed, false);
    limiter.clear();
    assert.equal(limiter.consume('k', 1).allowed, true, 'nach clear() muss der Schluessel wieder zaehlen');
  });

  it('abgelaufene Fenster werden entfernt, nicht nur nicht getroffen', () => {
    // `prune` war unbedeckt (Zeilen 52, 55-57). Ohne das waechst die Map
    // unbegrenzt. Der Nachweis laeuft ueber die Speichergrenze unten.
    const now = 1_000;
    const limiter = new RateLimiter({ windowMs: 1_000, maxKeys: 4, now: () => now });
    for (let i = 0; i < 20; i += 1) limiter.consume(`k${i}`, 10);
    // Alle 20 Schluessel sind abgelaufen, also muss die Grenze greifen und
    // die Map auf maxKeys fallen. Ohne prune blieben 20 Eintraege stehen.
    const belegt = (limiter as unknown as { windows: Map<string, unknown> }).windows.size;
    assert.ok(belegt <= 4, `nach dem Ablauf duerfen hoechstens 4 Eintraege stehen, es stehen ${belegt}`);
  });

  it('die Speichergrenze verdraengt in Einfuegereihenfolge', () => {
    // Kein Fenster ist abgelaufen, also greift allein die Groessengrenze. Der
    // Nachweis laeuft ueber den Zaehler: ein verdraengter Schluessel beginnt
    // wieder bei 1, ein erhaltener zaehlt weiter.
    let now = 1_000;
    const limiter = new RateLimiter({ windowMs: 600_000, maxKeys: 2, now: () => now });
    assert.equal(limiter.consume('a', 10).remaining, 9);
    now += 1_000;
    assert.equal(limiter.consume('b', 10).remaining, 9);
    now += 1_000;
    assert.equal(limiter.consume('c', 10).remaining, 9, 'der dritte Schluessel verdraengt den ersten');
    assert.equal(limiter.consume('b', 10).remaining, 8, 'der zweite Schluessel zaehlt weiter: er wurde nicht verdraengt');
    assert.equal(limiter.consume('c', 10).remaining, 8, 'der dritte zaehlt ebenfalls weiter');
    // 'a' wurde verdraengt: nach erneutem Zugriff beginnt er wieder bei 1.
    assert.equal(limiter.consume('a', 10).remaining, 9, 'der verdraengte Schluessel beginnt wieder bei eins');
  });

  it('genau an der Fenstersgrenze beginnt ein neues Fenster', () => {
    // Die Bedingung ist `now - startedAt >= windowMs`. Der Randfall:
    // genau windowMs ist **neues** Fenster, eine Millisekunde vorher nicht.
    let now = 1_000;
    const limiter = new RateLimiter({ windowMs: 60_000, now: () => now });
    assert.equal(limiter.consume('k', 2).remaining, 1);
    now = 1_000 + 59_999;
    assert.equal(limiter.consume('k', 2).remaining, 0, '59,999 s nach Fensterbeginn ist noch dasselbe Fenster');
    now = 1_000 + 60_000;
    assert.equal(limiter.consume('k', 2).remaining, 1, 'genau 60 s nach Fensterbeginn ist ein neues Fenster');
  });

  it('retryAfterSeconds ist mindestens 1 und rundet auf', () => {
    // `Math.max(1, Math.ceil(...))`: bei 0 Rest waere 0 die Antwort, was
    // einem Client sagt "jetzt erneut versuchen" und ihn in eine Schleife
    // schickt.
    let now = 1_000;
    const limiter = new RateLimiter({ windowMs: 1_500, now: () => now });
    const r = limiter.consume('k', 1);
    assert.equal(r.retryAfterSeconds, 2, '1,5 s Fenster, sofort geprueft: aufwaerts auf 2');
    now = 1_000 + 1_400;
    assert.equal(limiter.consume('k', 1).retryAfterSeconds, 1, '100 ms Rest bleiben 1 s, nicht 0');
  });
});

describe('Eingabegrenzen des Präsentationsparsers an der Kante', () => {
  it('genau MAX_VP_TOKEN_CHARS ist erlaubt, ein Zeichen mehr nicht', () => {
    // `vpTokenLimitError` war an den Grenzen unbedeckt (Zeilen 83-90). Der
    // Vergleich ist `>`, nicht `>=`.
    const token = (laenge: number): string => 'a'.repeat(laenge);
    const vp = (t: string): Record<string, unknown> => ({ pid: [t] });
    assert.equal(vpTokenLimitError('g', vp(token(MAX_VP_TOKEN_CHARS))), undefined);
    assert.equal(vpTokenLimitError('g', vp(token(MAX_VP_TOKEN_CHARS + 1))), 'vp_token_too_long');
  });

  it('genau MAX_DISCLOSURES ist erlaubt, eine mehr nicht', () => {
    // Der Parser zaehlt die gefuellten Teile zwischen issuer-jwt und kb-jwt.
    // Leere Teile zaehlen nicht, sonst wuerde ein Token mit Doppeltilde
    // faelschlich abgelehnt. `slice(1, -1)` nimmt die beiden Endte weg,
    // `filter` laesst nur die gefuellten.
    const vp = (t: string): Record<string, unknown> => ({ pid: [t] });
    const disclosure = (n: number): string => `head~${Array.from({ length: n }, (_, i) => `d${i}`).join('~')}~kb`;
    assert.equal(vpTokenLimitError('g', vp(disclosure(MAX_DISCLOSURES))), undefined, 'genau an der Grenze muss durchgehen');
    assert.equal(vpTokenLimitError('g', vp(disclosure(MAX_DISCLOSURES + 1))), 'too_many_disclosures');
    // Gegenprobe fuer den Leerfilter: dieselbe Zahl an Disclosures, aber mit
    // leeren Teilen dazwischen. Wuerden die mitgezaehlt, waere das abgelehnt.
    assert.equal(vpTokenLimitError('g', vp(disclosure(MAX_DISCLOSURES).replaceAll('~', '~~'))), undefined);
  });

  it('genau MAX_STATE_CHARS ist erlaubt, ein Zeichen mehr nicht', () => {
    const vp = { pid: ['x'] };
    assert.equal(vpTokenLimitError('s'.repeat(MAX_STATE_CHARS), vp), undefined);
    assert.equal(vpTokenLimitError('s'.repeat(MAX_STATE_CHARS + 1), vp), 'state_invalid');
    assert.equal(vpTokenLimitError('', vp), 'state_invalid');
  });

  it('vp_token muss genau einen Schluessel mit genau einer Praesentation haben', () => {
    // Formfehler, die sonst als 500 durchgehen wuerden.
    assert.equal(vpTokenLimitError('g', { pid: [], wc: [] }), 'vp_token_invalid', 'zwei Schluessel');
    assert.equal(vpTokenLimitError('g', { pid: [] }), 'vp_token_invalid', 'leere Liste');
    assert.equal(vpTokenLimitError('g', { pid: ['a', 'b'] }), 'vp_token_invalid', 'zwei Praesentationen');
    assert.equal(vpTokenLimitError('g', { pid: [1] }), 'vp_token_invalid', 'kein String');
    assert.equal(vpTokenLimitError('g', []), 'vp_token_invalid', 'Array statt Objekt');
    assert.equal(vpTokenLimitError('g', null), 'vp_token_invalid', 'null');
  });

  it('genau MAX_CLAIMS ist erlaubt, eine mehr nicht', () => {
    assert.doesNotThrow(() => validateClaims(Array.from({ length: MAX_CLAIMS }, () => 'given_name')));
    assert.throws(() => validateClaims(Array.from({ length: MAX_CLAIMS + 1 }, () => 'given_name')), ServiceInputError);
    assert.throws(() => validateClaims([]), ServiceInputError);
  });

  it('vct an beiden Enden der Zeichenvorratgrenze', () => {
    assert.doesNotThrow(() => validateVct('a'));
    assert.throws(() => validateVct(''), ServiceInputError);
    assert.throws(() => validateVct(' '.repeat(5)), ServiceInputError, 'Steuerzeichen und Leerzeichen sind nicht im VCT-Vorrat');
  });
});

describe('Datenminimierung: nur angefragte Claims kommen durch', () => {
  it('ein nicht angefragtes Feld faellt raus, egal wie es im Credential stand', () => {
    // Die eigentliche Aufgabe von `nurAngefragteClaims`. Der Nachweis deckt
    // Klartext und unbekannte Namen ab; Hashes koennen ohne Offenlegung
    // keinen Wert liefern und sind damit nicht betroffen.
    const gefiltert = nurAngefragteClaims(
      { given_name: 'Ada', family_name: 'Lovelace', secret_note: 'intern', _age: 42 },
      ['given_name'],
    );
    assert.deepEqual(Object.keys(gefiltert), ['given_name']);
  });

  it('mehrere angefragte Claims kommen vollstaendig durch', () => {
    const gefiltert = nurAngefragteClaims({ given_name: 'Ada', family_name: 'Lovelace', x: 1 }, ['given_name', 'family_name']);
    assert.deepEqual(gefiltert, { given_name: 'Ada', family_name: 'Lovelace' });
  });

  it('ohne Anfrageliste bleibt nichts uebrig', () => {
    assert.deepEqual(nurAngefragteClaims({ a: 1, b: 2 }, []), {});
  });

  it('ein angefragter Claim, den das Credential nicht liefert, fehlt ohne Fehler', () => {
    // Kein Fehler, keine Null. Ein nicht befuelltes Feld ist kein Fehler, das
    // Ergebnis traegt dann einfach weniger.
    assert.deepEqual(nurAngefragteClaims({ given_name: 'Ada' }, ['given_name', 'birth_date']), { given_name: 'Ada' });
  });

  it('__proto__ in der Anfrageliste erzeugt kein Feld im Ergebnis', () => {
    // Eine Anfrageliste aus Mandantenkonfiguration. Wird sie mit `__proto__`
    // gefuettert, darf daraus kein schreibbares Feld werden. Der Filter baut
    // ein leeres Objekt und traegt nur erlaubte Namen ein.
    const gefiltert = nurAngefragteClaims({ __proto__: 'x', given_name: 'Ada' } as Record<string, unknown>, ['given_name']);
    assert.deepEqual(Object.keys(gefiltert), ['given_name']);
    assert.equal(({} as Record<string, unknown>).given_name, undefined, 'nichts am Prototypen geaendert');
  });
});

describe('Konfigfehler beim Mandanten', () => {
  it('ein kaputtes Anfrageprofil bricht den Mandanten ab, nicht den Dienst', () => {
    // `TenantStore.add` fing den Profilfehler ab undwarf mit Kontext
    // (unbedeckt waren die Zeilen 59-61). Der Mandant darf danach nicht
    // teilweise eingetragen sein.
    const store = new TenantStore();
    assert.throws(
      () => store.add({ id: 'kaputt', name: 'K (TEST)', apiKey: 'test-api-key-profil', requestProfile: { id: 'x', claims: ['nicht_bekannt'] } }),
      /Mandant "kaputt"/,
    );
    // byApiKey liefert undefined statt zu werfen: der Mandant darf nach dem
    // fehlgeschlagenen add nicht auffindbar sein.
    assert.equal(store.byApiKey('test-api-key-profil'), undefined, 'der Mandant darf nicht teilweise eingetragen sein');
  });

  it('Pflichtfelder und Mindestlaenge des Schluessels', () => {
    const store = new TenantStore();
    assert.throws(() => store.add({ id: '  ', name: 'X', apiKey: '12345678' }), /Pflicht/);
    assert.throws(() => store.add({ id: 'ok', name: '   ', apiKey: '12345678' }), /Pflicht/);
    assert.throws(() => store.add({ id: 'ok', name: 'X', apiKey: 'kurz' }), /8 Zeichen/);
  });

  it('nur credentialId "pid" wird unterstuetzt', () => {
    // Wichtig fuer Datenminimierung: ein anderes Credential zu erlauben
    // waere eine Ausweitung, keine Konfiguration.
    const store = new TenantStore();
    assert.throws(
      () => store.add({ id: 'fremd', name: 'X', apiKey: '12345678', requestProfile: { id: 'x', claims: ['given_name'], credentialId: 'lid' } }),
      /credentialId "lid" wird nicht unterst/,
    );
  });

  it('ein unbekanntes Feld im Anfrageprofil wird abgelehnt', () => {
    // Offene Konfiguration: ein Tippfehler im Feldnamen wuerde sonst still
    // ignoriert und der Mandant bekamme ein anderes Profil als gedacht.
    assert.throws(
      () => parseRequestProfile({ claims: ['given_name'], cliams: ['x'] }, 'p'),
      /unbekanntes Feld/,
    );
  });
});
