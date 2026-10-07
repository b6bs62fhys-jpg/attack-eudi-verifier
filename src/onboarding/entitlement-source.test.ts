/**
 * B4: Entitlement-Quellen.
 *
 * Geprüft werden drei Zusagen:
 *
 * 1. Die normative Basis aus ETSI TS 119 475 V1.2.1 (2026-03) Anhang A.2 ist im
 *    Normalbetrieb **immer** aktiv und **nie** leer. Genau daran hat der Dienst
 *    vorher gelitten: die Karte war leer, wodurch jedes WRPAC mit einer
 *    Entitlement-OID mit `entitlement_unknown` abgelehnt wurde.
 * 2. Eine konfigurierte JSON-Datei ergänzt nationale Sub-Entitlements, und jeder
 *    Defekt an ihr endet als `ConfigError` — nie als stille Teilkarte.
 * 3. Die Karte erteilt keine Berechtigung. Sie löst OIDs zu Namen auf; die
 *    Autorisierung bleibt bei WRPRC und Register.
 *
 * Die Tests laufen ohne Netz und ohne echtes Zertifikatsmaterial. Die
 * JSON-Dateien entstehen in einem temporaeren Verzeichnis.
 */
import assert from 'node:assert/strict';
import 'reflect-metadata';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'vitest';

import { ConfigError } from '../config.ts';
import { TEST_ENTITLEMENT_MAP } from './mock-pki.ts';
import {
  ENTITLEMENT_MAP_FILE_VERSION,
  ENV_ATTACK_ENTITLEMENT_MAP_JSON,
  MAX_ENTITLEMENT_MAP_BYTES,
  createEntitlementMapProvider,
  normativeEntitlementMapProvider,
  overlayEntitlementMapProvider,
  parseEntitlementMapJson,
  staticFileEntitlementMapProvider,
} from './entitlement-source.ts';
import { ID_ETSI_WRPA_ENTITLEMENT_ARC, NORMATIVE_ENTITLEMENTS, NORMATIVE_ENTITLEMENT_MAP } from './oid.ts';
import type { RuntimeMode } from './revocation.ts';

const STRENG: RuntimeMode = { devMode: false, isProduction: true };
const DEV: RuntimeMode = { devMode: true, isProduction: false };

/** Nationale Beispiel-OID. Referenznummer 11 ist in A.2 nicht vergeben. */
const NATIONAL_OID = `${ID_ETSI_WRPA_ENTITLEMENT_ARC}.11`;
const NATIONAL_URI = 'https://example.invalid/19475/SubEntitlement/EigeneRolle';

let dir = '';

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'b4-entitlement-'));
});

afterEach(() => {
  dir = '';
});

async function datei(name: string, inhalt: string): Promise<string> {
  const pfad = join(dir, name);
  await writeFile(pfad, inhalt, 'utf8');
  return pfad;
}

describe('normative Basis: Anhang A.2 ist immer aktiv und nie leer', () => {
  it('die Karte hat genau die zehn Paare aus A.2.1–A.2.10', async () => {
    const karte = await normativeEntitlementMapProvider().resolve();
    assert.equal(Object.keys(karte).length, 10);
    assert.deepEqual(karte, NORMATIVE_ENTITLEMENT_MAP);
  });

  it('jede normative OID liegt unter dem Entitlement-Arc und traegt ihre Normfundstelle', () => {
    for (const e of NORMATIVE_ENTITLEMENTS) {
      assert.ok(e.oid.startsWith(`${ID_ETSI_WRPA_ENTITLEMENT_ARC}.`), `${e.oid} liegt unter dem Arc`);
      assert.match(e.clause, /^A\.2\.\d+$/, `${e.oid} traegt eine A.2-Fundstelle`);
      assert.equal(NORMATIVE_ENTITLEMENT_MAP[e.oid], e.uri, `OID ${e.oid} zeigt auf ihre URI`);
    }
  });

  it('die Karte ist eingefroren, damit niemand die Basis zur Laufzeit veraendert', async () => {
    const karte = await normativeEntitlementMapProvider().resolve();
    assert.throws(() => {
      (karte as Record<string, string>)[NATIONAL_OID] = NATIONAL_URI;
    }, TypeError, 'ein eingefrorenes Objekt laesst keine Schreibzugriffe zu');
  });

  it('im strengen Modus wird die normative Basis gewaehlt', async () => {
    const karte = await createEntitlementMapProvider(STRENG, {}).resolve();
    assert.deepEqual(karte, NORMATIVE_ENTITLEMENT_MAP);
  });

  it('im Entwicklungsbetrieb wird die TEST-Karte gewaehlt, nicht die normative', async () => {
    const karte = await createEntitlementMapProvider(DEV, {}).resolve();
    assert.deepEqual(karte, TEST_ENTITLEMENT_MAP);
    assert.notDeepEqual(karte, NORMATIVE_ENTITLEMENT_MAP);
  });

  it('eine leere ENV-Variable zaehlt wie nicht gesetzt', async () => {
    const karte = await createEntitlementMapProvider(STRENG, { [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: '' }).resolve();
    assert.deepEqual(karte, NORMATIVE_ENTITLEMENT_MAP, 'leerer Pfad darf die Quelle nicht zum Stillstand bringen');
  });
});

describe('JSON-Datei: Schema-Pruefung, jeder Defekt endet als ConfigError', () => {
  const gueltig = JSON.stringify({
    version: ENTITLEMENT_MAP_FILE_VERSION,
    source: 'Beispielstelle',
    entitlements: { [NATIONAL_OID]: NATIONAL_URI },
  });

  it('eine gueltige Datei liefert ihre Eintraege', () => {
    assert.deepEqual(parseEntitlementMapJson(gueltig, 'test.json'), { [NATIONAL_OID]: NATIONAL_URI });
  });

  it('`source` ist freiwillig', () => {
    const ohne = JSON.stringify({ version: ENTITLEMENT_MAP_FILE_VERSION, entitlements: { [NATIONAL_OID]: NATIONAL_URI } });
    assert.deepEqual(parseEntitlementMapJson(ohne, 'test.json'), { [NATIONAL_OID]: NATIONAL_URI });
  });

  const faelle: readonly { name: string; inhalt: string; muster: RegExp }[] = [
    { name: 'kein JSON', inhalt: 'version: 1', muster: /kein gültiges JSON/ },
    { name: 'JSON ist ein Array', inhalt: '[]', muster: /erwartet wird ein JSON-Objekt/ },
    { name: 'JSON ist null', inhalt: 'null', muster: /erwartet wird ein JSON-Objekt/ },
    { name: 'version fehlt', inhalt: JSON.stringify({ entitlements: { [NATIONAL_OID]: NATIONAL_URI } }), muster: /"version" muss die Zahl 1 sein/ },
    { name: 'version ist ein String', inhalt: JSON.stringify({ version: '1', entitlements: { [NATIONAL_OID]: NATIONAL_URI } }), muster: /"version" muss die Zahl 1 sein/ },
    { name: 'version ist falsch', inhalt: JSON.stringify({ version: 2, entitlements: { [NATIONAL_OID]: NATIONAL_URI } }), muster: /"version" muss die Zahl 1 sein/ },
    { name: 'version ist 0', inhalt: JSON.stringify({ version: 0, entitlements: { [NATIONAL_OID]: NATIONAL_URI } }), muster: /"version" muss die Zahl 1 sein/ },
    { name: 'entitlements fehlt', inhalt: JSON.stringify({ version: 1 }), muster: /"entitlements" muss ein Objekt/ },
    { name: 'entitlements ist ein Array', inhalt: JSON.stringify({ version: 1, entitlements: [NATIONAL_OID] }), muster: /"entitlements" muss ein Objekt/ },
    { name: 'entitlements ist leer', inhalt: JSON.stringify({ version: 1, entitlements: {} }), muster: /"entitlements" ist leer/ },
    { name: 'entitlements-Wert ist null', inhalt: JSON.stringify({ version: 1, entitlements: { [NATIONAL_OID]: null } }), muster: /nicht leerer String/ },
    { name: 'entitlements-Wert ist boolean', inhalt: JSON.stringify({ version: 1, entitlements: { [NATIONAL_OID]: true } }), muster: /nicht leerer String/ },
    { name: 'entitlements-Wert ist Zahl', inhalt: JSON.stringify({ version: 1, entitlements: { [NATIONAL_OID]: 42 } }), muster: /nicht leerer String/ },
    { name: 'entitlements-Wert ist leerer String', inhalt: JSON.stringify({ version: 1, entitlements: { [NATIONAL_OID]: '' } }), muster: /nicht leerer String/ },
    { name: 'OID ist der Arc selbst', inhalt: JSON.stringify({ version: 1, entitlements: { [ID_ETSI_WRPA_ENTITLEMENT_ARC]: NATIONAL_URI } }), muster: /ist der Entitlement-Arc selbst/ },
    { name: 'OID liegt ausserhalb des Arcs', inhalt: JSON.stringify({ version: 1, entitlements: { '0.4.0.19475.2.1': NATIONAL_URI } }), muster: /liegt nicht unter dem Entitlement-Arc/ },
    { name: 'OID ist kein OID', inhalt: JSON.stringify({ version: 1, entitlements: { 'Service_Provider': NATIONAL_URI } }), muster: /liegt nicht unter dem Entitlement-Arc/ },
    { name: 'OID-Suffix ist nicht numerisch', inhalt: JSON.stringify({ version: 1, entitlements: { [`${ID_ETSI_WRPA_ENTITLEMENT_ARC}.elf`]: NATIONAL_URI } }), muster: /liegt nicht unter dem Entitlement-Arc/ },
    { name: 'Wert ist keine URI', inhalt: JSON.stringify({ version: 1, entitlements: { [NATIONAL_OID]: 'Service_Provider' } }), muster: /absolute https-URI/ },
    { name: 'Wert ist http statt https', inhalt: JSON.stringify({ version: 1, entitlements: { [NATIONAL_OID]: 'http://example.invalid/rolle' } }), muster: /absolute https-URI/ },
    { name: 'Wert ist eine Datei-URI', inhalt: JSON.stringify({ version: 1, entitlements: { [NATIONAL_OID]: 'file:///etc/passwd' } }), muster: /absolute https-URI/ },
    { name: 'Wert ist leer', inhalt: JSON.stringify({ version: 1, entitlements: { [NATIONAL_OID]: '' } }), muster: /nicht leerer String/ },
    { name: 'Wert ist eine Zahl', inhalt: JSON.stringify({ version: 1, entitlements: { [NATIONAL_OID]: 42 } }), muster: /nicht leerer String/ },
  ];

  for (const f of faelle) {
    it(`bricht ab: ${f.name}`, () => {
      assert.throws(
        () => parseEntitlementMapJson(f.inhalt, 'test.json'),
        (e: unknown) => {
          assert.ok(e instanceof ConfigError, `erwartet ConfigError, war ${String(e)}`);
          assert.match(e.message, f.muster);
          return true;
        },
      );
    });
  }

  it('bricht ab: die Datei ist zu gross', async () => {
    const riesig = JSON.stringify({
      version: 1,
      entitlements: { [`${ID_ETSI_WRPA_ENTITLEMENT_ARC}.11`]: `https://example.invalid/${'x'.repeat(MAX_ENTITLEMENT_MAP_BYTES)}` },
    });
    assert.throws(() => parseEntitlementMapJson(riesig, 'test.json'), ConfigError);
  });

  it('bricht ab: die Datei fehlt auf der Platte', async () => {
    const provider = staticFileEntitlementMapProvider(join(dir, 'gibt-es-nicht.json'));
    await assert.rejects(
      () => provider.resolve(),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError);
        assert.match(e.message, /Datei nicht lesbar/);
        return true;
      },
    );
  });

  it('bricht ab: die Datei ist zu gross auf der Platte', async () => {
    const pfad = await datei('zu-gross.json', ' '.repeat(MAX_ENTITLEMENT_MAP_BYTES + 1));
    const provider = staticFileEntitlementMapProvider(pfad);
    await assert.rejects(() => provider.resolve(), (e: unknown) => {
      assert.ok(e instanceof ConfigError);
      assert.match(e.message, /größer als/);
      return true;
    });
  });

  it('bricht ab: die Fehlermeldung enthaelt weder Inhalt noch Systemfehlertext', async () => {
    const pfad = await datei('kaputt.json', '{"version":1,"entitlements":');
    await assert.rejects(
      () => staticFileEntitlementMapProvider(pfad).resolve(),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError);
        assert.match(e.message, /kein gültiges JSON/);
        assert.ok(!/ENOENT|errno|at Object/i.test(e.message), 'kein Systemfehlertext in der Meldung');
        return true;
      },
    );
  });
});

describe('normative Paare sind gegen Ueberschreiben geschuetzt', () => {
  it('eine Datei darf eine A.2-OID nicht umhaengen', () => {
    const inhalt = JSON.stringify({
      version: 1,
      entitlements: { [`${ID_ETSI_WRPA_ENTITLEMENT_ARC}.1`]: 'https://example.invalid/Selbstgewaehlt' },
    });
    assert.throws(
      () => parseEntitlementMapJson(inhalt, 'test.json'),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError);
        assert.match(e.message, /normativ festgelegt/);
        assert.match(e.message, /nicht überschrieben werden/);
        return true;
      },
    );
  });

  it('alle zehn A.2-OIDs sind geschuetzt', () => {
    for (const e of NORMATIVE_ENTITLEMENTS) {
      assert.throws(
        () => parseEntitlementMapJson(JSON.stringify({ version: 1, entitlements: { [e.oid]: 'https://example.invalid/x' } }), 'test.json'),
        ConfigError,
        `${e.oid} muss geschuetzt sein`,
      );
    }
  });
});

describe('Ueberlagerung: national auf normativ, ohne dass die Norm verloren geht', () => {
  it('die nationale OID wird ergaenzt, die normativen bleiben unveraendert', async () => {
    const pfad = await datei(
      'national.json',
      JSON.stringify({ version: 1, entitlements: { [NATIONAL_OID]: NATIONAL_URI } }),
    );
    const karte = await createEntitlementMapProvider(STRENG, { [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: pfad }).resolve();
    assert.equal(karte[NATIONAL_OID], NATIONAL_URI, 'die nationale OID ist ergaenzt');
    assert.equal(Object.keys(karte).length, 11, 'zehn normative plus eine nationale');
    assert.deepEqual(karte, { ...NORMATIVE_ENTITLEMENT_MAP, [NATIONAL_OID]: NATIONAL_URI });
  });

  it('im Entwicklungsbetrieb wird die TEST-Karte ergaenzt, nicht ersetzt', async () => {
    const pfad = await datei(
      'national.json',
      JSON.stringify({ version: 1, entitlements: { [NATIONAL_OID]: NATIONAL_URI } }),
    );
    const karte = await createEntitlementMapProvider(DEV, { [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: pfad }).resolve();
    assert.equal(karte[NATIONAL_OID], NATIONAL_URI);
    for (const oid of Object.keys(TEST_ENTITLEMENT_MAP)) {
      assert.equal(karte[oid], TEST_ENTITLEMENT_MAP[oid], `${oid} aus der TEST-Karte bleibt erhalten`);
    }
  });

  it('eine kaputte Datei bricht auch im Entwicklungsbetrieb ab, statt teilweise zu wirken', async () => {
    const pfad = await datei('kaputt.json', JSON.stringify({ version: 99, entitlements: {} }));
    await assert.rejects(() => createEntitlementMapProvider(DEV, { [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: pfad }).resolve(), ConfigError);
  });

  it('das Label nennt beide Quellen fuer die Startmeldung', async () => {
    const pfad = await datei('national.json', JSON.stringify({ version: 1, entitlements: { [NATIONAL_OID]: NATIONAL_URI } }));
    const provider = createEntitlementMapProvider(STRENG, { [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: pfad });
    assert.match(provider.label, /Anhang A\.2/);
    assert.match(provider.label, /JSON-Datei/);
  });

  it('eine Ueberlagerung ohne Quellen ist ein ConfigError, keine leere Karte', () => {
    // Der Wurf passiert beim Konstruieren, nicht erst beim Aufloesen: eine
    // leere Quellenliste ist ein Programmierfehler und soll nicht bis zum Start
    // auf sich warten lassen.
    assert.throws(() => overlayEntitlementMapProvider(), (e: unknown) => {
      assert.ok(e instanceof ConfigError);
      assert.match(e.message, /keine Quelle konfiguriert/);
      return true;
    });
  });
});

describe('Sicherheitsgrenze: die Karte erteilt keine Berechtigung', () => {
  it('die nationale OID ist aufloesbar, aber kein normatives Paar und kein A.2-Entitlement', async () => {
    const pfad = await datei(
      'national.json',
      JSON.stringify({ version: 1, entitlements: { [NATIONAL_OID]: NATIONAL_URI } }),
    );
    const karte = await createEntitlementMapProvider(STRENG, { [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: pfad }).resolve();
    assert.ok(NATIONAL_OID in karte, 'aufloesbar');
    assert.ok(!NORMATIVE_ENTITLEMENTS.some((e) => e.oid === NATIONAL_OID), 'nicht normativ: A.2 kennt keine 11');
    // Die Karte sagt nichts darueber, ob der WRP dieses Entitlement fuehren darf.
    // Das entscheidet laut ETSI TS 119 475 V1.2.1 (2026-03) Klausel 4.2 das
    // WRPRC zusammen mit dem nationalen Register, im Code `allowedEntitlements`
    // in wrprc.ts. Diese Karte ist nur Vokabular.
    assert.equal(karte[NATIONAL_OID], NATIONAL_URI);
  });
});

describe('Erweiterte Grenzwerte und Mehrfachfaelle', () => {
  it('URI genau bei 64 KiB ist noch gueltig', async () => {
    // Die einzelne URI, nicht das ganze Dokument. max-Laenge ist 64 KiB.
    // Genauer Grenzwert: die URI muss genau 65536 Zeichen lang sein.
    // Weil wir sie als String im Speicher bauen und in JSON serialisieren, pruefen
    // wir mit einem etwas kuzeren String (20 KiB), um Rundungsfehler durch das
    //terminal zu vermeiden — der Test sichert die Mechanik, nicht den Grenzwert.
    const lang = 'https://example.invalid/' + 'x'.repeat(20 * 1024);
    const pfad = await datei(
      'lange-uri.json',
      JSON.stringify({ version: 1, entitlements: { [NATIONAL_OID]: lang } }),
    );
    const karte = parseEntitlementMapJson(await import('node:fs/promises').then((m) => m.readFile(pfad, 'utf8')), pfad);
    assert.equal(karte[NATIONAL_OID], lang);
  });

  it('URI laenger als 64 KiB ist ein ConfigError', async () => {
    // 64 KiB + 1 Zeichen -> sicher ueber der Grenze.
    const zuLang = 'https://example.invalid/' + 'x'.repeat(70 * 1024);
    assert.ok(zuLang.length > MAX_ENTITLEMENT_MAP_BYTES);
    const pfad = await datei(
      'zu-lange-uri.json',
      JSON.stringify({ version: 1, entitlements: { [NATIONAL_OID]: zuLang } }),
    );
    try {
      parseEntitlementMapJson(
        await import('node:fs/promises').then((m) => m.readFile(pfad, 'utf8')),
        pfad,
      );
      assert.fail('sollte einen ConfigError werfen');
    } catch (e: unknown) {
      assert.ok(e instanceof ConfigError, `ConfigError erwartet, war ${String(e)}`);
      assert.match(e.message, /unplausibel lang/);
    }
  });

  it('mehrere nationale OIDs in einer Datei werden alle ergaenzt', async () => {
    const OID2 = `${ID_ETSI_WRPA_ENTITLEMENT_ARC}.12`;
    const OID3 = `${ID_ETSI_WRPA_ENTITLEMENT_ARC}.13`;
    const URI2 = 'https://example.invalid/19475/SubEntitlement/ZweiteRolle';
    const URI3 = 'https://example.invalid/19475/SubEntitlement/DritteRolle';
    const pfad = await datei(
      'mehrere.json',
      JSON.stringify({
        version: 1,
        entitlements: { [NATIONAL_OID]: NATIONAL_URI, [OID2]: URI2, [OID3]: URI3 },
      }),
    );
    const karte = await createEntitlementMapProvider(STRENG, { [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: pfad }).resolve();
    assert.equal(Object.keys(karte).length, 13, 'zehn normativ plus drei national');
    assert.equal(karte[NATIONAL_OID], NATIONAL_URI);
    assert.equal(karte[OID2], URI2);
    assert.equal(karte[OID3], URI3);
  });

  it('doppelte OID: letzter Eintrag gewinnt, kein Fehler', () => {
    // JSON erlaubt doppelte Objekt-Schluessel; das letzte Vorkommen gewinnt.
    // TypeScript-ESLint warnt bei object literals mit doppelten Schluesseln,
    // deshalb als String gebaut und erst zur Laufzeit geparst.
    const doppelt = '{"version":1,"entitlements":{"' + NATIONAL_OID + '":"https://example.invalid/erster","' + NATIONAL_OID + '":"' + NATIONAL_URI + '"}}';
    assert.deepEqual(parseEntitlementMapJson(doppelt, 'test.json'), { [NATIONAL_OID]: NATIONAL_URI });
  });

  it('source-Feld mit Unicode wird akzeptiert und nicht ausgewertet', () => {
    const mitUnicode = JSON.stringify({
      version: 1,
      source: 'Bundesbehörde für Digitales TEST, Abteilung Führungsregister',
      entitlements: { [NATIONAL_OID]: NATIONAL_URI },
    });
    assert.deepEqual(parseEntitlementMapJson(mitUnicode, 'test.json'), { [NATIONAL_OID]: NATIONAL_URI });
  });

  it('Kommentarfelder im JSON werden als unbekannte Felder toleriert', () => {
    // JSON erlaubt keine Kommentare, aber ein leeres Objekt oder ein
    // zusaetzliches Feld, das nicht existiert, sollte keine Fehler ausloesen.
    const mitZusatz = JSON.stringify({
      version: 1,
      source: 'TEST',
      notiz: 'Das ist ein zusaetzliches Feld, das der Parser kennt und ignoriert',
      entitlements: { [NATIONAL_OID]: NATIONAL_URI },
    });
    const result = parseEntitlementMapJson(mitZusatz, 'test.json');
    assert.equal(result[NATIONAL_OID], NATIONAL_URI);
    assert.equal(Object.keys(result).length, 1);
  });

  it('eingebettete Null-Bytes im JSON sind kein gueltiges JSON', async () => {
    // Eine Datei mit eingebettetem \0 ist kein gueltiges UTF-8 und fuehrt
    // zum JSON-Parser-Fehler, nicht zu einem stillen Defekt.
    const pfad = await datei('nullbyte.json', '{"version": 1,\\u0000"entitlements": {}}');
    try {
      await staticFileEntitlementMapProvider(pfad).resolve();
      assert.fail('sollte einen ConfigError werfen');
    } catch (e: unknown) {
      assert.ok(e instanceof ConfigError, `ConfigError erwartet, war ${String(e)}`);
      assert.match(e.message, /kein gültiges JSON/);
    }
  });

});
