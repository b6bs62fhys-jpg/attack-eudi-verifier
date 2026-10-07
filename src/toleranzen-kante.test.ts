/**
 * Kanten der Toleranzen: festschreibend, nicht ausbauend.
 *
 * Dieses Dokument ist der Ausgangspunkt der Arbeit, keine Ergänzung. Die
 * Grenzfälle der Zertifikatsprüfung sind in `src/onboarding/gueltigkeit.test.ts`
 * ausführlich belegt. Hier stehen die **übrigen** Toleranzen, die bis jetzt
 * keinen Kantentest hatten — und zwar an genau den Stellen, an denen eine
 * erzwungene Zahl (60) und nicht der zentrale Wert steht.
 *
 * Grund der Aufteilung: Die Bindung von `ALLOWED_SKEW_SECONDS`,
 * `TokenStatusListChecker`, `CrlRevocationChecker` und `OcspRevocationChecker`
 * an `DEFAULT_CLOCK_SKEW_SECONDS` ändert **kein** Verhalten, wenn beide 60
 * sind. Genau deshalb ist ein Test nötig, der vorher grün ist und nachher rot
 * würde, falls jemand die Zahl über den zentralen Wert hinaus verändert.
 *
 * Alle Zeitpunkte kommen aus einer injizierten Uhr. Kein Test liest die
 * echte Uhr; das ist der Grund, warum diese Tests nicht im Flake-Wächter
 * stehen müssen.
 *
 * Der Abschnitt zu den Konstruktor-Defaults ist bewusst weiß-box: er liest
 * das abgeleitete private Feld. Das ist kein sauberer Test, aber es ist der
 * einzige, der den **Standardwert** eines Objekts festnagelt, ohne für
 * CRL, OCSP und Statusliste je eine volle ASN.1- bzw. JOSE-Fixture zu bauen.
 * Der Standardwert ist genau das, was hier geändert wird — der
 * Zeitvergleich selbst ist es nicht.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'vitest';
import 'reflect-metadata';
import { SignJWT, generateKeyPair, exportJWK, type JWK } from 'jose';

import { DEFAULT_CLOCK_SKEW_SECONDS } from './lib/cert-validity.ts';
import { loadConfig, ConfigError, ENV_ATTACK_CLOCK_SKEW_SECONDS } from './config.ts';
import { RegistrarClient, type RegistrarFetcher } from './onboarding/registrar.ts';
import { TokenStatusListChecker } from './service/credential-status.ts';
import { CrlRevocationChecker } from './onboarding/crl-revocation.ts';
import { OcspRevocationChecker } from './onboarding/ocsp-revocation.ts';

/** Heutiger Stand, an allen vier Stellen. Nicht als Sollwert zu lesen. */
const HEUTE_60 = 60;

const env = (wert: string): Record<string, string> => ({ [ENV_ATTACK_CLOCK_SKEW_SECONDS]: wert });

describe('Zentrale Uhrabweichung', () => {
  it('der geteilte Standard ist 60 Sekunden', () => {
    // Wird von mehreren Modulen geteilt. Ändert sich diese Zahl, muss jede
    // nachfolgende Erwartung mitziehen.
    assert.equal(DEFAULT_CLOCK_SKEW_SECONDS, HEUTE_60);
  });

  it('die Umgebungsvariable akzeptiert 0 und die Obergrenze 300', () => {
    // Beide Ränder sind erlaubt. 0 heißt "keine Toleranz".
    assert.equal(loadConfig(env('0')).clockSkewSeconds, 0);
    assert.equal(loadConfig(env('300')).clockSkewSeconds, 300);
  });

  it('die Umgebungsvariable lehnt alles außerhalb und Nichtganzzahliges ab', () => {
    // fail closed: ein unbrauchbarer Wert bricht den Start ab, statt still
    // auf den Standard zurückzufallen.
    for (const wert of ['-1', '301', '1.5', 'abc', 'NaN', 'Infinity', '1e3']) {
      assert.throws(
        () => loadConfig(env(wert)),
        (fehler: unknown) => fehler instanceof ConfigError,
        `${wert} muss abgelehnt werden`,
      );
    }
  });

  it('ohne die Variable gilt der Standard 60', () => {
    assert.equal(loadConfig({}).clockSkewSeconds, HEUTE_60);
    // Leerer String ist wie nicht gesetzt, nicht ein Fehler.
    assert.equal(loadConfig(env('')).clockSkewSeconds, HEUTE_60);
  });
});

describe('Registrar-Antwort (Toleranz für iat in der Zukunft)', () => {
  /** Signiert eine Antwort mit gegebenem iat und ruft sie ab. */
  async function antwortMitIat(iat: number, jetzt: number): Promise<string> {
    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const jwk: JWK = await exportJWK(publicKey);
    const jws = await new SignJWT({ items: [], nextCursor: undefined })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuedAt(iat)
      .sign(privateKey);

    const fetcher: RegistrarFetcher = async () => ({ status: 200, text: async () => jws });
    const client = new RegistrarClient({
      registryUri: 'https://registrar.test/api/v1',
      pinnedPublicJwk: jwk,
      fetcher,
      // Rate-Limit-Bremse ausschalten, damit die Uhrmessung nichts verfälscht.
      minRequestIntervalMs: 0,
      now: () => jetzt,
      // Der Test soll die Zeitgrenze selbst setzen, nicht den Standard.
      maxResponseAgeSeconds: 600,
    });
    return client.getWrpList().then(
      () => 'gueltig',
      (fehler: Error) => fehler.message,
    );
  }

  it('eine Antwort mit iat 60 s in der Zukunft wird angenommen (Kante)', async () => {
    // `age < -ALLOWED_SKEW_SECONDS` aus registrar.ts:214 ist ein striktes `<`,
    // deshalb ist exakt 60 noch erlaubt.
    assert.equal(await antwortMitIat(1_000 + HEUTE_60, 1_000), 'gueltig');
  });

  it('eine Sekunde darüber wird abgelehnt', async () => {
    // `ErrRegistrarStale` aus registrar.ts:214. Der Text ist der belegte
    // Fehlercode des Klienten, nicht der Fehlercode der HTTP-Antwort.
    assert.match(await antwortMitIat(1_000 + HEUTE_60 + 1, 1_000), /nicht mehr aktuell/);
  });

  it('eine Antwort mit iat 60 s in der Vergangenheit wird angenommen (Kante)', async () => {
    // Die Gegenseite ist `maxResponseAgeSeconds`, nicht die Uhrabweichung.
    assert.equal(await antwortMitIat(1_000 - 600, 1_000), 'gueltig');
  });
});

describe('Standard der Prüfer, die die erzwungene Zahl 60 führen', () => {
  /**
   * Liest das abgeleitete private Feld. Siehe Kopfkommentar: das ist der
   * einzige Weg, den Standardwert ohne große Fixture festzuhalten.
   */
  function feld(objekt: object, name: string): number {
    return (objekt as unknown as Record<string, number>)[name];
  }

  it('TokenStatusListChecker steht auf 60', () => {
    const checker = new TokenStatusListChecker({ trustedSigners: () => [] });
    assert.equal(feld(checker, 'clockSkewSeconds'), HEUTE_60);
  });

  it('CrlRevocationChecker steht auf 60 Sekunden, das Feld ist in Millisekunden', () => {
    const checker = new CrlRevocationChecker();
    assert.equal(feld(checker, 'clockSkewMs'), HEUTE_60 * 1000);
  });

  it('OcspRevocationChecker steht auf 60 und rechnet es in Millisekunden um', () => {
    const checker = new OcspRevocationChecker();
    assert.equal(feld(checker, 'clockSkewSeconds'), HEUTE_60);
    assert.equal(feld(checker, 'clockSkewMs'), HEUTE_60 * 1000);
  });

  it('ein gesetzter Wert überschreibt den Standard in allen dreien', () => {
    // Gegenrichtung: der Standard wird nicht benutzt, wenn einer da ist.
    assert.equal(feld(new TokenStatusListChecker({ trustedSigners: () => [], clockSkewSeconds: 7 }), 'clockSkewSeconds'), 7);
    assert.equal(feld(new CrlRevocationChecker({ clockSkewSeconds: 7 }), 'clockSkewMs'), 7000);
    assert.equal(feld(new OcspRevocationChecker({ clockSkewSeconds: 7 }), 'clockSkewSeconds'), 7);
  });
});

describe('Registrar: allowedSkewSeconds als geprüfte Option', () => {
  const basis = async (): Promise<JWK> => {
    const { publicKey } = await generateKeyPair('ES256');
    return (await exportJWK(publicKey)) as JWK;
  };

  it('ohne Angabe gilt derselbe Standard wie zentral, 60', async () => {
    const client = new RegistrarClient({ registryUri: 'https://registrar.test', pinnedPublicJwk: await basis() });
    const wert = (client as unknown as Record<string, number>).allowedSkewSeconds;
    assert.equal(wert, HEUTE_60);
  });

  it('nimmt 0 und die Obergrenze 300 an', async () => {
    for (const wert of [0, 300]) {
      const client = new RegistrarClient({ registryUri: 'https://registrar.test', pinnedPublicJwk: await basis(), allowedSkewSeconds: wert });
      assert.equal((client as unknown as Record<string, number>).allowedSkewSeconds, wert);
    }
  });

  it('lehnt alles außerhalb der Grenze und Nichtganzzahliges beim Aufbau ab', () => {
    // fail closed und im Konstruktor: der Prozess bricht ab, statt die erste
    // Anfrage mit einer stillschweigend zu grossen Toleranz zu beantworten.
    for (const wert of [-1, 301, 1.5, Number.NaN]) {
      assert.throws(
        () => new RegistrarClient({ registryUri: 'https://registrar.test', pinnedPublicJwk: {} as JWK, allowedSkewSeconds: wert }),
        ConfigError,
        `${wert} muss abgelehnt werden`,
      );
    }
  });
});
