/**
 * B3: strukturelle Vorbereitung des Onboarding-Gates.
 *
 * Geprüft wird das Fail-Closed-Verhalten bei fehlendem Material: Der Dienst darf
 * nicht still mit `undefined` durchlaufen, sondern muss den Zustand sprechend
 * melden. Und sobald Material vorhanden ist, muss das Gate ohne Codeänderung
 * entstehen — das ist der Zweck der Vorbereitung.
 *
 * Es wird bewusst **kein** Produktivverhalten verdrahtet: alle Tests nutzen
 * TEST-Material aus `mock-pki.ts` oder injiziertes Material.
 */
import assert from 'node:assert/strict';
import 'reflect-metadata';
import { describe, it } from 'vitest';

import { ConfigError } from '../config.ts';
import { createAccessCa, createWrprcIssuer, createWrprcLeaf, signWrprc, TEST_ENTITLEMENT_MAP, TEST_UNKNOWN_ENTITLEMENT_OID, type AccessCa, type WrprcIssuer } from './mock-pki.ts';
import { ErrTenantRegistrationInvalid } from './errors.ts';
import { ID_ETSI_WRPA_ENTITLEMENT_ARC, NORMATIVE_ENTITLEMENT_MAP, isOidUnder } from './oid.ts';
import { createEntitlementMapProvider, ENV_ATTACK_ENTITLEMENT_MAP_JSON } from './entitlement-source.ts';
import { NO_REVOCATION, type RuntimeMode } from './revocation.ts';
import { OcspRevocationChecker } from './ocsp-revocation.ts';
import {
  describeOnboardingState,
  ENV_ATTACK_ONBOARDING_ACCESS_CA_PEM,
  ENV_ATTACK_ONBOARDING_WRPRC_ISSUER_PEM,
  loadAnchorsPem,
  resolveOnboardingGate,
  type OnboardingMaterial,
} from './onboarding-wiring.ts';
import { TenantStore } from '../service/tenant.ts';

const STRENG = { devMode: false, isProduction: true };
const DEV = { devMode: true, isProduction: false };

function tenants(): TenantStore {
  const store = new TenantStore();
  store.add({ id: 't1', name: 'Test', apiKey: 'test-api-key-b3', requestProfile: { id: 'p', claims: ['given_name'] } });
  return store;
}

async function testMaterial(): Promise<OnboardingMaterial> {
  const accessCa = await createAccessCa('B3 Access CA TEST');
  const wrprc = await createWrprcIssuer('B3 WRPRC Issuer TEST');
  return {
    accessCaAnchors: [accessCa.caCertDer],
    wrprcIssuerAnchors: [new Uint8Array(wrprc.certDer)],
    entitlementMap: TEST_ENTITLEMENT_MAP,
  };
}

/** Zu PEM, 64 Zeichen pro Zeile. `X509Certificate` lehnt PEM mit Leerzeilen ab. */
function toPem(der: Uint8Array): string {
  const zeilen = Buffer.from(der).toString('base64').match(/.{1,64}/g)?.join('\n') ?? '';
  return `-----BEGIN CERTIFICATE-----\n${zeilen}\n-----END CERTIFICATE-----\n`;
}

/** Laufzeitgeneriertes TEST-Ankermaterial fuer die Ende-zu-Ende-Tests. */
async function ankerMaterial(): Promise<{ accessCa: AccessCa; wrprcIssuer: WrprcIssuer }> {
  return { accessCa: await createAccessCa('Entitlement Access CA TEST'), wrprcIssuer: await createWrprcIssuer('Entitlement WRPRC Issuer TEST') };
}

/**
 * Signierter, inhaltlich beliebiger WRPRC.Fuer die Entitlement-Pruefung wird er
 * nicht ausgewertet: `RelyingPartyOnboardingGate.verifyTenant` laesst zuerst
 * `loadWrpac` laufen, und genau dort ist der zu pruefende Pfad. Ein gueltig
 * signierter Token haelt den Test trotzdem realistisch, statt an der
 * Reihenfolge der Pruefungen zu kleben.
 */
async function signierteWrprc(wrprcIssuer: WrprcIssuer): Promise<string> {
  const leaf = await createWrprcLeaf(wrprcIssuer, 'Entitlement WRPRC Signer TEST');
  const chain = [new Uint8Array(leaf.certDer), new Uint8Array(wrprcIssuer.certDer)];
  return signWrprc({ sub: 'wrp-entitlement-test', registryUri: 'https://registrar.example/api/v1', entitlements: [] }, leaf.key.privateKey, chain);
}

/**
 * Baut ein Gate ueber den **echten** Materialpfad: die Anker liegen als
 * PEM-Dateien in einem temporaeren Verzeichnis und werden ueber die
 * Umgebungsvariablen benannt. Nur so wird der Weg geprueft, der auch im Betrieb
 * laeuft — inklusive der Entscheidung ueber die Entitlement-Karte.
 */
async function gateAusEnv(
  config: RuntimeMode,
  material: { accessCa: AccessCa; wrprcIssuer: WrprcIssuer },
  store: TenantStore,
  extraEnv: Record<string, string> = {},
) {
  const { writeFile, mkdtemp } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = await mkdtemp(join(tmpdir(), 'b3-entitlement-'));
  const accessPath = join(dir, 'access-ca.pem');
  const wrprcPath = join(dir, 'wrprc.pem');
  await writeFile(accessPath, toPem(material.accessCa.caCertDer));
  await writeFile(wrprcPath, toPem(new Uint8Array(material.wrprcIssuer.certDer)));
  return resolveOnboardingGate({
    config,
    env: {
      [ENV_ATTACK_ONBOARDING_ACCESS_CA_PEM]: accessPath,
      [ENV_ATTACK_ONBOARDING_WRPRC_ISSUER_PEM]: wrprcPath,
      ...extraEnv,
    },
    revocation: new OcspRevocationChecker(),
    tenants: store,
  });
}

describe('B3: fehlendes Material (fail closed statt stillem undefined)', () => {
  it('ohne Umgebungsvariablen -> kein Gate, kein Abbruch, aber sprechender Zustand', async () => {
    const gate = await resolveOnboardingGate({ config: STRENG, env: {}, revocation: new OcspRevocationChecker(), tenants: tenants() });
    assert.equal(gate, undefined, 'ohne Material wird kein Gate gebaut');
    const zustand = describeOnboardingState({ gate: undefined });
    assert.match(zustand, /NICHT aktiv/);
    assert.ok(zustand.includes(ENV_ATTACK_ONBOARDING_ACCESS_CA_PEM), 'nennt die zu setzende Variable');
    assert.ok(zustand.includes(ENV_ATTACK_ONBOARDING_WRPRC_ISSUER_PEM));
    assert.ok(!/-----BEGIN|serialNumber|CN=/.test(zustand), 'keine Zertifikatsdaten in der Meldung');
  });

  it('nur eine der beiden Variablen gesetzt -> kein Gate, Zustand nennt den Grund', async () => {
    const gate = await resolveOnboardingGate({
      config: STRENG,
      env: { [ENV_ATTACK_ONBOARDING_ACCESS_CA_PEM]: '/nicht/da.pem' },
      revocation: new OcspRevocationChecker(),
      tenants: tenants(),
    });
    assert.equal(gate, undefined);
  });

  it('required=true mit fehlendem Material -> ConfigError statt stillem Durchlaufen', async () => {
    await assert.rejects(
      () => resolveOnboardingGate({ config: STRENG, env: {}, revocation: new OcspRevocationChecker(), tenants: tenants(), required: true }),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError, `ConfigError erwartet, war ${String(e)}`);
        assert.match(e.message, /Onboarding-Material/);
        return true;
      },
    );
  });

  it('required=true mit halbem Material -> ConfigError mit beiden Variablennamen', async () => {
    const material = await testMaterial();
    await assert.rejects(
      () =>
        resolveOnboardingGate({
          config: STRENG,
          env: {},
          revocation: new OcspRevocationChecker(),
          tenants: tenants(),
          required: true,
          loadMaterial: async () => ({ ...material, wrprcIssuerAnchors: [] }),
        }),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError);
        assert.match(e.message, /ATTACK_ONBOARDING_ACCESS_CA_PEM/);
        assert.match(e.message, /ATTACK_ONBOARDING_WRPRC_ISSUER_PEM/);
        return true;
      },
    );
  });
});

describe('B3: Sperrquelle wird unabhaengig vom Material fail closed geprueft', () => {
  it('NO_REVOCATION in Produktion bricht ab, auch wenn kein Gate entsteht', async () => {
    // Sonst koennte NO_REVOCATION unbemerkt durchrutschen und spaeter, sobald
    // Material nachwächst, eine ungepruefte Kette akzeptieren.
    await assert.rejects(
      () => resolveOnboardingGate({ config: STRENG, env: {}, revocation: NO_REVOCATION, tenants: tenants() }),
      (e: unknown) => {
        assert.ok(e instanceof ConfigError);
        assert.match(e.message, /Sperrprüfung ist abgeschaltet/);
        return true;
      },
    );
  });

  it('NO_REVOCATION mit Entwicklungsschalter ist erlaubt (Gegenprobe)', async () => {
    const gate = await resolveOnboardingGate({ config: DEV, env: {}, revocation: NO_REVOCATION, tenants: tenants() });
    assert.equal(gate, undefined);
  });

  it('echte OCSP-Pruefung wird akzeptiert (Gegenprobe)', async () => {
    const gate = await resolveOnboardingGate({ config: STRENG, env: {}, revocation: new OcspRevocationChecker(), tenants: tenants() });
    assert.equal(gate, undefined, 'ohne Material weiterhin kein Gate, aber keine Ablehnung der Sperrquelle');
  });
});

describe('B3: mit Material entsteht das Gate ohne Codeaenderung', () => {
  it('injiziertes TEST-Material -> Gate wird gebaut und beschreibt sich als aktiv', async () => {
    const material = await testMaterial();
    const gate = await resolveOnboardingGate({
      config: STRENG,
      env: {},
      revocation: new OcspRevocationChecker(),
      tenants: tenants(),
      loadMaterial: async () => material,
    });
    assert.ok(gate, 'mit Material muss ein Gate entstehen');
    assert.equal(typeof gate.verifyTenant, 'function');
    const zustand = describeOnboardingState({ gate });
    assert.match(zustand, /aktiv/);
    assert.ok(!/-----BEGIN|serialNumber/.test(zustand), 'keine Zertifikatsdaten in der Meldung');
  });

  it('PEM-Dateien aus der Umgebung werden gelesen und erzeugen ein Gate', async () => {
    const material = await testMaterial();
    const { writeFile, mkdtemp } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = await mkdtemp(join(tmpdir(), 'b3-'));
    const accessPath = join(dir, 'access-ca.pem');
    const wrprcPath = join(dir, 'wrprc.pem');
    const toPem = (der: Uint8Array): string => {
      // 64 Zeichen pro Zeile, ohne führendes/.abschließendes Leerzeichen:
      // `X509Certificate` lehnt PEM mit zusätzlichen Leerzeilen ab.
      const zeilen = Buffer.from(der).toString('base64').match(/.{1,64}/g)?.join('\n') ?? '';
      return `-----BEGIN CERTIFICATE-----\n${zeilen}\n-----END CERTIFICATE-----\n`;
    };
    await writeFile(accessPath, toPem(material.accessCaAnchors[0] as Uint8Array));
    await writeFile(wrprcPath, toPem(material.wrprcIssuerAnchors[0] as Uint8Array));

    const gate = await resolveOnboardingGate({
      config: STRENG,
      env: { [ENV_ATTACK_ONBOARDING_ACCESS_CA_PEM]: accessPath, [ENV_ATTACK_ONBOARDING_WRPRC_ISSUER_PEM]: wrprcPath },
      revocation: new OcspRevocationChecker(),
      tenants: tenants(),
    });
    assert.ok(gate, 'PEM-Dateien muessen ein Gate erzeugen');
  });
});

describe('B3: PEM-Leser', () => {
  it('nicht lesbare Datei -> ConfigError mit Variablennamen', async () => {
    await assert.rejects(() => loadAnchorsPem('/gibt/es/nicht.pem', 'TEST_PEM'), (e: unknown) => {
      assert.ok(e instanceof ConfigError);
      assert.match(e.message, /TEST_PEM: Datei nicht lesbar/);
      return true;
    });
  });

  it('Datei ohne Zertifikat -> ConfigError', async () => {
    const { writeFile, mkdtemp } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = await mkdtemp(join(tmpdir(), 'b3-leer-'));
    const p = join(dir, 'leer.pem');
    await writeFile(p, 'kein Zertifikat hier');
    await assert.rejects(() => loadAnchorsPem(p, 'TEST_PEM'), (e: unknown) => {
      assert.ok(e instanceof ConfigError);
      assert.match(e.message, /keine Zertifikate gefunden/);
      return true;
    });
  });
});

/**
 * Regression: Die TEST-Entitlement-Karte aus `mock-pki.ts` war ueber den
 * Standard-Materialpfad verdrahtet und damit auch im normalen Betrieb aktiv.
 * Sie deckt nur vier OIDs aus ETSI TS 119 475 Anhang A.2 ab. Ein WRPAC mit
 * jeder anderen OID unter dem Entitlement-Arc wurde dadurch stillschweigend
 * abgelehnt, ohne dass der Betrieb die Ursache benennen konnte.
 *
 * Erwartetes Verhalten: die Karte greift ausschliesslich im ausdruecklichen
 * Test- und Demo-Betrieb (`ATTACK_DEV_MODE=true`). Sonst gilt die normative
 * Basis aus Anhang A.2, und ein WRPAC mit einer OID ausserhalb jeder Quelle
 * wird sauber mit `entitlement_unknown` abgelehnt. (Vor dem 26.09.2026 war die
 * Karte sonst **leer**; diese Aussage ist mit der Quellenabstraktion bewusst
 * umgekehrt worden — die Ablehnung unbekannter OIDs bleibt bestehen.)
 */
describe('Regression: TEST-Entitlement-Karte nur im Entwicklungsbetrieb', () => {
  const ZUGELASSENE_OID = Object.keys(TEST_ENTITLEMENT_MAP)[0] as string;
  /** Liegt unter dem Entitlement-Arc, ist aber keiner der vier TEST-Eintraege. */
  const FREMD_OID = TEST_UNKNOWN_ENTITLEMENT_OID;

  it('die vier TEST-OIDs liegen unter dem Entitlement-Arc, die fremde auch', () => {
    assert.ok(isOidUnder(ZUGELASSENE_OID, ID_ETSI_WRPA_ENTITLEMENT_ARC), 'Voraussetzung: TEST-OID liegt unter dem Arc');
    assert.ok(isOidUnder(FREMD_OID, ID_ETSI_WRPA_ENTITLEMENT_ARC), 'Voraussetzung: fremde OID liegt ebenfalls unter dem Arc');
    assert.ok(!(FREMD_OID in TEST_ENTITLEMENT_MAP), 'die fremde OID darf nicht in der TEST-Karte stehen');
  });

  it('strenger Modus: die Karte ist die normative Basis aus Anhang A.2, nicht leer', async () => {
    const karte = await createEntitlementMapProvider(STRENG, {}).resolve();
    assert.deepEqual(karte, NORMATIVE_ENTITLEMENT_MAP, 'ohne Entwicklungsschalter gilt die normative Basis');
    assert.equal(Object.keys(karte).length, 10, 'Anhang A.2.1–A.2.10 sind zehn Paare');
  });

  it('strenger Modus: die TEST-Karte ist NICHT die Quelle', async () => {
    const karte = await createEntitlementMapProvider(STRENG, {}).resolve();
    assert.notDeepEqual(karte, TEST_ENTITLEMENT_MAP, 'die vier TEST-OIDs duerfen den Normalbetrieb nicht bestimmen');
    // Die vier TEST-OIDs sind alle auch normativ, die normative Basis ist also
    // eine echte Obermenge. Genau das war vorher der Ausfallgrund.
    for (const oid of Object.keys(TEST_ENTITLEMENT_MAP)) {
      assert.ok(oid in karte, `${oid} ist in A.2 und damit aufgeloesbar`);
    }
  });

  it('Entwicklungsbetrieb: die TEST-Karte ist die Quelle (Gegenprobe)', async () => {
    assert.deepEqual(await createEntitlementMapProvider(DEV, {}).resolve(), TEST_ENTITLEMENT_MAP);
  });

  it('ein von Hand gebautes Config-Objekt kann die TEST-Karte nicht in Produktion schieben', async () => {
    // `config.ts` verbietet die Kombination beim Laden des Configs. Hier ist
    // die zweite, unabhaengige Absicherung derselben Zusage geprueft: auch wenn
    // jemand ein RuntimeMode-Objekt direkt konstruiert, greift nicht die
    // TEST-Karte, sondern die normative Basis.
    const karte = await createEntitlementMapProvider({ devMode: true, isProduction: true }, {}).resolve();
    assert.deepEqual(karte, NORMATIVE_ENTITLEMENT_MAP);
    assert.notDeepEqual(karte, TEST_ENTITLEMENT_MAP);
  });

  /**
   * Ende-zu-Ende ueber den echten Materialpfad: PEM-Dateien aus der Umgebung,
   * strenger Modus, danach ein Mandant mit einem WRPAC, dessen OID nicht in
   * der TEST-Karte steht. Das Gate muss das ablehnen.
   *
   * Ehrliche Einordnung: dieser Test haelt die Zusage "fremde OID wird
   * abgelehnt" fest und waere auch mit dem alten Fehler gruen — die fremde OID
   * stand ja nie in der Karte. **Der Test, der den Fehler tatsaechlich faengt,
   * ist der folgende** ("auch eine OID aus der TEST-Karte wird abgelehnt").
   * Beide stehen hier, weil sie zwei verschiedene Zusageen sichern: die eine
   * gegen die unvollstaendige Karte, die andere gegen die Karte selbst.
   */
  it('nicht-dev Modus: WRPAC mit OID ausserhalb der TEST-Karte wird abgelehnt, nicht durchgewunken', async () => {
    const { accessCa, wrprcIssuer } = await ankerMaterial();
    const wrpac = await accessCa.issueWrpac({ subjectCn: 'Produktiv RP (OID ausserhalb TEST)', entitlementOids: [FREMD_OID] });
    const store = new TenantStore();
    store.add({
      id: 't-fremd',
      name: 'Mandant mit fremder Entitlement-OID',
      apiKey: 'test-api-key-entitlement',
      registration: { wrpacChain: [wrpac.certDer, accessCa.caCertDer], wrprc: await signierteWrprc(wrprcIssuer) },
    });

    const gate = await gateAusEnv(STRENG, { accessCa, wrprcIssuer }, store);
    assert.ok(gate, 'mit Ankerdateien muss ein Gate entstehen');

    await assert.rejects(
      () => gate.verifyTenant('t-fremd'),
      (e: unknown) => {
        assert.ok(e instanceof ErrTenantRegistrationInvalid, `Erwartet: TenantRegistrationInvalid, war ${String(e)}`);
        // Der innere Fehlercode muss benannt sein, damit der Betrieb die
        // Ursache belegen kann statt sie zu raten.
        assert.equal(e.reason, 'entitlement_unknown', 'Ablehnung muss als entitlement_unknown begruendet sein');
        return true;
      },
    );
  });

  it('nicht-dev Modus: eine OID aus Anhang A.2 wird entitlement-seitig aufgeloest, nicht mehr mit entitlement_unknown abgelehnt', async () => {
    // **Dieser Test war der, der den alten Fehler faengt, und seine Zusage ist
    // mit dem 26.09.2026 bewusst umgekehrt.** Vorher stand im strengen Modus eine
    // leere Karte, wodurch auch `.1` (Service_Provider) mit
    // `entitlement_unknown` abgelehnt wurde. Genau das war der Ausfallgrund: das
    // Gate war ausserhalb des Entwicklungsschalters nicht betreibbar, nur
    // abweisend. Jetzt loest die normative Basis `.1` auf, der Lauf macht
    // weiter, und die Ablehnung kommt aus einer spaeteren Stufe.
    //
    // Geprueft wird deshalb **nicht** "wird akzeptiert": der Weg scheitert
    // weiterhin, aber nicht mehr an der Entitlements. Der Testbaender sind
    // laufzeitgenerierte TEST-Zertifikate ohne OCSP-AIA, deshalb endet der Lauf
    // in der Sperrpruefung. Genau darin liegt die Aussage: der Fehlercode ist
    // nicht langer `entitlement_unknown`.
    const { accessCa, wrprcIssuer } = await ankerMaterial();
    const wrpac = await accessCa.issueWrpac({ subjectCn: 'Produktiv RP (OID aus A.2)', entitlementOids: [ZUGELASSENE_OID] });
    const store = new TenantStore();
    store.add({
      id: 't-a2oid',
      name: 'Mandant mit A.2-OID im Produktivbetrieb',
      apiKey: 'test-api-key-a2oid',
      registration: { wrpacChain: [wrpac.certDer, accessCa.caCertDer], wrprc: await signierteWrprc(wrprcIssuer) },
    });

    const gate = await gateAusEnv(STRENG, { accessCa, wrprcIssuer }, store);
    assert.ok(gate);

    // Die OID liegt in A.2, also in der normativen Quelle.
    assert.ok(ZUGELASSENE_OID in NORMATIVE_ENTITLEMENT_MAP, 'Voraussetzung: die OID ist normativ festgelegt');

    await assert.rejects(
      () => gate.verifyTenant('t-a2oid'),
      (e: unknown) => {
        assert.ok(e instanceof ErrTenantRegistrationInvalid);
        assert.notEqual(
          e.reason,
          'entitlement_unknown',
          'der Entitlement-Schritt muss die A.2-OID aufloesen; eine Ablehnung hier waere der alte Fehler',
        );
        return true;
      },
    );
  });

  it('Entwicklungsbetrieb: dieselbe fremde OID wird weiterhin sauber abgelehnt (Gegenprobe)', async () => {
    // Die TEST-Karte aendert nichts an der Pruefung selbst: eine OID, die nicht
    // in ihr steht, wird auch im Entwicklungsbetrieb abgelehnt. Der Unterschied
    // ist nur, welche OIDs ueberhaupt infrage kommen.
    const { accessCa, wrprcIssuer } = await ankerMaterial();
    const wrpac = await accessCa.issueWrpac({ subjectCn: 'Test RP (OID ausserhalb TEST)', entitlementOids: [FREMD_OID] });
    const store = new TenantStore();
    store.add({
      id: 't-dev-fremd',
      name: 'Testmandant mit fremder OID',
      apiKey: 'test-api-key-dev-fremd',
      registration: { wrpacChain: [wrpac.certDer, accessCa.caCertDer], wrprc: await signierteWrprc(wrprcIssuer) },
    });

    const gate = await gateAusEnv(DEV, { accessCa, wrprcIssuer }, store);
    assert.ok(gate);
    await assert.rejects(
      () => gate.verifyTenant('t-dev-fremd'),
      (e: unknown) => {
        assert.ok(e instanceof ErrTenantRegistrationInvalid);
        assert.equal(e.reason, 'entitlement_unknown');
        return true;
      },
    );
  });
});

/**
 * Ende-zu-Ende ueber die Datei-Quelle: eine OID, die weder in Anhang A.2 noch in
 * der TEST-Karte steht, sondern ausschliesslich in der konfigurierten
 * JSON-Datei. Im strengen Modus (ohne Entwicklungsschalter) muss das Gate sie
 * entitlement-seitig aufloesen, statt sie mit `entitlement_unknown` abzulehnen.
 * Das war der Ausfallgrund vor dem 26.09.2026: das Gate war ausserhalb des
 * Entwicklungsschalters nur abweisend.
 *
 * Die Gegenprobe ohne Datei sichert, dass der Test die Datei-Quelle und nicht
 * zufaellig die normative Basis trifft.
 */
describe('Ende-zu-Ende: eine OID aus der JSON-Datei wird im strengen Modus aufgeloest', () => {
  /** In A.2 nicht definiert (Referenznummer 11 fehlt), also nur ueber die Datei erreichbar. */
  const NATIONALE_OID = TEST_UNKNOWN_ENTITLEMENT_OID;

  /** Schreibt eine gueltige TEST-Datei mit genau einer nationalen Entitlement-Zeile. */
  async function testDatei(): Promise<string> {
    const { writeFile, mkdtemp } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = await mkdtemp(join(tmpdir(), 'entitlement-datei-'));
    const pfad = join(dir, 'entitlements.json');
    await writeFile(
      pfad,
      JSON.stringify({
        version: 1,
        source: 'TEST Beispielbetrieb, erfunden',
        entitlements: { [NATIONALE_OID]: 'https://example.invalid/19475/SubEntitlement/EigeneRolle' },
      }),
    );
    return pfad;
  }

  it('mit Datei: die nationale OID wird aufgeloest, entitlement_unknown tritt nicht auf', async () => {
    const pfad = await testDatei();

    // Vorbedingung: die Quelle selbst muss die OID liefern, sonst testet der
    // Lauf nur, dass eine spaetere Stufe scheitert.
    const karte = await createEntitlementMapProvider(STRENG, { [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: pfad }).resolve();
    assert.equal(karte[NATIONALE_OID], 'https://example.invalid/19475/SubEntitlement/EigeneRolle');
    assert.ok(!(NATIONALE_OID in NORMATIVE_ENTITLEMENT_MAP), 'Voraussetzung: die OID ist nicht normativ');

    const { accessCa, wrprcIssuer } = await ankerMaterial();
    const wrpac = await accessCa.issueWrpac({ subjectCn: 'Produktiv RP (Datei-Quelle TEST)', entitlementOids: [NATIONALE_OID] });
    const store = new TenantStore();
    store.add({
      id: 't-datei',
      name: 'Mandant mit nationaler Entitlement-OID aus der Datei',
      apiKey: 'test-api-key-dateiquelle',
      registration: { wrpacChain: [wrpac.certDer, accessCa.caCertDer], wrprc: await signierteWrprc(wrprcIssuer) },
    });

    const gate = await gateAusEnv(STRENG, { accessCa, wrprcIssuer }, store, { [ENV_ATTACK_ENTITLEMENT_MAP_JSON]: pfad });
    assert.ok(gate, 'mit Ankerdateien muss ein Gate entstehen');

    await assert.rejects(
      () => gate.verifyTenant('t-datei'),
      (e: unknown) => {
        assert.ok(e instanceof ErrTenantRegistrationInvalid, `Erwartet: TenantRegistrationInvalid, war ${String(e)}`);
        assert.notEqual(
          e.reason,
          'entitlement_unknown',
          'die OID steht in der Datei-Quelle; eine Ablehnung hier waere der alte Fehler',
        );
        return true;
      },
    );
  });

  it('Gegenprobe ohne Datei: dieselbe OID wird mit entitlement_unknown abgelehnt', async () => {
    // Sichert, dass der positive Test an der Datei haengt und nicht an einer
    // zufaellig gefuellten Karte.
    const { accessCa, wrprcIssuer } = await ankerMaterial();
    const wrpac = await accessCa.issueWrpac({ subjectCn: 'Produktiv RP ohne Datei TEST', entitlementOids: [NATIONALE_OID] });
    const store = new TenantStore();
    store.add({
      id: 't-ohne-datei',
      name: 'Mandant ohne konfigurierte Datei',
      apiKey: 'test-api-key-ohne-datei',
      registration: { wrpacChain: [wrpac.certDer, accessCa.caCertDer], wrprc: await signierteWrprc(wrprcIssuer) },
    });

    const gate = await gateAusEnv(STRENG, { accessCa, wrprcIssuer }, store);
    assert.ok(gate);

    await assert.rejects(
      () => gate.verifyTenant('t-ohne-datei'),
      (e: unknown) => {
        assert.ok(e instanceof ErrTenantRegistrationInvalid);
        assert.equal(e.reason, 'entitlement_unknown', 'ohne Datei darf die OID unbekannt bleiben');
        return true;
      },
    );
  });
});
