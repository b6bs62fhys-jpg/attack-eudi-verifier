/**
 * Paket 2: CRL beim Start eingebunden, kombiniert mit OCSP, fail closed.
 *
 * Geprüft werden:
 *   - die Konfiguration der Sperrquellen (Standard, gültige und ungültige
 *     Werte, CRL-Pflicht im Produktionsmodus),
 *   - die Kombination (ein Status gilt sofort, Rückfall nur nach Fehler,
 *     Ablehnung, wenn alle scheitern),
 *   - der CRL-Cache (Gültigkeit aus nextUpdate, Obergrenze, keine Fehler im
 *     Cache, Bindung an den Aussteller, ein Abruf für gleichzeitige Prüfungen),
 *   - der Ernstfall aus der Sandbox: eine Aussteller-Kette, deren Zertifikat
 *     nur eine CRL-Adresse trägt, wird mit der Standardkonfiguration geprüft
 *     statt mit revocation_source_missing abgelehnt,
 *   - der Dienststart im Produktionsmodus.
 * Die CRLs kommen von einem echten lokalen HTTP-Server (127.0.0.1).
 */
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';
import { X509Certificate, X509CrlGenerator, type X509CrlEntryParams } from '@peculiar/x509';

import {
  ConfigError,
  ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM,
  ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM,
  ENV_ATTACK_VERIFIER_KEY_PEM,
  ENV_NODE_ENV,
} from '../config.ts';
import { generateTestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { bootstrapService } from '../service/bootstrap.ts';
import { enforceIssuerChainRevocation } from '../service/issuer-revocation.ts';
import { CrlRevocationChecker } from './crl-revocation.ts';
import { ErrRevocationSourceMissing, ErrRevocationTimeout, ErrRevocationUnavailable, OnboardingError } from './errors.ts';
import { createAccessCa, TEST_ENTITLEMENT_MAP, type AccessCa, type IssuedWrpac } from './mock-pki.ts';
import { OcspRevocationChecker } from './ocsp-revocation.ts';
import { NO_REVOCATION, type RevocationChecker, type RevocationStatus } from './revocation.ts';
import {
  buildRevocationChecker,
  describeRevocationSources,
  ENV_ATTACK_ISSUER_REVOCATION_SOURCES,
  ENV_ATTACK_ONBOARDING_REVOCATION_SOURCES,
  FallbackRevocationChecker,
  parseRevocationSources,
} from './revocation-source.ts';

const DEV = { devMode: true, isProduction: false };
const NO_DEV = { devMode: false, isProduction: false };
const PROD = { devMode: false, isProduction: true };

let ca!: AccessCa;
let otherCa!: AccessCa;
let leaf!: IssuedWrpac;
let secondLeaf!: IssuedWrpac;
let server!: http.Server;
let base!: string;
/** Antwort und Abrufzähler je Pfad. */
const routes = new Map<string, () => { status: number; body: Uint8Array | string }>();
const hits = new Map<string, number>();

function codeOf(e: unknown): string {
  return e instanceof OnboardingError ? e.code : `kein OnboardingError: ${String(e)}`;
}

async function crlDer(entries: X509CrlEntryParams[] = [], opts: { nextUpdate?: Date; thisUpdate?: Date; signer?: AccessCa } = {}): Promise<Uint8Array> {
  const signer = opts.signer ?? ca;
  const crl = await X509CrlGenerator.create({
    issuer: new X509Certificate(Uint8Array.from(signer.caCertDer)).subject,
    thisUpdate: opts.thisUpdate ?? new Date(Date.now() - 60_000),
    nextUpdate: opts.nextUpdate ?? new Date(Date.now() + 3600_000),
    entries,
    signingKey: signer.caKey.privateKey,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
  });
  return new Uint8Array(crl.rawData);
}

function serve(path: string, body: Uint8Array | string, status = 200): void {
  hits.set(path, 0);
  routes.set(path, () => ({ status, body }));
}

const hitCount = (path: string) => hits.get(path) ?? 0;

beforeAll(async () => {
  ca = await createAccessCa('Sperrquellen CA TEST');
  otherCa = await createAccessCa('Andere CA TEST');
  server = http.createServer((req, res) => {
    const path = req.url ?? '';
    const route = routes.get(path);
    if (!route) {
      res.writeHead(404);
      res.end();
      return;
    }
    hits.set(path, hitCount(path) + 1);
    const { status, body } = route();
    res.writeHead(status, { 'content-type': 'application/pkix-crl' });
    res.end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const oid = Object.keys(TEST_ENTITLEMENT_MAP)[0] as string;
  // Nur eine CRL-Adresse, keine OCSP-Adresse: so wie die CA-Zertifikate der
  // offiziellen Sandbox-Vertrauensliste.
  leaf = await ca.issueWrpac({ subjectCn: 'Nur CRL Blatt (TEST)', entitlementOids: [oid], crlUrl: `${base}/ca.crl` });
  secondLeaf = await ca.issueWrpac({ subjectCn: 'Zweites Blatt (TEST)', entitlementOids: [oid], crlUrl: `${base}/ca.crl` });
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('Konfiguration der Sperrquellen', () => {
  const key = ENV_ATTACK_ISSUER_REVOCATION_SOURCES;

  it('ohne Angabe: OCSP zuerst, CRL als Rückfall', () => {
    assert.deepEqual(parseRevocationSources({}, key, PROD), ['ocsp', 'crl']);
    assert.deepEqual(parseRevocationSources({ [key]: '  ' }, key, PROD), ['ocsp', 'crl']);
  });

  it('gültige Werte, Reihenfolge bleibt, Groß und Leerzeichen egal', () => {
    assert.deepEqual(parseRevocationSources({ [key]: 'crl' }, key, PROD), ['crl']);
    assert.deepEqual(parseRevocationSources({ [key]: ' CRL , ocsp ' }, key, PROD), ['crl', 'ocsp']);
    assert.deepEqual(parseRevocationSources({ [key]: 'ocsp' }, key, NO_DEV), ['ocsp']);
    assert.deepEqual(parseRevocationSources({ [key]: 'ocsp' }, key, DEV), ['ocsp']);
  });

  for (const [titel, wert, muster] of [
    ['unbekannte Quelle', 'ocsp,crlx', /unbekannte Sperrquelle "crlx"/],
    ['leerer Eintrag', 'ocsp,', /unbekannte Sperrquelle ""/],
    ['doppelte Quelle', 'crl,crl', /nur einmal/],
  ] as const) {
    it(`${titel} -> ConfigError`, () => {
      assert.throws(() => parseRevocationSources({ [key]: wert }, key, NO_DEV), (e: unknown) => e instanceof ConfigError && muster.test(e.message));
    });
  }

  it('Produktionsmodus ohne CRL -> ConfigError mit Begründung', () => {
    assert.throws(
      () => parseRevocationSources({ [key]: 'ocsp' }, key, PROD),
      (e: unknown) => e instanceof ConfigError && /Produktionsmodus/.test(e.message) && /CRL-Adressen/.test(e.message) && /Start abgebrochen/.test(e.message),
    );
  });

  it('Beschreibung für Startmeldung und CLI', () => {
    assert.equal(describeRevocationSources(['ocsp', 'crl']), 'ocsp, Rückfall crl');
    assert.equal(describeRevocationSources(['crl']), 'nur crl');
  });
});

describe('Kombination: Status gilt sofort, Rückfall nur nach Fehler', () => {
  const der = new Uint8Array([1]);
  function stub(verhalten: () => Promise<RevocationStatus>): RevocationChecker & { calls: number } {
    const s = {
      calls: 0,
      async checkRevoked(): Promise<RevocationStatus> {
        s.calls += 1;
        return verhalten();
      },
    };
    return s;
  }
  const kombi = (a: RevocationChecker, b: RevocationChecker) =>
    new FallbackRevocationChecker([
      { name: 'ocsp', checker: a },
      { name: 'crl', checker: b },
    ]);

  it('good der ersten Quelle: zweite wird nicht gefragt', async () => {
    const a = stub(async () => 'good');
    const b = stub(async () => 'revoked');
    assert.equal(await kombi(a, b).checkRevoked(der, 'leaf', der), 'good');
    assert.equal(b.calls, 0);
  });

  it('revoked der ersten Quelle wird nie durch die zweite überstimmt', async () => {
    const b = stub(async () => 'good');
    assert.equal(await kombi(stub(async () => 'revoked'), b).checkRevoked(der, 'leaf', der), 'revoked');
    assert.equal(await kombi(stub(async () => 'suspended'), b).checkRevoked(der, 'leaf', der), 'suspended');
    assert.equal(b.calls, 0);
  });

  it('keine OCSP-Adresse: CRL entscheidet, auch auf revoked', async () => {
    const ohneAdresse = () => stub(async () => { throw new ErrRevocationSourceMissing(); });
    assert.equal(await kombi(ohneAdresse(), stub(async () => 'good')).checkRevoked(der, 'leaf', der), 'good');
    assert.equal(await kombi(ohneAdresse(), stub(async () => 'revoked')).checkRevoked(der, 'leaf', der), 'revoked');
  });

  it('OCSP nicht erreichbar: CRL entscheidet', async () => {
    assert.equal(await kombi(stub(async () => { throw new ErrRevocationUnavailable(); }), stub(async () => 'good')).checkRevoked(der, 'leaf', der), 'good');
  });

  it('alle scheitern: Ablehnung mit dem aussagekräftigsten Fehler', async () => {
    const fehlt = () => stub(async () => { throw new ErrRevocationSourceMissing(); });
    await assert.rejects(kombi(fehlt(), stub(async () => { throw new ErrRevocationTimeout(); })).checkRevoked(der, 'leaf', der), (e: unknown) => codeOf(e) === 'revocation_timeout');
    await assert.rejects(kombi(stub(async () => { throw new ErrRevocationUnavailable(); }), fehlt()).checkRevoked(der, 'leaf', der), (e: unknown) => codeOf(e) === 'revocation_unavailable');
    await assert.rejects(kombi(fehlt(), fehlt()).checkRevoked(der, 'leaf', der), (e: unknown) => codeOf(e) === 'revocation_source_missing');
  });

  it('ohne Quelle ist der Checker nicht baubar', () => {
    assert.throws(() => new FallbackRevocationChecker([]), ConfigError);
  });

  it('buildRevocationChecker: eine Quelle direkt, zwei kombiniert, mit kürzeren Zeitgrenzen', () => {
    const gesehen: Array<[string, boolean]> = [];
    const fabriken = {
      ocsp: (combined: boolean) => {
        gesehen.push(['ocsp', combined]);
        return NO_REVOCATION;
      },
      crl: (combined: boolean) => {
        gesehen.push(['crl', combined]);
        return new CrlRevocationChecker();
      },
    };
    assert.ok(buildRevocationChecker(['crl'], fabriken) instanceof CrlRevocationChecker);
    const kombiniert = buildRevocationChecker(['ocsp', 'crl'], fabriken);
    assert.ok(kombiniert instanceof FallbackRevocationChecker);
    assert.deepEqual(kombiniert.sources.map((q) => q.name), ['ocsp', 'crl']);
    assert.deepEqual(gesehen, [['crl', false], ['ocsp', true], ['crl', true]]);
  });
});

describe('CRL-Cache: Gültigkeit aus nextUpdate', () => {
  const caDer = () => ca.caCertDer;

  it('zwei Zertifikate desselben Ausstellers: ein Abruf', async () => {
    serve('/cache-eins.crl', await crlDer());
    const checker = new CrlRevocationChecker({ crlUrlFor: () => `${base}/cache-eins.crl` });
    assert.equal(await checker.checkRevoked(leaf.certDer, 'leaf', caDer()), 'good');
    assert.equal(await checker.checkRevoked(secondLeaf.certDer, 'leaf', caDer()), 'good');
    assert.equal(await checker.checkRevoked(leaf.certDer, 'leaf', caDer()), 'good');
    assert.equal(hitCount('/cache-eins.crl'), 1);
  });

  it('ein gesperrtes Zertifikat bleibt auch aus dem Cache gesperrt', async () => {
    const serial = new X509Certificate(Uint8Array.from(leaf.certDer)).serialNumber;
    serve('/cache-gesperrt.crl', await crlDer([{ serialNumber: serial, revocationDate: new Date(Date.now() - 1000) }]));
    const checker = new CrlRevocationChecker({ crlUrlFor: () => `${base}/cache-gesperrt.crl` });
    assert.equal(await checker.checkRevoked(leaf.certDer, 'leaf', caDer()), 'revoked');
    assert.equal(await checker.checkRevoked(secondLeaf.certDer, 'leaf', caDer()), 'good');
    assert.equal(await checker.checkRevoked(leaf.certDer, 'leaf', caDer()), 'revoked');
    assert.equal(hitCount('/cache-gesperrt.crl'), 1);
  });

  it('nach nextUpdate wird neu geholt', async () => {
    const start = Date.now();
    serve('/cache-next.crl', await crlDer([], { nextUpdate: new Date(start + 10 * 60_000) }));
    let jetzt = start;
    const checker = new CrlRevocationChecker({ crlUrlFor: () => `${base}/cache-next.crl`, now: () => new Date(jetzt) });
    await checker.checkRevoked(leaf.certDer, 'leaf', caDer());
    jetzt = start + 9 * 60_000;
    await checker.checkRevoked(leaf.certDer, 'leaf', caDer());
    assert.equal(hitCount('/cache-next.crl'), 1, 'vor nextUpdate aus dem Cache');
    serve('/cache-next.crl', await crlDer([], { thisUpdate: new Date(start + 10 * 60_000), nextUpdate: new Date(start + 70 * 60_000) }));
    jetzt = start + 11 * 60_000;
    await checker.checkRevoked(leaf.certDer, 'leaf', caDer());
    assert.equal(hitCount('/cache-next.crl'), 1, 'nach nextUpdate neu geholt (Zähler wurde mit der neuen Liste zurückgesetzt)');
  });

  it('nach nextUpdate gilt eine nicht erneuerte Liste nicht weiter, wenn sie abgelaufen ist', async () => {
    const start = Date.now();
    serve('/cache-alt.crl', await crlDer([], { nextUpdate: new Date(start + 5 * 60_000) }));
    let jetzt = start;
    const checker = new CrlRevocationChecker({ crlUrlFor: () => `${base}/cache-alt.crl`, now: () => new Date(jetzt), clockSkewSeconds: 60 });
    await checker.checkRevoked(leaf.certDer, 'leaf', caDer());
    jetzt = start + 10 * 60_000;
    await assert.rejects(checker.checkRevoked(leaf.certDer, 'leaf', caDer()), (e: unknown) => codeOf(e) === 'revocation_list_expired');
    assert.equal(hitCount('/cache-alt.crl'), 2);
  });

  it('Obergrenze: auch bei fernem nextUpdate höchstens maxCacheTtlMs', async () => {
    const start = Date.now();
    serve('/cache-cap.crl', await crlDer([], { nextUpdate: new Date(start + 7 * 24 * 3600_000) }));
    let jetzt = start;
    const checker = new CrlRevocationChecker({ crlUrlFor: () => `${base}/cache-cap.crl`, now: () => new Date(jetzt), maxCacheTtlMs: 3600_000 });
    await checker.checkRevoked(leaf.certDer, 'leaf', caDer());
    jetzt = start + 30 * 60_000;
    await checker.checkRevoked(leaf.certDer, 'leaf', caDer());
    assert.equal(hitCount('/cache-cap.crl'), 1);
    jetzt = start + 2 * 3600_000;
    await checker.checkRevoked(leaf.certDer, 'leaf', caDer());
    assert.equal(hitCount('/cache-cap.crl'), 2);
  });

  it('Fehler werden nicht gespeichert', async () => {
    serve('/cache-fehler.crl', 'kaputt', 500);
    const checker = new CrlRevocationChecker({ crlUrlFor: () => `${base}/cache-fehler.crl` });
    await assert.rejects(checker.checkRevoked(leaf.certDer, 'leaf', caDer()), (e: unknown) => codeOf(e) === 'revocation_unavailable');
    const gut = await crlDer();
    routes.set('/cache-fehler.crl', () => ({ status: 200, body: gut }));
    assert.equal(await checker.checkRevoked(leaf.certDer, 'leaf', caDer()), 'good');
    assert.equal(hitCount('/cache-fehler.crl'), 2);
  });

  it('der Cache ist an den Aussteller gebunden: eine fremde CA bekommt keine fremde Liste', async () => {
    serve('/cache-aussteller.crl', await crlDer());
    const checker = new CrlRevocationChecker({ crlUrlFor: () => `${base}/cache-aussteller.crl` });
    assert.equal(await checker.checkRevoked(leaf.certDer, 'leaf', caDer()), 'good');
    // Dieselbe Adresse, aber gegen eine andere CA geprüft: neu holen, und die
    // Liste passt nicht zum Aussteller.
    await assert.rejects(checker.checkRevoked(leaf.certDer, 'leaf', otherCa.caCertDer), (e: unknown) => codeOf(e) === 'revocation_list_malformed');
    assert.equal(hitCount('/cache-aussteller.crl'), 2);
  });

  it('gleichzeitige Prüfungen teilen sich einen Abruf', async () => {
    serve('/cache-parallel.crl', await crlDer());
    const checker = new CrlRevocationChecker({ crlUrlFor: () => `${base}/cache-parallel.crl` });
    const ergebnisse = await Promise.all(Array.from({ length: 5 }, () => checker.checkRevoked(leaf.certDer, 'leaf', caDer())));
    assert.deepEqual(ergebnisse, ['good', 'good', 'good', 'good', 'good']);
    assert.equal(hitCount('/cache-parallel.crl'), 1);
  });

  it('volle Liste: der älteste Eintrag fällt heraus', async () => {
    serve('/cache-a.crl', await crlDer());
    serve('/cache-b.crl', await crlDer());
    let ziel = '/cache-a.crl';
    const checker = new CrlRevocationChecker({ crlUrlFor: () => `${base}${ziel}`, maxCacheEntries: 1 });
    await checker.checkRevoked(leaf.certDer, 'leaf', caDer());
    ziel = '/cache-b.crl';
    await checker.checkRevoked(leaf.certDer, 'leaf', caDer());
    ziel = '/cache-a.crl';
    await checker.checkRevoked(leaf.certDer, 'leaf', caDer());
    assert.equal(hitCount('/cache-a.crl'), 2);
    checker.clearCache();
    await checker.checkRevoked(leaf.certDer, 'leaf', caDer());
    assert.equal(hitCount('/cache-a.crl'), 3);
  });
});

describe('Ernstfall Sandbox: Aussteller-Kette nur mit CRL-Adresse', () => {
  function standardKette(): RevocationChecker {
    return buildRevocationChecker(parseRevocationSources({}, ENV_ATTACK_ISSUER_REVOCATION_SOURCES, PROD), {
      ocsp: () => new OcspRevocationChecker({ timeoutMs: 1_000 }),
      crl: () => new CrlRevocationChecker({ timeoutMs: 1_000 }),
    });
  }

  it('OCSP allein lehnt ab (revocation_source_missing), so war es vorher', async () => {
    serve('/ca.crl', await crlDer());
    await assert.rejects(
      enforceIssuerChainRevocation(new OcspRevocationChecker({ timeoutMs: 1_000 }), [leaf.certDer], [ca.caCertDer]),
      (e: unknown) => codeOf(e) === 'revocation_source_missing',
    );
  });

  it('Standardkonfiguration: gültige CRL -> angenommen', async () => {
    serve('/ca.crl', await crlDer());
    await enforceIssuerChainRevocation(standardKette(), [leaf.certDer], [ca.caCertDer]);
  });

  it('Standardkonfiguration: Blatt auf der CRL -> certificate_revoked', async () => {
    const serial = new X509Certificate(Uint8Array.from(leaf.certDer)).serialNumber;
    serve('/ca.crl', await crlDer([{ serialNumber: serial, revocationDate: new Date(Date.now() - 1000) }]));
    await assert.rejects(enforceIssuerChainRevocation(standardKette(), [leaf.certDer], [ca.caCertDer]), (e: unknown) => codeOf(e) === 'certificate_revoked');
  });

  it('Standardkonfiguration: CRL nicht erreichbar -> abgelehnt', async () => {
    serve('/ca.crl', 'weg', 503);
    await assert.rejects(enforceIssuerChainRevocation(standardKette(), [leaf.certDer], [ca.caCertDer]), (e: unknown) => codeOf(e) === 'revocation_unavailable');
  });

  it('CRL einer fremden CA -> abgelehnt', async () => {
    serve('/ca.crl', await crlDer([], { signer: otherCa }));
    await assert.rejects(enforceIssuerChainRevocation(standardKette(), [leaf.certDer], [ca.caCertDer]), (e: unknown) => codeOf(e) === 'revocation_list_malformed');
  });
});

describe('Dienststart: Sperrquellen im Produktionsmodus', () => {
  let dir!: string;
  let env!: Record<string, string>;

  function derToPem(der: Uint8Array, label: string): string {
    const lines = Buffer.from(der).toString('base64').match(/.{1,64}/g)?.join('\n') ?? '';
    return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
  }

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'attack-sperrquellen-'));
    const verifier = await generateTestKeyMaterial('Sperrquellen Verifier TEST');
    const issuer = await generateTestKeyMaterial('Sperrquellen Issuer TEST');
    await writeFile(join(dir, 'key.pem'), derToPem(new Uint8Array(await crypto.subtle.exportKey('pkcs8', verifier.privateKey)), 'PRIVATE KEY'));
    await writeFile(join(dir, 'chain.pem'), derToPem(verifier.certDerBytes, 'CERTIFICATE'));
    await writeFile(join(dir, 'anchors.pem'), derToPem(issuer.certDerBytes, 'CERTIFICATE'));
    env = {
      [ENV_NODE_ENV]: 'production',
      ATTACK_PUBLIC_BASE_URL: 'https://verifier.example',
      [ENV_ATTACK_VERIFIER_KEY_PEM]: join(dir, 'key.pem'),
      [ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM]: join(dir, 'chain.pem'),
      [ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM]: join(dir, 'anchors.pem'),
    };
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('Standard: beide Pfade OCSP mit CRL-Rückfall, getrennte Instanzen, Startmeldung', async () => {
    const warnungen: string[] = [];
    const boot = await bootstrapService(env, (m) => warnungen.push(m));
    assert.deepEqual(boot.issuerRevocationSources, ['ocsp', 'crl']);
    assert.deepEqual(boot.onboardingRevocationSources, ['ocsp', 'crl']);
    assert.ok(boot.issuerRevocation instanceof FallbackRevocationChecker);
    assert.ok(boot.onboardingRevocation instanceof FallbackRevocationChecker);
    // Das Gate erbt die Gnadenfrist des Credential-Pfads nicht: eigene Instanz.
    assert.notEqual(boot.onboardingRevocation, boot.issuerRevocation);
    const [issuerOcsp] = (boot.issuerRevocation as FallbackRevocationChecker).sources;
    const [gateOcsp] = (boot.onboardingRevocation as FallbackRevocationChecker).sources;
    assert.ok(issuerOcsp?.checker instanceof OcspRevocationChecker && gateOcsp?.checker instanceof OcspRevocationChecker);
    assert.notEqual(issuerOcsp?.checker, gateOcsp?.checker);
    assert.ok(warnungen.includes(`Sperrquellen Aussteller-Kette: ocsp, Rückfall crl (${ENV_ATTACK_ISSUER_REVOCATION_SOURCES}).`));
  });

  it('nur CRL ist erlaubt', async () => {
    const boot = await bootstrapService({ ...env, [ENV_ATTACK_ISSUER_REVOCATION_SOURCES]: 'crl' }, () => {});
    assert.ok(boot.issuerRevocation instanceof CrlRevocationChecker);
  });

  it('nur OCSP bricht im Produktionsmodus den Start ab, für beide Pfade', async () => {
    for (const key of [ENV_ATTACK_ISSUER_REVOCATION_SOURCES, ENV_ATTACK_ONBOARDING_REVOCATION_SOURCES]) {
      await assert.rejects(bootstrapService({ ...env, [key]: 'ocsp' }, () => {}), (e: unknown) => e instanceof ConfigError && e.message.startsWith(key));
    }
  });

  it('Tippfehler bricht auch im Entwicklungsbetrieb ab', async () => {
    await assert.rejects(
      bootstrapService({ ATTACK_DEV_MODE: 'true', [ENV_ATTACK_ISSUER_REVOCATION_SOURCES]: 'osp' }, () => {}),
      (e: unknown) => e instanceof ConfigError && /unbekannte Sperrquelle/.test(e.message),
    );
  });

  it('Entwicklungsbetrieb bleibt ohne Sperrprüfung (bestehende Lockerung)', async () => {
    const boot = await bootstrapService({ ATTACK_DEV_MODE: 'true' }, () => {});
    assert.equal(boot.issuerRevocation, NO_REVOCATION);
    assert.equal(boot.onboardingRevocation, NO_REVOCATION);
  });
});
