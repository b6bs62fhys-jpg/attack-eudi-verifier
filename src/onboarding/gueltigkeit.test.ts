/**
 * Härtung 9: Gültigkeitszeitraum aller Zertifikate fail closed (Onboarding).
 *
 *   - WRPAC-Kette (validateWrpacChain) und WRPRC-x5c-Kette (verifyWrprc):
 *     jedes Zertifikat (Blatt, Zwischenzertifikat, Anker) muss zum
 *     Prüfzeitpunkt gültig sein; eigene Codes certificate_expired und
 *     certificate_not_yet_valid.
 *   - Uhrabweichung konfigurierbar (Standard 60 s), Tests an beiden Grenzen.
 *   - Pflichttest: der Fund aus dem Bericht (WRPAC notAfter +1 Tag, geprüft
 *     nach 400 Tagen) wird jetzt abgelehnt.
 * Alle Zeitpunkte kommen aus einer injizierten Uhr.
 */
import assert from 'node:assert/strict';
import { beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';
import { BasicConstraintsExtension, KeyUsageFlags, KeyUsagesExtension, X509Certificate, X509CertificateGenerator } from '@peculiar/x509';

import { certificateValidityFailure, chainValidityFailure, DEFAULT_CLOCK_SKEW_SECONDS } from '../lib/cert-validity.ts';
import { TenantStore } from '../service/tenant.ts';
import { ErrTenantRegistrationInvalid, OnboardingError } from './errors.ts';
import { createAccessCa, createWrprcIssuer, createWrprcLeaf, signWrprc, TEST_ENTITLEMENT_MAP, type AccessCa, type IssuedWrpac, type WrprcIssuer } from './mock-pki.ts';
import { RelyingPartyOnboardingGate } from './onboarding-gate.ts';
import { WRPRC_POLICY_OID } from './oid.ts';
import { NO_REVOCATION } from './revocation.ts';
import { validateWrpacChain } from './wrpac.ts';
import { verifyWrprc } from './wrprc.ts';

const DAY = 86_400_000;
const SERVICE_PROVIDER_URI = TEST_ENTITLEMENT_MAP['0.4.0.19475.1.1'];
const DEV = { devMode: true, isProduction: false };

let accessCa!: AccessCa;
let wrpac!: IssuedWrpac;
let leafCert!: X509Certificate;
let caCert!: X509Certificate;

const at = (base: Date, offsetMs: number) => new Date(base.getTime() + offsetMs);
const certificateFrom = (der: Uint8Array) => new X509Certificate(Uint8Array.from(der));

async function rejectsWithCode(fn: () => Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(fn, (e: unknown) => {
    assert.ok(e instanceof OnboardingError, `OnboardingError erwartet: ${String(e)}`);
    assert.equal(e.code, code);
    return true;
  });
}

const chain = (now: Date, clockSkewSeconds?: number) =>
  validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: NO_REVOCATION, now, clockSkewSeconds });

beforeAll(async () => {
  accessCa = await createAccessCa();
  wrpac = await accessCa.issueWrpac({ subjectCn: 'Zeit GmbH (TEST)', entitlementOids: [Object.keys(TEST_ENTITLEMENT_MAP)[0]], notAfterDays: 1 });
  leafCert = certificateFrom(wrpac.certDer);
  caCert = certificateFrom(accessCa.caCertDer);
});

describe('Pflichttest: Fund aus dem Bericht', () => {
  it('WRPAC mit notAfter +1 Tag, geprüft nach 400 Tagen -> certificate_expired (vorher akzeptiert)', async () => {
    await rejectsWithCode(() => chain(new Date(Date.now() + 400 * DAY)), 'certificate_expired');
  });
  it('dasselbe WRPAC heute -> akzeptiert (Gegenprobe)', async () => {
    await chain(new Date());
  });
});

describe('WRPAC-Kette: Grenzen mit Standardabweichung (60 s)', () => {
  it('Standard ist 60 Sekunden', () => {
    assert.equal(DEFAULT_CLOCK_SKEW_SECONDS, 60);
  });
  // Marge bewusst 4 s statt 1 s (B13): X.509 kodiert notBefore/notAfter
  // sekundengenau, die Erzeugung rundet dabei bis zu 999 ms ab. Bei 1 s
  // Abstand lag der erlaubte Grenzfall real nur ~340 ms vom verbotenen entfernt
  // und kippte unter Last in die verbotene Zone (beobachtet als Flaker).
  // 4 s liegen klar über der maximalen Rundung und prüfen dieselbe Semantik:
  // innerhalb der Toleranz gültig, eine Sekunde darüber abgelehnt.
  it('notAfter + 60 s -> gültig, erst + 64 s -> certificate_expired', async () => {
    await chain(at(leafCert.notAfter, 60_000));
    await rejectsWithCode(() => chain(at(leafCert.notAfter, 64_000)), 'certificate_expired');
  });
  it('notBefore - 60 s -> gültig, erst - 64 s -> certificate_not_yet_valid', async () => {
    await chain(at(leafCert.notBefore, -60_000));
    await rejectsWithCode(() => chain(at(leafCert.notBefore, -64_000)), 'certificate_not_yet_valid');
  });
});

describe('WRPAC-Kette: konfigurierte Uhrabweichung', () => {
  it('Abweichung 0: eine Sekunde nach notAfter -> abgelehnt, genau notAfter -> gültig', async () => {
    await chain(leafCert.notAfter, 0);
    await rejectsWithCode(() => chain(at(leafCert.notAfter, 1_000), 0), 'certificate_expired');
  });
  it('Abweichung 300: notAfter + 300 s gültig, + 301 s abgelehnt', async () => {
    await chain(at(leafCert.notAfter, 300_000), 300);
    await rejectsWithCode(() => chain(at(leafCert.notAfter, 301_000), 300), 'certificate_expired');
  });
});

describe('WRPAC-Kette: auch der Anker wird geprüft', () => {
  it('Anker abgelaufen (Blatt noch gültig) -> certificate_expired', async () => {
    // Das Blatt läuft 1 Tag, der Anker 30 Tage: nach 31 Tagen ist auch der Anker abgelaufen.
    const longLeaf = await accessCa.issueWrpac({ subjectCn: 'Lang GmbH (TEST)', entitlementOids: [Object.keys(TEST_ENTITLEMENT_MAP)[0]], notAfterDays: 400 });
    const afterAnchor = at(caCert.notAfter, 61_000);
    assert.ok(certificateFrom(longLeaf.certDer).notAfter > afterAnchor, 'Blatt ist zu diesem Zeitpunkt noch gültig');
    await rejectsWithCode(
      () => validateWrpacChain(longLeaf.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: NO_REVOCATION, now: afterAnchor }),
      'certificate_expired',
    );
    await validateWrpacChain(longLeaf.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: NO_REVOCATION, now: new Date() });
  });
});

async function intermediateIssuer(root: WrprcIssuer, notBefore: Date, notAfter: Date): Promise<WrprcIssuer> {
  const key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const cert = await X509CertificateGenerator.create({
    serialNumber: crypto.randomUUID().replace(/-/g, ''),
    subject: 'CN=WRPRC Zwischen-CA TEST ONLY, C=DE',
    issuer: certificateFrom(root.certDer).subject,
    notBefore,
    notAfter,
    publicKey: key.publicKey,
    signingKey: root.key.privateKey,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: [new BasicConstraintsExtension(true, 0, true), new KeyUsagesExtension(KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign, true)],
  });
  return { certDer: new Uint8Array(cert.rawData), key };
}

describe('WRPRC-x5c-Kette', () => {
  let issuer!: WrprcIssuer;
  let raw!: string;
  let leaf!: X509Certificate;
  const nowSeconds = () => Math.floor(Date.now() / 1000);
  const options = (now: Date, clockSkewSeconds?: number) => ({
    wrprcIssuerAnchors: [issuer.certDer],
    allowedEntitlements: [SERVICE_PROVIDER_URI],
    revocation: NO_REVOCATION,
    now: Math.floor(now.getTime() / 1000),
    clockSkewSeconds,
  });

  /**
   * Einmal berechnetes Gültigkeitsfenster, an Issuer **und** Blatt übergeben.
   *
   * Vorher las `mock-pki.ts` die echte Uhr pro Zertifikat: `IN_FUTURE(30)`
   * beim Erzeugen. Der Issuer entstand zuerst, sein `notAfter` lag also
   * minimal früher als das des Blattes. Die Gültigkeitsprüfung läuft aber über
   * die **ganze Kette** (`chainValidityFailure` prüft Blatt *und* Anker), der
   * Test hat die Grenze dagegen nur aus `leaf.notAfter` gerechnet. Damit galt:
   *
   *   `issuer.notAfter + 60 s < now` und `now = leaf.notAfter + 60 s`
   *   ⟺ `issuer.notAfter < leaf.notAfter`
   *
   * Der Test wurde also rot, sobald die Erzeugung der beiden Zertifikate
   * unter Last mehr als die 4 s Marge beanspruchte — ungefähr jeder neunte
   * Lauf des vollen Laufs. Durch ein gemeinsames Fenster ist `notAfter` beider
   * Zertifikate identisch und die Grenze exakt; eine Marge ist nicht mehr
   * nötig. Das ist Zeitinjektion, kein Margenvergrößern.
   */
  const FENSTER = {
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
  };
  /** Sekundenbasis des Tokens, abgeleitet aus derselben Zeit wie das Fenster. */
  const TOKEN_IAT = Math.floor(FENSTER.notBefore.getTime() / 1000);

  beforeAll(async () => {
    issuer = await createWrprcIssuer('WRPRC Issuer TEST ONLY', FENSTER);
    const leafMaterial = await createWrprcLeaf(issuer, 'Zeit GmbH (TEST)', FENSTER);
    leaf = certificateFrom(leafMaterial.certDer);
    // Token lange gültig, damit nur der Zertifikatszeitraum entscheidet.
    raw = await signWrprc(
      { sub: 'wrp-zeit', iat: TOKEN_IAT, exp: TOKEN_IAT + 300 * 86_400, registry_uri: 'https://TEST-registrar.example/api/v1', entitlements: [SERVICE_PROVIDER_URI], policy_id: [WRPRC_POLICY_OID] },
      leafMaterial.key.privateKey,
      [leafMaterial.certDer, issuer.certDer],
    );
  });

  it('heute -> gültig (Gegenprobe)', async () => {
    await verifyWrprc(raw, options(new Date()));
  });
  // Exakt, weil Issuer und Blatt dasselbe notAfter haben: die Prüfung ist
  // `notAfter + clockSkew < now`, also ist +60 s der letzte gültige Punkt und
  // +61 s der erste abgelaufene. Vorher stand hier 64 s mit der Begründung,
  // die sekundengenaue X.509-Kodierung brauche eine Marge.
  it('Blatt: notAfter + 60 s gültig, erst + 61 s certificate_expired', async () => {
    await verifyWrprc(raw, options(at(leaf.notAfter, 60_000)));
    await rejectsWithCode(() => verifyWrprc(raw, options(at(leaf.notAfter, 61_000))), 'certificate_expired');
  });
  it('der Anker der Kette hat dasselbe notAfter wie das Blatt', () => {
    // Ohne das ist der Test darüber wieder von der Erzeugungsdauer abhängig.
    const anker = certificateFrom(issuer.certDer);
    assert.equal(anker.notAfter.getTime(), leaf.notAfter.getTime());
  });
  it('Blatt: notBefore - 61 s -> certificate_not_yet_valid (Token-iat liegt davor, zählt nicht)', async () => {
    await rejectsWithCode(() => verifyWrprc(raw, options(at(leaf.notBefore, -61_000), 60)), 'certificate_not_yet_valid');
  });

  it('Zwischenzertifikat als Anker (nicht selbstsigniert) abgelaufen -> certificate_expired, gültig -> akzeptiert', async () => {
    const root = await createWrprcIssuer('WRPRC Root TEST ONLY');
    const now = Date.now();
    for (const [label, notAfter, expected] of [
      ['abgelaufen', new Date(now - DAY), 'certificate_expired'],
      ['gültig', new Date(now + 30 * DAY), undefined],
    ] as const) {
      const inter = await intermediateIssuer(root, new Date(now - 10 * DAY), notAfter);
      const leafMaterial = await createWrprcLeaf(inter, `Zwischen ${label} (TEST)`);
      const token = await signWrprc(
        { sub: 'wrp-zw', iat: nowSeconds(), exp: nowSeconds() + 3600, registry_uri: 'https://TEST-registrar.example/api/v1', entitlements: [SERVICE_PROVIDER_URI], policy_id: [WRPRC_POLICY_OID] },
        leafMaterial.key.privateKey,
        [leafMaterial.certDer, inter.certDer],
      );
      const verify = () => verifyWrprc(token, { wrprcIssuerAnchors: [inter.certDer], allowedEntitlements: [SERVICE_PROVIDER_URI], revocation: NO_REVOCATION });
      if (expected) await rejectsWithCode(verify, expected);
      else await verify();
    }
  });
});

describe('Hilfsfunktion: jedes Zertifikat der Kette (Blatt, Zwischenzertifikat, Anker)', () => {
  async function selfSigned(notBefore: Date, notAfter: Date): Promise<Uint8Array> {
    const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const cert = await X509CertificateGenerator.createSelfSigned({ serialNumber: '01', name: 'CN=Zeit TEST', notBefore, notAfter, keys, signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' } });
    return new Uint8Array(cert.rawData);
  }

  it('abgelaufenes Zwischenzertifikat in der Mitte -> certificate_expired', async () => {
    const now = new Date();
    const valid = await selfSigned(new Date(now.getTime() - DAY), new Date(now.getTime() + DAY));
    const expired = await selfSigned(new Date(now.getTime() - 10 * DAY), new Date(now.getTime() - DAY));
    const future = await selfSigned(new Date(now.getTime() + DAY), new Date(now.getTime() + 10 * DAY));
    assert.equal(chainValidityFailure([valid, expired, valid], now), 'certificate_expired');
    assert.equal(chainValidityFailure([valid, future, valid], now), 'certificate_not_yet_valid');
    assert.equal(chainValidityFailure([valid, valid, valid], now), undefined);
  });
  it('nicht lesbares Zertifikat gilt als abgelaufen (im Zweifel ablehnen)', () => {
    assert.equal(certificateValidityFailure(new Uint8Array([1, 2, 3]), new Date()), 'certificate_expired');
  });
  it('ungültige Uhrzeit -> abgelehnt', async () => {
    const valid = await selfSigned(new Date(Date.now() - DAY), new Date(Date.now() + DAY));
    assert.equal(certificateValidityFailure(valid, new Date(Number.NaN)), 'certificate_expired');
  });
});

describe('Onboarding-Gate mit injizierter Uhr', () => {
  async function gate(now: () => Date, clockSkewSeconds?: number) {
    const issuer = await createWrprcIssuer();
    const leaf = await createWrprcLeaf(issuer, 'Zeit GmbH (TEST)');
    const s = Math.floor(Date.now() / 1000);
    const wrprc = await signWrprc(
      { sub: 'wrp-gate-zeit', iat: s - 3600, exp: s + 300 * 86_400, registry_uri: 'https://TEST-registrar.example/api/v1', entitlements: [SERVICE_PROVIDER_URI], policy_id: [WRPRC_POLICY_OID] },
      leaf.key.privateKey,
      [leaf.certDer, issuer.certDer],
    );
    const tenants = new TenantStore();
    tenants.add({ id: 'tenant-zeit', name: 'Zeit (TEST)', apiKey: 'test-api-key-zeit', registration: { wrpacChain: wrpac.chain, wrprc } });
    return new RelyingPartyOnboardingGate({
      tenants,
      accessCaAnchors: [accessCa.caCertDer],
      wrprcIssuerAnchors: [issuer.certDer],
      entitlementMap: TEST_ENTITLEMENT_MAP,
      revocation: NO_REVOCATION,
      mode: DEV,
      now,
      clockSkewSeconds,
    });
  }

  it('abgelaufenes WRPAC -> tenant_registration_invalid mit Ursache certificate_expired', async () => {
    const g = await gate(() => at(leafCert.notAfter, 61_000));
    await assert.rejects(() => g.verifyTenant('tenant-zeit'), (e: unknown) => e instanceof ErrTenantRegistrationInvalid && e.reason === 'certificate_expired');
  });
  it('größere konfigurierte Abweichung lässt denselben Zeitpunkt zu (Gegenprobe)', async () => {
    const g = await gate(() => at(leafCert.notAfter, 61_000), 120);
    await g.verifyTenant('tenant-zeit');
  });
});
