/**
 * Härtung 1: Sperrprüfung WRPAC/WRPRC fail closed.
 *
 * Jeder Fehlerpfad der Sperrprüfung führt zur Ablehnung mit eigenem Code,
 * jeweils mit positiver Gegenprobe:
 *   - enforceRevocation: nur ausdrücklich 'good' passiert
 *   - CrlRevocationChecker (CRL nach RFC 5280): nicht erreichbar, Zeitgrenze,
 *     HTTP-Fehler, Größengrenze, falsches Format, fremder Aussteller,
 *     ungültige Signatur, abgelaufene Liste, fehlendes nextUpdate,
 *     unbekannter Status, gesperrt, ausgesetzt, keine Sperrquelle
 *   - NO_REVOCATION nur mit Entwicklungsschalter (sonst ConfigError)
 * Die CRLs werden über echte lokale HTTP-Server (127.0.0.1) ausgeliefert.
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';
import { X509Certificate, X509CrlGenerator, X509CrlReason, type X509CrlEntryParams } from '@peculiar/x509';

import { ConfigError } from '../config.ts';
import { TenantStore } from '../service/tenant.ts';
import { CrlRevocationChecker, crlUrlFromDistributionPoints } from './crl-revocation.ts';
import { ErrTenantRegistrationInvalid, OnboardingError } from './errors.ts';
import { createAccessCa, createWrprcIssuer, createWrprcLeaf, generateTestKeyPair, signWrprc, TEST_ENTITLEMENT_MAP, type AccessCa, type IssuedWrpac } from './mock-pki.ts';
import { RelyingPartyOnboardingGate } from './onboarding-gate.ts';
import { WRPRC_POLICY_OID } from './oid.ts';
import { assertRevocationAllowed, enforceRevocation, NO_REVOCATION, type RevocationChecker } from './revocation.ts';
import { validateWrpacChain } from './wrpac.ts';
import { verifyWrprc } from './wrprc.ts';

const DEV = { devMode: true, isProduction: false };
const NO_DEV = { devMode: false, isProduction: false };
const PROD = { devMode: false, isProduction: true };

let accessCa!: AccessCa;
let caSubject!: string;
let wrpac!: IssuedWrpac;
let wrpacSerial!: string;
let crlServer!: http.Server;
let crlBase!: string;
/** Antwort des CRL-Servers je Pfad. */
const routes = new Map<string, (res: http.ServerResponse) => void>();

function codeOf(e: unknown): string {
  return e instanceof OnboardingError ? e.code : `kein OnboardingError: ${String(e)}`;
}

async function rejectsWithCode(fn: () => Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(fn, (e: unknown) => {
    assert.equal(codeOf(e), code);
    return true;
  });
}

async function crlDer(options: { entries?: X509CrlEntryParams[]; nextUpdate?: Date | null; thisUpdate?: Date; signingKey?: CryptoKey; issuer?: string }): Promise<Uint8Array> {
  const crl = await X509CrlGenerator.create({
    issuer: options.issuer ?? caSubject,
    thisUpdate: options.thisUpdate ?? new Date(Date.now() - 60_000),
    ...(options.nextUpdate === null ? {} : { nextUpdate: options.nextUpdate ?? new Date(Date.now() + 3600_000) }),
    entries: options.entries ?? [],
    signingKey: options.signingKey ?? accessCa.caKey.privateKey,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
  });
  return new Uint8Array(crl.rawData);
}

function serve(path: string, body: Uint8Array | string, status = 200): string {
  routes.set(path, (res) => {
    res.writeHead(status, { 'content-type': 'application/pkix-crl' });
    res.end(body);
  });
  return `${crlBase}${path}`;
}

/** Checker, der die CRL-Adresse fest vorgibt (statt CRL Distribution Points). */
function checkerFor(url: string, extra: Partial<ConstructorParameters<typeof CrlRevocationChecker>[0]> = {}): CrlRevocationChecker {
  return new CrlRevocationChecker({ crlUrlFor: () => url, timeoutMs: 1_000, ...extra });
}

const certificateFrom = (der: Uint8Array) => new X509Certificate(Uint8Array.from(der));

async function closedPortUrl(): Promise<string> {
  const probe = http.createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const port = (probe.address() as { port: number }).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return `http://127.0.0.1:${port}/crl`;
}

beforeAll(async () => {
  accessCa = await createAccessCa();
  caSubject = certificateFrom(accessCa.caCertDer).subject;
  crlServer = http.createServer((req, res) => {
    const handler = routes.get(req.url ?? '');
    if (handler) return handler(res);
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => crlServer.listen(0, '127.0.0.1', resolve));
  crlBase = `http://127.0.0.1:${(crlServer.address() as { port: number }).port}`;
  wrpac = await accessCa.issueWrpac({ subjectCn: 'Sperr GmbH (TEST)', entitlementOids: [Object.keys(TEST_ENTITLEMENT_MAP)[0]], crlUrl: `${crlBase}/cdp.crl` });
  wrpacSerial = certificateFrom(wrpac.certDer).serialNumber;
});

afterAll(async () => {
  crlServer.closeAllConnections();
  await new Promise<void>((resolve) => crlServer.close(() => resolve()));
});

describe('enforceRevocation: nur ausdrücklich "good" passiert', () => {
  const der = new Uint8Array([1]);
  const make = (impl: () => Promise<unknown>): RevocationChecker => ({ checkRevoked: impl as RevocationChecker['checkRevoked'] });

  it('good -> akzeptiert (Gegenprobe)', async () => {
    await enforceRevocation(make(async () => 'good'), der, 'leaf', der);
  });
  it('revoked -> certificate_revoked', async () => {
    await rejectsWithCode(() => enforceRevocation(make(async () => 'revoked'), der, 'leaf', der), 'certificate_revoked');
  });
  it('suspended -> certificate_suspended', async () => {
    await rejectsWithCode(() => enforceRevocation(make(async () => 'suspended'), der, 'leaf', der), 'certificate_suspended');
  });
  it('kein Rückgabewert (undefined) -> revocation_status_unknown', async () => {
    await rejectsWithCode(() => enforceRevocation(make(async () => undefined), der, 'leaf', der), 'revocation_status_unknown');
  });
  it('unbekannter Statuswert -> revocation_status_unknown', async () => {
    await rejectsWithCode(() => enforceRevocation(make(async () => 'GOOD'), der, 'leaf', der), 'revocation_status_unknown');
  });
  it('beliebige Ausnahme -> revocation_unavailable (keine Rohmeldung)', async () => {
    await rejectsWithCode(() => enforceRevocation(make(async () => { throw new Error('ECONNREFUSED /intern/pfad'); }), der, 'leaf', der), 'revocation_unavailable');
  });
  it('Checker hängt -> revocation_timeout', async () => {
    await rejectsWithCode(() => enforceRevocation(make(() => new Promise(() => undefined)), der, 'leaf', der, 50), 'revocation_timeout');
  });
});

describe('CrlRevocationChecker: Status aus der CRL', () => {
  it('leere, frische CRL -> Kette akzeptiert (Gegenprobe)', async () => {
    const url = serve('/good.crl', await crlDer({}));
    await validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checkerFor(url) });
  });
  it('Blatt auf der CRL -> certificate_revoked', async () => {
    const url = serve('/revoked.crl', await crlDer({ entries: [{ serialNumber: wrpacSerial, reason: X509CrlReason.keyCompromise }] }));
    await rejectsWithCode(() => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checkerFor(url) }), 'certificate_revoked');
  });
  it('Eintrag ohne Grund -> certificate_revoked', async () => {
    const url = serve('/revoked-noreason.crl', await crlDer({ entries: [{ serialNumber: wrpacSerial }] }));
    await rejectsWithCode(() => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checkerFor(url) }), 'certificate_revoked');
  });
  it('certificateHold -> certificate_suspended', async () => {
    const url = serve('/hold.crl', await crlDer({ entries: [{ serialNumber: wrpacSerial, reason: X509CrlReason.certificateHold }] }));
    await rejectsWithCode(() => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checkerFor(url) }), 'certificate_suspended');
  });
  it('removeFromCRL in Basis-CRL -> revocation_status_unknown', async () => {
    const url = serve('/remove.crl', await crlDer({ entries: [{ serialNumber: wrpacSerial, reason: X509CrlReason.removeFromCRL }] }));
    await rejectsWithCode(() => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checkerFor(url) }), 'revocation_status_unknown');
  });
  it('anderes Zertifikat auf der CRL -> Blatt akzeptiert (Gegenprobe)', async () => {
    const other = await accessCa.issueWrpac({ subjectCn: 'Andere GmbH (TEST)', entitlementOids: [Object.keys(TEST_ENTITLEMENT_MAP)[0]] });
    const url = serve('/other.crl', await crlDer({ entries: [{ serialNumber: certificateFrom(other.certDer).serialNumber }] }));
    await validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checkerFor(url) });
  });
});

describe('CrlRevocationChecker: Fehlerpfade lehnen ab', () => {
  it('Sperrliste nicht erreichbar (Mock-Server aus) -> revocation_unavailable', async () => {
    const url = await closedPortUrl();
    await rejectsWithCode(() => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checkerFor(url) }), 'revocation_unavailable');
  });
  it('HTTP 500 -> revocation_unavailable', async () => {
    const url = serve('/500.crl', 'kaputt', 500);
    await rejectsWithCode(() => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checkerFor(url) }), 'revocation_unavailable');
  });
  it('Zeitüberschreitung -> revocation_timeout', async () => {
    routes.set('/slow.crl', () => {
      /* antwortet nie */
    });
    const checker = checkerFor(`${crlBase}/slow.crl`, { timeoutMs: 100 });
    await rejectsWithCode(() => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checker }), 'revocation_timeout');
  });
  it('Zeitgrenze greift auch, wenn der Server den Körper nie beendet', async () => {
    routes.set('/trickle.crl', (res) => {
      res.writeHead(200, { 'content-type': 'application/pkix-crl' });
      res.write(Buffer.from([0x30]));
    });
    const checker = checkerFor(`${crlBase}/trickle.crl`, { timeoutMs: 100 });
    await rejectsWithCode(() => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checker }), 'revocation_timeout');
  });
  it('Liste größer als die Grenze -> revocation_list_too_large', async () => {
    const url = serve('/big.crl', new Uint8Array(4096));
    await rejectsWithCode(
      () => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checkerFor(url, { maxBytes: 1024 }) }),
      'revocation_list_too_large',
    );
  });
  it('falsches Format -> revocation_list_malformed', async () => {
    const url = serve('/garbage.crl', 'das ist keine CRL');
    await rejectsWithCode(() => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checkerFor(url) }), 'revocation_list_malformed');
  });
  it('fremder Aussteller -> revocation_list_malformed', async () => {
    const url = serve('/foreign.crl', await crlDer({ issuer: 'CN=Fremde CA TEST, C=DE' }));
    await rejectsWithCode(() => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checkerFor(url) }), 'revocation_list_malformed');
  });
  it('ungültige Signatur -> revocation_list_signature_invalid', async () => {
    const otherKey = await generateTestKeyPair();
    const url = serve('/badsig.crl', await crlDer({ signingKey: otherKey.privateKey }));
    await rejectsWithCode(() => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checkerFor(url) }), 'revocation_list_signature_invalid');
  });
  it('abgelaufene Liste (nextUpdate vorbei) -> revocation_list_expired', async () => {
    const url = serve('/expired.crl', await crlDer({ thisUpdate: new Date(Date.now() - 7200_000), nextUpdate: new Date(Date.now() - 3600_000) }));
    await rejectsWithCode(() => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checkerFor(url) }), 'revocation_list_expired');
  });
  it('Liste aus der Zukunft (thisUpdate) -> revocation_list_expired', async () => {
    const url = serve('/future.crl', await crlDer({ thisUpdate: new Date(Date.now() + 3600_000), nextUpdate: new Date(Date.now() + 7200_000) }));
    await rejectsWithCode(() => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checkerFor(url) }), 'revocation_list_expired');
  });
  it('ohne nextUpdate -> revocation_list_malformed', async () => {
    const url = serve('/nonext.crl', await crlDer({ nextUpdate: null }));
    await rejectsWithCode(() => validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: checkerFor(url) }), 'revocation_list_malformed');
  });
  it('Zertifikat ohne CRL-Distribution-Point -> revocation_source_missing', async () => {
    const plain = await accessCa.issueWrpac({ subjectCn: 'Ohne CDP GmbH (TEST)', entitlementOids: [Object.keys(TEST_ENTITLEMENT_MAP)[0]] });
    await rejectsWithCode(() => validateWrpacChain(plain.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: new CrlRevocationChecker() }), 'revocation_source_missing');
  });
  it('CRL-Distribution-Point aus dem Zertifikat wird genutzt (Gegenprobe)', async () => {
    assert.equal(crlUrlFromDistributionPoints(certificateFrom(wrpac.certDer)), `${crlBase}/cdp.crl`);
    serve('/cdp.crl', await crlDer({}));
    await validateWrpacChain(wrpac.certDer, { accessCaAnchors: [accessCa.caCertDer], revocation: new CrlRevocationChecker({ timeoutMs: 1_000 }) });
  });
});

describe('Sperrprüfung WRPRC über CRL', () => {
  it('gesperrtes WRPRC-Blatt -> certificate_revoked, nicht gesperrt -> akzeptiert', async () => {
    const issuer = await createWrprcIssuer();
    const leaf = await createWrprcLeaf(issuer, 'Sperr GmbH (TEST)');
    const now = Math.floor(Date.now() / 1000);
    const raw = await signWrprc(
      { sub: 'wrp-crl', iat: now, exp: now + 3600, registry_uri: 'https://TEST-registrar.example/api/v1', entitlements: [TEST_ENTITLEMENT_MAP['0.4.0.19475.1.1']], policy_id: [WRPRC_POLICY_OID] },
      leaf.key.privateKey,
      [leaf.certDer, issuer.certDer],
    );
    const issuerSubject = certificateFrom(issuer.certDer).subject;
    const make = async (entries: X509CrlEntryParams[]) =>
      new Uint8Array((await X509CrlGenerator.create({ issuer: issuerSubject, thisUpdate: new Date(Date.now() - 60_000), nextUpdate: new Date(Date.now() + 3600_000), entries, signingKey: issuer.key.privateKey, signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' } })).rawData);
    const options = { wrprcIssuerAnchors: [issuer.certDer], allowedEntitlements: [TEST_ENTITLEMENT_MAP['0.4.0.19475.1.1']] };

    const goodUrl = serve('/wrprc-good.crl', await make([]));
    await verifyWrprc(raw, { ...options, revocation: checkerFor(goodUrl) });

    const revokedUrl = serve('/wrprc-revoked.crl', await make([{ serialNumber: certificateFrom(leaf.certDer).serialNumber }]));
    await rejectsWithCode(() => verifyWrprc(raw, { ...options, revocation: checkerFor(revokedUrl) }), 'certificate_revoked');

    const closed = await closedPortUrl();
    await rejectsWithCode(() => verifyWrprc(raw, { ...options, revocation: checkerFor(closed) }), 'revocation_unavailable');
  });
});

describe('Onboarding-Gate: Sperrquelle nicht erreichbar -> Mandant abgelehnt', () => {
  async function gateWith(revocation: RevocationChecker): Promise<RelyingPartyOnboardingGate> {
    const issuer = await createWrprcIssuer();
    const leaf = await createWrprcLeaf(issuer, 'Sperr GmbH (TEST)');
    const now = Math.floor(Date.now() / 1000);
    const wrprc = await signWrprc(
      { sub: 'wrp-gate', iat: now, exp: now + 3600, registry_uri: 'https://TEST-registrar.example/api/v1', entitlements: [TEST_ENTITLEMENT_MAP['0.4.0.19475.1.1']], policy_id: [WRPRC_POLICY_OID] },
      leaf.key.privateKey,
      [leaf.certDer, issuer.certDer],
    );
    const tenants = new TenantStore();
    tenants.add({ id: 'tenant-crl', name: 'Kunde CRL (TEST)', apiKey: 'test-api-key-crl', registration: { wrpacChain: wrpac.chain, wrprc } });
    return new RelyingPartyOnboardingGate({
      tenants,
      accessCaAnchors: [accessCa.caCertDer],
      wrprcIssuerAnchors: [issuer.certDer],
      entitlementMap: TEST_ENTITLEMENT_MAP,
      revocation,
      mode: NO_DEV,
    });
  }

  it('Mock-Sperrliste nicht erreichbar -> tenant_registration_invalid (Ursache revocation_unavailable)', async () => {
    const url = await closedPortUrl();
    const gate = await gateWith(checkerFor(url));
    await assert.rejects(
      () => gate.verifyTenant('tenant-crl'),
      (e: unknown) => e instanceof ErrTenantRegistrationInvalid && e.reason === 'revocation_unavailable',
    );
  });
});

describe('NO_REVOCATION nur mit Entwicklungsschalter', () => {
  it('Entwicklungsschalter aktiv -> erlaubt (Gegenprobe)', () => {
    assertRevocationAllowed(NO_REVOCATION, DEV);
  });
  it('ohne Entwicklungsschalter -> ConfigError', () => {
    assert.throws(() => assertRevocationAllowed(NO_REVOCATION, NO_DEV), ConfigError);
  });
  it('Produktionsmodus -> ConfigError', () => {
    assert.throws(() => assertRevocationAllowed(NO_REVOCATION, PROD), ConfigError);
    assert.throws(() => assertRevocationAllowed(NO_REVOCATION, { devMode: true, isProduction: true }), ConfigError);
  });
  it('ohne Modusangabe gilt streng -> ConfigError', () => {
    assert.throws(() => assertRevocationAllowed(NO_REVOCATION), ConfigError);
  });
  it('echter Checker im Produktionsmodus -> erlaubt', () => {
    assertRevocationAllowed(new CrlRevocationChecker(), PROD);
  });
  it('Onboarding-Gate mit NO_REVOCATION im Produktionsmodus -> Aufbau bricht ab', () => {
    const build = (mode?: typeof PROD) =>
      new RelyingPartyOnboardingGate({ tenants: new TenantStore(), accessCaAnchors: [], wrprcIssuerAnchors: [], entitlementMap: TEST_ENTITLEMENT_MAP, revocation: NO_REVOCATION, mode });
    assert.throws(() => build(PROD), ConfigError);
    assert.throws(() => build(undefined), ConfigError);
    assert.doesNotThrow(() => build(DEV));
  });
});
