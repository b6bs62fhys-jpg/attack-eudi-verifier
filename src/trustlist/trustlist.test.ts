/**
 * Tests für das Trust-List-Monitoring (Baustein A).
 * Nur TEST-Schlüssel im Speicher, Abrufe ausschließlich gegen den lokalen
 * Mock-Server (127.0.0.1, ephemerer Port). Kein Netzwerk.
 */
import assert from 'node:assert/strict';
import { afterAll, beforeAll, beforeEach, describe, it } from 'vitest';
import 'reflect-metadata';

import { generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import {
  JwsTrustListSignatureVerifier,
  TrustListFetchError,
  TrustListFormatError,
  TrustListMonitor,
  TrustListSignatureError,
  sha256Hex,
  type TrustListSignatureVerifier,
  type TrustListView,
} from './monitor.ts';
import {
  TrustListServer,
  buildTrustListDocument,
  signTrustListDocument,
  trustListEntry,
} from './mock-server.ts';
import type { TrustListDocument } from './types.ts';

interface TestContext {
  authority: TestKeyMaterial;
  attacker: TestKeyMaterial;
  issuerA: TestKeyMaterial;
  issuerB: TestKeyMaterial;
  verifier: TrustListSignatureVerifier;
}

let ctx: TestContext;

async function fetchText(uri: string) {
  const res = await fetch(uri);
  return { status: res.status, body: await res.text() };
}

function docOf(key: TestKeyMaterial, providerName = 'Trust Provider TEST'): TrustListDocument {
  const seconds = Math.floor(Date.now() / 1000);
  return buildTrustListDocument({
    id: 'urn:TEST:trust-list:1',
    issuer: 'TEST-Trust-List-Authority 1',
    issuedAt: seconds - 60,
    nextUpdate: seconds + 24 * 3600,
    version: 'v-test-1',
    entries: [
      trustListEntry({
        providerName,
        anchorFingerprintHex: sha256Hex(key.certDerBytes),
        subjectCommonName: 'EUDI Issuer TEST ONLY',
      }),
    ],
  });
}

beforeAll(async () => {
  ctx = {
    authority: await generateTestKeyMaterial('Trust List Authority TEST'),
    attacker: await generateTestKeyMaterial('Fake Trust List Authority TEST'),
    issuerA: await generateTestKeyMaterial('EUDI Issuer A TEST'),
    issuerB: await generateTestKeyMaterial('EUDI Issuer B TEST'),
    verifier: new JwsTrustListSignatureVerifier(({} as JsonWebKey), 'TEST-Trust-List-Authority 1'),
  };
  ctx.verifier = new JwsTrustListSignatureVerifier(ctx.authority.publicJwk, 'TEST-Trust-List-Authority 1');
});

describe('Trust-List-Monitoring (Baustein A)', () => {
  let server: TrustListServer | undefined;

  beforeEach(async () => {
    await server?.close();
    server = new TrustListServer({ authorityKey: ctx.authority, corruptKey: ctx.attacker });
  });

  afterAll(async () => {
    await server?.close();
  });

  it('lädt und verifiziert eine gültig signierte Trust List (TEST) und vertraut dem gelisteten Issuer', async () => {
    ctx.verifier = new JwsTrustListSignatureVerifier(ctx.authority.publicJwk, 'TEST-Trust-List-Authority 1');
    const uri = await server!.start(docOf(ctx.issuerA));

    const monitor = new TrustListMonitor({ uri: uri+'/trustlist', fetcher: fetchText, verifier: ctx.verifier, minFetchIntervalMs: 0 });
    const result = await monitor.refresh();

    assert.equal(result.fetched, true);
    assert.equal(result.applied, true);
    assert.ok(monitor.view().isLoaded);
    assert.ok(monitor.view().lastVerifiedAt);
    const view: TrustListView = monitor.view();
    assert.equal(view.document.id, 'urn:TEST:trust-list:1');

    assert.equal(monitor.isIssuerTrusted(ctx.issuerA.certDerBytes), true);
    assert.equal(monitor.isIssuerTrusted(ctx.issuerB.certDerBytes), false);
    assert.equal(monitor.isIssuerTrusted(ctx.attacker.certDerBytes), false);
  });

  it('erkennt Änderungen zwischen zwei Abrufen (added/removed) und benachrichtigt', async () => {
    ctx.verifier = new JwsTrustListSignatureVerifier(ctx.authority.publicJwk, 'TEST-Trust-List-Authority 1');
    const uri = await server!.start(docOf(ctx.issuerA, 'Provider A TEST'));
    const changes: unknown[] = [];
    const monitor = new TrustListMonitor({ uri: uri+'/trustlist', fetcher: fetchText, verifier: ctx.verifier, minFetchIntervalMs: 0, onChange: (c) => changes.push(...c) });

    const first = await monitor.refresh();
    assert.deepEqual(first.changes.map((c) => c.change), ['added']);
    assert.deepEqual(changes.map((c) => (c as { change: string }).change), ['added']);

    const docB = buildTrustListDocument({
      id: 'urn:TEST:trust-list:1',
      issuer: 'TEST-Trust-List-Authority 1',
      issuedAt: Math.floor(Date.now() / 1000),
      nextUpdate: Math.floor(Date.now() / 1000) + 24 * 3600,
      version: 'v-test-2',
      entries: [
        trustListEntry({
          providerName: 'Provider B TEST',
          anchorFingerprintHex: sha256Hex(ctx.issuerB.certDerBytes),
          subjectCommonName: 'EUDI Issuer B TEST ONLY',
        }),
      ],
    });
    server!.setDocument(docB);

    const second = await monitor.refresh(true);
    const kinds = second.changes.map((c) => c.change).sort();
    assert.deepEqual(kinds, ['added', 'removed']);
    assert.equal(second.currentVersion, 'v-test-2');

    assert.equal(monitor.isIssuerTrusted(ctx.issuerB.certDerBytes), true);
    assert.equal(monitor.isIssuerTrusted(ctx.issuerA.certDerBytes), false);
  });

  it('bedient Wiederholungsabrufe innerhalb der Cache-TTL aus dem Cache', async () => {
    ctx.verifier = new JwsTrustListSignatureVerifier(ctx.authority.publicJwk);
    const uri = await server!.start(docOf(ctx.issuerA));
    const monitor = new TrustListMonitor({ uri: uri+'/trustlist', fetcher: fetchText, verifier: ctx.verifier, minFetchIntervalMs: 0 });

    const first = await monitor.refresh();
    const second = await monitor.refresh();

    assert.equal(first.fetched, true);
    assert.equal(second.fetched, false);
    assert.equal(server!.requestCount, 1);
  });

  it('lehnt eine Trust List mit falscher Signatur ab und hält den letzten gültigen Stand (fail closed)', async () => {
    ctx.verifier = new JwsTrustListSignatureVerifier(ctx.authority.publicJwk);
    const uri = await server!.start(docOf(ctx.issuerA));
    const monitor = new TrustListMonitor({ uri: uri+'/trustlist', fetcher: fetchText, verifier: ctx.verifier, minFetchIntervalMs: 0 });
    await monitor.refresh();
    const versionBefore = monitor.view().document.version;

    server!.setCorruptSignature(true);
    await assert.rejects(() => monitor.refresh(true), (err: unknown) => err instanceof TrustListSignatureError && err.code === 'trust_list_signature_invalid');

    assert.equal(monitor.view().document.version, versionBefore);
    assert.equal(monitor.isIssuerTrusted(ctx.issuerA.certDerBytes), true);
  });

  it('lehnt einen HTTP-Fehler ab und hält den letzten gültigen Stand', async () => {
    ctx.verifier = new JwsTrustListSignatureVerifier(ctx.authority.publicJwk);
    const uri = await server!.start(docOf(ctx.issuerA));
    const monitor = new TrustListMonitor({ uri: uri+'/trustlist', fetcher: fetchText, verifier: ctx.verifier, minFetchIntervalMs: 0 });
    await monitor.refresh();

    server!.setStatus(404);
    await assert.rejects(() => monitor.refresh(true), (err: unknown) => err instanceof TrustListFetchError && err.code === 'trust_list_fetch_failed');
    assert.equal(monitor.isIssuerTrusted(ctx.issuerA.certDerBytes), true);
  });

  it('lehnt einen Issuer ab, der nicht auf der aktuellen Trust List steht (Politik-Fail closed)', async () => {
    ctx.verifier = new JwsTrustListSignatureVerifier(ctx.authority.publicJwk);
    const uri = await server!.start(docOf(ctx.issuerA));
    const monitor = new TrustListMonitor({ uri: uri+'/trustlist', fetcher: fetchText, verifier: ctx.verifier, minFetchIntervalMs: 0 });
    await monitor.refresh();

    const policy = monitor.asIssuerTrustPolicy();
    assert.equal(policy.isIssuerTrusted(ctx.issuerA.certDerBytes), true);
    assert.equal(policy.isIssuerTrusted(ctx.issuerB.certDerBytes), false);
  });

  it('lehnt ein strukturell ungueltiges Trust-List-Dokument ab', async () => {
    ctx.verifier = new JwsTrustListSignatureVerifier(ctx.authority.publicJwk);
    const malformed = {
      id: 'urn:TEST:trust-list:1',
      issuer: 'TEST-Trust-List-Authority 1',
      issuedAt: Math.floor(Date.now() / 1000),
      nextUpdate: Math.floor(Date.now() / 1000) + 3600,
      version: 'v-broken',
      entries: [{ providerName: 'Provider X TEST', country: 'DE' }],
    } as unknown as TrustListDocument;

    await assert.rejects(async () => ctx.verifier.verify(await signTrustListDocument(malformed, ctx.authority)), (err: unknown) => err instanceof TrustListFormatError);

    const uri = await server!.start(docOf(ctx.issuerA));
    const monitor = new TrustListMonitor({ uri: uri+'/trustlist', fetcher: fetchText, verifier: ctx.verifier, minFetchIntervalMs: 0 });
    await monitor.refresh();
    server!.setDocument(malformed as TrustListDocument);
    await assert.rejects(() => monitor.refresh(true), (err: unknown) => err instanceof TrustListFormatError);
    assert.equal(monitor.isIssuerTrusted(ctx.issuerA.certDerBytes), true);
  });

  it('begrenzt Netzabrufe auf minFetchIntervalMs (auch bei force)', async () => {
    ctx.verifier = new JwsTrustListSignatureVerifier(ctx.authority.publicJwk);
    const uri = await server!.start(docOf(ctx.issuerA));
    let t = Date.now();
    const monitor = new TrustListMonitor({
      uri: uri + '/trustlist',
      fetcher: fetchText,
      verifier: ctx.verifier,
      now: () => t,
      minFetchIntervalMs: 60_000,
    });

    const first = await monitor.refresh();
    assert.equal(first.fetched, true);
    assert.equal(server!.requestCount, 1);

    const forced = await monitor.refresh(true);
    assert.equal(forced.fetched, false, 'innerhalb des Intervalls kein Netzabruf, auch bei force');
    assert.equal(server!.requestCount, 1);

    t += 60_001;
    const later = await monitor.refresh(true);
    assert.equal(later.fetched, true);
    assert.equal(server!.requestCount, 2);
  });

  it('koalesziert parallele Abrufe (Single-Flight)', async () => {
    ctx.verifier = new JwsTrustListSignatureVerifier(ctx.authority.publicJwk);
    const uri = await server!.start(docOf(ctx.issuerA));
    const monitor = new TrustListMonitor({ uri: uri + '/trustlist', fetcher: fetchText, verifier: ctx.verifier, minFetchIntervalMs: 0 });

    const [a, b, c] = await Promise.all([monitor.refresh(), monitor.refresh(), monitor.refresh()]);

    assert.equal(a.fetched, true);
    assert.equal(b.fetched, true);
    assert.equal(c.fetched, true);
    assert.equal(server!.requestCount, 1, 'parallele Aufrufe teilen sich einen Netzabruf');
  });
});