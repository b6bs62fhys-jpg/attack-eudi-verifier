/**
 * Paket 6 f: Härtung des SD-JWT-VC-Parsers und des Key Binding.
 *
 * Eigenschaftsbasiert, aber ohne neue Abhängigkeit: ein deterministischer
 * Generator mit festem Startwert, wie in praesentations-fuzz.test.ts. Anders als
 * dort läuft hier die echte Kryptografie: gültige Präsentationen mit Test-Schlüsseln
 * werden gezielt kaputt gemacht und dem Dienst vorgelegt.
 *
 * Eigenschaften, die gelten müssen:
 *   1. Der Dienst wirft nie. Jede Eingabe ergibt eine Antwort mit `ok` und `valid`.
 *   2. Ein veränderter Token wird nie angenommen. Einzige Ausnahme sind
 *      Änderungen, die die dekodierten Bytes nicht ändern (ungenutzte Bits
 *      im letzten Base64url-Zeichen); das prüft `gleicheBytes`.
 *   3. Eine nicht angenommene Präsentation liefert dem Mandanten kein Ergebnis.
 *   4. Eine Präsentation, die abgelehnt wird, verbraucht nur ihre eigene Sitzung.
 *
 * Behoben, weil die Bibliothek es angenommen hat (jetzt `sdjwt-checks.ts`, RFC 9901):
 * dieselbe Offenlegung zweimal, derselbe Digest zweimal in `_sd`, ein Salt, das kein
 * Text ist, ein KB-JWT mit zwei Tage altem `iat` und ein KB-JWT mit `typ` `JWT`. Alle
 * fünf Tests dazu waren vor der Korrektur rot.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createLocalJWKSet, jwtVerify, SignJWT } from 'jose';
import { describe, it } from 'vitest';
import 'reflect-metadata';

import { buildSdJwtVc, generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { AuditLog } from './audit.ts';
import { VerifierService } from './service.ts';
import { TenantStore } from './tenant.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';
import { MAX_VP_TOKEN_CHARS } from './limits.ts';

/** xorshift32 mit festem Startwert, siehe praesentations-fuzz.test.ts. */
function zufall(saat: number): () => number {
  let zustand = saat | 0 || 1;
  return () => {
    zustand ^= zustand << 13;
    zustand ^= zustand >>> 17;
    zustand ^= zustand << 5;
    return ((zustand >>> 0) % 1_000_000) / 1_000_000;
  };
}

const b64u = (text: string) => Buffer.from(text, 'utf8').toString('base64url');
const sha256b64u = (text: string) => createHash('sha256').update(text).digest('base64url');

interface Umgebung {
  verifier: TestKeyMaterial;
  issuer: TestKeyMaterial;
  holder: TestKeyMaterial;
  service: VerifierService;
}

async function umgebung(): Promise<Umgebung> {
  const tenants = new TenantStore();
  tenants.add({ id: 'haertung', name: 'Härtung (TEST)', apiKey: 'test-api-key-haertung', requestProfile: { id: 'test-given-name', claims: ['given_name'] } });
  const verifier = await generateTestKeyMaterial('Härtung Verifier TEST');
  const issuer = await generateTestKeyMaterial('Härtung Issuer TEST');
  const holder = await generateTestKeyMaterial('Härtung Holder TEST');
  const service = new VerifierService(
    tenants,
    new AuditLog(),
    { privateKey: verifier.privateKey, publicKey: verifier.publicKey, publicJwk: verifier.publicJwk, certificateChain: [verifier.certDerBytes] },
    issuer.certDerBytes,
    undefined,
    undefined,
    undefined,
    undefined,
    true,
    DEV_TEST_OPTIONS,
  );
  service.baseUrl = 'http://127.0.0.1:9';
  return { verifier, issuer, holder, service };
}

interface Sitzung {
  state: string;
  sessionId: string;
  nonce: string;
  audience: string;
}

async function neueSitzung(u: Umgebung): Promise<Sitzung> {
  const created = await u.service.createRequest('haertung', {});
  const { payload } = await jwtVerify(created.requestObject, createLocalJWKSet({ keys: [u.verifier.publicJwk] }));
  return { state: created.state, sessionId: created.sessionId, nonce: String(payload.nonce), audience: String(payload.client_id) };
}

/** Gültiger Token der Mock-Wallet für die Sitzung. */
async function gueltig(u: Umgebung, s: Sitzung, extra: Partial<Parameters<typeof buildSdJwtVc>[0]> = {}): Promise<string> {
  return (await buildSdJwtVc({ issuerKey: u.issuer, holderKey: u.holder, nonce: s.nonce, audience: s.audience, ...extra })).sdJwt;
}

interface SelbstGebaut {
  /** Ersetzt die `_sd`-Liste im Issuer-JWT (Digests). Standard: ein Digest der ersten Offenlegung. */
  sdDigests?: string[];
  /** Offenlegungen (bereits base64url) hinter dem Issuer-JWT. */
  offenlegungen?: string[];
  /** Zusätzliche Claims im Issuer-JWT. */
  payload?: Record<string, unknown>;
  /** Ohne KB-JWT liefern. */
  ohneKb?: boolean;
  /** KB-JWT verändern. */
  kb?: { aud?: string; nonce?: string; iat?: number; sdHash?: string; typ?: string; key?: TestKeyMaterial; alg?: string };
}

/** Baut einen Token von Hand, mit echter Signatur des Ausstellers und des Halters. */
async function selbstGebaut(u: Umgebung, s: Sitzung, o: SelbstGebaut = {}): Promise<string> {
  const standard = b64u(JSON.stringify(['salz-1', 'given_name', 'Ada']));
  const offenlegungen = o.offenlegungen ?? [standard];
  const holderJwk = (await crypto.subtle.exportKey('jwk', u.holder.publicKey)) as JsonWebKey;
  const now = Math.floor(Date.now() / 1000);
  const issuerJwt = await new SignJWT({
    iss: 'https://TEST-issuer.de',
    vct: 'urn:eu.europa.ec.eudi:pid:1',
    iat: now,
    exp: now + 3600,
    _sd_alg: 'sha-256',
    _sd: o.sdDigests ?? [sha256b64u(standard)],
    cnf: { jwk: holderJwk },
    ...o.payload,
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'vc+sd-jwt', x5c: [u.issuer.x5cBase64] })
    .sign(u.issuer.privateKey);
  let sdJwt = `${issuerJwt}~${offenlegungen.map((d) => `${d}~`).join('')}`;
  if (o.ohneKb) return sdJwt;
  const kb = o.kb ?? {};
  const kbJwt = await new SignJWT({ iat: kb.iat ?? now, nonce: kb.nonce ?? s.nonce, aud: kb.aud ?? s.audience, sd_hash: kb.sdHash ?? sha256b64u(sdJwt) })
    .setProtectedHeader({ alg: kb.alg ?? 'ES256', typ: kb.typ ?? 'kb+jwt' })
    .sign((kb.key ?? u.holder).privateKey);
  sdJwt += kbJwt;
  return sdJwt;
}

/** Legt dem Dienst eine Präsentation vor und liefert Antwort und Ergebnisstatus. */
async function vorlegen(u: Umgebung, s: Sitzung, token: string) {
  const outcome = await u.service.handlePresentation(s.state, { pid: [token] });
  return { outcome, ergebnis: u.service.getResult('haertung', s.sessionId) };
}

function abgelehnt(r: Awaited<ReturnType<typeof vorlegen>>, wo: string): void {
  assert.equal(r.outcome.valid, false, `${wo}: wurde angenommen: ${JSON.stringify(r.outcome)}`);
  assert.notEqual(r.ergebnis.status, 'completed', `${wo}: der Mandant hat ein Ergebnis bekommen`);
}

/** Dekodierte Bytes aller Segmente gleich, auch wenn ungenutzte Bits im letzten Zeichen abweichen. */
function gleicheBytes(a: string, b: string): boolean {
  const teileA = a.split('~');
  const teileB = b.split('~');
  if (teileA.length !== teileB.length) return false;
  for (let i = 0; i < teileA.length; i += 1) {
    const segA = (teileA[i] as string).split('.');
    const segB = (teileB[i] as string).split('.');
    if (segA.length !== segB.length) return false;
    for (let j = 0; j < segA.length; j += 1) {
      const x = segA[j] as string;
      const y = segB[j] as string;
      if (!/^[A-Za-z0-9_-]*$/.test(x) || !/^[A-Za-z0-9_-]*$/.test(y)) {
        if (x !== y) return false;
        continue;
      }
      if (Buffer.compare(Buffer.from(x, 'base64url'), Buffer.from(y, 'base64url')) !== 0) return false;
    }
  }
  return true;
}

describe('Grundlage: der gebaute Token ist gültig (sonst wären alle Ablehnungen wertlos)', () => {
  it('Mock-Wallet-Token und selbst gebauter Token werden angenommen', async () => {
    const u = await umgebung();
    const s1 = await neueSitzung(u);
    const r1 = await vorlegen(u, s1, await gueltig(u, s1));
    assert.equal(r1.outcome.valid, true, JSON.stringify(r1.outcome));
    const s2 = await neueSitzung(u);
    const r2 = await vorlegen(u, s2, await selbstGebaut(u, s2));
    assert.equal(r2.outcome.valid, true, JSON.stringify(r2.outcome));
    assert.equal(r2.ergebnis.status, 'completed');
  });
});

describe('abgeschnittene Token', () => {
  it('jede Kürzung (an jeder 7. Stelle und an allen Trennzeichen) wird abgelehnt, ohne Wurf', async () => {
    const u = await umgebung();
    const vorlage = await gueltig(u, await neueSitzung(u));
    const stellen = new Set<number>();
    for (let i = 0; i < vorlage.length; i += 7) stellen.add(i);
    for (let i = 0; i < vorlage.length; i += 1) if (vorlage[i] === '~' || vorlage[i] === '.') for (const d of [-1, 0, 1]) stellen.add(i + d);
    stellen.delete(vorlage.length);
    for (const stelle of stellen) {
      const s = await neueSitzung(u);
      const token = (await gueltig(u, s)).slice(0, Math.min(stelle, vorlage.length - 1));
      abgelehnt(await vorlegen(u, s, token), `gekürzt auf ${stelle}`);
    }
  }, 120_000);

  it('Teile fehlen: nur Issuer-JWT, ohne KB, nur Tilden, leer', async () => {
    const u = await umgebung();
    for (const bauen of [
      async (s: Sitzung) => (await gueltig(u, s)).split('~')[0] as string,
      async (s: Sitzung) => `${(await gueltig(u, s)).split('~')[0]}~`,
      async (s: Sitzung) => selbstGebaut(u, s, { ohneKb: true }),
      async () => '~~~~',
      async () => '',
      async () => '~',
    ]) {
      const s = await neueSitzung(u);
      abgelehnt(await vorlegen(u, s, await bauen(s)), 'Teil fehlt');
    }
  });
});

describe('zufällige Veränderungen eines gültigen Tokens', () => {
  it('Zeichen ersetzen, einfügen, löschen, Segmente vertauschen: nie angenommen, außer bei gleichen Bytes', async () => {
    const u = await umgebung();
    const rnd = zufall(20261008);
    const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_~.';
    let angenommenGleich = 0;
    for (let lauf = 0; lauf < 300; lauf += 1) {
      const s = await neueSitzung(u);
      const original = await gueltig(u, s);
      let token = original;
      const art = Math.floor(rnd() * 5);
      const pos = Math.floor(rnd() * token.length);
      const zeichen = ALPHABET[Math.floor(rnd() * ALPHABET.length)] as string;
      if (art === 0) token = token.slice(0, pos) + zeichen + token.slice(pos + 1);
      else if (art === 1) token = token.slice(0, pos) + zeichen + token.slice(pos);
      else if (art === 2) token = token.slice(0, pos) + token.slice(pos + 1);
      else if (art === 3) {
        const teile = token.split('~');
        const i = Math.floor(rnd() * teile.length);
        const j = Math.floor(rnd() * teile.length);
        [teile[i], teile[j]] = [teile[j] as string, teile[i] as string];
        token = teile.join('~');
      } else {
        const teile = token.split('.');
        teile.splice(Math.floor(rnd() * teile.length), 1, zeichen.repeat(1 + Math.floor(rnd() * 5)));
        token = teile.join('.');
      }
      const r = await vorlegen(u, s, token);
      if (token === original || gleicheBytes(token, original)) {
        angenommenGleich += 1;
        continue;
      }
      abgelehnt(r, `Lauf ${lauf}, Art ${art}, Stelle ${pos}`);
    }
    assert.ok(angenommenGleich < 300);
  }, 240_000);

  it('Trennzeichen im Anhang: zusätzliche Tilden, Punkte, Leerzeichen und Zeilenumbrüche', async () => {
    const u = await umgebung();
    for (const anhang of ['~', '~~', '.', ' ', '\n', '\r\n', '~x', '\u0000', '..']) {
      const s = await neueSitzung(u);
      const token = (await gueltig(u, s)) + anhang;
      const r = await vorlegen(u, s, token);
      // Ein angehängtes Zeichen darf nie zu einem Ergebnis für den Mandanten führen, das nicht zum Token passt.
      if (r.outcome.valid) assert.equal(r.ergebnis.status, 'completed');
      else abgelehnt(r, `Anhang ${JSON.stringify(anhang)}`);
    }
  });
});

describe('Offenlegungen', () => {
  it('doppelte Offenlegung desselben Claims', async () => {
    const u = await umgebung();
    const s = await neueSitzung(u);
    const d = b64u(JSON.stringify(['salz-1', 'given_name', 'Ada']));
    abgelehnt(await vorlegen(u, s, await selbstGebaut(u, s, { offenlegungen: [d, d] })), 'zweimal dieselbe Offenlegung');
  });

  it('doppelte Digests in _sd', async () => {
    const u = await umgebung();
    const s = await neueSitzung(u);
    const d = b64u(JSON.stringify(['salz-1', 'given_name', 'Ada']));
    abgelehnt(await vorlegen(u, s, await selbstGebaut(u, s, { offenlegungen: [d], sdDigests: [sha256b64u(d), sha256b64u(d)] })), 'doppelter Digest');
  });

  it('Offenlegung ohne passenden Digest im Issuer-JWT', async () => {
    const u = await umgebung();
    const s = await neueSitzung(u);
    const d = b64u(JSON.stringify(['salz-1', 'given_name', 'Ada']));
    const fremd = b64u(JSON.stringify(['salz-2', 'family_name', 'Lovelace']));
    abgelehnt(await vorlegen(u, s, await selbstGebaut(u, s, { offenlegungen: [d, fremd] })), 'nicht referenzierte Offenlegung');
    const s2 = await neueSitzung(u);
    abgelehnt(await vorlegen(u, s2, await selbstGebaut(u, s2, { offenlegungen: [fremd], sdDigests: [sha256b64u(d)] })), 'Digest ohne Offenlegung, fremde Offenlegung');
  });

  it('kaputte Formen der Offenlegung', async () => {
    const u = await umgebung();
    const formen: unknown[] = [
      ['nur-salz'],
      ['salz', 'given_name'],
      ['salz', 'given_name', 'Ada', 'zu-viel'],
      ['salz', 42, 'Ada'],
      [42, 'given_name', 'Ada'],
      'kein array',
      { salz: 1 },
      null,
      [],
      [null, null, null],
    ];
    for (const form of formen) {
      const s = await neueSitzung(u);
      const d = b64u(JSON.stringify(form));
      abgelehnt(await vorlegen(u, s, await selbstGebaut(u, s, { offenlegungen: [d], sdDigests: [sha256b64u(d)] })), `Form ${JSON.stringify(form)}`);
    }
    for (const roh of ['kein base64!', '%%%', 'e30', b64u('{kein json'), b64u(''), '=']) {
      const s = await neueSitzung(u);
      abgelehnt(await vorlegen(u, s, await selbstGebaut(u, s, { offenlegungen: [roh], sdDigests: [sha256b64u(roh)] })), `roh ${roh}`);
    }
  });

  it('verbotene und kollidierende Claim-Namen in der Offenlegung', async () => {
    const u = await umgebung();
    // `_sd` und `...` sind in SD-JWT reserviert. `iss`, `vct`, `exp` und `cnf` stehen schon im
    // Issuer-JWT; eine Offenlegung darf sie nicht überschreiben.
    for (const name of ['_sd', '...', 'iss', 'vct', 'exp', 'cnf', '_sd_alg', '__proto__', 'constructor']) {
      const s = await neueSitzung(u);
      const d = b64u(JSON.stringify(['salz-x', name, name === 'cnf' ? { jwk: {} } : 'böse']));
      const r = await vorlegen(u, s, await selbstGebaut(u, s, { offenlegungen: [d], sdDigests: [sha256b64u(d)] }));
      abgelehnt(r, `Claim-Name ${name}`);
    }
  });

  it('__proto__ als zusätzliche Offenlegung verschmutzt weder das Ergebnis noch Object.prototype', async () => {
    const u = await umgebung();
    const s = await neueSitzung(u);
    const d1 = b64u(JSON.stringify(['salz-1', 'given_name', 'Ada']));
    const d2 = b64u(JSON.stringify(['salz-2', '__proto__', { polluted: true }]));
    const r = await vorlegen(u, s, await selbstGebaut(u, s, { offenlegungen: [d1, d2], sdDigests: [sha256b64u(d1), sha256b64u(d2)] }));
    assert.equal(({} as Record<string, unknown>).polluted, undefined);
    if (r.outcome.valid && r.ergebnis.status === 'completed') assert.deepEqual(r.ergebnis.result.claims, { given_name: 'Ada' });
  });

  it('riesige und tief verschachtelte Werte: kein Absturz, keine Annahme', async () => {
    const u = await umgebung();
    let tief: unknown = 'x';
    for (let i = 0; i < 5000; i += 1) tief = [tief];
    for (const wert of ['A'.repeat(20_000), tief, { a: 'b'.repeat(10_000) }, 'ü'.repeat(5_000)]) {
      const s = await neueSitzung(u);
      const d = b64u(JSON.stringify(['salz-1', 'given_name', wert]));
      const r = await vorlegen(u, s, await selbstGebaut(u, s, { offenlegungen: [d], sdDigests: [sha256b64u(d)] }));
      // Zu große Eingaben müssen abgelehnt werden. Kleinere dürfen angenommen werden, dann aber nur mit genau diesem Claim.
      if (r.outcome.valid) assert.deepEqual(Object.keys((r.ergebnis as { result: { claims: object } }).result.claims), ['given_name']);
    }
  });

  it('sehr viele Offenlegungen: über der Grenze abgelehnt, ohne Wurf', async () => {
    const u = await umgebung();
    for (const anzahl of [64, 65, 500, 5000]) {
      const s = await neueSitzung(u);
      const ds = Array.from({ length: anzahl }, (_, i) => b64u(JSON.stringify([`salz-${i}`, `feld_${i}`, i])));
      const r = await vorlegen(u, s, await selbstGebaut(u, s, { offenlegungen: ds, sdDigests: ds.map(sha256b64u) }));
      abgelehnt(r, `${anzahl} Offenlegungen`);
    }
  });
});

describe('riesige Eingaben', () => {
  it('Token an und über der Größengrenze: 422 oder Ablehnung, nie ein Wurf', async () => {
    const u = await umgebung();
    for (const laenge of [MAX_VP_TOKEN_CHARS - 1, MAX_VP_TOKEN_CHARS, MAX_VP_TOKEN_CHARS + 1, 200_000, 2_000_000]) {
      const s = await neueSitzung(u);
      const r = await vorlegen(u, s, 'a'.repeat(laenge));
      abgelehnt(r, `${laenge} Zeichen`);
    }
  });

  it('zufällige Zeichenfolgen mit Trennzeichen: nie angenommen, nie ein Wurf', async () => {
    const u = await umgebung();
    const rnd = zufall(8102026);
    const ALPHABET = 'abcxyzABC019-_~.= \n\u0000ü中';
    for (let lauf = 0; lauf < 150; lauf += 1) {
      const s = await neueSitzung(u);
      const laenge = Math.floor(rnd() * 600);
      let token = '';
      for (let i = 0; i < laenge; i += 1) token += ALPHABET[Math.floor(rnd() * ALPHABET.length)];
      abgelehnt(await vorlegen(u, s, token), `Zufallstoken ${lauf}`);
    }
  }, 120_000);

  it('vp_token in unerwarteten Formen: Zahl, null, Objekt, verschachtelte Arrays, leere Liste', async () => {
    const u = await umgebung();
    const formen: unknown[] = [{ pid: [] }, { pid: [null] }, { pid: [42] }, { pid: [[]] }, { pid: [{}] }, { pid: [{ a: 1 }, { b: 2 }] }, {}, { pid: ['a', 'b', 'c'] }, { __proto__: { pid: ['x'] } }];
    for (const form of formen) {
      const s = await neueSitzung(u);
      const outcome = await u.service.handlePresentation(s.state, form as Record<string, Array<string | object>>);
      assert.equal(outcome.valid, false, JSON.stringify(form));
      assert.notEqual(u.service.getResult('haertung', s.sessionId).status, 'completed');
    }
  });
});

describe('Key Binding', () => {
  it('KB-JWT verändert: falsche Nonce, falsche Audience, alter Zeitpunkt, falscher sd_hash', async () => {
    const u = await umgebung();
    const jetzt = Math.floor(Date.now() / 1000);
    const faelle: Array<[string, SelbstGebaut['kb']]> = [
      ['falsche Nonce', { nonce: 'andere-nonce' }],
      ['Nonce leer', { nonce: '' }],
      ['falsche Audience', { aud: 'x509_hash:falsch' }],
      ['Audience leer', { aud: '' }],
      ['Zeitpunkt vor 2 Tagen', { iat: jetzt - 172_800 }],
      ['Zeitpunkt in 2 Tagen', { iat: jetzt + 172_800 }],
      ['sd_hash falsch', { sdHash: sha256b64u('anderer inhalt') }],
      ['sd_hash leer', { sdHash: '' }],
      ['typ falsch', { typ: 'JWT' }],
    ];
    for (const [name, kb] of faelle) {
      const s = await neueSitzung(u);
      abgelehnt(await vorlegen(u, s, await selbstGebaut(u, s, { kb })), name);
    }
  });

  it('KB-JWT mit fremdem Schlüssel signiert (nicht der Schlüssel aus cnf)', async () => {
    const u = await umgebung();
    const fremd = await generateTestKeyMaterial('Fremder Halter TEST');
    const s = await neueSitzung(u);
    abgelehnt(await vorlegen(u, s, await selbstGebaut(u, s, { kb: { key: fremd } })), 'fremder Halterschlüssel');
  });

  it('KB-JWT mit alg none oder unbekanntem Algorithmus', async () => {
    const u = await umgebung();
    const s = await neueSitzung(u);
    const basis = await selbstGebaut(u, s, { ohneKb: true });
    const jetzt = Math.floor(Date.now() / 1000);
    for (const kopf of [{ alg: 'none', typ: 'kb+jwt' }, { alg: 'HS256', typ: 'kb+jwt' }, { alg: 'ES512', typ: 'kb+jwt' }, { typ: 'kb+jwt' }]) {
      const sitzung = await neueSitzung(u);
      const ohneKb = await selbstGebaut(u, sitzung, { ohneKb: true });
      const nutzdaten = { iat: jetzt, nonce: sitzung.nonce, aud: sitzung.audience, sd_hash: sha256b64u(ohneKb) };
      const kb = `${b64u(JSON.stringify(kopf))}.${b64u(JSON.stringify(nutzdaten))}.`;
      abgelehnt(await vorlegen(u, sitzung, ohneKb + kb), `KB-Kopf ${JSON.stringify(kopf)}`);
    }
    assert.ok(basis.endsWith('~'));
  });

  it('KB-JWT einer anderen Sitzung (Replay über Sitzungen)', async () => {
    const u = await umgebung();
    const alt = await neueSitzung(u);
    const gestohlen = await gueltig(u, alt);
    const neu = await neueSitzung(u);
    abgelehnt(await vorlegen(u, neu, gestohlen), 'Token der anderen Sitzung');
  });

  it('Offenlegung nach dem KB-JWT angehängt oder KB-JWT doppelt: abgelehnt', async () => {
    const u = await umgebung();
    const s1 = await neueSitzung(u);
    const t1 = await gueltig(u, s1);
    abgelehnt(await vorlegen(u, s1, `${t1}~${b64u(JSON.stringify(['salz-9', 'family_name', 'X']))}~`), 'Anhang nach KB');
    const s2 = await neueSitzung(u);
    const t2 = await gueltig(u, s2);
    const kb = t2.slice(t2.lastIndexOf('~') + 1);
    abgelehnt(await vorlegen(u, s2, `${t2}~${kb}`), 'KB doppelt');
  });

  it('der Aussteller-Schlüssel signiert das KB-JWT (Halter und Aussteller vertauscht)', async () => {
    const u = await umgebung();
    const s = await neueSitzung(u);
    abgelehnt(await vorlegen(u, s, await selbstGebaut(u, s, { kb: { key: u.issuer } })), 'KB mit Ausstellerschlüssel');
  });
});

describe('eine abgelehnte Präsentation beschädigt nichts', () => {
  it('nach vielen Fehlversuchen auf anderen Sitzungen bleibt eine frische Sitzung nutzbar', async () => {
    const u = await umgebung();
    for (let i = 0; i < 20; i += 1) {
      const s = await neueSitzung(u);
      await vorlegen(u, s, `kaputt-${i}~~`);
    }
    const s = await neueSitzung(u);
    const r = await vorlegen(u, s, await gueltig(u, s));
    assert.equal(r.outcome.valid, true, JSON.stringify(r.outcome));
  });

  it('ein Fehlversuch auf einer Sitzung lässt die Sitzung nicht für einen zweiten, gültigen Versuch offen', async () => {
    // Einmalnutzung: wer eine Sitzung mit Müll verbrennt, braucht eine neue.
    const u = await umgebung();
    const s = await neueSitzung(u);
    await vorlegen(u, s, 'kaputt~~');
    const zweiter = await u.service.handlePresentation(s.state, { pid: [await gueltig(u, s)] });
    assert.equal(zweiter.valid, false, 'die verbrauchte Sitzung darf nicht erneut angenommen werden');
  });
});
