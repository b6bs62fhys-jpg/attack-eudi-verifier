/**
 * Einheitentests für sdjwt-checks.ts: jeder feste Grund einzeln, mit
 * handgebauten Token ohne Kryptografie (die Prüfung liest nur Form und Zeit).
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'vitest';

import { kbJwtFailure, publicCodeFor, sdJwtStructureFailure, type SdJwtStructureOptions } from './sdjwt-checks.ts';

const b64u = (value: unknown) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value), 'utf8').toString('base64url');
const digest = (text: string) => createHash('sha256').update(text).digest('base64url');
const NOW = new Date('2026-10-08T12:00:00Z');
const IAT = Math.floor(NOW.getTime() / 1000);
const OPTIONS: SdJwtStructureOptions = { now: NOW, maxKbAgeSeconds: 360, clockSkewSeconds: 60 };

function jwt(header: unknown, payload: unknown): string {
  return `${b64u(header)}.${b64u(payload)}.c2ln`;
}

function token(o: { sd?: unknown; disclosures?: string[]; kbPayload?: unknown; kbHeader?: unknown; issuerPayload?: unknown; kb?: string | null } = {}): string {
  const d = b64u(['salz', 'given_name', 'Ada']);
  const disclosures = o.disclosures ?? [d];
  const issuer = jwt({ alg: 'ES256' }, o.issuerPayload ?? { _sd: o.sd ?? [digest(d)] });
  const kb = o.kb === null ? '' : (o.kb ?? jwt(o.kbHeader ?? { alg: 'ES256', typ: 'kb+jwt' }, o.kbPayload ?? { iat: IAT, nonce: 'n' }));
  return `${issuer}~${disclosures.map((x) => `${x}~`).join('')}${kb}`;
}

describe('sdJwtStructureFailure', () => {
  it('gültige Form: kein Fehler', () => {
    assert.equal(sdJwtStructureFailure(token()), undefined);
  });

  it('Disclosure mit zwei Elementen (Array-Element) ist zulässig', () => {
    const d = b64u(['salz', 'wert']);
    assert.equal(sdJwtStructureFailure(token({ disclosures: [d], issuerPayload: { arr: [{ '...': digest(d) }] } })), undefined);
  });

  it('kein Tilde oder leerer Token: sd_jwt_malformed', () => {
    assert.equal(sdJwtStructureFailure(''), 'sd_jwt_malformed');
    assert.equal(sdJwtStructureFailure('nurissuer'), 'sd_jwt_malformed');
  });

  it('Issuer-Nutzdaten kein Objekt oder kein JSON: sd_jwt_malformed', () => {
    assert.equal(sdJwtStructureFailure(token({ issuerPayload: [] })), 'sd_jwt_malformed');
    assert.equal(sdJwtStructureFailure(`x.${b64u('{kaputt')}.y~${jwt({ typ: 'kb+jwt' }, { iat: IAT })}`), 'sd_jwt_malformed');
    assert.equal(sdJwtStructureFailure(`~${jwt({}, {})}`), 'sd_jwt_malformed');
  });

  it('_sd ist keine Liste von Texten: sd_jwt_malformed', () => {
    assert.equal(sdJwtStructureFailure(token({ issuerPayload: { _sd: 'x' } })), 'sd_jwt_malformed');
    assert.equal(sdJwtStructureFailure(token({ issuerPayload: { _sd: [1] } })), 'sd_jwt_malformed');
    assert.equal(sdJwtStructureFailure(token({ issuerPayload: { a: [{ '...': 5 }] } })), 'sd_jwt_malformed');
  });

  it('KB-JWT fehlt: kb_jwt_missing', () => {
    assert.equal(sdJwtStructureFailure(token({ kb: null })), 'kb_jwt_missing');
  });

  it('Offenlegung: leer, kein Base64url-JSON, falsche Länge, Salt kein Text, Name kein Text: disclosure_malformed', () => {
    for (const d of ['', b64u('{kaputt'), b64u(['nur-salz']), b64u(['a', 'b', 'c', 'd']), b64u([42, 'n', 'v']), b64u(['', 'n', 'v']), b64u(['s', 42, 'v']), b64u({ a: 1 }), b64u('null')]) {
      assert.equal(sdJwtStructureFailure(token({ disclosures: [d], sd: [digest(d)] })), 'disclosure_malformed', d);
    }
  });

  it('dieselbe Offenlegung zweimal: disclosure_duplicate', () => {
    const d = b64u(['salz', 'given_name', 'Ada']);
    assert.equal(sdJwtStructureFailure(token({ disclosures: [d, d], sd: [digest(d)] })), 'disclosure_duplicate');
  });

  it('derselbe Digest zweimal in _sd, auch verschachtelt: digest_duplicate', () => {
    const d = b64u(['salz', 'given_name', 'Ada']);
    assert.equal(sdJwtStructureFailure(token({ disclosures: [d], sd: [digest(d), digest(d)] })), 'digest_duplicate');
    assert.equal(sdJwtStructureFailure(token({ disclosures: [d], issuerPayload: { _sd: [digest(d)], address: { _sd: [digest(d)] } } })), 'digest_duplicate');
    assert.equal(sdJwtStructureFailure(token({ disclosures: [d], issuerPayload: { _sd: [digest(d)], arr: [{ '...': digest(d) }] } })), 'digest_duplicate');
  });

  it('Digest, der in einer Offenlegung wiederkehrt: digest_duplicate', () => {
    const inner = b64u(['s2', 'strasse', 'Hauptstr']);
    const outer = b64u(['s1', 'address', { _sd: [digest(inner)] }]);
    assert.equal(sdJwtStructureFailure(token({ disclosures: [outer, inner], issuerPayload: { _sd: [digest(outer), digest(inner)] } })), 'digest_duplicate');
    assert.equal(sdJwtStructureFailure(token({ disclosures: [outer, inner], issuerPayload: { _sd: [digest(outer)] } })), undefined, 'verschachtelt ohne Wiederholung ist gültig');
  });

  it('zu tiefe Verschachtelung in einer Offenlegung: disclosure_malformed', () => {
    let tief: unknown = { _sd: [] };
    for (let i = 0; i < 100; i += 1) tief = { n: tief };
    const d = b64u(['s', 'x', tief]);
    assert.equal(sdJwtStructureFailure(token({ disclosures: [d], sd: [digest(d)] })), 'disclosure_malformed');
  });

});

describe('kbJwtFailure', () => {
  it('gültig: kein Fehler', () => {
    assert.equal(kbJwtFailure(token(), OPTIONS), undefined);
  });

  it('fehlt oder unlesbar: kb_jwt_missing', () => {
    assert.equal(kbJwtFailure(token({ kb: null }), OPTIONS), 'kb_jwt_missing');
    assert.equal(kbJwtFailure(token({ kb: 'kein.jwt.hier' }), OPTIONS), 'kb_jwt_missing');
  });

  it('typ, iat fehlt oder kein Zahl, zu alt, in der Zukunft', () => {
    assert.equal(kbJwtFailure(token({ kbHeader: { alg: 'ES256', typ: 'JWT' } }), OPTIONS), 'kb_jwt_typ_invalid');
    assert.equal(kbJwtFailure(token({ kbHeader: { alg: 'ES256' } }), OPTIONS), 'kb_jwt_typ_invalid');
    assert.equal(kbJwtFailure(token({ kbPayload: { nonce: 'n' } }), OPTIONS), 'kb_jwt_iat_invalid');
    assert.equal(kbJwtFailure(token({ kbPayload: { iat: '1700000000' } }), OPTIONS), 'kb_jwt_iat_invalid');
    assert.equal(kbJwtFailure(token({ kbPayload: { iat: null } }), OPTIONS), 'kb_jwt_iat_invalid');
    assert.equal(kbJwtFailure(token({ kbPayload: { iat: IAT - 361 } }), OPTIONS), 'kb_jwt_too_old');
    assert.equal(kbJwtFailure(token({ kbPayload: { iat: IAT + 61 } }), OPTIONS), 'kb_jwt_in_future');
  });

  it('Grenzen des Zeitfensters gelten genau', () => {
    assert.equal(kbJwtFailure(token({ kbPayload: { iat: IAT - 360 } }), OPTIONS), undefined);
    assert.equal(kbJwtFailure(token({ kbPayload: { iat: IAT + 60 } }), OPTIONS), undefined);
  });
});

describe('publicCodeFor', () => {
  it('unlesbar und fehlendes KB-JWT überlässt der Dienst der Bibliothek', () => {
    assert.equal(publicCodeFor('sd_jwt_malformed'), undefined);
    assert.equal(publicCodeFor('kb_jwt_missing'), undefined);
  });
  it('Offenlegungen und Digests: credential_malformed; KB-JWT: presentation_invalid', () => {
    for (const f of ['disclosure_malformed', 'disclosure_duplicate', 'digest_duplicate'] as const) assert.equal(publicCodeFor(f), 'credential_malformed');
    for (const f of ['kb_jwt_typ_invalid', 'kb_jwt_iat_invalid', 'kb_jwt_too_old', 'kb_jwt_in_future'] as const) assert.equal(publicCodeFor(f), 'presentation_invalid');
  });
});
