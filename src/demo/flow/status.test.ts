import assert from 'node:assert/strict';
import { describe, it } from 'vitest';

import { REJECTION_REASONS, USER_MESSAGES, applyPollResponse, createFlowState, rejectionReason, safeReturnUrl } from './status.js';

describe('Flow-Statuslogik', () => {
  it('bleibt wartend und zeigt nach Abschluss die freigegebenen Claims', () => {
    let state = createFlowState();
    assert.equal(state.status, 'waiting');

    state = applyPollResponse(state, 200, { status: 'pending' });
    assert.equal(state.status, 'waiting');
    assert.equal(state.claims, null);

    state = applyPollResponse(state, 200, {
      status: 'completed',
      result: { at: '2026-09-25T10:00:00.000Z', claims: { given_name: 'Ada' } },
    });
    assert.equal(state.status, 'completed');
    assert.deepEqual(state.claims, { given_name: 'Ada' });
    assert.equal(state.at, '2026-09-25T10:00:00.000Z');
    assert.equal(state.message, USER_MESSAGES.completed);
  });

  it('liefert bei Ablauf und unbekannter Sitzung generische Meldungen', () => {
    let state = createFlowState();

    state = applyPollResponse(state, 200, { status: 'expired' });
    assert.equal(state.status, 'expired');
    assert.equal(state.claims, null);
    assert.equal(state.message, USER_MESSAGES.expired);

    state = applyPollResponse(state, 404, null);
    assert.equal(state.status, 'failed');
    assert.equal(state.claims, null);
    assert.equal(state.message, USER_MESSAGES.unknown);

    state = applyPollResponse(state, 200, { status: 'rejected' });
    assert.equal(state.status, 'failed');
    assert.equal(state.message, USER_MESSAGES.failed);

    state = applyPollResponse(state, 200, null);
    assert.equal(state.status, 'failed');

    const internalDetail = /(error|undefined|jwt|token|stack|pem|exception|base64|session=|path)/i;
    for (const message of Object.values(USER_MESSAGES)) assert.equal(internalDetail.test(message), false);
    for (const reason of Object.values(REJECTION_REASONS)) assert.equal(internalDetail.test(reason), false);
  });
});

describe('Ablehnung', () => {
  it('erkennt eine Ablehnung als abgeschlossen mit valid false und nennt den Grund', () => {
    // Ohne diesen Zweig wuerde die Oberflaeche eine Ablehnung als Erfolg
    // anzeigen, weil der Dienst sie als `completed` meldet.
    const state = applyPollResponse(createFlowState(), 200, {
      status: 'completed',
      result: { at: '2026-09-26T10:00:00.000Z', valid: false, error: 'issuer_certificate_revoked', claims: {} },
    });

    assert.equal(state.status, 'rejected');
    assert.equal(state.claims, null, 'bei Ablehnung werden keine Claims angezeigt');
    assert.equal(state.error, 'issuer_certificate_revoked', 'der technische Code bleibt sichtbar');
    assert.equal(state.message, 'Das Ausstellerzertifikat ist gesperrt.');
  });

  it('bildet jeden gemessenen Szenario-Code auf einen konkreten Grund ab', () => {
    const erwartet: [string, string][] = [
      ['issuer_trust_anchor_not_found', 'Der Aussteller steht nicht auf der Trust List.'],
      ['issuer_certificate_revoked', 'Das Ausstellerzertifikat ist gesperrt.'],
      ['session_expired', 'Die Prüfanfrage war abgelaufen, bevor die Wallet geantwortet hat.'],
    ];
    for (const [code, text] of erwartet) assert.equal(rejectionReason(code), text, code);
  });

  it('erklaert beim generischen Code, dass der Verifier keinen Detailgrund nennt', () => {
    // Der Dienst unterscheidet falsche Nonce, abgelaufenen Nachweis und
    // manipulierte Offenlegung absichtlich nicht. Die Oberflaeche soll das
    // sagen, statt eine erfundene Genauigkeit vorzutaeuschen.
    const reason = rejectionReason('presentation_invalid');
    assert.ok(reason !== null);
    assert.match(reason, /bewusst keinen Detailgrund/);
  });

  it('faellt bei unbekanntem Code auf eine generelle Meldung zurueck', () => {
    assert.equal(rejectionReason('gibt_es_nicht'), null);
    assert.equal(rejectionReason(''), null);
    assert.equal(rejectionReason(undefined), null);

    const state = applyPollResponse(createFlowState(), 200, { status: 'completed', result: { valid: false, error: 'gibt_es_nicht' } });
    assert.equal(state.status, 'rejected', 'eine Ablehnung bleibt eine Ablehnung');
    assert.equal(state.message, USER_MESSAGES.rejected);
  });
});

describe('safeReturnUrl', () => {
  it('erlaubt gleich-origine relative Pfade', () => {
    assert.equal(safeReturnUrl('/'), '/');
    assert.equal(safeReturnUrl('/return.html'), '/return.html');
    assert.equal(safeReturnUrl('/v/42?x=1'), '/v/42?x=1');
    assert.equal(safeReturnUrl('/a/b/c'), '/a/b/c');
  });

  it('lehnt fremde und manipulierte Ziele ab', () => {
    for (const value of ['https://evil.example', 'http://evil.example/x', '//evil.example', '//evil.example/x', '/\\evil.example', '/a/\\evil', '/javascript:alert(1)', '/a/https://evil.example', '/redirect?to=https://evil.example', 'javascript:alert(1)', '', undefined, null, '/a\nhttps://evil.example']) {
      assert.equal(safeReturnUrl(value), null, String(value));
    }
  });
});
