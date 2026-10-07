/**
 * Abgelehnte Präsentationen über den ganzen HTTP-Ablauf.
 *
 * **Der Auftrag ging von 422 aus. Das stimmt nur zur Hälfte, und die
 * Unterscheidung ist der eigentliche Befund.**
 *
 * `src/service/app.ts:256` setzt den Status so:
 *
 *   return sendJson(res, outcome.ok ? 200 : 422, outcome);
 *
 * `ok: false` bedeutet: die Anfrage konnte nicht verarbeitet werden —
 * unbekannte Sitzung, Formfehler, Replay, JWE-Problem. Das ergibt 422.
 *
 * `ok: true, valid: false` bedeutet: die Präsentation **wurde** verarbeitet
 * und inhaltlich abgelehnt — falscher Aussteller, fehlender Claim, kaputtes
 * Token. Das ergibt **200** mit `valid: false` und einem Fehlercode.
 *
 * Der Kommentar in `app.ts:254-255` nennt genau diese Trennung: "Betroffen
 * sind alle abgelehnten Präsentationen: unknown_state, state_invalid,
 * vp_token_invalid, Replay und die JWE-Fehlerpfade" — das sind die
 * `ok: false`-Fälle. Inhaltliche Ablehnungen stehen dort nicht.
 *
 * Es ist berechtigt: eine inhaltlich abgelehnte Präsentation **wurde
 * ausgewertet**, der Prüfer kann daraus etwas ableiten. 422 würde sagen "ich
 * konnte das nicht verarbeiten" und wäre falsch.
 *
 * Dieser Test hält beide Ausgänge fest. Ein Umstellen des Dienstes auf 422
 * für alle Ablehnungen wäre eine Verhaltensänderung und wäre hier zu sehen.
 *
 * Vorhanden in anderen Dateien, nicht hier wiederholt:
 *   - abgelaufene Sitzung → `session_expired` (nachweis.test.ts:155)
 *   - wiederholter Ergebnisabruf → 404 (e2e-vollablauf.test.ts:259)
 *   - 422-Zuordnung generell (e2e-vollablauf.test.ts:293-298) — dort geht es
 *     um die Statuszuordnung auf einer gelöschten Sitzung, nicht um ein
 *     schlechtes Token
 *
 * Ergänzt sind hier: formal gültiger, inhaltlich unbrauchbarer Token; falscher
 * Aussteller; fehlender Pflichtclaim; Datenminimierung über drei Ausgaben
 * (Antwort, Log, Audit).
 *
 * Alles über HTTP, nicht über interne Methoden. Der Statuscode entsteht erst in
 * der Route. Schlüssel im Arbeitsspeicher, Server auf 127.0.0.1, nichts wird
 * nach außen gesendet.
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, it, vi } from 'vitest';
import 'reflect-metadata';

import { buildSdJwtVc, generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { createApp } from './app.ts';
import { AuditLog } from './audit.ts';
import { VerifierService, type ServiceKeys } from './service.ts';
import { TenantStore } from './tenant.ts';
import { DEV_TEST_OPTIONS } from './test-support.ts';

const KEY = 'test-api-key-422-A';
const CLAIMS = ['given_name'] as const;

/** Die Marke, die nirgends auftauchen darf. Absichtlich unverwechselbar. */
const MARKER = 'MARKER-NICHT-ANGEFRAGT-7f3a91';

let verifier!: TestKeyMaterial;
let issuer!: TestKeyMaterial;
let fremderIssuer!: TestKeyMaterial;
let holder!: TestKeyMaterial;
let app!: http.Server;
let base = '';
let service!: VerifierService;
let audit!: AuditLog;
const tenants = new TenantStore();

interface Sitzung {
  state: string;
  nonce: string;
  clientId: string;
  sessionId: string;
}

async function sitzung(claims: string[] = [...CLAIMS]): Promise<Sitzung> {
  const created = await fetch(`${base}/v1/verification-requests`, {
    method: 'POST',
    headers: { authorization: `Bearer ${KEY}`, 'content-type': 'application/json' },
    body: JSON.stringify({ claims }),
  });
  assert.equal(created.status, 201, 'die Sitzung muss anlegbar sein, sonst prueft der Rest nichts');
  const body = (await created.json()) as { state: string; requestObject: string; sessionId: string };
  const { payload } = await jwtVerify(body.requestObject, createLocalJWKSet({ keys: [verifier.publicJwk] }));
  return { state: body.state, sessionId: body.sessionId, nonce: String(payload.nonce), clientId: String(payload.client_id) };
}

async function praesentation(state: string, sdJwt: string): Promise<Response> {
  return fetch(`${base}/direct_post`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ vp_token: { pid: [sdJwt] }, state }),
  });
}

beforeAll(async () => {
  verifier = await generateTestKeyMaterial('422 Verifier TEST');
  issuer = await generateTestKeyMaterial('422 Aussteller TEST');
  // Ein zweiter, vollstaendig eigener Aussteller. Nicht dieselbe CA, nicht
  // dieselbe Schluesselrichtung: das ist der Punkt des Falls.
  fremderIssuer = await generateTestKeyMaterial('422 Fremder Aussteller TEST');
  holder = await generateTestKeyMaterial('422 Holder TEST');

  tenants.add({ id: 'tenant-422', name: 'Kunde 422 (TEST)', apiKey: KEY, requestTtlSeconds: 300 });
  const keys: ServiceKeys = {
    privateKey: verifier.privateKey,
    publicKey: verifier.publicKey,
    publicJwk: verifier.publicJwk,
    certificateChain: [verifier.certDerBytes],
  };
  audit = new AuditLog();
  // `fremdesZertifikat` bewusst gesetzt: der Dienst haelt genau dieses
  // Aussteller-Zertifikat als Anker. Eine Praesentation eines anderen
  // Ausstellers muss daran scheitern, nicht an etwas Zufaelligem.
  service = new VerifierService(tenants, audit, keys, issuer.certDerBytes, undefined, undefined, undefined, undefined, true, DEV_TEST_OPTIONS);
  app = createApp({ appLabel: 'e2e-422', tenants, service });
  await new Promise<void>((resolve) => app.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(app.address() as { port: number }).port}`;
  service.baseUrl = base;
});

afterAll(() => {
  app?.closeAllConnections();
  void app?.close();
});

describe('Formal gültig, inhaltlich unbrauchbar', () => {
  it('ein vp_token, der kein SD-JWT ist, läuft durch den ganzen Dienst und wird inhaltlich abgelehnt', async () => {
    // Formal gültig: ein nichtleerer String. `vpTokenLimitError` in
    // `src/service/limits.ts:64` laesst ihn durch, weil die Form stimmt und die
    // Länge unter der Grenze liegt.
    //
    // Damit ist dieser Fall etwas anderes als `vp_token_invalid` aus
    // `fehlerbilder.test.ts:305` (dort ist `[1]` keine Zeichenkette). Hier
    // kommt der Inhalt bis zur Bibliothek und wird von ihr abgelehnt. Der
    // Fehlercode kommt aus `presentationErrorCode`, nicht aus der Formprüfung.
    const s = await sitzung();
    const formalGueltig = 'aGVsbG8.dies.ist.kein.sd-jwt';

    const res = await praesentation(s.state, formalGueltig);
    const body = (await res.json()) as { ok?: boolean; error?: string; valid?: boolean };

    // 200, nicht 422: die Präsentation wurde verarbeitet und inhaltlich
    // abgelehnt. Siehe Kopfkommentar.
    assert.equal(res.status, 200, `eine inhaltlich abgelehnte Präsentation ergibt 200, bekam ${res.status}`);
    assert.equal(body.ok, true, 'der Dienst hat die Anfrage verarbeitet');
    assert.equal(body.valid, false, 'sie darf nicht als gültig gelten');
    assert.equal(body.error, 'presentation_invalid');
    assert.notEqual(body.error, 'vp_token_invalid', 'der Fall muss die Formprüfung passieren, sonst prüft er nichts');

    // Gegenprobe: eine frische Sitzung mit demselben Ablauf nimmt ein echtes
    // SD-JWT an. Eine eigene Sitzung, weil die erste nach dem Versuch
    // verbraucht ist — sonst prüfte die Gegenprobe den Replay-Schutz statt der
    // Ablehnung. Gerade gemessen: dieselbe Sitzung ein zweites Mal zu
    // präsentieren ergibt `session_reused`.
    const s2 = await sitzung();
    const echt = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: s2.nonce, audience: s2.clientId });
    const danach = await praesentation(s2.state, echt.sdJwt);
    assert.equal(((await danach.json()) as { valid?: boolean }).valid, true, 'derselbe Ablauf muss ein echtes SD-JWT annehmen');

    // Und die verbrauchte Sitzung: der Replay-Schutz greift.
    const replay = await praesentation(s2.state, echt.sdJwt);
    const replayBody = (await replay.json()) as { error?: string };
    assert.equal(replay.status, 422, 'eine zweite Präsentation auf dieselbe Sitzung ist eine 422-Fehlermeldung, keine 200-Ablehnung');
    assert.equal(replayBody.error, 'session_reused');
  });

  it('ein leerer vp_token wird an der Form abgelehnt, nicht in der Verarbeitung', async () => {
    // Die Gegenseite, damit klar ist, dass der vorige Test nicht einfach
    // "irgendwas wird abgelehnt" zeigt.
    const s = await sitzung();
    const res = await praesentation(s.state, '');
    const body = (await res.json()) as { error?: string };
    assert.equal(res.status, 422);
    assert.equal(body.error, 'vp_token_invalid');
  });
});

describe('Falscher Aussteller', () => {
  it('eine Präsentation eines fremden Ausstellers wird abgelehnt', async () => {
    // Der Dienst haelt `issuer.certDerBytes` als Anker. Eine Präsentation mit
    // dem x5c eines voellig anderen Ausstellers darf nicht durch.
    const s = await sitzung();
    const fremd = await buildSdJwtVc({ issuerKey: fremderIssuer, holderKey: holder, nonce: s.nonce, audience: s.clientId });

    const res = await praesentation(s.state, fremd.sdJwt);
    const body = (await res.json()) as { ok?: boolean; error?: string; valid?: boolean };

    // Hier ist der Fall anders gelagert als beim kaputten Token: der
    // Vertrauensanker wird geprüft, bevor die Bibliothek die Präsentation
    // überhaupt auswertet. Deshalb `ok: true` und 200 — gemessen, nicht
    // angenommen.
    assert.equal(res.status, 200, `bekam ${res.status}`);
    assert.equal(body.ok, true);
    assert.equal(body.valid, false, 'es darf kein gültiges Ergebnis entstehen');
    assert.equal(body.error, 'issuer_trust_anchor_not_found', 'der Anker muss der Ablehnungsgrund sein');

    // Gegenprobe: derselbe Pfad mit dem richtigen Aussteller funktioniert.
    const s2 = await sitzung();
    const echt = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: s2.nonce, audience: s2.clientId });
    const gut = await praesentation(s2.state, echt.sdJwt);
    assert.equal(((await gut.json()) as { valid?: boolean }).valid, true, 'der richtige Aussteller muss durchkommen');
  });
});

describe('Fehlender Pflichtclaim', () => {
  it('eine Präsentation ohne den angefragten Claim wird abgelehnt', async () => {
    // Angefragt ist `given_name`. Geliefert wird ein Credential mit
    // `family_name` stattdessen. Der Claim fehlt im Hash-Bestand, die
    // DCQL-Abfrage kann ihn nicht erfuellen.
    const s = await sitzung();
    const ohneAngefragten = await buildSdJwtVc({
      issuerKey: issuer,
      holderKey: holder,
      nonce: s.nonce,
      audience: s.clientId,
      claimName: 'family_name',
    });

    const res = await praesentation(s.state, ohneAngefragten.sdJwt);
    const body = (await res.json()) as { error?: string; valid?: boolean };

    // Zwei moegliche Ausgaenge, und beide sind in Ordnung:
    //  422 mit einem Ablehnungscode, wenn die Bibliothek bzw. der Dienst die
    //       fehlende Erfuellung ablehnt
    //  200 mit valid=false, wenn die Abfrage schlicht nichts findet — der
    //       Dienst nimmt gegenueber der Bibliothek an und signalisiert die
    //       Ablehnung im Ergebnis
    // Beides wird hier festgehalten, damit eine Aenderung auffaellt. Wichtig
    // ist nur: **kein** gueltiges Ergebnis.
    if (res.status === 422) {
      assert.ok(
        ['query_invalid', 'presentation_invalid', 'credential_malformed'].includes(body.error ?? ''),
        `unbekannter Fehlercode: ${String(body.error)}`,
      );
    } else {
      assert.equal(res.status, 200, `unerwarteter Status: ${res.status}`);
      assert.equal(body.valid, false, 'ohne den angefragten Claim darf kein gueltiges Ergebnis entstehen');
    }
  });

  it('derselbe Ablauf mit dem richtigen Claim ergibt valid=true', async () => {
    // Die positive Haelfte. Ohne sie wuerde der vorige Test auch dann
    // gruen sein, wenn der Dienst alles ablehnte.
    const s = await sitzung();
    const richtig = await buildSdJwtVc({ issuerKey: issuer, holderKey: holder, nonce: s.nonce, audience: s.clientId });
    const res = await praesentation(s.state, richtig.sdJwt);
    assert.equal(((await res.json()) as { valid?: boolean }).valid, true);
  });
});

describe('Datenminimierung: der Marker erscheint nirgends', () => {
  it('ein nicht angefragter Claim fehlt im Ergebnis und im Log', async () => {
    // `e2e-vollablauf.test.ts:320` prueft das Ergebnis, aber nicht das Log.
    // Hier beides, mit einer eindeutigen Marke: taucht der Wert irgendwo im
    // Log auf, ist er mit `indexOf` zu finden.
    const s = await sitzung();

    // Log abfangen, bevor die Praesentation durchlaeuft.
    const geloggt: string[] = [];
    const spies = (['log', 'warn', 'error'] as const).map((methode) =>
      vi.spyOn(console, methode).mockImplementation((...args: unknown[]) => {
        geloggt.push(args.map((a) => String(a)).join(' '));
      }),
    );

    let res!: Response;
    let ergebnis!: { valid?: boolean };
    try {
      const gebaut = await buildSdJwtVc({
        issuerKey: issuer,
        holderKey: holder,
        nonce: s.nonce,
        audience: s.clientId,
        // Die Marke als Klartext-Claim im Issuer-JWT: sie ist damit im
        // Credential enthalten, wurde aber nie angefragt und nie
        // offengelegt.
        extraClaims: { [MARKER]: 'darf nirgends auftauchen', _nebenmarker: 1 },
      });
      res = await praesentation(s.state, gebaut.sdJwt);
      ergebnis = (await res.json()) as { valid?: boolean };
    } finally {
      for (const spion of spies) spion.mockRestore();
    }

    assert.equal(ergebnis.valid, true, 'die Präsentation selbst muss gueltig sein, sonst prueft die Minierung nichts');

    // Das Ergebnis holen. Auch hier die Log-Ausgabe pruefen, denn der
    // Ergebnisabruf schreibt selbst Protokoll.
    const geloggt2: string[] = [];
    const spies2 = (['log', 'warn', 'error'] as const).map((methode) =>
      vi.spyOn(console, methode).mockImplementation((...args: unknown[]) => {
        geloggt2.push(args.map((a) => String(a)).join(' '));
      }),
    );
    let antwort!: { status: number; body: { result?: { claims?: Record<string, unknown> } } };
    try {
      const got = await fetch(`${base}/v1/verification-requests/${s.sessionId}`, { headers: { authorization: `Bearer ${KEY}` } });
      antwort = { status: got.status, body: (await got.json()) as { result?: { claims?: Record<string, unknown> } } };
    } finally {
      for (const spion of spies2) spion.mockRestore();
    }

    assert.equal(antwort.status, 200, 'das Ergebnis muss abrufbar sein');
    const claims = antwort.body.result?.claims ?? {};

    // 1. Das Angefragte kommt an.
    assert.equal(claims.given_name, 'Ada', 'der angefragte Claim muss im Ergebnis stehen');
    assert.deepEqual(Object.keys(claims), [...CLAIMS], `im Ergebnis darf nur ${CLAIMS.join(',')} stehen`);

    // 2. Die Marke steht nicht im Ergebnis.
    assert.ok(!JSON.stringify(claims).includes(MARKER), 'die Marke steht im Ergebnis');

    // 3. Und sie steht nicht im Log — weder beim Präsentieren noch beim
    //    Ergebnisabruf. Das ist der Teil, den der vorhandene Test nicht hat.
    for (const zeile of [...geloggt, ...geloggt2]) {
      assert.ok(!zeile.includes(MARKER), `die Marke steht im Log: ${zeile}`);
      assert.ok(!zeile.includes('darf nirgends auftauchen'), `der Marker-Wert steht im Log: ${zeile}`);
    }
  });

  it('der Logger verwirft Claim-Felder auch dann, wenn ein Aufrufer sie uebergibt', async () => {
    // Zweite, unabhaengige Ebene: `src/lib/logger.ts:13` hat eine
    // Feld-Whitelist. Auch wenn ein Aufrufer `claims` uebergibt, darf der Wert
    // nicht landen. Das ist der Grund, warum der vorige Test ueberhaupt
    // aussagekraeftig ist.
    const geloggt: string[] = [];
    const spione = (['log', 'warn', 'error'] as const).map((methode) =>
      vi.spyOn(console, methode).mockImplementation((...args: unknown[]) => {
        geloggt.push(args.map((a) => String(a)).join(' '));
      }),
    );
    try {
      const { logger } = await import('../lib/logger.ts');
      logger.info('test_ereignis', { claims: `ich enthalte ${MARKER}`, vp_token: MARKER, session: 'ok', zaehler: 3 });
    } finally {
      for (const spion of spione) spion.mockRestore();
    }
    const alles = geloggt.join('\n');
    assert.ok(!alles.includes(MARKER), 'die Whitelist des Loggers hat die Marke durchgelassen');
    assert.ok(alles.includes('zaehler'), 'unbedenkliche Felder muessen weiterhin erscheinen');
  });
});

describe('Audit-Log als zweite Sicht', () => {
  it('das Audit-Protokoll nennt weder die Marke noch den Claim-Wert', async () => {
    // Der Audit-Log ist eine dritte Ausgabe, die weder HTTP-Antwort noch
    // Konsolen-Log ist. Er wird hier geprueft, damit die Aussage nicht nur
    // fuer zwei Kanaele gilt.
    const s = await sitzung();
    const gebaut = await buildSdJwtVc({
      issuerKey: issuer,
      holderKey: holder,
      nonce: s.nonce,
      audience: s.clientId,
      extraClaims: { [MARKER]: 'darf nirgends auftauchen' },
    });
    await praesentation(s.state, gebaut.sdJwt);

    const eintraege = audit.list();
    assert.ok(eintraege.length > 0, 'es muss Audit-Eintraege geben, sonst prueft der Test nichts');
    const alles = JSON.stringify(eintraege);
    assert.ok(!alles.includes(MARKER), 'die Marke steht im Audit-Protokoll');
  });
});
