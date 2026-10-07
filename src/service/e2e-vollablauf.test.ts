/**
 * Vollständiger Systemdurchlauf: ein Testfall, ein Durchlauf, alle Schichten.
 *
 * Dieser Test ist die Antwort auf die Frage "funktioniert das Ganze
 * zusammenspielend?". Die vorhandenen Tests decken jeweils Ausschnitte ab —
 * Onboarding-Gate, OCSP, Trust List, Ergebnis genau einmal, Löschen — aber
 * keinen einzigen Durchlauf, in dem alle Schichten gleichzeitig aktiv sind
 * und die Prüfung über HTTP statt über interne Methoden läuft.
 *
 * Aktiv sind hier gleichzeitig, mit echtem Material:
 *
 *   - das Onboarding-Gate mit TEST-WRPAC/WRPRC aus `mock-pki.ts`, verdrahtet
 *     als echtes `RelyingPartyOnboardingGate`
 *   - die Aussteller-Sperrprüfung über den echten `OcspRevocationChecker`
 *     gegen `TestOcspResponder`, inklusive OCSP-Rundlauf über die
 *     AIA-Erweiterung des Ausstellerzertifikats
 *   - die Trust List über `TrustListMonitor` mit JWS-Signaturprüfung
 *   - die Credential-Statusprüfung über `TokenStatusListChecker` gegen
 *     `TestStatusListServer`
 *
 * Der Ablauf läuft über HTTP, nicht über `service.getResult()`: create,
 * Request-Object abrufen, `direct_post`, Ergebnis abrufen, löschen, erneut
 * abrufen. Genau dieser letzte Schritt fehlt in den bestehenden Tests; das
 * Muster stammt aus `nachweis.test.ts`.
 *
 * Nichts wird gemockt, was im Dienst ein echter Pfad ist. Alle Schlüssel
 * entstehen im Arbeitsspeicher, alle Server hören auf 127.0.0.1, es wird nichts
 * nach außen gesendet und nichts auf die Platte geschrieben.
 */
import assert from 'node:assert/strict';
import type http from 'node:http';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, it } from 'vitest';
import 'reflect-metadata';

import { buildSdJwtVc, generateTestKeyMaterial, type TestKeyMaterial } from '../decision-test/mock-wallet.ts';
import { NO_REVOCATION } from '../onboarding/revocation.ts';
import { RelyingPartyOnboardingGate } from '../onboarding/onboarding-gate.ts';
import { TEST_ENTITLEMENT_MAP } from '../onboarding/mock-pki.ts';
import { createApp } from './app.ts';
import { AuditLog } from './audit.ts';
import { PID_VCT_DEFAULT } from './profile.ts';
import { VerifierService } from './service.ts';
import { DEV_MODE } from './test-support.ts';
import { TenantStore } from './tenant.ts';
import { buildDemoTestEnvironment, DEMO_SUBJECT_CN, DEMO_TENANT_ID, type DemoTestEnvironment } from '../demo/test-environment.ts';

const KEY = 'e2e-vollablauf-api-key';
const CLAIMS = ['given_name', 'age_over_18'] as const;

let env!: DemoTestEnvironment;
let service!: VerifierService;
let audit!: AuditLog;
let verifierKey!: TestKeyMaterial;
let app!: http.Server;
let base = '';
const tenants = new TenantStore();

/** Status und Body eines Aufrufs; der Body bleibt Text, weil 204 keinen hat. */
interface Raw {
  status: number;
  text: string;
  headers: Headers;
}

async function call(method: string, path: string, body?: unknown): Promise<Raw> {
  // `responseUri` und `requestObjectUri` sind absolute URLs aus der Antwort.
  // Ein Pfad wird gegen die Testbasis gesetzt, eine absolute URL nicht.
  const url = /^https?:\/\//.test(path) ? path : `${base}${path}`;
  const res = await fetch(url, {
    method,
    headers: {
      authorization: `Bearer ${KEY}`,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, text: await res.text(), headers: res.headers };
}

function json(raw: Raw): Record<string, unknown> {
  return JSON.parse(raw.text) as Record<string, unknown>;
}

beforeAll(async () => {
  env = await buildDemoTestEnvironment({});

  tenants.add({
    id: DEMO_TENANT_ID,
    name: `E2E ${DEMO_SUBJECT_CN}`,
    apiKey: KEY,
    requestTtlSeconds: 300,
    registration: env.registration,
    requestProfile: { id: 'e2e', vct: PID_VCT_DEFAULT, claims: [...CLAIMS], credentialId: 'pid' },
  });

  // Das Gate prüft die Registrierungskette des Mandanten. Die TEST-WRPAC-Kette
  // aus mock-pki trägt keine OCSP-Adresse, deshalb NO_REVOCATION an dieser
  // Stelle. Die Sperrprüfung der präsentierten Ausstellerkette läuft
  // unabhängig davon über den echten OcspRevocationChecker.
  const gate = new RelyingPartyOnboardingGate({
    tenants,
    accessCaAnchors: env.accessCaAnchors,
    wrprcIssuerAnchors: env.wrprcIssuerAnchors,
    entitlementMap: TEST_ENTITLEMENT_MAP,
    revocation: NO_REVOCATION,
    mode: DEV_MODE,
  });

  verifierKey = await generateTestKeyMaterial('E2E Verifier TEST');
  audit = new AuditLog();
  service = new VerifierService(
    tenants,
    audit,
    {
      privateKey: verifierKey.privateKey,
      publicKey: verifierKey.publicKey,
      publicJwk: verifierKey.publicJwk,
      certificateChain: [verifierKey.certDerBytes],
    },
    [env.issuer.certDerBytes, env.revokedIssuer.certDerBytes, env.untrustedIssuer.certDerBytes],
    undefined,
    undefined,
    env.issuerTrust,
    gate,
    true,
    // Anders als in den Demo-Tests ist die Statusprüfung hier aktiv. Damit
    // muss die Präsentation eine echte Statuslisten-Referenz tragen, sonst
    // bricht `readStatusReference` mit credential_status_missing ab.
    { mode: DEV_MODE, credentialStatus: env.credentialStatus, issuerRevocation: env.ocspChecker },
  );

  app = createApp({ appLabel: 'e2e-vollablauf-test', tenants, service });
  await new Promise<void>((resolve) => app.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${(app.address() as { port: number }).port}`;
  service.baseUrl = base;
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    app.closeAllConnections();
    app.close(() => resolve());
  });
  await env.close();
});

describe('Vollständiger Systemdurchlauf', () => {
  it('Onboarding-Gate, OCSP, Trust List und Statusliste zusammen über den ganzen HTTP-Ablauf', async () => {
    // --- 1. Prüfanfrage anlegen -------------------------------------------------
    const created = await call('POST', '/v1/verification-requests', { claims: [...CLAIMS] });
    assert.equal(created.status, 201, created.text);
    const session = json(created) as {
      sessionId: string;
      state: string;
      requestObject: string;
      requestObjectUri: string;
      responseUri: string;
      expiresAt: number;
    };
    // Die Antwort trägt die Kennungen für die Wallet plus den Ablaufzeitpunkt.
    for (const key of ['sessionId', 'state', 'requestObject', 'requestObjectUri', 'responseUri'] as const) {
      assert.equal(typeof session[key], 'string', `${key} muss in der Antwort stehen`);
      assert.ok(session[key].length > 0, `${key} darf nicht leer sein`);
    }
    assert.equal(typeof session.expiresAt, 'number', 'expiresAt ist ein Zeitstempel, kein Text');
    assert.ok(session.expiresAt * 1000 > Date.now(), 'die Sitzung ist bei der Erstellung noch nicht abgelaufen');

    // Der Gate-Pfad hat den Mandanten durchlassen, sonst gäbe es keine 201.
    assert.ok(
      audit.list().some((e) => e.event === 'request_created' && e.detail?.includes(session.sessionId)),
      'Audit protokolliert die Erstellung der Sitzung',
    );

    // --- 2. Request Object über die angebotene URI abrufen ----------------------
    // Die Wallet läuft nicht über diese Instanz, deshalb wird der Pfad hier
    // direkt abgerufen und der Inhaltstyp geprüft.
    const requestObjectRes = await fetch(session.requestObjectUri);
    assert.equal(requestObjectRes.status, 200);
    assert.equal(
      requestObjectRes.headers.get('content-type'),
      'application/oauth-authz-req+jwt',
      'der Wallet wird ein JAR angeboten',
    );
    const servedRequestObject = await requestObjectRes.text();
    assert.equal(servedRequestObject, session.requestObject, 'das ausgelieferte JAR ist das erzeugte');

    // --- 3. Wallet-Antwort simulieren -------------------------------------------
    const payload = (await jwtVerify(session.requestObject, createLocalJWKSet({ keys: [verifierKey.publicJwk] }))).payload;
    const nonce = typeof payload.nonce === 'string' ? payload.nonce : '';
    const audience = typeof payload.client_id === 'string' ? payload.client_id : '';
    assert.ok(nonce, 'das Request Object trägt eine Nonce, an die die Antwort gebunden sein muss');
    assert.ok(audience, 'das Request Object trägt eine Audience');

    const built = await buildSdJwtVc({
      issuerKey: env.issuer,
      holderKey: env.holder,
      nonce,
      audience,
      vct: PID_VCT_DEFAULT,
      additionalDisclosures: { age_over_18: true },
      // Datenminimierung wie in [interne Notiz, nicht veröffentlicht] beschrieben: das
      // Geburtsdatum steckt im Credential (Hash im Issuer-JWT), wird aber
      // nicht offengelegt, weil niemand danach gefragt hat.
      withheldDisclosures: { birth_date: '1990-01-01' },
      // Statuslisten-Referenz auf Index 0 der TEST-Liste; Index 0 ist der
      // gültige Eintrag. Ohne diesen Claim lehnt `readStatusReference` ab.
      extraClaims: { status: { status_list: { idx: 0, uri: env.statusListUri } } },
    });

    const presented = await call('POST', session.responseUri, { vp_token: { pid: [built.sdJwt] }, state: session.state });
    assert.equal(presented.status, 200, presented.text);
    const outcome = json(presented) as { ok: boolean; valid: boolean; error?: string };
    assert.equal(outcome.ok, true, presented.text);
    assert.equal(outcome.valid, true, `die Präsentation muss angenommen werden, bekam ${outcome.error}`);
    assert.equal(outcome.error ?? '', '', 'ein angenommenes Ergebnis trägt keinen Ablehnungscode');

    // --- 4. Ergebnis über HTTP abrufen ------------------------------------------
    const got = await call('GET', `/v1/verification-requests/${session.sessionId}`);
    assert.equal(got.status, 200, got.text);
    const body = json(got) as {
      status: string;
      result: { valid: boolean; error: string; claims: Record<string, unknown>; issuerCountry: string };
    };
    assert.equal(body.status, 'completed');
    assert.equal(body.result.valid, true);
    assert.equal(body.result.error, '');
    assert.equal(body.result.issuerCountry, 'DE');
    // Datenminimierung, wie in [interne Notiz, nicht veröffentlicht] zugesagt: alle
    // angefragten Attribute kommen an, und nichts aus dem Credential, was die
    // Wallet zurueckgehalten hat.
    assert.equal(body.result.claims.given_name, 'Ada');
    assert.equal(body.result.claims.age_over_18, true);
    assert.ok(
      !Object.prototype.hasOwnProperty.call(body.result.claims, 'birth_date'),
      'birth_date steckt nur als Hash im Credential und darf nicht herausgegeben werden',
    );

    // Das `status`-Claim stand nur im Issuer-signierten JWT, wurde nie
    // offengelegt und war nicht angefragt. Es darf deshalb nicht im Ergebnis
    // stehen. Vorher kam es ueber `claims = ver.parsed.claims` ungefiltert
    // durch; der Schnitt sitzt jetzt in nurAngefragteClaims
    // (src/service/profile.ts).
    assert.ok(
      !Object.prototype.hasOwnProperty.call(body.result.claims, 'status'),
      'ein nicht angefragtes Klartext-Claim aus dem Issuer-JWT darf nicht im Ergebnis stehen',
    );
    assert.deepEqual(
      Object.keys(body.result.claims).sort(),
      [...CLAIMS].sort(),
      'im Ergebnis stehen genau die angefragten Attribute, nichts sonst',
    );

    // --- 5. Das Ergebnis gibt es genau einmal -----------------------------------
    // Festgeschrieben in ergebnis-einmal.test.ts: ein zweiter Abruf bekommt 404,
    // und zwar ununterscheidbar von einer nie existierenden Sitzung. Der
    // Verbrauch darf nicht vom Löschen zu unterscheiden sein, sonst verrät der
    // Dienst, ob eine Sitzung je existiert hat.
    const again = await call('GET', `/v1/verification-requests/${session.sessionId}`);
    assert.equal(again.status, 404, 'nach dem Abruf ist das Ergebnis verbraucht');
    const never = await call('GET', `/v1/verification-requests/${crypto.randomUUID()}`);
    assert.equal(again.text, never.text, 'verbraucht und nie vorhanden müssen identisch antworten');

    // Auch das Request Object ist mit dem Ergebnis weg.
    const roAfter = await call('GET', `/v1/verification-requests/${session.sessionId}/request-object`);
    assert.equal(roAfter.status, 404, 'nach dem Ergebnisabruf ist auch das Request Object entfernt');

    // --- 6. Löschen einer offenen Sitzung ---------------------------------------
    // Eine eigene Sitzung, weil die erste nach dem Ergebnisabruf schon
    // aufgeräumt ist. Sonst würde der Löschpfad nie erreicht.
    const second = json(await call('POST', '/v1/verification-requests', { claims: [...CLAIMS] })) as {
      sessionId: string;
      state: string;
      requestObject: string;
      responseUri: string;
    };
    assert.notEqual(second.sessionId, session.sessionId, 'die zweite Sitzung ist eine eigene');

    const deleted = await call('DELETE', `/v1/verification-requests/${second.sessionId}`);
    assert.equal(deleted.status, 204, deleted.text);
    assert.equal(deleted.text, '', '204 trägt keinen Body');

    const afterDelete = await call('GET', `/v1/verification-requests/${second.sessionId}`);
    assert.equal(afterDelete.status, 404, 'eine gelöschte Sitzung ist nicht mehr abrufbar');
    assert.equal(json(afterDelete).error, 'not_found');
    // Auch das Löschen selbst darf danach nichts mehr löschen.
    const deleteAgain = await call('DELETE', `/v1/verification-requests/${second.sessionId}`);
    assert.equal(deleteAgain.status, 404, 'ein zweites Löschen trifft nichts');

    // Und eine Präsentation auf die gelöschte Sitzung wird abgelehnt.
    //
    // Und eine Präsentation auf die gelöschte Sitzung wird abgelehnt.
    //
    // 422, nicht 401. Die Route ist öffentlich, es gab nichts zu
    // authentifizieren; 401 ist exklusiv für den API-Schlüssel reserviert.
    // Vorher gab app.ts jeder abgelehnten Präsentation 401, wodurch ein Client
    // den Schlüssel erneuert hätte, obwohl die Sitzung nicht mehr existiert.
    const late = await call('POST', second.responseUri, { vp_token: { pid: [built.sdJwt] }, state: second.state });
    assert.equal(late.status, 422, 'eine abgelehnte Präsentation trägt 422, nicht 401');
    assert.equal(json(late).error, 'unknown_state');

    // Und 401 bleibt für das, wofür es reserviert ist: fehlender Schlüssel.
    const ohneSchluessel = await call('GET', `/v1/verification-requests/${second.sessionId}`);
    // Der `call`-Helfer setzt den Schlüssel immer; für diesen Fall direkt.
    const anonym = await fetch(`${base}/v1/verification-requests/${second.sessionId}`);
    await anonym.arrayBuffer();
    assert.equal(anonym.status, 401, 'ohne Schlüssel weiterhin 401, mit Schlüssel nicht');
    assert.ok(ohneSchluessel.status !== 401, 'mit gültigem Schlüssel darf hier nicht 401 stehen');

    // --- 8. Der Weg durch das System ist im Audit nachvollziehbar ----------------
    const events = audit.list().map((e) => e.event);
    for (const expected of ['request_created', 'presentation_valid', 'result_read'] as const) {
      assert.ok(events.includes(expected), `Audit muss ${expected} enthalten, hat ${[...new Set(events)].join(', ')}`);
    }
    assert.ok(
      !events.includes('presentation_invalid'),
      'im Gutfall darf das Audit keine Ablehnung protokollieren',
    );
  });

  it('ein nicht angefragter Klartext-Claim aus dem Issuer-JWT landet nicht im Ergebnis', async () => {
    // DerRegressionstest fuer den Datenminimierungs-Befund aus Paket 3.
    //
    // `extraClaims` landen als Klartext im vom Aussteller signierten JWT, nicht
    // als selektive Offenlegung. Die Bibliothek gab sie ueber `parsed.claims`
    // trotzdem aus, und der Dienst reichte das ungefiltert weiter. Damit
    // bekam der Prüfer Felder, die er nie angefragt hat und die die Wallet nie
    // offengelegt hat — im Widerspruch zu [interne Notiz, nicht veröffentlicht] und zum
    // eIDAS-Grundsatz der Datenminimierung.
    //
    // Vorher war der Fehler nur für gehashte Claims auffällig, denn für einen
    // Hash ohne Offenlegung existiert kein passender Wert. Der Klartextfall
    // blieb deshalb unbemerkt.
    const erlaubt = ['given_name'];
    const veroechter = 'fachlicher_zusatz';

    // Mandant mit einem eigenen, minimalen Profil: nur `given_name`.
    const key = 'e2e-datensparsamkeit-key';
    const profilMandant = 'e2e-datensparsamkeit';
    tenants.add({
      id: profilMandant,
      name: 'E2E Datensparsamkeit (TEST)',
      apiKey: key,
      requestTtlSeconds: 300,
      registration: env.registration,
      requestProfile: { id: 'minimal', vct: PID_VCT_DEFAULT, claims: [...erlaubt], credentialId: 'pid' },
    });

    const created = await fetch(`${base}/v1/verification-requests`, {
      method: 'POST',
      headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
      body: JSON.stringify({ claims: [...erlaubt] }),
    });
    const session = (await created.json()) as { state: string; requestObject: string; responseUri: string; sessionId: string };
    assert.equal(created.status, 201, 'der eigene Mandant muss durch das Gate');

    const payload = (await jwtVerify(session.requestObject, createLocalJWKSet({ keys: [verifierKey.publicJwk] }))).payload;
    const built = await buildSdJwtVc({
      issuerKey: env.issuer,
      holderKey: env.holder,
      nonce: String(payload.nonce ?? ''),
      audience: String(payload.client_id ?? ''),
      vct: PID_VCT_DEFAULT,
      // Drei Klartext-Felder im Issuer-JWT, die angefragt werden. Keines
      // davon ist ein PID-Attribut, keines wird offengelegt.
      extraClaims: {
        [veroechter]: 'nicht angefragt und nicht offengelegt',
        _internes_merkmal: 42,
        status: { status_list: { idx: 0, uri: env.statusListUri } },
      },
    });

    const presented = await call('POST', session.responseUri, { vp_token: { pid: [built.sdJwt] }, state: session.state });
    assert.equal(json(presented).valid, true, 'die Praesentation selbst muss gueltig sein');

    const got = await fetch(`${base}/v1/verification-requests/${session.sessionId}`, {
      headers: { authorization: `Bearer ${key}` },
    });
    assert.equal(got.status, 200, 'das Ergebnis des eigenen Mandanten muss abrufbar sein');
    const body = (await got.json()) as { result: { claims: Record<string, unknown> } };
    const ergebnis = body.result.claims;

    // Das Angefragte kommt an.
    assert.deepEqual(Object.keys(ergebnis), erlaubt, `im Ergebnis darf nur ${erlaubt.join(',')} stehen`);
    assert.equal(ergebnis.given_name, 'Ada');

    // Das nicht Angefragte kommt nicht an — unabhaengig davon, wie es im
    // Credential stand. Genau das ist die Zusage aus [interne Notiz, nicht veröffentlicht].
    for (const feld of [veroechter, '_internes_merkmal', 'status']) {
      assert.ok(
        !Object.prototype.hasOwnProperty.call(ergebnis, feld),
        `${feld} steht im Issuer-JWT, wurde nie angefragt und nie offengelegt — darf nicht im Ergebnis sein`,
      );
    }
  });

  it('nach dem Löschen bleibt der Mandant nutzbar und das Gate gilt je Anfrage', async () => {
    // Der erste Durchlauf hat die Mandantenregistrierung durch das Gate
    // geschickt, der zweite. Der dritte beweist, dass das Gate den Mandanten
    // nicht verbraucht: Registrierung und Entitlement gelten je Anfrage, nicht
    // einmalig.
    const created = await call('POST', '/v1/verification-requests', { claims: ['given_name'] });
    assert.equal(created.status, 201, created.text);
    const third = json(created) as { sessionId: string; state: string; requestObject: string; responseUri: string };
    assert.notEqual(third.sessionId, '', 'neue Sitzung nach dem Löschen der zweiten');

    const payload = (await jwtVerify(third.requestObject, createLocalJWKSet({ keys: [verifierKey.publicJwk] }))).payload;
    const built = await buildSdJwtVc({
      issuerKey: env.issuer,
      holderKey: env.holder,
      nonce: String(payload.nonce ?? ''),
      audience: String(payload.client_id ?? ''),
      vct: PID_VCT_DEFAULT,
      extraClaims: { status: { status_list: { idx: 0, uri: env.statusListUri } } },
    });
    const presented = await call('POST', third.responseUri, { vp_token: { pid: [built.sdJwt] }, state: third.state });
    assert.equal(json(presented).valid, true, 'auch die dritte Sitzung wird angenommen');
  });
});
