# Attack Integrationsleitfaden

Dieser Leitfaden richtet sich an Entwicklerinnen und Entwickler bei Banken,
Fintechs und Versicherern ohne EUDI-Wallet-Vorwissen. Er beschreibt den
API-Vertrag in `openapi.yaml` sowie die TypeScript-/Python-SDK-Kandidaten unter
`sdk/`.

## 1. Umgebungen und Zugang

### Lokaler TEST-Betrieb

Die lokale Entwicklung verwendet ausschließlich synthetische TEST-Schlüssel,
TEST-Zertifikate, TEST-Walletdaten und TEST-API-Schlüssel:

```bash
ATTACK_DEV_MODE=true npm run service
```

Der Dienst lauscht standardmäßig auf `http://127.0.0.1:8080`. Das ist keine
echte Wallet, keine öffentliche Sandbox und kein Behörden-Endpunkt.

### Sandbox-Zugang

Das Repository enthält keine echte Sandbox-URL, keine Zugangsdaten und keine
Kundendaten. Einen Sandbox-Zugang muss das zuständige Wallet-Programm bzw. der
Betreiber vergeben. Endpunkt und Zugangsdaten sind anschließend in der
Deployment-Konfiguration zu hinterlegen. Keine URLs raten oder erfinden.

Vor einem Sandbox-Test sind zu bestätigen:

1. erlaubte Wallet- und Credential-Formate;
2. Callback-/Redirect- und Verschlüsselungsanforderungen;
3. Verifier-Trust-Anker und Zertifikatskette;
4. Provisionierung von Mandanten und API-Schlüsseln;
5. Aufbewahrung, Löschung und Incident-Reporting.

## 2. Prüfanfrage erstellen

Der Applikationsserver erstellt eine Anfrage für einen Mandanten. Der API-Key
ist ein serverseitiges Geheimnis und darf nicht in Browser-Code gelangen.

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/verification-requests \
  -H 'Authorization: Bearer test-api-key-tenant-A' \
  -H 'Content-Type: application/json' \
  -d '{"claims":["age_over_18"]}'
```

Die Antwort enthält `sessionId`, `state`, `responseUri` und ein signiertes
`requestObject`. Diese Werte werden an die Wallet-Integration übergeben. Das
vollständige Schema steht in `openapi.yaml`.

### TypeScript

```ts
import { AttackClient } from '@eudi-verify-sdk/typescript';

const client = new AttackClient({
  baseUrl: process.env.ATTACK_URL ?? 'http://127.0.0.1:8080',
  apiKey: process.env.ATTACK_API_KEY,
});

const request = await client.createPresentationRequest({
  claims: ['age_over_18'],
});
console.log(request.requestObjectUri);
```

Die Antwort enthält außerdem `walletUrl`, den Aufruf für eine echte Wallet
(`openid4vp://?client_id=...&request_uri=...&request_uri_method=get`). Als Link
auf demselben Gerät oder als QR-Code für ein zweites Gerät anzeigen. Request URI
und Response URI darin kommen aus `ATTACK_PUBLIC_BASE_URL`.

## 3. Wallet-Antwort empfangen und prüfen

Die Wallet sendet an den öffentlichen Endpunkt `/direct_post`. Der Dienst
prüft Protokollzustand, Signatur, Disclosure-Hashes, Key-Binding, Issuer-
Vertrauen, Sperrung der Issuer-Zertifikate und den Credential-Status. Ein
Browser-Erfolgssignal darf nicht als Verifikationsergebnis verwendet werden.

Nach der Wallet-Antwort wird das Ergebnis mit dem Mandanten-API-Key gelesen:

```bash
curl -sS \
  -H 'Authorization: Bearer test-api-key-tenant-A' \
  http://127.0.0.1:8080/v1/verification-requests/SESSION_ID
```

Das Ergebnis hat den Status `pending`, `completed`, `expired` oder
`not_found`. Ein fertiges Ergebnis enthält `valid`, geprüfte Claims, das
Ausstellerland und optional einen stabilen Fehlercode. Fertige Ergebnisse sind
bewusst nur einmal abrufbar.

Das SDK meldet nicht erfolgreiche API-Antworten als `AttackApiError` mit
HTTP-Status und stabilem `code`. Die öffentliche Wallet-Antwort nutzt `ok` und
`valid`; `valid: false` ist eine fachliche Ablehnung, kein Transportfehler.

### Wallet-Antworten: nicht angenommen (422) und inhaltlich abgelehnt (200)

`/direct_post` ist öffentlich, es gibt auf dieser Route also nie einen
API-Key, gegen den man sich authentifizieren könnte. **Der HTTP-Status sagt
dabei nur, ob der Dienst die Präsentation verarbeiten konnte — nicht, ob sie
gültig ist.** Das sind zwei verschiedene Fragen mit zwei verschiedenen
Antworten.

Eine nicht angenommene Wallet-Antwort beantwortet der Dienst mit **HTTP 422
Unprocessable Entity** und einem lesbaren Grund im Body:

```bash
curl -sS -i -X POST http://127.0.0.1:8080/direct_post \
-H 'content-type: application/json' \
-d '{"state":"STATE","vp_token":{"pid":["SD_JWT"]}}'
```

```
HTTP/1.1 422 Unprocessable Entity
content-type: application/json; charset=utf-8

{"ok":false,"valid":false,"error":"unknown_state"}
```

Eine **verarbeitete, aber inhaltlich abgelehnte** Wallet-Antwort trägt dagegen
**HTTP 200**. Der Dienst hat die Präsentation ausgewertet und sie abgelehnt,
etwa weil das Aussteller-Zertifikat abgelaufen ist. Der Grund steht im Feld
`error`:

```bash
curl -sS -i -X POST http://127.0.0.1:8080/direct_post \
-H 'content-type: application/json' \
-d '{"state":"STATE","vp_token":{"pid":["ABGELAUFENES_SD_JWT"]}}'
```

```
HTTP/1.1 200 OK
content-type: application/json; charset=utf-8

{"ok":true,"valid":false,"error":"certificate_expired"}
```

422 heißt also **nicht** „Präsentation abgelehnt", sondern „Präsentation nicht
verarbeitbar": unbekannte oder abgelaufene Sitzung, Formfehler, Replay,
JWE-Problem. Wer eine 422 sieht, muss die Nutzlast oder die Sitzung prüfen. Wer
ein 200 mit `valid: false` sieht, bekommt ein Prüfergebnis und sollte es
fachlich auswerten, nicht wiederholen.

Alle drei SDKs liefern diesen Body als `PresentationResponse` zurück, statt
eine Ausnahme zu werfen. Erst `ok` prüfen, dann `valid`, dann `error`:

```ts
const outcome = await attack.submitPresentation({ response: walletJwe });
if (!outcome.ok) {
  // 422: nicht verarbeitbar. unknown_state, state_invalid, vp_token_invalid,
  // session_reused, …  Nutzlast oder Sitzung prüfen.
  console.error(outcome.error);
} else if (!outcome.valid) {
  // 200: verarbeitet und inhaltlich abgelehnt. z. B. certificate_expired.
  console.error(outcome.error);
} else {
  // 200 und gültig
}
```

**Nur `valid` zu prüfen genügt nicht**, denn bei 422 ist `valid` ebenfalls
`false`. Ein Client, der `valid` allein auswertet, hält eine nicht verarbeitbare
Präsentation für ein fachliches Prüfergebnis.

**401 bleibt der Authentifizierung vorbehalten.** Es bedeutet einen fehlenden
oder unbekannten Mandanten-API-Key, und zwar nur auf den mandantenpflichtigen
Routen. Eine Wallet-Antwort erzeugt ihn nie.

## 4. Fehlerbehandlung

Nach Fehlerkategorie behandeln, nicht nach lokalisiertem Meldungstext:

- `401 unauthorized`: API-Key fehlt oder ist ungültig;
- `403 tenant_not_registered` oder `tenant_registration_invalid`: das aktive
  Onboarding-Material lehnt den Mandanten ab;
- `400 claims_invalid`, `vct_invalid` oder `registration_ref_invalid`: Eingabe
  passt nicht zum Mandantenprofil;
- `credential_revoked`, `credential_suspended` oder `credential_status_*`:
  Credential-Status fehlgeschlagen;
- `issuer_certificate_revoked` oder `issuer_revocation_check_failed`:
  Statusprüfung der Issuer-Zertifikatskette fehlgeschlagen;
- `unknown_state`, `state_invalid`, `vp_token_invalid`, `session_reused`,
  `session_expired` sowie die Familie `malformed_jwe_header` /
  `jwe_decrypt_failed`: die Wallet-Antwort wurde nicht angenommen. Diese
  kommen auf `/direct_post` als **HTTP 422** mit `ok: false`. Kein Wiederholen
  mit derselben Nutzlast;
- codes der inhaltlichen Ablehnung wie `certificate_expired`,
  `certificate_not_yet_valid`, `issuer_trust_anchors_empty` oder
  `credential_revoked`: die Wallet-Antwort **wurde verarbeitet** und abgelehnt.
  Sie kommt als **HTTP 200** mit `ok: true, valid: false`. Fachlich auswerten,
  nicht wiederholen.
- `500 internal_error`: nur gemäß Idempotenz- und Incident-Policy wiederholen;
  niemals eine erfolgreiche Verifikation annehmen.

### Migration: 401 zu 422 bei abgelehnten Wallet-Antworten

Bis zum 27.09.2026 beantwortete `/direct_post` **jede abgelehnte**
Wallet-Antwort mit 401, auch `unknown_state`. Das war eine inkompatible
Änderung für Integratoren.

Diese Migration betrifft nur die Fälle, in denen der Dienst die Präsentation
**nicht verarbeiten konnte** (`ok: false`, heute 422). Verarbeitete und
inhaltlich abgelehnte Präsentationen (`ok: true, valid: false`) waren und sind
200 und von dieser Umstellung nicht betroffen.

Der Grund der Umstellung: 401 ist in `docs/fehlercodes.md` als fehlender oder
unbekannter API-Key definiert, und ist jetzt der einzige Status mit dieser
Bedeutung. Weil `/direct_post` öffentlich ist, ließ sich ein 401 dort nicht
korrekt behandeln — wer der Dokumentation folgte, erneuerte den Key, obwohl die
Sitzung schlicht nicht mehr existierte.

Was im bestehenden Code zu prüfen ist:

| Verhalten vorher | Erwartet jetzt |
|---|---|
| `direct_post` liefert 401 → `error` aus dem Body lesen | Liefert 422, gleiche Body-Form |
| `direct_post` 401 → mit neuem API-Key wiederholen | 422 ist kein Auth-Problem; `error` auswerten |
| `direct_post` liefert 200 mit `valid: false` | unverändert; es war nie ein 401-Fall, `error` ist der fachliche Ablehnungsgrund |
| `direct_post` 200 mit `valid: false` → als verarbeitbar behandeln | richtig: verarbeitet und abgelehnt, nicht wiederholen |
| SDK-Aufruf warf bei abgelehnter Präsentation | SDKs liefern die `PresentationResponse` |
| 401 auf mandantenpflichtigen Routen | unverändert, weiterhin 401 `unauthorized` |

Eine robuste Prüfung ignoriert den Status und liest den Body, das ist vor und
nach der Änderung richtig:

```ts
const outcome = await attack.submitPresentation({ response: walletJwe });
if (!outcome.ok) {
  switch (outcome.error) {
    case 'unknown_state':
    case 'session_expired': /* neue Prüfanfrage stellen */ break;
    case 'state_invalid':
    case 'vp_token_invalid': /* die Wallet hat etwas falsches gesendet */ break;
    default: /* nicht automatisch wiederholen */ break;
  }
}
```

Die vollständige Liste steht in `docs/fehlercodes.md`, die Response-Schemas in
`openapi.yaml`.

## 5. Checkliste für den Produktivbetrieb

Vor dem Produktivbetrieb sind alle TEST-Annahmen zu ersetzen:

1. echte Verifier-Identität und Zertifikatskette bereitstellen;
2. Issuer-Trust-Anker über einen geprüften Betriebsprozess konfigurieren;
3. Trust-Policy und Quelle für Credential-Token-Statuslisten konfigurieren;
4. entscheiden, ob und wie das WRPAC/WRPRC-Onboarding-Gate aktiviert wird;
5. das passende nationale Registrar-Profil beschaffen und prüfen;
6. TLS, Secret-Management, Persistenz, Backups und Monitoring betreiben;
7. Aufbewahrung, Löschung, Zugriffsprotokollierung und Incident Response
   festlegen;
8. Wallet-Interop- und Sicherheitstests mit freigegebenen Testdaten ausführen.

Das Repository stellt TEST-Infrastruktur und lokale Mocks bereit. Es enthält
keinen amtlichen Registerzugang, keine echten Sandbox-Zugangsdaten und kein
Produktivdeployment.
