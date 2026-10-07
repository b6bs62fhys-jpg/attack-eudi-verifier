# Quickstart Integration

Für Entwicklerinnen und Entwickler, die den Prüfdienst lokal ansprechen
wollen, bevor sie ihn in eine eigene Anwendung einbinden. Voraussetzungen:
Node.js 22.12 oder neuer, ein Klon dieses Repositorys und `npm ci`. Docker ist
nicht nötig.

Der Dienst läuft hier im Entwicklungsbetrieb mit TEST-Mandanten,
TEST-Schlüsseln und TEST-Zertifikaten. Eine echte Wallet kommt nicht vor; die
Wallet-Antwort wird aus der Mock-Wallet des Repositorys erzeugt.

Alle Ausgaben stammen aus einem echten Lauf und sind wörtlich übernommen.
`sessionId`, `state`, `expiresAt` und das Request Object sind bei jedem Lauf
andere.

## 0. Dienst starten

```bash quickstart
NODE_ENV=development ATTACK_DEV_MODE=true ATTACK_ALLOW_SELF_SIGNED=true \
  PORT=18100 node --experimental-strip-types src/service/run.ts
```

Das ist ein **blockierender** Befehl, der Dienst läuft weiter. Für die Befehle
unten eine zweite Konsole verwenden.

Die Ausgabe enthält Warnungen, unter anderem:

```text
{"event":"bootstrap_warning","message":"!!! WARNUNG: ATTACK_DEV_MODE=true ist AKTIV !!!"}
{"event":"bootstrap_warning","message":"!!! Credential-Statusprüfung ist ABGESCHALTET (ATTACK_DEV_MODE aktiv). !!!"}
{"event":"service_started","app":"attack-service","host":"127.0.0.1","port":18100}
```

Ob der Dienst bereit ist:

```bash quickstart
curl -s http://127.0.0.1:18100/live
```

```text
HTTP 200
{"ok":true,"status":"live","app":"attack-service"}
```

Im Entwicklungsbetrieb sind zwei Testmandanten vorhanden. Ihre Schlüssel stehen
in `DEV_TEST_TENANTS` in `src/service/bootstrap.ts` und werden nur mit
`ATTACK_DEV_MODE=true` außerhalb von Produktion angelegt:

| Mandant | Schlüssel |
|---|---|
| tenant-a | `test-api-key-tenant-A` |
| tenant-b | `test-api-key-tenant-B` |

Der Schlüssel gehört in den `authorization`-Header, **nicht** in `x-api-key`.
Siehe Fehlerfall F3.

## 1. Sitzung anlegen

```bash quickstart
curl -s -X POST http://127.0.0.1:18100/v1/verification-requests \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer test-api-key-tenant-A' \
  -d '{"claims":["given_name","birth_date"]}'
```

```text
HTTP 201
{
  "sessionId": "a1077728-050c-4945-ad72-e279caebbada",
  "state": "a1077728-050c-4945-ad72-e279caebbada",
  "expiresAt": 1790757810659,
  "requestObject": "eyJ0eXAiOiJvYXV0aC1yZXErand0IiwiYWxnIjoiRVMyNTYi...",
  "responseUri": "http://127.0.0.1:18100/direct_post",
  "requestObjectUri": "http://127.0.0.1:18100/v1/verification-requests/a1077728-050c-4945-ad72-e279caebbada/request-object",
  "walletUrl": "openid4vp://?client_id=x509_hash%3A...&request_uri=http%3A%2F%2F127.0.0.1%3A18100%2Fv1%2Fverification-requests%2Fa1077728-050c-4945-ad72-e279caebbada%2Frequest-object&request_uri_method=get"
}
```

`walletUrl` ist der Aufruf für eine echte Wallet, als Link auf demselben Gerät
oder als QR-Code. Im Produktionsbetrieb stehen darin die Adressen aus
`ATTACK_PUBLIC_BASE_URL`; hier zeigt er auf 127.0.0.1 und ist nur für den
lokalen Ablauf.

`claims` darf nur Namen enthalten, die im Anfrageprofil des Mandanten stehen.
Das Standardprofil `pid_basis` kennt `given_name` und `birth_date`
(`REQUEST_PROFILE_TEMPLATES` in `src/service/profile.ts`). `family_name` gehört
nicht dazu, siehe Fehlerfall F2.

`state` und `sessionId` sind hier gleich. Das ist eine Eigenschaft der
aktuellen Implementierung und keine Zusage. Eine Integration sollte beide
Werte getrennt behandeln.

## 2. Antwort der Wallet simulieren

Eine echte Wallet steht hier nicht zur Verfügung. Der Nachweis wird aus der
Mock-Wallet des Repositorys erzeugt. Das ist Testmaterial ohne Verbindung zu
einer echten Wallet oder einem echten Aussteller.

```bash quickstart
node --experimental-strip-types tools/quickstart-sdjwt.mjs > /tmp/wallet.txt
```

Einreichen:

```bash quickstart
curl -s -X POST http://127.0.0.1:18100/direct_post \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "vp_token=$(cat /tmp/wallet.txt)" \
  --data-urlencode "state=a1077728-050c-4945-ad72-e279caebbada"
```

```text
HTTP 200
{"ok":true,"valid":false,"error":"issuer_trust_anchor_not_found"}
```

**HTTP 200, nicht 422.** Der Dienst hat den Nachweis verarbeitet und inhaltlich
abgelehnt, weil der Testaussteller nicht im Entwicklungsanker steht. 422 hieße
"konnte ich nicht verarbeiten", 200 heißt "habe ich geprüft, passt nicht".

## 3. Ergebnis abholen

```bash quickstart
curl -s http://127.0.0.1:18100/v1/verification-requests/a1077728-050c-4945-ad72-e279caebbada \
  -H 'authorization: Bearer test-api-key-tenant-A'
```

```text
HTTP 200
{"status":"pending"}
```

**Das ist kein Fehler, sondern gewollt.** Bei einer Ablehnung hinterlegt der
Dienst kein Ergebnis. Ein Test sichert das ab: „gesperrtes
Aussteller-Zertifikat -> Präsentation abgelehnt (issuer_certificate_revoked)“
in `src/service/issuer-revocation.test.ts` prüft, dass der Status danach
`pending` bleibt.

**Was das für eine Integration heißt:** Aus `valid: false` folgt **kein**
abrufbares Ergebnis. Wer auf ein Ergebnis wartet, wartet vergeblich, bis die
Sitzung verfällt. Das Ergebnis wird nur dann abgelegt, wenn die Prüfung
durchläuft. Wer beides braucht, muss die Antwort von Schritt 2 auswerten.

Sitzungen verfallen ohne eigene Angabe im Mandanten nach 300 Sekunden
(`src/service/tenant.ts`), ein fertiges Ergebnis nach 60 Sekunden
(`DEFAULT_RESULT_TTL_SECONDS` in `src/config.ts`, einstellbar über
`ATTACK_RESULT_TTL_SECONDS`). Ein Ergebnis lässt sich genau einmal abrufen.

## 4. Fehlerfälle

Alle Codes sind in [Fehlercodes](fehlercodes.md) beschrieben.

### F1, unbekannter Zustand

```bash quickstart
curl -s -X POST http://127.0.0.1:18100/direct_post \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "vp_token=$(cat /tmp/wallet.txt)" \
  --data-urlencode "state=gibt-es-nicht"
```

```text
HTTP 422
{"ok":false,"valid":false,"error":"unknown_state"}
```

Ein `state`, zu dem kein offener Auftrag gehört. HTTP 422 heißt: Die
Präsentation konnte nicht verarbeitet werden.

### F2, unvollständige oder unbekannte Angabe

```bash quickstart
curl -s -X POST http://127.0.0.1:18100/v1/verification-requests \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer test-api-key-tenant-A' \
  -d '{"claims":["family_name"]}'
```

```text
HTTP 400
{"error":"claims_invalid"}
```

`family_name` steht nicht im Anfrageprofil. Der Dienst nennt absichtlich
keinen Detailgrund, sondern nur den festen Code (`src/service/app.ts`).

### F3, fehlender oder falscher Schlüssel

```bash quickstart
curl -s -X POST http://127.0.0.1:18100/v1/verification-requests \
  -H 'content-type: application/json' \
  -d '{}'
```

```text
HTTP 401
{"error":"unauthorized"}
```

Derselbe Code gilt für einen unbekannten Schlüssel.

### F4, abgelaufene Sitzung

Nur mit veränderter Zeit erzeugbar, deshalb hier nicht als ausführbares Beispiel:

| Code | HTTP | Bedeutung |
|---|---|---|
| `not_found` | 404 | Beim Ergebnisabruf: Sitzung unbekannt, gelöscht, verbraucht, abgelaufen oder einem fremden Mandanten gehörend. Bewusst nicht unterscheidbar. |
| `session_expired` | 422 | Bei `POST /direct_post`: Sitzung abgelaufen. |

Warum nicht ausführbar: Die Ablaufzeit steht in Sekunden im Mandanten
(`requestTtlSeconds` in `src/service/tenant.ts`). Ein schneller Ablauf ließe
sich nur mit einem veränderten Mandanten zeigen, also nicht mit dem hier
beschriebenen Dienst.

## 5. Dienst beenden

```bash quickstart
pkill -f "src/service/run.ts"
```

## 6. Selbsttest dieser Beispiele

Die `curl`-Beispiele in diesem Dokument werden von einem Test ausgeführt, nicht
nur beschrieben. Er prüft, dass jeder Befehl läuft und den dokumentierten
Statuscode liefert. Der Startbefehl und `pkill` laufen im Test nicht; der Test
startet den Dienst selbst, mit eigenem Testmandanten.

```bash
npx vitest run src/quickstart-beispiele.test.ts
```

Wird ein Codeblock geändert, sodass der Test ihn nicht mehr starten kann oder
der dokumentierte Statuscode nicht mehr stimmt, schlägt der Test fehl.

## 7. Was der Dienst heute nicht kann

Belege und Einzelheiten stehen in der [Interoperabilitätsmatrix](interop-matrix.md).

| Nicht vorhanden | Bedeutung für eine Integration |
|---|---|
| **mdoc** | Anfragen und Präsentationen laufen ausschließlich im Format `dc+sd-jwt`. Eine Wallet, die nur mdoc anbietet, wird nicht bedient. |
| **LOTL** | Es gibt keine Trust List nach ETSI TS 119 612. Geprüft wird nur, was als Anker konfiguriert ist. Deshalb endet Schritt 2 mit `issuer_trust_anchor_not_found`. |
| **Credential Sets** | Nicht implementiert. |
| **Registrar-Anbindung** | Der Client existiert im Code, ist aber nicht verdrahtet. |
| **Test mit einer echten Wallet** | Der Dienst wurde Ende zu Ende nur gegen die Mock-Wallet dieses Repositorys getestet. Mit einer echten Wallet, einer Sandbox (auch nicht der SPRIND-Sandbox) oder einer nationalen Wallet wurde er nicht getestet. |
| **Zertifizierung** | Es liegt weder eine Zertifizierung noch ein Konformitätsnachweis vor ([eIDAS und ARF Zuordnung](eidas-arf-konformitaet.md)). |
| **Externe Prüfung** | Weder Penetrationstest noch externes Security-Review ([Sicherheit](sicherheit.md)). |
| **Referenzkunden** | Es gibt keine. |
| **Datenhaltung** | Sitzungen und Ergebnisse liegen nur im Arbeitsspeicher und sind flüchtig. Als Nachweis gegenüber Dritten reicht das nicht ([Bedrohungsmodell](bedrohungsmodell.md), S15). |
| **Produktionsbetrieb** | Hier läuft der Dienst im Entwicklungsbetrieb mit Testmaterial, auf Port 18100 und ohne TLS. Was für den Produktionsbetrieb nötig ist, steht im [Integrationsleitfaden](integration-guide.de.md) und in [Deployment](deployment.md). |
