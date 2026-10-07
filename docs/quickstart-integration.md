# Quickstart Integration

Für einen Entwickler, der den Prüfdienst lokal ansprechen will. Voraussetzung:
Node 22, ein checkout dieses Repositorys, `npm ci`. **Kein Docker, kein
Colima.** Bearbeitet am 30.09.2026 auf `main` commit `88f9cb8`.

> **Produktname: `Attack`.** Arbeitsname, bewusst nur hier geführt, damit
> `tools/rename.mjs` ihn ersetzen kann (`docs/umbenennung-inventar.md`).

Alle Ausgaben in diesem Dokument sind wörtlich kopiert. Keine ist erfunden und
keine ist zusammengebaut.

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

Im Entwicklungsbetrieb sind zwei Testmandanten vorhanden, die Schlüssel stehen
in `src/service/bootstrap.ts:40-41`:

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
  "requestObjectUri": "http://127.0.0.1:18100/v1/verification-requests/a1077728-050c-4945-ad72-e279caebbada/request-object"
}
```

`claims` darf nur Namen enthalten, die im Anfrageprofil des Mandanten stehen.
Das Standardprofil `pid_basis` kennt `given_name` und `birth_date`
(`src/service/profile.ts:13-18`). `family_name` gehört nicht dazu, siehe
Fehlerfall F2.

`state` und `sessionId` sind hier gleich, das ist Zufall der Implementierung und
keine Zusage für andere Fälle.

## 2. Antwort der Wallet simulieren

Eine echte Wallet steht hier nicht zur Verfügung. Der Nachweis wird aus dem
Mock-Wallet des Repositorys erzeugt, das ist Testmaterial ohne jede Verbindung
zu einer Wallet oder einem Aussteller.

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
Dienst kein Ergebnis. Geprüft in
`src/service/issuer-revocation.test.ts:228`, dort steht als Grund
"kein Ergebnis bei gesperrtem Zertifikat".

**Was das für eine Integration heißt:** Aus `valid: false` folgt **kein**
abrufbares Ergebnis. Wer auf ein Ergebnis wartet, wartet vergeblich, bis die
Sitzung verfällt. Das Ergebnis wird nur dann abgelegt, wenn die Prüfung
durchläuft. Wer beides braucht, muss die Antwort von Schritt 2 auswerten.

Sitzungen verfallen nach 300 Sekunden im Entwicklungsbetrieb, das Ergebnis
selbst nach 60 Sekunden (`src/config.ts:50`).

## 4. Fehlerfälle

Alle Codes aus `docs/fehlercodes.md`, dort mit Zeile belegt.

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

`docs/fehlercodes.md:165`. Ein `state`, zu dem kein offener Auftrag gehört.

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

`docs/fehlercodes.md:71`. `family_name` steht nicht im Anfrageprofil. Der
Dienst nennt absichtlich keinen Detailgrund, siehe `src/service/app.ts:291-293`.

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

`docs/fehlercodes.md:58`.

### F4, abgelaufene Sitzung

Nur mit veränderter Zeit erzeugbar, deshalb hier nicht als ausführbares Beispiel:

| Code | HTTP | Bedeutung |
|---|---|---|
| `not_found` | 404 | Sitzung unbekannt, gelöscht, verbraucht, abgelaufen oder einem fremden Mandanten gehörend. Bewusst nicht unterscheidbar, `docs/fehlercodes.md:60`. |
| `session_expired` | 422 | Sitzung abgelaufen, `docs/fehlercodes.md:166`. |

Warum nicht ausführbar: Die Ablaufzeit steht im Mandantenprofil in Sekunden,
`src/service/tenant.ts:37`. Ein Schnelllauf ließe sich nur mit verändertem
Profil bauen, das wäre ein anderer Dienst als der hier beschriebene.

## 5. Dienst beenden

```bash quickstart
pkill -f "src/service/run.ts"
```

## 6. Selbsttest dieser Beispiele

Die Befehle in diesem Dokument werden von einem Test ausgeführt, nicht nur
beschrieben:

```bash
npx vitest run src/quickstart-beispiele.test.ts
```

Wird ein Codeblock geändert, sodass der Test ihn nicht mehr starten kann oder
der dokumentierte Statuscode nicht mehr stimmt, schlägt der Test fehl.

## 7. Was der Dienst heute nicht kann

Alles hier ist dem Stand von `main` commit `88f9cb8` vom 30.09.2026
zugeordnet. Belege in `docs/interop-matrix.md`.

| Nicht vorhanden | Bedeutung für eine Integration |
|---|---|
| **mdoc** | Anfragen und Präsentationen laufen ausschließlich im Format `dc+sd-jwt`. Eine Wallet, die mdoc verlangt, wird nicht bedient. `docs/interop-matrix.md` Abschnitt 3. |
| **LOTL** | Es gibt keine Trust List nach TS 119 612. Geprüft wird nur, was als Anker konfiguriert ist. Deshalb endet Schritt 2 mit `issuer_trust_anchor_not_found`. `docs/interop-matrix.md` Abschnitt 3. |
| **Credential Sets** | Nicht implementiert. `docs/interop-matrix.md` Abschnitt 3. |
| **Registratur-Anbindung** | Der Client existiert im Code, wird aber nicht verdrahtet. `docs/interop-matrix.md` Abschnitt 3. |
| **Test mit einer echten Wallet** | Es wurde **kein** Test gegen eine echte Wallet durchgeführt. Der Nachweis in Schritt 2 stammt aus lokal erzeugtem Testmaterial. `docs/interop-matrix.md` Abschnitt 4. |
| **Zertifizierung** | Es liegt weder eine Zertifizierung noch ein Konformitätsnachweis vor. `docs/eidas-arf-konformitaet.md:4`. |
| **Externe Prüfung** | Weder Penetrationstest noch externes Review. `docs/produktionsreife.md:76`. |
| **Referenzkunden** | Es gibt keine. |
| **Datenhaltung** | Ergebnisse liegen nur im Arbeitsspeicher und sind flüchtig. Für Nachweiszwecke reicht das nicht, `docs/bedrohungsmodell.md` S15. |
| **Produktionsbetrieb** | Hier läuft der Dienst im Entwicklungsbetrieb mit Testmaterial, Port 18100, ohne TLS. |
