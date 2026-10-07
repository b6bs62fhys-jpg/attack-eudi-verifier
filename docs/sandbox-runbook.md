# Sandbox Runbook: erster echter Durchlauf mit der EUDI Wallet

Stand: 07.10.2026. Ziel: Attack nimmt eine Test PID aus der Sandbox Wallet auf
einem iPhone an, im Produktionsmodus und ohne Entwicklungsschalter. Jede
Aussage über die Sandbox ist mit einer Quelle aus Abschnitt 9 belegt. Was nur
vermutet ist, steht ausdrücklich als offen da.

Legende: ✅ erledigt, ⏳ wartet auf SPRIND, ☐ offen bei Yannik, 🔒 geht erst mit Zugangsdaten, die noch fehlen.

## 0. Was Yannik tun muss

| # | Schritt | Stand |
|---|---|---|
| 1 | Absichtserklärung über das [Intent Formular](https://2eut7s.share-eu1.hsforms.com/2QlEzCm_NR6SbkHuq9vbFWw) abgeben, ein Formular je Use Case [Q1]. Prüfen, ob das schon geschehen ist. | ☐ |
| 2 | Anfrage zum Stand an partner@eudi.sprind.org | ✅ 07.10.2026 gesendet |
| 3 | Kick-off Call. Termine monatlich, angekündigt im Ecosystem Knowledge Center [Q1] | ⏳ |
| 4 | Nach dem Kick-off zwei E-Mail-Adressen an partner@eudi.sprind.org senden: Operational Contact und Technical Contact. Dazu die E-Mail-Adresse, die für die iOS Wallet freigeschaltet werden soll; sie muss zu einer Apple ID gehören [Q2] | ☐ nach 3 |
| 5 | Einladung in die Closed Beta: TestFlight Einladung per Mail [Q2] | ⏳ |
| 6 | Zugang zum Sandbox Registrar: Mail zum Setzen des Passworts, kommt nicht von @eudi.sprind.org, also Spam prüfen. Nach einer Woche ohne Zugang im Mattermost nachfragen [Q2] | ⏳ |
| 7 | Nutzungsbedingungen annehmen. Der Vertrag entsteht erst mit Annahme des Angebots im Onboarding [Q4, Nr. 2.4]; Zugangs und Registrierungszertifikat setzen die Annahme voraus [Q3] | ⏳ dann ☐ |
| 8 | Zugangszertifikat im Registrar anlegen (Abschnitt 2.2 und 2.3) | 🔒 nach 6 und 7 |
| 9 | Credential Request anlegen, daraus entsteht das Registrierungszertifikat (Abschnitt 2.4) | 🔒 nach 6 und 7 |
| 10 | iPhone: TestFlight mit automatischen Updates, Wallet installieren, Test PID über simulierte eID (Abschnitt 4.1) | 🔒 nach 5 |
| 11 | Mac mini: Tunnel, Dienst, erster Durchlauf (Abschnitte 3 und 4) | ☐ nach 8 bis 10 |
| 12 | Für echte Piloten klären: registriert sich die Relying Party selbst oder Attack als Dienstleister (Abschnitt 7) | ☐ |

Regeln aus den Nutzungsbedingungen, die für jeden Test gelten:

* Nur Testdaten, keine echten personenbezogenen Daten ("No Real Data Policy") [Q4, Nr. 3.3]. Die simulierte eID liefert Testdaten.
* Keine Lasttests und kein Penetration Testing gegen die Sandbox [Q4, Nr. 3.1].
* Zugangsdaten nicht weitergeben [Q4, Nr. 2.5 und 9.2].
* Nicht öffentliche Unterlagen aus der Sandbox vertraulich behandeln [Q4, Nr. 5.1]. Dieses Runbook stützt sich nur auf öffentliche Quellen.

## 1. Was die Sandbox vom Verifier verlangt und wo Attack steht

| Anforderung | Beleg | Attack |
|---|---|---|
| Signiertes Request Object (JAR), abgeholt über `request_uri` | [Q5] 1.1 und 1.3 | erfüllt |
| `client_id` = `x509_hash:` plus base64url SHA-256 des Zugangszertifikats (DER) | [Q6], [Q5] 1.3 | erfüllt |
| Im `x5c` Kopf nur das Zugangszertifikat, kein weiteres Zertifikat | [Q7] | per Konfiguration: Kettendatei enthält nur das Zugangszertifikat (Abschnitt 2.3) |
| Registrierungszertifikat als `verifier_info` mit `"format": "registration_cert"`; fehlt es, lehnt die Wallet ab | [Q7], [Q5] 1.3 | **neu**: `ATTACK_REGISTRATION_CERTIFICATE_FILE`. Gesendet als Liste wie in OpenID4VP 1.0 und der Referenzimplementierung [Q12]; die Doku zeigt nur ein Fragment als Objekt |
| `response_mode` `direct_post.jwt`, Antwort verschlüsselt mit ECDH-ES und A128GCM, Schlüssel frisch je Anfrage | [Q5] 1.2 | erfüllt (angeboten A128GCM und A256GCM, Schlüssel je Sitzung) |
| `vp_formats_supported` mit `sd-jwt_alg_values` und `kb-jwt_alg_values` | [Q5] 1.2, [Q12] | **neu korrigiert**, vorher mit Unterstrichen |
| PID als SD-JWT VC mit `vct` `urn:eudi:pid:de:1`, Claims `given_name`, `family_name`, `birthdate` | [Q8], [Q5] 1.2 | **neu**: Profilvorlage `pid_de` |
| `response_uri` als HTTPS Adresse, die die Wallet erreicht; HTTPS Endpunkte sind Voraussetzung | [Q5] 1.3, [Q1] | **neu**: `ATTACK_PUBLIC_BASE_URL`, im Produktionsmodus Pflicht |
| Aufruf der Wallet: `openid4vp://?client_id=...&request_uri=...&request_uri_method=get` | [Q5] 1.3.2 | **neu**: Feld `walletUrl` in jeder Prüfanfrage, QR Code auf der Demo Flowseite |
| Vertrauensanker der PID Aussteller aus der Sandbox Vertrauensliste | [Q9], [Q10] | Datei nach Abschnitt 2.5 |
| Sperrprüfung der Aussteller Kette; die CA Zertifikate der Vertrauensliste tragen nur CRL Adressen | [Q10] | **neu**: CRL eingebunden, im Produktionsmodus Pflicht |
| mdoc (ISO 18013-5) | [Q11] | nicht unterstützt; für die Online PID per SD-JWT nach [Q5] nicht nötig |
| Nach `direct_post` eine Antwort mit `redirect_uri` | [Q5] 1.3.3 (Entwurf) | **fehlt**, siehe Abschnitt 8 |

## 2. Material vorbereiten (Mac mini)

Alle Dateien liegen in einem eigenen Verzeichnis, nur für den eigenen Benutzer lesbar:

```bash
mkdir -p ~/attack-sandbox && chmod 700 ~/attack-sandbox
```

Im Repository einmal die Abhängigkeiten installieren:

```bash
npm ci
```

### 2.1 Überblick der Dateien

| Datei | Woher | Variable |
|---|---|---|
| `verifier-key.pem` | Abschnitt 2.2 | `ATTACK_VERIFIER_KEY_PEM` |
| `verifier-chain.pem` | Abschnitt 2.3 | `ATTACK_VERIFIER_CERT_CHAIN_PEM` |
| `registration-certificate.json` | Abschnitt 2.4 | `ATTACK_REGISTRATION_CERTIFICATE_FILE` |
| `issuer-anchors.pem` | Abschnitt 2.5 | `ATTACK_ISSUER_TRUST_ANCHORS_PEM` |
| `tenants.json` | Abschnitt 2.6 | `ATTACK_TENANTS_FILE` |

### 2.2 Schlüssel und CSR erzeugen 🔒 (Einfügen erst mit Registrar Zugang)

Die ersten beiden Befehle stammen wörtlich aus der offiziellen Anleitung [Q13]. Der private Schlüssel verlässt den Mac nie; in den Registrar kommt nur der CSR.

```bash
cd ~/attack-sandbox
openssl ecparam -name secp256r1 -genkey -noout -out private.key
openssl req -new -key private.key -out public.csr -subj "/"
pbcopy < public.csr
```

Der Dienst erwartet den Schlüssel im Format PKCS#8. `openssl ecparam` schreibt dagegen `-----BEGIN EC PRIVATE KEY-----`, und der Dienst bricht damit ab ("Private-Key unbrauchbar (EC P-256 PKCS#8 erwartet)"). Am 07.10.2026 lokal geprüft: nach dieser Umwandlung lädt der Dienst den Schlüssel.

```bash
openssl pkcs8 -topk8 -nocrypt -in private.key -out verifier-key.pem
chmod 600 private.key verifier-key.pem
```

Im Registrar: **Integration → Access certificates → New access certificate**, Namen vergeben, CSR einfügen, **Generate certificate** [Q13].

### 2.3 Zugangszertifikat einbinden 🔒

Der Registrar liefert das Zugangszertifikat als `.crt` [Q7]. In die Kettendatei kommt nur dieses eine Zertifikat [Q7]:

```bash
cd ~/attack-sandbox
openssl x509 -in access-certificate.crt -out verifier-chain.pem
openssl x509 -in verifier-chain.pem -noout -subject -issuer -dates -ext crlDistributionPoints
```

Prüfen, dass Schlüssel und Zertifikat zusammengehören (keine Ausgabe heißt: gleich):

```bash
diff <(openssl x509 -in verifier-chain.pem -noout -pubkey) <(openssl pkey -in verifier-key.pem -pubout)
```

Zum Vergleich mit der `client_id` im Request Object, Befehl aus [Q6]:

```bash
openssl x509 -in verifier-chain.pem -outform DER | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '='
```

### 2.4 Registrierungszertifikat anlegen 🔒

Für eine Relying Party entsteht es aus einem Credential Request: **Configuration → Credential requests → New request** [Q14]. Eintragen:

* Credential format: das Format, das der Registrar anbietet. Die Doku nennt als Beispiel `vc+sd-jwt` [Q14]; Attack fragt `dc+sd-jwt` an. Ob der Unterschied die Wallet "over-asking" melden lässt, ist offen (Abschnitt 8).
* VCT: `urn:eudi:pid:de:1`
* Requested data, je Zeile ein Claim: `given_name`, `family_name`, `birthdate`. Genau diese drei fragt das Profil `pid_de` an. Was über die Erklärung hinausgeht, zeigt die Wallet als "over-asking" an [Q14].
* Reason for the request: kurz auf Deutsch und Englisch. Der Text erscheint in der Wallet [Q14].

Die Datei `registration-certificate.json` nach `~/attack-sandbox/` legen. Ihr genauer Aufbau ist öffentlich nicht beschrieben, nur dass sie ein JWT enthält [Q7]. Der Dienst nimmt das JWT selbst oder eine JSON-Datei mit genau einem JWT darin und bricht sonst beim Start ab.

### 2.5 Vertrauensanker der PID Aussteller

Die Sandbox Vertrauensliste [Q10] ist ein signiertes JWT; den Signierschlüssel stellt dieselbe Seite als `certificate.pem` bereit. Das Skript prüft die Signatur und schreibt alle Zertifikate der PID Aussteller Liste in eine PEM-Datei. Im Repository ausführen, weil es `jose` aus den Abhängigkeiten braucht. Am 07.10.2026 mit den echten Dateien geprüft: Signatur gültig, vier Zertifikate (PIDP Preprod CA, PIDP Demo CA, Deutschland PID-Signer Test CA 1-26-1 2026, Deutschland PID-Status-List-Signer Test CA 1-26-2 2026), der Dienst lädt alle vier.

```bash
cd ~/attack-sandbox
curl -fsSO https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/certificate.pem
curl -fsSO https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt
```

```bash
TL_DIR=~/attack-sandbox node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
import { compactVerify, importX509 } from "jose";
const dir = process.env.TL_DIR;
const key = await importX509(readFileSync(`${dir}/certificate.pem`, "utf8"), "ES256");
const { payload } = await compactVerify(readFileSync(`${dir}/pid-provider.jwt`, "utf8").trim(), key);
const list = JSON.parse(new TextDecoder().decode(payload));
const pems = new Set();
for (const entity of list.LoTE.TrustedEntitiesList)
  for (const service of entity.TrustedEntityServices)
    for (const cert of service.ServiceInformation.ServiceDigitalIdentity.X509Certificates ?? [])
      pems.add(`-----BEGIN CERTIFICATE-----\n${cert.val.match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`);
writeFileSync(`${dir}/issuer-anchors.pem`, [...pems].join(""));
console.log(`Signatur gültig, ${pems.size} Zertifikate nach issuer-anchors.pem geschrieben`);
'
```

Hinweis: Dem `certificate.pem` wird hier vertraut, weil es von derselben offiziellen HTTPS Adresse kommt. Eine unabhängige Bestätigung dieses Signierzertifikats ist in den öffentlichen Unterlagen nicht beschrieben.

### 2.6 Mandant anlegen

Der Befehl läuft ohne Entwicklungsschalter. Der API-Schlüssel erscheint genau einmal; sofort im Passwortmanager speichern. In der Datei steht nur sein SHA-256-Hash.

```bash
npm run cli -- tenant add --id attack-sandbox --name "Attack Sandbox" --profile pid_de --file ~/attack-sandbox/tenants.json
```

## 3. Weg A für den Sandbox Test: Cloudflare Tunnel vom Mac mini

Das iPhone muss Request URI und Response URI über öffentliches HTTPS erreichen [Q5]. Ein Cloudflare Tunnel gibt dem lokal laufenden Dienst eine öffentliche HTTPS Adresse, ohne Portfreigabe am Router.

```bash
brew install cloudflared
```

Wichtig: als Ziel `http://127.0.0.1:8080` angeben, nicht `localhost`. Der Dienst lauscht nur auf 127.0.0.1 (`ATTACK_HOST`, Vorgabe), und `localhost` kann auf dem Mac zuerst auf `::1` auflösen.

### 3.1 Quick Tunnel (sofort, ohne Konto)

```bash
cloudflared tunnel --url http://127.0.0.1:8080
```

`cloudflared` gibt eine Adresse unter `trycloudflare.com` aus. Laut Cloudflare [Q15]: keine Verfügbarkeitszusage, höchstens 200 gleichzeitige Anfragen, und die Adresse ändert sich bei jedem Start. Das Terminal offen lassen.

### 3.2 Benannter Tunnel (feste Adresse, eigene Domain bei Cloudflare)

Voraussetzung: die Domain ist bei Cloudflare angelegt und nutzt die Cloudflare Nameserver [Q16].

```bash
cloudflared tunnel login
cloudflared tunnel create attack-sandbox
```

`create` nennt die Tunnel UUID und den Pfad der Zugangsdatei im Verzeichnis `~/.cloudflared`. Dann `~/.cloudflared/config.yml` anlegen, nach dem Muster in [Q16]:

```yaml
url: http://127.0.0.1:8080
tunnel: <Tunnel-UUID>
credentials-file: /Users/<benutzer>/.cloudflared/<Tunnel-UUID>.json
```

```bash
cloudflared tunnel route dns attack-sandbox sandbox.<deine-domain>
cloudflared tunnel run attack-sandbox
cloudflared tunnel info attack-sandbox
```

### 3.3 Öffentliche Adresse in die Konfiguration des Dienstes

Request URI und Response URI bildet der Dienst aus `ATTACK_PUBLIC_BASE_URL`. Beim Quick Tunnel also erst den Tunnel starten, die ausgegebene Adresse übernehmen, dann den Dienst starten. Nach jedem Neustart des Quick Tunnels den Dienst mit der neuen Adresse neu starten; vorher erzeugte Prüfanfragen tragen die alte Adresse.

In einem zweiten Terminal, im Repository:

```bash
export NODE_ENV=production
export ATTACK_PUBLIC_BASE_URL=https://<adresse-aus-cloudflared>
export ATTACK_VERIFIER_KEY_PEM=$HOME/attack-sandbox/verifier-key.pem
export ATTACK_VERIFIER_CERT_CHAIN_PEM=$HOME/attack-sandbox/verifier-chain.pem
export ATTACK_ISSUER_TRUST_ANCHORS_PEM=$HOME/attack-sandbox/issuer-anchors.pem
export ATTACK_REGISTRATION_CERTIFICATE_FILE=$HOME/attack-sandbox/registration-certificate.json
export ATTACK_TENANTS_FILE=$HOME/attack-sandbox/tenants.json
npm run service
```

Erwartete Startmeldungen: `Mandantendatei: 1 aktiv, 0 gesperrt`, `Registrierungszertifikat geladen`, `Sperrquellen Aussteller-Kette: ocsp, Rückfall crl`. Die Meldung `Onboarding-Gate: NICHT aktiv` ist hier richtig: das Gate prüft Registrierungen von Mandanten, nicht das eigene Zugangszertifikat; das prüft die Wallet. Deshalb meldet `/ready` im Produktionsmodus `onboarding: failed`; Prüfanfragen funktionieren trotzdem.

Diagnose mit denselben Variablen. Im Produktionsmodus muss `ATTACK_DEV_MODE=false` ausdrücklich gesetzt sein, sonst bricht das CLI ab, weil es für die Diagnose standardmäßig den Entwicklungsschalter annimmt (am 07.10.2026 geprüft):

```bash
ATTACK_DEV_MODE=false npm run cli -- doctor
```

### 3.4 Prüfen, dass das iPhone die Adresse erreicht

Vom Mac:

```bash
curl -s "$ATTACK_PUBLIC_BASE_URL/live"
```

Erwartet: `{"ok":true,"status":"live","app":"attack-service"}`.

Vom iPhone: WLAN ausschalten, damit der Weg wirklich über das Internet geht, dann in Safari `https://<adresse>/live` öffnen. Erscheint dieselbe Antwort, erreicht das iPhone den Dienst.

## 4. Erster Durchlauf mit dem iPhone 🔒

### 4.1 Test PID in der Wallet

Nach [Q8]: Wallet öffnen, **Use simulated eID card** einschalten, **Get Started**, **Yes, ID card is available**, **Yes, card PIN is set and known**, **Agree by entering your card PIN**, eine beliebige sechsstellige PIN eingeben, dann die Wallet PIN setzen. Mit simulierter eID wird jede PIN angenommen. Eine PID reicht für 10 Präsentationen, danach neu ausstellen [Q8]. TestFlight auf automatische Updates stellen [Q8].

### 4.2 Prüfanfrage erzeugen

Lokal aufrufen, damit der API-Schlüssel nicht über den Tunnel läuft. Die Adressen in der Antwort kommen trotzdem aus `ATTACK_PUBLIC_BASE_URL`.

```bash
export ATTACK_API_KEY='<schlüssel aus 2.6>'
curl -s -X POST http://127.0.0.1:8080/v1/verification-requests -H "authorization: Bearer $ATTACK_API_KEY" > request.json
cat request.json
```

Prüfen, dass das Request Object öffentlich abrufbar ist:

```bash
curl -s -o /dev/null -w '%{http_code} %{content_type}\n' "$(node -p 'require("./request.json").requestObjectUri')"
```

Erwartet: `200 application/oauth-authz-req+jwt`.

### 4.3 QR Code anzeigen und scannen

```bash
brew install qrencode
qrencode -o wallet-qr.png "$(node -p 'require("./request.json").walletUrl')" && open wallet-qr.png
```

Mit der Kamera des iPhones scannen; der `openid4vp://` Link öffnet die Wallet. Das Request Object gilt 120 Sekunden ab Erzeugung (Abschnitt 8); dauert es länger, eine neue Prüfanfrage erzeugen. Der QR Code auf der Demo Flowseite (`npm run demo`) zeigt auf 127.0.0.1 und taugt nur für die lokale Demo.

### 4.4 In der Wallet bestätigen

Die Wallet zeigt den Anfragenden aus dem Zugangszertifikat und den Zweck aus dem Registrierungszertifikat [Q7]. Mit der Wallet PIN bestätigen.

### 4.5 Ergebnis abrufen

```bash
curl -s "http://127.0.0.1:8080/v1/verification-requests/$(node -p 'require("./request.json").sessionId')" -H "authorization: Bearer $ATTACK_API_KEY"
```

Erfolg: `"status":"completed"` mit `"valid":true` und den drei Claims. Ein fertiges Ergebnis bleibt 60 Sekunden abrufbar (`ATTACK_RESULT_TTL_SECONDS`, bis 3600). Für den Nachweis festhalten: Commit von Attack, Version der Wallet, Zeitpunkt, die Antwort ohne Claim Werte.

## 5. Fehlerbilder

| Beobachtung | Wahrscheinliche Ursache | Vorgehen |
|---|---|---|
| Start bricht ab: `ATTACK_PUBLIC_BASE_URL ist im Produktionsmodus Pflicht` | Variable fehlt | Abschnitt 3.3 |
| Start bricht ab: `Private-Key unbrauchbar` | Schlüssel nicht PKCS#8 | Abschnitt 2.2, Umwandlung |
| Start bricht ab: `ATTACK_REGISTRATION_CERTIFICATE_FILE: ...` | Datei fehlt, kein oder mehrere JWTs, abgelaufen | Datei aus dem Registrar neu laden |
| Prüfanfrage endet mit 500, im Log `http_request_failed` mit `error_type` `JarBuildError` | Schlüssel passt nicht zum Zertifikat oder Zertifikat selbstsigniert | Abschnitt 2.3, Abgleich |
| HTTP 401 | Schlüssel falsch, Mandant gesperrt, Dienst nach `tenant add` nicht neu gestartet | `npm run cli -- tenant list --file ...` |
| Wallet: "Validation Error: Could not trust certificate chain" | Zugangszertifikat fehlt im `x5c` [Q7] | `verifier-chain.pem` enthält nur das `.crt`? |
| Wallet zeigt keinen Zweck oder warnt vor "over-asking" | Registrierungszertifikat fehlt oder Claims weichen ab [Q7], [Q14] | Abschnitt 2.4 |
| Wallet lädt die Anfrage nicht | Tunnel weg, Adresse alt, Request Object älter als 120 s | Abschnitt 3.4, neue Prüfanfrage |
| Ergebnis `valid: false`, Code `issuer_*` | Aussteller nicht unter den Ankern | Abschnitt 2.5 |
| Ergebnis `valid: false`, Code `revocation_*` | CRL der D-Trust oder Bundesdruckerei nicht erreichbar oder abgelaufen | `curl -sI` auf die CRL Adresse aus dem Zertifikat |
| Ergebnis `valid: false`, Code `status_list_signature_invalid` | bekannte Lücke, Abschnitt 8 Punkt 1 | Code Änderung nötig |

Wallet Logs: im Menü der Wallet **Download Logs** [Q8]. Bekannte Fehler der iOS Wallet: [Issue Tracker iOS](https://github.com/german-national-wallet/issues-tracker-ios/issues) [Q8].

## 6. Weg B für einen echten Piloten: kleiner Linux Server mit Docker und Caddy

Beispiel: ein kleiner Cloud Server (etwa bei Hetzner) mit Ubuntu LTS, eine eigene Domain, Docker, und Caddy als TLS Proxy vor dem Dienst. Der Dienst selbst spricht nur HTTP; TLS gehört dem Proxy.

### 6.1 Server und DNS

* Server mit SSH Schlüssel anlegen, Firewall nur für 22, 80 und 443 öffnen.
* DNS: A Eintrag (und AAAA, falls IPv6) für `verifier.<domain>` auf die Server IP.
* Caddy holt das Zertifikat automatisch, wenn die DNS Einträge auf den Server zeigen, die Ports 80 und 443 von außen erreichbar sind und das Datenverzeichnis beschreibbar und dauerhaft ist [Q17].
* Docker Engine nach der offiziellen Anleitung installieren: <https://docs.docker.com/engine/install/ubuntu/>.

### 6.2 Dateien auf dem Server

Dieselben fünf Dateien wie in Abschnitt 2, aber für den Piloten: eigenes Zugangszertifikat, eigenes Registrierungszertifikat, Anker der produktiven Aussteller. Ablage unter `/opt/attack/secrets`, Rechte 600. Der Container läuft als Benutzer `node` mit UID 1000; die Dateien müssen für diese UID lesbar sein:

```bash
sudo chown -R 1000:1000 /opt/attack/secrets && sudo chmod 600 /opt/attack/secrets/*
```

Das Produktionsimage enthält kein CLI. Mandanten deshalb auf dem eigenen Rechner mit `npm run cli -- tenant add --file tenants.json` anlegen, die Datei per `scp` auf den Server kopieren und den Dienst neu starten.

### 6.3 Image und Start

```bash
git clone https://github.com/b6bs62fhys-jpg/attack-eudi-verifier.git /opt/attack/src
cd /opt/attack/src && docker build -t attack-verifier:pilot .
```

`/opt/attack/Caddyfile`:

```text
verifier.<domain> {
	reverse_proxy attack:8080
}
```

`/opt/attack/compose.yaml`:

```yaml
services:
  attack:
    image: attack-verifier:pilot
    restart: unless-stopped
    environment:
      NODE_ENV: production
      ATTACK_HOST: 0.0.0.0
      ATTACK_PUBLIC_BASE_URL: https://verifier.<domain>
      ATTACK_VERIFIER_KEY_PEM: /run/secrets/verifier-key.pem
      ATTACK_VERIFIER_CERT_CHAIN_PEM: /run/secrets/verifier-chain.pem
      ATTACK_ISSUER_TRUST_ANCHORS_PEM: /run/secrets/issuer-anchors.pem
      ATTACK_REGISTRATION_CERTIFICATE_FILE: /run/secrets/registration-certificate.json
      ATTACK_TENANTS_FILE: /run/secrets/tenants.json
    volumes:
      - /opt/attack/secrets:/run/secrets:ro
  caddy:
    image: caddy:2
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /opt/attack/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
volumes:
  caddy_data:
  caddy_config:
```

Der Dienst veröffentlicht keinen eigenen Port; erreichbar ist er nur über Caddy.

```bash
cd /opt/attack && docker compose up -d
curl -s https://verifier.<domain>/live
```

### 6.4 Hinweise für den Pilotbetrieb

* `/ready` meldet im Produktionsmodus `onboarding: failed`, solange das Onboarding Gate nicht aktiv ist. Als Healthcheck deshalb `/live` verwenden, wie im Dockerfile.
* Hinter Caddy (und hinter dem Tunnel) sieht der Dienst für alle öffentlichen Anfragen die Adresse des Proxys. Die öffentliche Ratenbegrenzung (Vorgabe 120 Anfragen je 60 Sekunden und IP) gilt dann für alle Wallets zusammen. Für einen Piloten mit vielen gleichzeitigen Nutzern `ATTACK_RATE_LIMIT_PUBLIC_PER_WINDOW` erhöhen.
* Ergebnisse, Sitzungen und Audit Log liegen nur im Arbeitsspeicher; ein Neustart löscht sie.
* Für den Produktivbetrieb des Ökosystems gelten andere Regeln als in der Sandbox: deutsche juristische Person [Q11], Legitimation beim Registrar über das ELSTER Zertifikat der Organisation [Q18]. Wer sich registriert, hängt an Abschnitt 7.

## 7. Offene Frage für echte Piloten: registriert sich die Relying Party selbst oder Attack als Dienstleister?

### 7.1 Fundstellen in der offiziellen Dokumentation

1. Developer Guide, "Joining the Ecosystem" [Q1]: Teilnehmen darf auch, wer "a service provider actively serving or expecting to serve organizations registered in Germany" ist. Für die Sandbox ist Attack als Dienstleister also zulässig.
2. Developer Guide, "Relying Party Technical Integration" [Q11]: Die Verifier Komponente kann von "a commercial service provider" kommen. Eine in Deutschland registrierte juristische Person ist für die Produktion Pflicht, nicht für die Sandbox.
3. Developer Guide, Konzeptseite "Access Certificate" (Entwurf) [Q18]: Das Zugangszertifikat stellt der Registrar nach einer Legitimation der Organisation über ihr ELSTER Zertifikat aus; das Schlüsselpaar erzeugt die Organisation selbst.
4. Architekturkonzept, "Wallet-Relying Party Authentication" [Q19], Abschnitt "Verifier-as-a-Service": Die vorgelegten Zertifikate müssen der Relying Party gehören, nicht dem Dienstleister; die Relying Party muss den Dienstleister offenlegen, etwa in der Datenschutzerklärung; und: "The service provider may use their own Access Certificate with delegation".
5. Derselbe Text, Abschnitt "Intermediaries" [Q19]: Der Intermediär nutzt sein eigenes Zugangszertifikat; das Registrierungszertifikat nennt Relying Party und Intermediär; die Wallet zeigt beide an; der Widerruf eines der beiden Zertifikate beendet die Beziehung.
6. Architekturkonzept, "Over-asking protection" [Q20]: Der Registrar prüft die Identität der Relying Party "including an optional intermediary".

### 7.2 Der Widerspruch

Fundstelle 4 verlangt im ersten Punkt Zertifikate der Relying Party und erlaubt im dritten Punkt dem Dienstleister ein eigenes Zugangszertifikat "with delegation". Fundstelle 5 lässt den Intermediär ohne Einschränkung sein eigenes Zugangszertifikat verwenden. Wie "delegation" technisch aussieht, ist in den gefundenen Unterlagen nicht beschrieben. Ob "Verifier-as-a-Service" und "Intermediary" zwei verschiedene Rollen sind oder dieselbe, sagt der Text nicht.

### 7.3 Folgen für Attack

| | Relying Party registriert sich selbst | Attack registriert sich als Intermediär |
|---|---|---|
| Zugangszertifikat | gehört der Relying Party; Schlüsselpaar erzeugt sie [Q18]. Attack braucht ihren privaten Schlüssel, um in ihrem Namen zu signieren, oder sie muss selbst signieren | Attack nutzt sein eigenes [Q19] |
| Registrierungszertifikat | auf die Relying Party ausgestellt | nennt Relying Party und Attack [Q19] |
| Anzeige in der Wallet | Relying Party | beide [Q19] |
| Code in Attack heute | eine Identität und ein Registrierungszertifikat für den ganzen Dienst. Nötig wäre beides je Mandant | eigenes Zugangszertifikat passt. Nötig wäre ein Registrierungszertifikat je Mandant |
| Widerruf | betrifft nur diese Relying Party | Widerruf des Attack Zertifikats trifft alle Mandanten [Q19] |

### 7.4 Haftung

In den gefundenen offiziellen Unterlagen ist die Haftung zwischen Relying Party und Dienstleister nicht geregelt. Die Nutzungsbedingungen der Sandbox regeln nur das Verhältnis zwischen SPRIND und dem Teilnehmer: Risiko beim Teilnehmer [Q4, Nr. 1.3 und 4.4], Haftung von SPRIND begrenzt [Q4, Nr. 7], Freistellung von SPRIND durch den Teilnehmer [Q4, Nr. 8]. Der Text der eIDAS Verordnung selbst wurde für dieses Runbook nicht ausgewertet. Das gehört vor einem Piloten in eine anwaltliche Prüfung und als Frage an SPRIND.

### 7.5 Fragen an SPRIND

1. Kann sich Attack als Intermediär registrieren und für jede Relying Party ein eigenes Registrierungszertifikat erhalten, das beide nennt?
2. Was bedeutet "with delegation" in "Verifier-as-a-Service", und wie wird die Delegation nachgewiesen?
3. Gilt in der Produktion die Legitimation über ELSTER für die Relying Party, für den Intermediär oder für beide?

## 8. Bekannte Lücken, die erst der echte Durchlauf zeigt

1. **Statuslisten Unterzeichner.** Attack nimmt eine Statusliste nur an, wenn ihr Unterzeichner Zertifikat Byte für Byte einem der Aussteller Anker entspricht. Die Vertrauensliste enthält für Statuslisten eine CA ("Deutschland PID-Status-List-Signer Test CA 1-26-2 2026") [Q10], also vermutlich ein darunter ausgestelltes Blattzertifikat als Unterzeichner. Trägt die Test PID einen Status Eintrag, endet die Prüfung dann mit `status_list_signature_invalid`. Behebung: Kettenprüfung für Statuslisten Unterzeichner. Nicht gebaut.
2. **`redirect_uri` nach `direct_post`.** Der Entwurf [Q5] 1.3.3 verlangt eine Antwort mit `redirect_uri`. Attack sendet keine. Für den ersten Test deshalb den Weg über den QR Code auf einem zweiten Gerät nehmen. Ob die Wallet ohne `redirect_uri` abschließt, ist offen.
3. **Gültigkeit des Request Objects.** Attack setzt `exp` auf 120 Sekunden nach Erzeugung. Der Entwurf [Q5] 1.3 empfiehlt 5 bis 10 Minuten, die Referenzimplementierung nutzt eine Stunde [Q12].
4. **Content-Type des Request Objects.** Attack liefert `application/oauth-authz-req+jwt` nach RFC 9101. Das Beispiel im Entwurf [Q5] 1.1 zeigt `application/json` und nennt sich selbst "illustrative".
5. **Format im Credential Request.** Siehe Abschnitt 2.4: `vc+sd-jwt` im Beispiel des Registrars, `dc+sd-jwt` in der Anfrage.
6. **Aufbau von `registration-certificate.json`.** Öffentlich nicht beschrieben; der Lader ist darauf ausgelegt, siehe Abschnitt 2.4.
7. **mdoc.** Nicht unterstützt.
8. **Aussteller Kette der echten PID.** Gegen eine echte PID ist Attack noch nie gelaufen. Welche CA die Sandbox PID tatsächlich signiert und ob ihre Blattzertifikate eine Sperradresse tragen, zeigt erst der Durchlauf.

## 9. Quellen

Developer Guide: Quelltext im Repository <https://gitlab.opencode.de/bmi/eudi-wallet/developer-guide>, Stand Commit `a584ab4e` vom 05.10.2026; veröffentlicht unter <https://bmi.usercontent.opencode.de/eudi-wallet/developer-guide/>. Seiten mit `draft: true` oder `unlisted: true` sind als Entwurf markiert.

| Kürzel | Quelle |
|---|---|
| Q1 | Developer Guide, `docs/sandbox/onboarding/joining.md` ("Joining the Ecosystem") |
| Q2 | Developer Guide, `docs/sandbox/onboarding/onboarding.md` ("Next Steps After the Kick-off Call") |
| Q3 | Developer Guide, `docs/sandbox/onboarding/sandbox_readiness_checklist.md` |
| Q4 | Developer Guide, `docs/sandbox/legal/sandbox_t&c.md` (SPRIND EUDI-Wallet Sandbox Nutzungsbedingungen, letzte Aktualisierung 22.01.2026) |
| Q5 | Developer Guide, `docs/rp/guide/dev/pid/online_flow.md` ("Presenting a PID online (SD-JWT)", Entwurf) |
| Q6 | Developer Guide, `docs/rp/guide/dev/client_id.md` ("Calculating the client_id", Entwurf) |
| Q7 | Developer Guide, `docs/rp/guide/presentation/registrar_certificate_usage.md` ("Using Registrar Certificates in Presentation Requests") |
| Q8 | Developer Guide, `docs/sandbox/onboarding/wallet_use_instructions.md` |
| Q9 | Developer Guide, `docs/rp/guide/presentation/pid_presentation.md` |
| Q10 | Sandbox Vertrauenslisten, <https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/>, erzeugt 06.10.2026, abgerufen 07.10.2026 |
| Q11 | Developer Guide, `docs/rp/onboarding/rp_highlevel_onboarding.md` ("Relying Party Technical Integration") |
| Q12 | EUDIPLO, Referenzimplementierung, die der EUDI Playground aus Q5 verwendet: <https://github.com/openwallet-foundation-labs/eudiplo>, `apps/backend/src/verifier/oid4vp/oid4vp.service.ts`, Stand Commit `1a0c2fa` vom 07.10.2026 |
| Q13 | Developer Guide, `docs/sandbox/alpha/access-certificates.md` (nicht verlinkt) |
| Q14 | Developer Guide, `docs/sandbox/alpha/registration-certificates.md` (nicht verlinkt) |
| Q15 | Cloudflare, Quick Tunnels: <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/>, abgerufen 07.10.2026 |
| Q16 | Cloudflare, lokal verwalteter Tunnel: <https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/create-local-tunnel/>, abgerufen 07.10.2026 |
| Q17 | Caddy, Automatic HTTPS: <https://caddyserver.com/docs/automatic-https>, abgerufen 07.10.2026 |
| Q18 | Developer Guide, `docs/concepts/access-certificate.md` (Entwurf, Version 1.0 vom 08.07.2026) |
| Q19 | Architekturkonzept, <https://gitlab.opencode.de/bmi/eudi-wallet/eidas-2.0-architekturkonzept>, Version 2.13.0 vom 15.09.2026, `architecture-proposal/content/ecosystem-concepts/trust/wallet-relying-party-authentication.md` |
| Q20 | Architekturkonzept, ebenda, `architecture-proposal/content/ecosystem-concepts/trust/overasking-protection.md` |
