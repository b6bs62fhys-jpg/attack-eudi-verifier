# Gegenstelle: walt.id wallet-api2 gegen den Attack Verifier

Stand: 08.10.2026. Dieses Dokument beschreibt einen lokalen Durchlauf mit einer
quelloffenen Fremd-Wallet. **Es ist kein Sandbox-Nachweis.** Die deutsche
Sandbox-Wallet, die deutsche Test-PID, die Sandbox-Zertifikate und TLS sind darin
nicht enthalten. Der Durchlauf zeigt, dass zwei unabhängige Implementierungen des
OpenID4VP-Ablaufs miteinander arbeiten, und er hat einen echten Fehler in Attack
aufgedeckt.

## Was verwendet wurde

| Teil | Stand |
|---|---|
| Wallet | `waltid/wallet-api2:latest`, Image-Digest `sha256:d5fab1868802c98a28ce2ccee5ac6cc282f0b3a7ad079382ed42934296b700b5`, meldet "walt.id wallet 1.1.1", Architektur arm64, Quelle <https://github.com/walt-id/waltid-identity> (Commit `6de00f6` vom 07.10.2026) |
| Dienst | Attack im Docker-Image dieses Repositorys, Entwicklungsbetrieb |
| Umgebung | Colima, beide Container im selben Docker-Netz, Wallet und Dienst sprechen über `http://attack:8080` |
| Material | nur Test-Schlüssel und Test-Zertifikate, erzeugt vom Skript `tools/interop-waltid.ts` |

Entwicklungsbetrieb heißt: `ATTACK_DEV_MODE=true` und `ATTACK_ALLOW_SELF_SIGNED=true`,
das Verifier-Zertifikat ist selbstsigniert, Sperr- und Statusprüfung sind aus, die
Adressen sind `http`. Die Wallet bekommt das Verifier-Zertifikat des Testlaufs als
Vertrauensanker für `x509_hash` (`clientIdTrust.x509TrustAnchors` in
`wallet-service.conf`); ohne Anker lehnt sie `x509_hash` ab.

## Was lief

Vier Durchläufe, jeder mit einem frischen Wallet-Konto, einem Halterschlüssel und
einem Test-Credential, das der Dienst über seinen Anker kennt:

| Profil | Credential | Ergebnis |
|---|---|---|
| `pid_basis` | `given_name`, `birth_date` (dazu nicht angefragte `family_name`, `age_over_18`) | angenommen, im Ergebnis genau `given_name` und `birth_date` |
| `age_over_18` | flacher Claim `age_over_18` | angenommen, im Ergebnis genau `age_over_18: true` |
| `age_over_18_de` | Objekt `age_equal_or_over`, jede Schwelle einzeln offenlegbar | angenommen; die Wallet legte nur Schwelle 18 offen, im Ergebnis `age_equal_or_over.18: true` |
| `age_over_18` und `age_over_18_de`, unter 18 | Schwelle 18 ist `false` | `valid: false`, `age_requirement_not_met`, abgeschlossenes Ergebnis ohne Claim-Wert |

Mit zusätzlich gesetzten Optionen lief ein fünfter Durchlauf (`pid_basis`):
`ATTACK_REGISTRATION_CERTIFICATE_FILE`, `ATTACK_REDIRECT_URI` und
`ATTACK_REQUEST_OBJECT_TTL_SECONDS=300`. Angenommen. Die Wallet übernahm das
`redirect_uri` der Antwort in ihr Feld `redirect_to`. Das Request Object mit 300
Sekunden Gültigkeit (eigener Signierpfad) hat die Wallet ebenfalls verarbeitet.

Damit ist belegt, dass die Wallet unser Request Object über `request_uri` mit
`request_uri_method=get` abholt, die `x509_hash` Client-ID samt `x5c` prüft,
unsere DCQL-Abfrage (flache und verschachtelte Pfade) versteht, ihre Antwort mit
unserem Schlüssel per `direct_post.jwt` (ECDH-ES) verschlüsselt und dass unser
Dienst Entschlüsselung, Signaturen, Key Binding und die neuen Strukturprüfungen
dieser Antwort besteht.

## Was der Durchlauf aufgedeckt hat

**Fehler in Attack, behoben.** Der Verschlüsselungsschlüssel im `client_metadata.jwks`
trug `"key_ops": []` und `"ext": true`, Reste des WebCrypto-Exports. Ein leeres
`key_ops` heißt nach RFC 7517, dass keine Operation erlaubt ist. Die Wallet lehnte
die Anfrage ab, nachdem sie Signatur und Vertrauensanker bereits akzeptiert hatte:
"client_metadata.jwks must contain an encryption key with alg=ECDH-ES". Der Schlüssel
trägt jetzt nur `kty`, `crv`, `x`, `y`, `alg`, `use` und `kid`; ein Test sichert das.
Die offizielle Beispielanfrage der Developer-Doku enthält ebenfalls nur `kty`, `crv`,
`x`, `y`, `alg` und `kid`. Ob die deutsche Sandbox-Wallet mit dem alten Schlüssel
dasselbe getan hätte, ist nicht bekannt.

**Beobachtung zur deutschen Altersschwelle.** Eine erste Testform, bei der das ganze
Objekt `age_equal_or_over` eine einzige Offenlegung war, legte die walt.id Wallet für
den Pfad `["age_equal_or_over", "18"]` gar nicht offen; unser Dienst lehnte die
Präsentation ohne Offenlegung ab (`presentation_invalid`). Mit einem Objekt, dessen
Schwellen einzeln offenlegbar sind (eigenes `_sd`), legte die Wallet genau Schwelle 18
offen. Wie die echte Sandbox-PID die Schwellen verpackt, ist öffentlich nicht
beschrieben. Die Vorlage `age_over_18_de` ist damit nur für die einzeln offenlegbare
Form gegen eine Fremd-Wallet gelaufen.

## Was nicht geprüft wurde

* Die deutsche Sandbox-Wallet, die Sandbox-Zertifikate, die Test-PID der Sandbox.
* TLS. Alle Adressen waren `http` im Docker-Netz.
* Das Produktionsverhalten: Sperrprüfung (OCSP und CRL), Statuslisten, Vertrauensanker
  aus der Sandbox-Vertrauensliste. Im Entwicklungsbetrieb sind sie aus.
* `verifier_info` mit einem echten Registrierungszertifikat. Die Wallet nahm den Eintrag
  mit einem selbst gebauten JWT ohne Beanstandung an; ihre Vorschau (`preview`) zeigte
  dazu aber keine Verifier-Angaben. Ob sie den Inhalt auswertet, ist damit nicht
  gezeigt.
* mdoc, Same-Device-Ablauf mit echtem App-Wechsel, Ablehnung durch den Nutzer in der
  Wallet.
* Lastverhalten und mehrere Wallets gleichzeitig.

## Nachstellen

Voraussetzungen: Docker (etwa über Colima), Node.js 22, dieses Repository mit
`npm ci`. Im Repository:

```bash
docker build -t attack:interop .
docker pull waltid/wallet-api2:latest
IM=$HOME/.attack-interop
node --experimental-strip-types tools/interop-waltid.ts $IM prepare
docker network create interop-net
docker run -d --name waltid-w2 --network interop-net -p 7006:7006 \
  -v "$IM/wallet-service.conf:/waltid-wallet-api2/config/wallet-service.conf:ro" \
  waltid/wallet-api2:latest
docker run -d --name attack-interop --network interop-net --network-alias attack -p 18090:8080 \
  -e NODE_ENV=development -e ATTACK_DEV_MODE=true -e ATTACK_ALLOW_SELF_SIGNED=true \
  -e ATTACK_PUBLIC_BASE_URL=http://attack:8080 \
  -e ATTACK_ISSUER_TRUST_ANCHORS_PEM=/interop/issuer-anchors.pem \
  -e ATTACK_VERIFIER_KEY_PEM=/interop/verifier-key.pem \
  -e ATTACK_VERIFIER_CERT_CHAIN_PEM=/interop/verifier-chain.pem \
  -e ATTACK_TENANTS_FILE=/interop/tenants.json \
  -v "$IM:/interop:ro" attack:interop
PROFILE=pid_basis node --experimental-strip-types tools/interop-waltid.ts $IM run
```

`PROFILE` ist `pid_basis`, `age_over_18` oder `age_over_18_de`; `UNDER18=1` setzt die
Schwelle 18 im Credential auf `false`. Das Skript gibt jeden Schritt mit Status und
gekürzter Antwort aus und endet mit Exit-Code 0, wenn der Dienst die Präsentation
angenommen hat.

Warum die Container im selben Netz laufen: Aus dem Container ließ sich der Mac nicht
erreichen (Verbindungen in ein Zeitlimit), deshalb stehen beide Dienste im Docker-Netz
und das Skript spricht sie über veröffentlichte Ports an.
