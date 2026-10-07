# Interoperabilitäts-Testmatrix

Diese Dokumentation erfasst die lokalen Interoperabilitätsprüfungen vom
27. September 2026. Verwendet wurden ausschließlich lokale Demo-Credentials
und synthetisches Testmaterial. Es wurden keine produktiven Wallets,
produktiven Aussteller oder echten Relying-Party-Zertifikate verwendet.

## Umfang und Baseline

Die eigene Testsuite des Attack-Verifiers ist die Baseline für den Parent-
Dienst. Sie deckt signierte Request Objects, `direct_post`,
`direct_post.jwt`, SD-JWT/KB-JWT und Mock-Wallet-Flows ab. Die beiden
Referenzsysteme haben jedoch keinen kompatiblen Backend-Vertrag mit Attack.
Ein direkter Cross-Projekt-Lauf benötigt daher einen Adapter, der nicht Teil
dieses Repositories ist.

Attack stellt bereit:

- `POST /v1/verification-requests`
- `GET /v1/verification-requests/{id}/request-object`
- `POST /direct_post`

`test/eudi-verify` erwartet dagegen `/sessions`, `/request/{id}`,
`/callback` und `/tokens/verify`. `test/miEUDIverifier` erwartet
`/ui/presentations` sowie ein anderes Verifier-Backend. Das ist eine
Schnittstellenabweichung und kein Nachweis für einen Fehler im Verifier.

## Matrix

| Referenzsystem | Lokaler Flow | Ergebnis | Einordnung |
|---|---|---|---|
| `test/eudi-verify` | Unit-/Integrationssuite | **Bestanden: 203 Tests** | Lokaler Mock-/Demo-Flow funktioniert |
| `test/eudi-verify` | Lokaler Server: Session, PAR, Request Object, JWS-Prüfung, verschlüsselter Callback | **Teilweise**: Session und Callback HTTP-erfolgreich; finale Prüfung fehlgeschlagen | Testdaten-/Protokollformat-Mismatch im mitgelieferten E2E-Skript |
| `test/eudi-verify` | Direkte Attack-Backend-Integration | **Nicht direkt ausführbar** | API-Vertrag weicht ab; Adapter erforderlich |
| `test/miEUDIverifier` | Release-Build | **Bestanden: 0 Warnungen, 0 Fehler** | Build funktioniert lokal |
| `test/miEUDIverifier` | .NET-Testsuite | **Blockiert** | .NET-8-Runtime fehlt; lokal ist nur .NET 10 vorhanden |
| `test/miEUDIverifier` | Wallet-Präsentation | **Blockiert** | PID-Wallet, erreichbares Backend und Ökosystem-Zertifikate fehlen |
| `test/miEUDIverifier` | Direkte Attack-Backend-Integration | **Nicht direkt ausführbar** | Anderes Backend und anderes Session-Modell |

## `test/eudi-verify`

Die lokale Suite des Projekts bestand mit 203 Tests. Der Demo-Server nahm
außerdem Session-Erstellung und verschlüsselten Callback an und lieferte ein
signiertes Request Object. Das mitgelieferte Skript
`examples/server/eudi-verify-e2e.ts` scheiterte danach mit:

```text
Invalid base64url character in vp_token/apu
```

Die Anfrage forderte ein `mso_mdoc`-Credential
(`org.iso.18013.5.1.mDL`), während das Skript eine SD-JWT-Präsentation baut
und nicht das zur Query passende mdoc liefert. Das ist ein
Test-Harness-/Testdaten-Mismatch und kein nachgewiesener Fehler im Attack-
Verifier. Zusätzlich beendet sich das Skript trotz `RESULT: FAILED` mit Exit
Code 0. Dieser Exit Code darf daher nicht als erfolgreicher Interop-Test
gewertet werden.

Mock-Engines und ein Demo-Wallet sind vorhanden. Sie prüfen Protokoll- und
Handler-Verhalten, begründen aber kein Vertrauen eines produktiven Wallets.
Ein echter Wallet-Lauf bleibt von Zertifikaten und Wallet-Credentials
abhängig.

## `test/miEUDIverifier`

Die .NET-Solution wurde im Release-Modus erfolgreich gebaut. Die Testausführung
startete nicht, weil Microsoft.NETCore.App 8.0 fehlt:

```text
Framework: Microsoft.NETCore.App, version 8.0.0
Vorhanden: 10.0.12
```

Die Dokumentation des Referenzsystems verlangt ein EUDI-Wallet mit PID. Für
den deutschen Pfad werden zusätzlich SPRIND-RP-Access- und
Registrierungszertifikat sowie passende PKCS#12-Konfiguration benötigt. Diese
fehlenden Test-Credentials sind kein Codefehler im Attack-Verifier.

## Zertifikats- und Trust-Blocker

Folgende Ergebnisse sind ausdrücklich durch fehlendes echtes Material
blockiert:

- Trust eines Verifier-Identitätszertifikats durch ein produktives Wallet;
- Issuer-Chain-Ankerung einer echten PID;
- deutsche Relying-Party-Access- und Registrierungszertifikate;
- echte Wallet-Präsentation gegen eines der Referenzsysteme;
- Ausführung des .NET-8-Testhosts auf dieser Maschine.

Synthetische Zertifikate und Mock-Wallets können lokale Parser- und
Protokollpfade prüfen, aber keine produktive Trust-List-Interoperabilität
beweisen.

## Gefundene Probleme

1. **Format-Mismatch im Referenz-E2E-Harness, Schweregrad: Testblocker.**
   `test/eudi-verify/examples/server/eudi-verify-e2e.ts` sendet eine SD-JWT-
   Präsentation für eine `mso_mdoc`-Query und meldet `RESULT: FAILED`, liefert
   aber Exit Code 0. Das Referenz-Harness muss vor einer automatischen
   Interop-Gate-Nutzung korrigiert werden. Es wurde nicht geändert.
2. **.NET-Testumgebung des Referenzsystems, Schweregrad: Umgebung.**
   `test/miEUDIverifier` zielt auf .NET 8, das lokal fehlt. Vor Ausführung der
   Suite kann kein Anwendungsfehler abgeleitet werden.

Es wurde kein echter Fehler im übergeordneten Attack-Verifier nachgewiesen.
