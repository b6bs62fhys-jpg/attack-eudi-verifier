# Interoperabilitätsmatrix

Dieses Dokument beschreibt, welche Protokollmerkmale der Dienst im Code
umsetzt, womit er getestet wurde und womit nicht. Jede Zeile nennt die Stelle
im Code und den zugehörigen Test. Was im Code nicht belegt ist, steht als
**nicht implementiert** oder **nicht nachgewiesen** in der Tabelle, nicht als
„geplant“.

Das Dokument ist **kein Konformitätsnachweis** und **kein Nachweis einer
Interoperabilität mit einer echten Wallet**. Ein solcher Nachweis liegt nicht
vor (siehe [eIDAS und ARF Zuordnung](eidas-arf-konformitaet.md), Zeile
„Offizieller ARF-/eIDAS-Konformitätsnachweis“).

## Teststand in einem Satz

Der Dienst wurde Ende zu Ende ausschließlich gegen die Mock-Wallet dieses
Repositorys getestet, mit TEST-Schlüsseln und TEST-Credentials, die im
Arbeitsspeicher erzeugt werden. Mit einer echten Wallet, einer Sandbox oder
einer nationalen Wallet wurde er noch nicht getestet.

| Gegenstelle | Ende zu Ende mit diesem Dienst getestet? | Beleg |
|---|---|---|
| Mock-Wallet dieses Repositorys (`src/decision-test/mock-wallet.ts`) | **Ja**, automatisiert. Anfrage anlegen, signiertes Request Object abrufen, Präsentation über `POST /direct_post`, Ergebnis abrufen, löschen, alles über HTTP gegen den echten Dienst. | `src/service/e2e-vollablauf.test.ts`, `src/service/service.test.ts` („End-to-End mit Mock-Wallet“), Demo `src/demo/scenario-runner.ts` |
| walt.id verifier-api2 | **Nein.** Als möglicher Baustein bewertet, siehe [Abschnitt 3](#3-bewertung-fremder-implementierungen). Dabei lief eine eigene Test-Wallet gegen walt.id, nicht gegen diesen Dienst. | `test/ERGEBNIS.md`, `test/waltid/evidence/waltid-run.txt` |
| eudi-verify | **Nein.** Als möglicher Baustein bewertet. Das Kit baut auf `@openeudi/openid4vp` auf; dieselbe Bibliothek ist der Protokollkern dieses Dienstes. Daraus folgt kein Interop-Nachweis für diesen Dienst. | `test/ERGEBNIS.md` (das Lauf-Protokoll ist nicht im Repository) |
| miEUDIverifier | **Nein.** Als möglicher Baustein bewertet und verworfen. | `test/ERGEBNIS.md`, `test/evidence/mieudi-verify.txt` |
| Deutsche EUDI-Wallet, SPRIND-Sandbox oder eine andere Sandbox | **Nein.** Ein Sandbox-Zugang liegt nicht vor. | keiner |
| Andere echte Wallet (Referenz-Wallet, nationale Wallet in Produktion) | **Nein.** | keiner |

## 1. Protokoll und Formate

Die eingesetzte OpenID4VP-Bibliothek ist `@openeudi/openid4vp` in Version
0.11.1 (`package.json`).

| Merkmal | Status | Beleg im Code | Test |
|---|---|---|---|
| OpenID4VP | implementiert | `@openeudi/openid4vp`, importiert in `src/service/service.ts` | `src/decision-test/decision.test.ts` |
| Response Mode `direct_post` | implementiert | Route `POST /direct_post` in `src/service/app.ts` | `src/service/direct-post-interop.test.ts` |
| Response Mode `direct_post.jwt` | implementiert | `src/onboarding/jar.ts`; Verarbeitung in `VerifierService.handleEncryptedPresentation` (`src/service/service.ts`) | `src/service/fehlerbilder.test.ts` |
| Signiertes Request Object (JAR) | implementiert | `src/onboarding/jar.ts`; `createSignedAuthorizationRequest` der Bibliothek in `src/service/service.ts` | `src/service/jar-parity.test.ts`, `src/decision-test/decision.test.ts` |
| Verschlüsselte Antwort (JWE) | implementiert | `handleEncryptedPresentation` in `src/service/service.ts` | `src/service/fehlerbilder.test.ts` |
| JWE `enc` Werte | implementiert | `A128GCM` und `A256GCM` (`DEFAULT_SUPPORTED_ENC_VALUES` in `src/onboarding/jar.ts`) | `src/service/jar-parity.test.ts` |
| JWE `alg` Wert | implementiert | `ECDH-ES` (`publicJwk.alg` in `src/service/service.ts`), frisches Schlüsselpaar je Sitzung | `src/service/jar-parity.test.ts` |
| Antwort als Form-Post | implementiert | `application/x-www-form-urlencoded`, `parseFormDirectPost` in `src/service/app.ts` | `src/service/direct-post-interop.test.ts` |
| DCQL | implementiert | `buildHaipQuery` der Bibliothek in `src/service/service.ts` | `src/decision-test/sd-jwt-nachweis.test.ts` |
| HAIP | teilweise | Query über `buildHaipQuery`; ein `HaipValidationError` wird auf `query_invalid` abgebildet (`presentationErrorCode` in `src/service/limits.ts`). Ein externer HAIP-Konformitätslauf fehlt. | `src/decision-test/decision.test.ts` |
| SD-JWT VC | implementiert | Format `dc+sd-jwt`; Prüfung über `verifyAuthorizationResponse` der Bibliothek in `src/service/service.ts` | `src/decision-test/sd-jwt-nachweis.test.ts` |
| Key Binding (KB-JWT) | teilweise | über die Bibliothek; die [eIDAS und ARF Zuordnung](eidas-arf-konformitaet.md) führt „VP-/SD-JWT-Validierung und Key Binding“ als „Teilweise erfüllt“ | `src/decision-test/` |
| Nur angefragte Claims im Ergebnis | implementiert | `nurAngefragteClaims` in `src/service/profile.ts` | `src/service/e2e-vollablauf.test.ts` („ein nicht angefragter Klartext-Claim aus dem Issuer-JWT landet nicht im Ergebnis“) |
| Replay-Schutz | implementiert | `session_reused` in `src/lib/session.ts` | `src/service/fehlerbilder.test.ts` |
| mdoc (`mso_mdoc`) | **nicht implementiert** | Kein mdoc-Pfad im Produktivcode. Anfragen und Präsentationen laufen nur im Format `dc+sd-jwt`. | **kein Test** |
| Credential Sets (Auswahl zwischen mehreren Nachweisen) | **nicht implementiert** | Die installierte Bibliotheksversion 0.11.1 bietet `buildCredentialSetQuery` nicht an. | **kein Test** |

## 2. Vertrauen und Sperrprüfung

| Merkmal | Status | Beleg im Code | Test |
|---|---|---|---|
| Aussteller-Vertrauensanker | implementiert | `loadIssuerTrustAnchorsPem` in `src/service/issuer-anchors.ts`; Start bricht bei fehlender, leerer oder unbrauchbarer Datei ab | `src/service/aussteller-anker.test.ts` |
| Vertrauensanker zur Laufzeit leer | implementiert | Ablehnung mit `issuer_trust_anchors_empty` in `src/service/service.ts` | `src/service/aussteller-anker.test.ts` |
| Verifier-Identität und Zertifikatskette | implementiert | `loadVerifierIdentity` und `resolveVerifierIdentity` in `src/service/verifier-identity.ts`; ohne Material bricht der Start in Produktion ab | `src/service/produktionsschalter.test.ts` |
| OCSP für die Ausstellerkette | implementiert | `OcspRevocationChecker` in `src/onboarding/ocsp-revocation.ts`, beim Start verdrahtet in `src/service/bootstrap.ts`. Getestet nur gegen einen lokalen Test-Responder, nicht gegen einen produktiven. | `src/onboarding/ocsp-revocation.test.ts`, `src/service/issuer-revocation.test.ts` |
| CRL | implementiert, **im Dienststart nicht verdrahtet** | `CrlRevocationChecker` in `src/onboarding/crl-revocation.ts`. `bootstrapService` setzt ihn nirgends ein; das Onboarding-Gate erhält im Produktionsbetrieb den OCSP-Prüfer. | `src/onboarding/revocation-fail-closed.test.ts` |
| Token Status List | implementiert | `TokenStatusListChecker` in `src/service/credential-status.ts`, verdrahtet in `src/service/bootstrap.ts`. Mit `ATTACK_DEV_MODE=true` abgeschaltet. Gegen echte Status-List-Aussteller nicht erprobt. | `src/service/credential-status.test.ts` |
| Trust List | **nur Testform** | `TrustListMonitor` in `src/trustlist/monitor.ts` prüft eine JWS-signierte Liste im eigenen Testformat (`trust-list+jwt.test`). Genutzt in Tests und in der Demo, im Dienststart nicht verdrahtet. | `src/trustlist/trustlist.test.ts` |
| LOTL (List of Trusted Lists nach ETSI TS 119 612) | **nicht implementiert** | Keine Verarbeitung im Produktivcode. Geprüft wird nur, was als Anker konfiguriert ist. | **kein Test** |
| WRPAC und WRPRC | teilweise | `src/onboarding/wrpac.ts`, `src/onboarding/wrprc.ts`, `resolveOnboardingGate` in `src/onboarding/onboarding-wiring.ts`. Das Gate ist nur aktiv, wenn `ATTACK_ONBOARDING_ACCESS_CA_PEM` und `ATTACK_ONBOARDING_WRPRC_ISSUER_PEM` gesetzt sind. Im Produktionsbetrieb ohne Gate meldet `/ready` `onboarding: failed` (`src/service/run.ts`). Echte Registrar- und Access-CA-Profile fehlen. | `src/onboarding/onboarding.test.ts`, `src/onboarding/onboarding-gate-hardening.test.ts`, `src/service/onboarding-gate.test.ts` |
| Registrar-Anbindung | **nicht implementiert** | Der Client in `src/onboarding/registrar.ts` existiert, wird aber nicht verdrahtet (siehe `registrar_*` in [Fehlercodes](fehlercodes.md)). | **kein Test** im Dienstablauf |

## 3. Bewertung fremder Implementierungen

Drei quelloffene Verifier wurden als mögliche Bausteine für den Kern dieses
Dienstes bewertet. **Keiner dieser Läufe hat diesen Dienst getestet.** Geprüft
wurde jeweils die fremde Implementierung gegen die Anforderung „startet lokal,
erzeugt ein signiertes Request Object mit DCQL für SD-JWT VC, validiert einen
Test-`vp_token`“. Die Quelltexte der drei Projekte liegen nicht in diesem
Repository.

| Projekt | Ergebnis der Bewertung | Vertrauensanker im Testlauf | Beleg |
|---|---|---|---|
| walt.id verifier-api2 (Release v1.0.0, Docker) | bestanden: Request Object mit `x509_hash`, ES256 und `x5c`, DCQL; eine eigene Test-Wallet (`test/waltid/wallet.ts`) legte eine SD-JWT-Präsentation vor, Ergebnis `SUCCESSFUL` | keine Vertrauensliste konfiguriert; die Aussteller-Signatur (`did:key`) wurde geprüft, eine Ankerprüfung fand nicht statt | `test/waltid/evidence/waltid-run.txt` |
| eudi-verify (mit `@openeudi/openid4vp` 0.10.0) | bestanden: signiertes Request Object nach HAIP, Testpräsentation `verified` | Aussteller-Signatur gegen `x5c` geprüft, Ankerprüfung ausdrücklich abgeschaltet (`skipTrustCheck`) | `test/ERGEBNIS.md`; das Lauf-Protokoll ist nicht im Repository |
| miEUDIverifier (.NET) | nicht bestanden: erzeugt selbst kein Request Object und validiert selbst keinen `vp_token`, beides delegiert es an ein externes Verifier-Backend | findet im Projekt nicht statt | `test/evidence/mieudi-verify.txt` |

Ergebnis der Bewertung: Der Dienst verwendet `@openeudi/openid4vp` als
Protokollbibliothek und bettet sie selbst ein, statt einen fremden Server zu
betreiben.

### Zweiter Lauf: Versuch einer direkten Kopplung

In einem zweiten Lauf wurde geprüft, ob sich diese Projekte direkt mit diesem
Dienst koppeln lassen. Das ist nicht gelungen:

| Projekt | Was geprüft wurde | Ergebnis |
|---|---|---|
| eudi-verify | eigene Test-Suite des Projekts | 203 Tests bestanden |
| eudi-verify | lokaler Server mit Session, Request Object, JWS-Prüfung, verschlüsseltem Callback | **teilweise**: Session und Callback per HTTP erfolgreich, die abschließende Prüfung schlug fehl. Das mitgelieferte Skript forderte ein `mso_mdoc` Credential an, lieferte aber eine SD-JWT-Präsentation (`Invalid base64url character in vp_token/apu`). Das Skript meldet `RESULT: FAILED` und endet trotzdem mit Exit Code 0. |
| eudi-verify | direkte Kopplung mit diesem Dienst | **nicht ausführbar**: das Projekt erwartet `/sessions`, `/request/{id}`, `/callback` und `/tokens/verify`, dieser Dienst bietet `/v1/verification-requests` und `/direct_post`. Ein Adapter existiert nicht. |
| miEUDIverifier | Release-Build | bestanden, 0 Fehler |
| miEUDIverifier | .NET-Test-Suite | mit `DOTNET_ROLL_FORWARD=Major` auf .NET 10 liefen 48 von 48 Tests; ohne diesen Schalter startet die Suite nicht, weil die .NET 8 Runtime fehlte |
| miEUDIverifier | Präsentation einer Wallet | **blockiert**: es fehlten eine Wallet mit PID, ein erreichbares Backend und die nötigen Zertifikate |
| miEUDIverifier | direkte Kopplung mit diesem Dienst | **nicht ausführbar**: anderes Backend (`/ui/presentations`) und anderes Sitzungsmodell |

Ein Fehler in diesem Dienst wurde in keinem dieser Läufe gefunden. Das ist
kein Beleg für Interoperabilität, weil keiner der Läufe diesen Dienst mit einer
Wallet verbunden hat.

## 4. Was für einen Test mit einer echten Wallet fehlt

Ein solcher Test ist **nicht gelaufen**. Er setzt voraus:

1. Eine Verifier-Identität mit Schlüssel und Zertifikatskette, der die Wallet
   vertraut ([Betrieb](betrieb.md), [Deployment](deployment.md)). Das
   selbstsignierte TEST-Zertifikat des Entwicklungsbetriebs würde eine
   profilkonforme Wallet (HAIP) ablehnen. Ausprobiert wurde das nicht.
2. Zugriffs- und Registrierungszertifikate (WRPAC, WRPRC) für Deutschland.
3. Die Aussteller-Vertrauensanker der echten PID.
4. Zugang zu einer Wallet mit PID in einer Testumgebung. Er liegt nicht vor.
5. Den Dienst im Produktionsmodus, mit `/ready` bereit.

Erwartetes Verhalten laut Code, sobald diese Voraussetzungen erfüllt sind:

| Ablauf | Erwartung |
|---|---|
| Anfrage anlegen | `POST /v1/verification-requests` erzeugt ein signiertes Request Object mit DCQL |
| Wallet-Antwort | über `POST /direct_post`, Ergebnis HTTP 200 mit `valid: true` |
| Inhaltliche Ablehnung | HTTP 200 mit `valid: false` und festem Fehlercode |
| Nicht verarbeitbare Antwort | HTTP 422 |
| Dieselbe Antwort erneut senden | Ablehnung mit `session_reused` |
| Ergebnis | enthält nur die angefragten Claims; das Audit-Log enthält keine Präsentationsinhalte (`src/service/audit-inhalt.test.ts`) |

## 5. Lücken

### 5.1 Nicht implementiert

| Merkmal | Bedeutung |
|---|---|
| mdoc (`mso_mdoc`) | Eine Wallet, die nur mdoc anbietet, wird nicht bedient. |
| LOTL nach ETSI TS 119 612 | Vertrauen entsteht nur über ausdrücklich konfigurierte Anker. |
| Credential Sets | Keine Auswahl zwischen alternativen Nachweisen in einer Anfrage. |
| Registrar-Anbindung | Der Client existiert, ist aber nicht verdrahtet. |
| Mandantenverwaltung im Produktionsbetrieb | Mandanten und API-Schlüssel entstehen nur im Entwicklungsbetrieb (`DEV_TEST_TENANTS` in `src/service/bootstrap.ts`). |
| Persistenz | Sitzungen, Ergebnisse, Audit-Log und Ratenbegrenzung liegen im Arbeitsspeicher eines Prozesses. |

### 5.2 Teilweise implementiert

| Merkmal | Was fehlt |
|---|---|
| HAIP-Profile | externer Konformitätslauf |
| SD-JWT-Validierung und Key Binding | vollständige Matrix für alle Credential-Formate |
| Credential-Status | Erprobung mit echten Status-List-Ausstellern |
| OCSP und CRL | Nachweis gegen produktive Responder; CRL ist nicht im Dienststart verdrahtet |
| Verifier-Identität und Anker | produktive PKI-Konfiguration |
| WRPAC und WRPRC | Gate nur mit zusätzlichem Material aktiv; echte Registrar- und Access-CA-Profile fehlen |

### 5.3 Nicht nachgewiesen

| Punkt | Stand |
|---|---|
| Interoperabilität mit einer echten Wallet | nicht getestet, siehe [Teststand](#teststand-in-einem-satz) |
| Test in einer Sandbox, auch nicht in der SPRIND-Sandbox | nicht getestet, kein Zugang |
| Offizieller ARF- und eIDAS-Konformitätsnachweis | nicht vorhanden |
| Externes Security-Review oder Penetrationstest | nicht vorhanden |
| Verfügbarkeit und horizontale Skalierung | nicht nachgewiesen, Zustände liegen im Arbeitsspeicher |
