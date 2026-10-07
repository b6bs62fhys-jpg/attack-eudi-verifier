# Interoperabilitätsmatrix

Stand: `main` commit `98998bb`, 29.09.2026. Jede Zeile nennt Datei und Zeile sowie
den zugehörigen Test. Was nicht im Code belegt ist, steht als **nicht
implementiert** oder **unbelegt**, nicht als „geplant".

> **Produktname: `Attack`.** Das ist ein Arbeitsname. Die Namensentscheidung ist offen.

Dieses Dokument beschreibt den Stand des Repositorys. Es ist **kein
Konformitätsnachweis** und **kein Nachweis einer durchgeführten
Interoperabilitätsprüfung**. Ein solcher Nachweis liegt nicht vor
(`docs/eidas-arf-konformitaet.md:37`).

## 1. Protokoll und Formate

| Merkmal | Status | Beleg | Test |
|---|---|---|---|
| OpenID4VP Version | implementiert | `@openeudi/openid4vp` **0.11.1** installiert (`package.json`); importiert in `src/service/service.ts:16` | `src/decision-test/decision.test.ts` |
| Response Mode `direct_post` | implementiert | `src/service/app.ts:238-256`, Route `POST /direct_post` | `src/service/direct-post-interop.test.ts` |
| Response Mode `direct_post.jwt` | implementiert | `src/onboarding/jar.ts:16, 53, 85`; Verarbeitung in `src/service/service.ts:624` | `src/service/fehlerbilder.test.ts` |
| Signiertes Request Object (JAR) | implementiert | `src/onboarding/jar.ts:85`; `createSignedAuthorizationRequest` in `src/service/service.ts:16` | `src/service/jar-parity.test.ts`, `src/decision-test/decision.test.ts` |
| Verschlüsselte Antwort (JWE) | implementiert | `src/service/service.ts:624-690`; Empfang verschlüsselter Antworten | `src/service/fehlerbilder.test.ts` |
| JWE `enc` Werte | implementiert | `A128GCM` und `A256GCM` in `src/onboarding/jar.ts:34` (`DEFAULT_SUPPORTED_ENC_VALUES`); Schlüsselalgorithmus `ECDH-ES` in `src/service/service.ts:330` | `src/service/jar-parity.test.ts` |
| JWE `alg` Wert | implementiert | `src/service/service.ts:330` (`publicJwk.alg = 'ECDH-ES'`) | `src/service/jar-parity.test.ts` |
| Anfrage als Form-Post | implementiert | `src/service/app.ts:79` (`application/x-www-form-urlencoded`), Verarbeitung in `src/service/app.ts:244` | `src/service/direct-post-interop.test.ts` |
| DCQL | implementiert | `src/service/service.ts:369` und `:498` (`buildHaipQuery`), Übergabe in `src/service/service.ts:406` | `src/decision-test/sd-jwt-nachweis.test.ts` |
| HAIP | teilweise | Query-Aufbau über `buildHaipQuery` (`src/service/service.ts:369`); `validateHaipQuery` in `src/service/limits.ts:88` | `src/decision-test/decision.test.ts`; `docs/eidas-arf-konformitaet.md` führt die Profile als „Teilweise erfüllt" |
| SD-JWT VC | implementiert | Formatangabe `dc+sd-jwt` in `src/service/service.ts:369`; Validierung `src/service/service.ts:530-560` | `src/decision-test/sd-jwt-nachweis.test.ts` |
| mdoc (mso_mdoc) | **nicht implementiert** | Kein Treffer im Produktivcode. Die Suche nach `mdoc` findet in `src/cli/main.ts:276, 383, 399` nur die Zeichenkette in `cmdOcsp`, also die OCSP-Abfrage, kein mdoc. | **kein Test** |
| Credential Sets (Disjuktion) | **nicht implementiert** | Die installierte Version 0.11.1 kennt `buildCredentialSetQuery` nicht; das wurde für die Version 0.12.0 geprüft und in [interner Bericht, nicht veröffentlicht] festgehalten. | **kein Test** |

## 2. Vertrauen und Sperrprüfung

| Merkmal | Status | Beleg | Test |
|---|---|---|---|
| Aussteller-Vertrauensanker | implementiert | `src/service/issuer-anchors.ts:23`; fail closed bei fehlender, leerer oder unbrauchbarer Datei in `src/service/issuer-anchors.ts:28, 32, 38` | `src/service/aussteller-anker.test.ts` |
| Vertrauensanker zur Laufzeit | implementiert | `src/service/service.ts:465-466` (`issuer_trust_anchors_empty`) | `src/service/aussteller-anker.test.ts:212, 229` |
| Verifier-Identität und Kette | implementiert | `src/service/verifier-identity.ts:68-119`; Startabbruch bei fehlendem Material | `src/service/produktionsschalter.test.ts:188` |
| OCSP | implementiert | `src/onboarding/ocsp-revocation.ts`; Grenze für veraltete Antworten in `:117` und `:122` | `src/onboarding/ocsp-revocation.test.ts:240, 248, 575` |
| CRL | implementiert | `src/onboarding/crl-revocation.ts` | `src/onboarding/revocation-fail-closed.test.ts` |
| Token Status List | implementiert | `src/service/credential-status.ts`; Verdrahtung in `src/service/bootstrap.ts:100` | `src/service/credential-status.test.ts:302, 310, 317` |
| LOTL (Liste der Trust Lists) | **nicht implementiert** | Kein Treffer in `src/`. Das Wort erscheint ausschließlich in Dokumenten ([interner Bericht, nicht veröffentlicht], [interner Bericht, nicht veröffentlicht], [interne Notiz, nicht veröffentlicht], [interne Notiz, nicht veröffentlicht], [interne Notiz, nicht veröffentlicht]), dort im Zusammenhang mit der geprüften Bibliotheksversion 0.12.0. | **kein Test** |
| WRPAC und WRPRC | teilweise | `src/onboarding/wrpac.ts`, `src/onboarding/wrprc.ts`, Verdrahtung in `src/onboarding/onboarding-wiring.ts:79`; im strengen Produktionsbetrieb meldet `/ready` `onboarding: failed` (`src/service/run.ts:47`) | `src/onboarding/onboarding.test.ts`, `src/onboarding/onboarding-gate-hardening.test.ts` |
| Registratur-Anbindung | **nicht implementiert** | `docs/fehlercodes.md:112` nennt den `RegistrarClient` als ungenutzt; `src/onboarding/registrar.ts` wird nicht verdrahtet | **kein Test** |

## 3. Was die Untermodule geprüft haben, und was nicht

Wichtig für die Einordnung: Die drei Untermodule unter `test/` wurden **nicht**
zum Test dieses Dienstes gegen eine Referenz-Wallet verwendet. Sie dienten der
Bewertung **anderer** Implementierungen als Kandidaten für den Kern.

Belege: `test/ERGEBNIS.md`. Die Untermodule selbst sind nicht Teil der öffentlichen Kopie dieses Repositorys.

| Untermodul | wofür es laut Beleg verwendet wurde | geprüft | nicht geprüft |
|---|---|---|---|
| `test/eudi-verify` (eudi-verify, `0f69ea69`) | Kandidatenbewertung einer Bibliothek | `test/ERGEBNIS.md` nennt „✅ ~45 min", signiertes Request Object mit HAIP, Issuer-Signatur „echt gegen das x5c-Zertifikat" | **Ob unser Dienst mit einer echten Wallet interoperiert.** Nicht Gegenstand. |
| `test/waltid/waltid-identity` | Kandidatenbewertung eines Verifier-Servers | `test/ERGEBNIS.md`: „✅ ~13 min", DCQL, x509_hash, ES256+x5c, Trust-Anker-Prüfungen liefen | **Ebenso nicht.** |
| `test/miEUDIverifier` | Kandidatenbewertung, **verworfen** | `test/ERGEBNIS.md`: „❌ erzeugt KEIN Request Object selbst", Trust-Anker-Prüfung findet laut Beleg „gar nicht statt" | wie oben |

**Belegte Evidenzdateien** laut `test/ERGEBNIS.md`:
`test/waltid/evidence/waltid-run.txt` und `test/evidence/mieudi-verify.txt` liegen
im Repository. Der Lauf von eudi-verify ist in der öffentlichen Kopie nicht enthalten.
Die Belege stammen aus lokalen Läufen gegen die Kandidaten, nicht gegen unseren
Dienst.

**Nicht belegt:** Ein Testlauf unseres Dienstes gegen eine dieser Implementierungen
als Wallet. `test/ERGEBNIS.md` vergleicht Kandidaten **untereinander und gegen
die Anforderung** „erzeugt signiertes Request Object", nicht gegen unseren
Dienst.

## 4. Interop-Testplan

Die folgenden Schritte sind **ein Plan, kein durchgeführter Ablauf.** Nichts
davon ist gelaufen. Nennenswerte Testumgebungen werden nur aufgeführt, wenn sie
im Repository belegt sind.

### Schritt 1: Voraussetzungen schaffen

| Schritt | Inhalt | Beleg für das, was existiert |
|---|---|---|
| 1.1 | Verifier-Identität bereitstellen (Schlüssel, Zertifikatskette) | `docs/betrieb.md` Abschnitt 1, `docs/deployment.md:29-32` |
| 1.2 | Aussteller-Vertrauensanker bereitstellen | `docs/deployment.md:32`, `src/service/issuer-anchors.ts:23` |
| 1.3 | Dienst im Produktionsmodus starten | `docs/deployment.md:10-19` |
| 1.4 | Prüfen, dass `/ready` bereit meldet | Route `src/service/app.ts:200-206`; Achtung: ohne Gate-Material meldet sie `onboarding: failed` (`src/service/run.ts:47`) |

### Schritt 2: Wallet-Zugang

| Schritt | Inhalt | Beleg |
|---|---|---|
| 2.1 | Zugang zu einer Referenz-Wallet beschaffen | Einladung zu einem Sandbox-Programm steht aus, Kickoff war am 17.09. |
| 2.2 | Konkrete Wallet, Version, Anbieter festlegen | **zu recherchieren**. Im Repository ist keine konkrete Referenz-Wallet benannt. |
| 2.3 | Testumgebung für die Wallet festlegen | **zu recherchieren** |

### Schritt 3: Ablauf gegen die echte Wallet

| Schritt | Inhalt | Sollverhalten laut Code |
|---|---|---|
| 3.1 | Authorization Request auslösen | `src/service/service.ts:406` erzeugt die Anfrage mit DCQL |
| 3.2 | Signiertes Request Object prüfen | `src/onboarding/jar.ts:85` |
| 3.3 | Wallet-Antwort über `direct_post` senden | `src/service/app.ts:238-256` |
| 3.4 | Status prüfen: 200 mit `valid: true` | `src/service/app.ts:256`, `docs/fehlercodes.md` |
| 3.5 | Ablehnungsfälle durchspielen | 200 mit `valid: false` bei inhaltlicher Ablehnung, 422 bei nicht verarbeitbarer Präsentation |
| 3.6 | Wiederverwendung derselben Antwort prüfen | muss mit `session_reused` scheitern, `src/lib/session.ts:81` |

### Schritt 4: Auswertung

| Schritt | Inhalt |
|---|---|
| 4.1 | Prüfen, dass die Antwort **nur die angeforderten** Claims enthält (`src/service/service.ts:527`) |
| 4.2 | Prüfen, dass das Audit-Log keinen Präsentationinhalt trägt (`src/service/audit-inhalt.test.ts`) |
| 4.3 | Abweichungen nach `docs/eidas-arf-konformitaet.md` zuordnen |
| 4.4 | Ergebnis als Ergänzung zu diesem Dokument festhalten |

### Externe Testumgebungen

| Umgebung | Beleg |
|---|---|
| Sandbox-Programm, Anmeldung erfolgt, Einladung ausstehend | interner Planungsstand |
| Konkrete Konformitätstestumgebung eines Anbieters | **nicht im Repository belegt**, zu recherchieren |

## 5. Abweichungen und Lücken

### 5.1 Nicht implementiert

| Merkmal | Beleg für das Fehlen |
|---|---|
| mdoc / mso_mdoc | kein Treffer im Produktivcode, siehe Abschnitt 1 |
| LOTL | kein Treffer in `src/`, nur Dokumentation, siehe Abschnitt 2 |
| Credential Sets (Disjuktion über mehrere Nachweise) | Version 0.11.1 kennt die Funktion nicht, siehe [interner Bericht, nicht veröffentlicht] |
| Registratur-Anbindung | `docs/fehlercodes.md:112` nennt den Client ungenutzt |

### 5.2 Teilweise implementiert

| Merkmal | Was fehlt | Beleg |
|---|---|---|
| HAIP-Profile | `docs/eidas-arf-konformitaet.md` führt sie als „Teilweise erfüllt" | dieselbe Zeile |
| VP- und SD-JWT-Validierung | Key Binding laut Zuordnung „Teilweise erfüllt" | dieselbe Zeile |
| Credential-Statusprüfung | reale Status-List-Aussteller laut Zuordnung nicht erprobt | dieselbe Zeile |
| Issuer-Kette, OCSP und CRL | Fail-closed-Verhalten vorhanden, Umfang „Teilweise erfüllt" | dieselbe Zeile |
| Verifier-Identität und Anker | Umfang „Teilweise erfüllt" | dieselbe Zeile |
| WRPAC und WRPRC | Gate im Produktionsbetrieb nicht aktiv | `src/service/run.ts:47` |

### 5.3 Nicht nachgewiesen

| Punkt | Beleg |
|---|---|
| Verfügbarkeit und horizontale Skalierung | `docs/eidas-arf-konformitaet.md`: „Nicht nachgewiesen", Zustände liegen im Arbeitsspeicher |
| Offizieller ARF- und eIDAS-Konformitätsnachweis | `docs/eidas-arf-konformitaet.md:37`: „Nicht erfüllt/nicht nachgewiesen" |
| Interoperabilität mit einer echten Wallet | **nicht gelaufen**, siehe Abschnitt 4 |
| Externes Security-Review | [interne Notiz, nicht veröffentlicht]: nicht vorhanden |

### 5.4 Als Arbeitsname geführt

Der Produktname in diesem Dokument ist ein Arbeitsname. Die Namensentscheidung ist offen.
