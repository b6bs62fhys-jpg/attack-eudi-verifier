# Konformitäts- und Konformitätszuordnung

Stand: 25.09.2026 · Branch `vereinigung-2026-09-25`

Dieses Dokument beschreibt den nachgewiesenen Prototyp-Stand. Es ist keine Konformitätsbescheinigung und keine Aussage über eine offizielle Zertifizierung.

## 1. Umgesetzte Zuordnung

| Bereich | Umsetzung im aktuellen Stand | Nachweis |
|---|---|---|
| OpenID4VP Authorization Request | Signiertes JAR nach RFC 9101/OpenID4VP-Struktur, `x509_hash`, ES256, `x5c`, `state`, `nonce`, `response_uri` | `src/service/service.ts`, `src/onboarding/jar.ts`, `src/service/service.test.ts` |
| DCQL | HAIP-DCQL-Abfrage über `@openeudi/openid4vp`; `pid_basis` und `age_over_18` als strikt validierte Mandantenprofile | `src/service/profile.ts`, `src/service/profile-service.test.ts` |
| PID-Profil | `pid_basis` fragt `given_name` und `birth_date`; `age_over_18` fragt nur `age_over_18` | [interne Notiz, nicht veröffentlicht], Profil-Tests |
| SD-JWT-VC | SD-JWT-VC mit selektiven Disclosures, Issuer-`x5c` und KB-JWT über die Bibliothek | `src/service/credential-status.test.ts`, `src/decision-test/sd-jwt-nachweis.test.ts` |
| Key Binding / Nonce | KB-JWT wird gegen Nonce und Audience geprüft; Abweichungen werden abgelehnt | `src/service/nachweis.test.ts`, `src/decision-test/sd-jwt-nachweis.test.ts` |
| Antwortverschlüsselung | `direct_post.jwt` mit ECDH-ES und A128GCM/A256GCM; frisches Schlüsselpaar je Sitzung, `kid = state`, Schlüsselverworfung nach Verarbeitung | `0187c2a`, `src/service/direct-post-interop.test.ts`, `src/service/service.ts` |
| JWE-Eingabe | JSON- und Form-Post; `response=<JWE>` sowie `{"response":"<JWE>"}`; `kid`-, State- und Replay-Prüfung | `src/service/app.ts`, `src/service/nachweis.test.ts` |
| Vertrauensanker | `StaticTrustStore` mit konfigurierten Ankern und RFC-5280-Kettenauswertung; Laufzeitprüfung auf leere/ungültige Anker | `2e5d8a4`, `679f46f`, `src/service/aussteller-anker.test.ts` |
| Mandantentrennung | Eigene Sitzungs- und Ergebnisräume, API-Key nur als SHA-256-Hash, fremde Ressource immer 404 | `src/service/tenant.ts`, `src/service/mandanten-matrix.test.ts` |
| Eingabegrenzen | 64 KiB Body, 32 KiB Präsentation, 48 KiB JWE, 64 Disclosures, feste Fehlercodes | `src/service/limits.ts`, `src/service/fehlerbilder.test.ts` |
| Ergebnis-Zugriff | Fertiges Ergebnis wird genau einmal ausgeliefert und danach vollständig entfernt | `src/service/ergebnis-einmal.test.ts` |
| Credential-Status | fail-closed Statusprüfung im Dienst; `NO_CREDENTIAL_STATUS` nur mit Entwicklungsschalter | `src/service/credential-status.ts`, `src/service/credential-status.test.ts` |
| RP-Onboarding | TEST-WRPAC/WRPRC-Gate und `registration_ref` als isolierte JAR-Erweiterung | `src/onboarding/`, `src/service/onboarding-gate.test.ts` |
| Flowseite | lokale statische Flowseite; interner API-Key-Proxy nur für Create-/Statusroute | `1fe5251`, `src/demo/flow-server.test.ts` |

## 2. Ausdrücklich nicht behauptet

- **Keine Live-Wallet-Interoperabilität**: Die JWE- und Form-Post-Tests verwenden lokale TEST-Schlüssel und einen programmierten Test-Envelope. Ein Durchlauf mit einer offiziellen EUDI-Wallet oder Sandbox wurde nicht ausgeführt.
- **Kein mdoc**: Der Prototyp unterstützt ausschließlich `dc+sd-jwt`; der mdoc-Pfad ist nicht umgesetzt.
- **Keine produktive Issuer-Revocation**: Der Service verwendet für die Credential-Prüfung `revocationPolicy: 'prefer'` (`src/service/service.ts:519`). Das Verhalten hängt damit an einer vom Dienst selbst gelieferten Statusliste und nicht an einer echten Sperrprüfung. Die eingesetzte Bibliotheksversion kennt in ihrem Typ auch `require`; eine erzwingende Prüfung ist jedoch nicht umgesetzt und nicht in Gebrauch. Die fail-closed-Prüfungen für WRPAC/WRPRC und Credential-Status sind davon getrennt und nicht als CRL/OCSP-Produktionspfad zu verstehen.
- **Keine ETSI-LOTL**: Das Trust-List-Monitoring im Prototyp verwendet eine TEST-JWS-Form, keine produktive ETSI-TS-119-612-XML-Signatur oder LoTE.
- **Keine Produktionsbetriebsverifikation**: TLS, Persistenz, Schlüsselrotation, Rate-Limiting, KMS/HSM, Deployment und externes Security-Audit fehlen.
- **DCQL-Feldname**: Für dieses Repository ist `birth_date` verbindlich. Eine externe Wallet oder ein anderes Profil, das `birthdate` erwartet, ist damit nicht automatisch kompatibel; das ist eine Interop-Frage und keine implizite Alias-Unterstützung.

## 3. Lokale Test- und Toolchain-Nachweise

Alle Zahlen sind gegen den Stand vom 27.09.2026 verifiziert.

- `npm ci`: 217 Pakete im Lockfile, davon 49 produktiv; `npm audit --audit-level=high` 0 Schwachstellen.
- `npm test`: 42 Testdateien, 622/622 Tests bestanden (Root-Suite).
- `npm run typecheck`: erfolgreich.
- `npm run test:coverage`: 78,97 % Statements, 77,88 % Branches, 84,36 % Functions, 81,95 % Lines; keine Schwelle erzwungen. Der Rückgang gegenüber dem Stand vor dem CLI ist eine Folge des Messverfahrens, kein Qualitätsverlust: `src/cli/main.test.ts` prüft den CLI als Unterprozess, und die Zeilen eines so gestarteten Programms zählen im Coverage-Lauf des Hauptprozesses nicht mit. Für eine Aussage über die Zeilenabdeckung des CLI wäre ein In-Prozess-Test nötig.
- SDK-Tests: 3 Tests im TypeScript-SDK (`sdk/typescript`), 31 Tests im Java/Kotlin-SDK (`sdk/kotlin`, davon 4 in Java geschrieben). Zusammen 672 Tests im Repository.
- `npm run loadtest`: Szenarien für Betriebs- und Fachrouten mit eigenem Exit-Code, getrennt von der Unit-Suite. Ergebnisse und SLO-Vorschlag in `docs/lasttest.md`.
- `npm run test:flake`: wiederholt die neun zeitabhängigen Testdateien zehnmal, ein einzelner roter Durchlauf bricht ab. Eigener CI-Job.
- `npm run site:url:check`: prüft, dass `site/robots.txt`, `site/sitemap.xml` und die hreflang-Einträge der Basis-URL aus `site.config.json` folgen.
- `npm run cli -- doctor`: liest dieselben Umgebungsvariablen und ruft dieselben Funktionen auf wie der Dienst beim Start. 9 Tests prüfen Rückgabewerte und die read-only-Zusage. Anleitung in `docs/cli-tool.md`.
- Flow-Demo-Smoke-Test: Startseite 200, Create über Proxy 201, nicht erlaubte `/direct_post`-Route 404.

Diese Nachweise sind lokale Tests. Ein GitHub-Actions-Lauf und ein Sandbox-Interop-Lauf stehen noch aus.

## 4. Bewertung

Der Prototyp erfüllt die eng begrenzte lokale Sicherheits- und Interop-Hypothese: signierte DCQL-Anfragen, SD-JWT-Präsentationen, direkte und JWE-verschlüsselte Antworten, Mandantentrennung sowie fail-closed Eingabe- und Ergebnisgrenzen sind implementiert und automatisiert getestet. Die fehlenden produktiven Trust-, Betriebs- und Live-Interop-Nachweise verhindern eine weitergehende Konformitätsaussage.
