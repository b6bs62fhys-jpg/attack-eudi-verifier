# Konformitäts- und Konformitätszuordnung

Stand: 08.10.2026

Dieses Dokument beschreibt den nachgewiesenen Prototyp-Stand. Es ist keine Konformitätsbescheinigung und keine Aussage über eine offizielle Zertifizierung.

## 1. Umgesetzte Zuordnung

| Bereich | Umsetzung im aktuellen Stand | Nachweis |
|---|---|---|
| OpenID4VP Authorization Request | Signiertes JAR nach RFC 9101/OpenID4VP-Struktur, `x509_hash`, ES256, `x5c` (nur das Zugangszertifikat), `state`, `nonce`, `response_uri`, `request_uri_method=get`; optional `verifier_info` mit dem Registrierungszertifikat; Gültigkeit einstellbar (30 bis 600 s, Standard 120) | `src/service/service.ts`, `src/onboarding/jar.ts`, `src/service/jar-parity.test.ts`, `src/service/sandbox-tauglichkeit.test.ts`, `src/service/redirect-und-gueltigkeit.test.ts` |
| Wallet-Aufruf | `walletUrl` (`openid4vp://?client_id=...&request_uri=...&request_uri_method=get`) in jeder Prüfanfrage, QR-Code auf der Demo-Flowseite | `src/service/sandbox-tauglichkeit.test.ts`, `src/demo/flow-demo.test.ts` |
| DCQL | HAIP-DCQL-Abfrage über `@openeudi/openid4vp`, danach Pfade für verschachtelte Altersschwellen; Profile `pid_basis`, `pid_de`, `age_over_18`, `age_over_18_de` | `src/service/profile.ts`, `src/service/profile-service.test.ts`, `src/service/alterspruefung.test.ts` |
| PID-Profile | `pid_basis`: `given_name`, `birth_date`; `pid_de`: vct `urn:eudi:pid:de:1` mit `given_name`, `family_name`, `birthdate`; `age_over_18`: nur `age_over_18`; `age_over_18_de`: nur `age_equal_or_over.18` | Profil-Tests, `docs/sandbox-runbook.md` mit Quellen |
| Altersprüfung | Antwort nur ja oder nein: `true` besteht, `false` ist ein klares Nein (`age_requirement_not_met`, abgeschlossenes Ergebnis ohne Claim-Wert), fehlender oder falsch getypter Claim wird abgelehnt | `src/service/alterspruefung.test.ts` |
| SD-JWT-VC | Selektive Disclosures, Issuer-`x5c` und KB-JWT über die Bibliothek; Strukturprüfung nach RFC 9901 davor (doppelte Offenlegungen und Digests, Salt kein Text), KB-JWT mit `typ` `kb+jwt` und Zeitfenster | `src/service/sdjwt-checks.ts`, `src/service/sdjwt-haertung.test.ts`, `src/decision-test/sd-jwt-nachweis.test.ts` |
| Key Binding / Nonce | KB-JWT wird gegen Nonce und Audience geprüft; Abweichungen werden abgelehnt | `src/service/nachweis.test.ts`, `src/service/sdjwt-haertung.test.ts` |
| Antwortverschlüsselung | `direct_post.jwt` mit ECDH-ES und A128GCM/A256GCM; frisches Schlüsselpaar je Sitzung, `kid = state`, Schlüsselverwerfung nach Verarbeitung; der öffentliche Schlüssel trägt nur `kty`, `crv`, `x`, `y`, `alg`, `use`, `kid` | `src/service/direct-post-interop.test.ts`, `src/service/sandbox-tauglichkeit.test.ts` |
| JWE-Eingabe | JSON- und Form-Post; `response=<JWE>` sowie `{"response":"<JWE>"}`; `kid`-, State- und Replay-Prüfung | `src/service/app.ts`, `src/service/nachweis.test.ts` |
| Vertrauensanker | `StaticTrustStore` mit konfigurierten Ankern und RFC-5280-Kettenauswertung; Laufzeitprüfung auf leere/ungültige Anker | `src/service/aussteller-anker.test.ts` |
| Sperrprüfung Aussteller-Kette | OCSP mit CRL als Rückfall (konfigurierbar), im Produktionsmodus ist CRL Pflicht; CRL-Cache bis `nextUpdate`; fail closed | `src/onboarding/revocation-source.ts`, `src/onboarding/revocation-source.test.ts`, `src/service/issuer-revocation.test.ts`, `src/service/issuer-revocation-anker-im-x5c.test.ts` |
| Credential-Status | fail-closed Statusprüfung; der Unterzeichner der Statusliste ist selbst Anker oder über die `x5c`-Kette von einem Anker signiert, mit Sperrprüfung seiner Kette | `src/service/credential-status.ts`, `src/lib/cert-chain.ts`, `src/service/status-list-kette.test.ts` |
| Mandanten | Mandantendatei für den Produktionsbetrieb, nur SHA-256-Hash des API-Schlüssels, CLI `tenant add/list/revoke`; eigene Sitzungs- und Ergebnisräume, fremde Ressource immer 404 | `src/service/tenant-file.ts`, `src/cli/tenant-command.ts`, `src/service/mandanten-matrix.test.ts` |
| Eingabegrenzen | 64 KiB Body, 32 KiB Präsentation, 48 KiB JWE, 64 Disclosures, feste Fehlercodes | `src/service/limits.ts`, `src/service/fehlerbilder.test.ts` |
| Ratenbegrenzung | je API-Schlüssel und je IP; hinter einem Proxy wertet der Dienst `X-Forwarded-For` nur von Proxys aus einer konfigurierten Liste aus | `src/lib/client-ip.ts`, `src/lib/client-ip.test.ts` |
| Ergebnis-Zugriff | Fertiges Ergebnis wird genau einmal ausgeliefert und danach vollständig entfernt | `src/service/ergebnis-einmal.test.ts` |
| RP-Onboarding | TEST-WRPAC/WRPRC-Gate und `registration_ref` als isolierte JAR-Erweiterung | `src/onboarding/`, `src/service/onboarding-gate.test.ts` |
| Flowseite | lokale statische Flowseite; interner API-Key-Proxy nur für Create-/Statusroute | `src/demo/flow-server.test.ts` |

## 2. Ausdrücklich nicht behauptet

- **Keine Interoperabilität mit der deutschen Sandbox-Wallet.** Ein Durchlauf mit der Sandbox-Wallet, der Sandbox-Test-PID oder den Sandbox-Zertifikaten wurde nicht ausgeführt. Ein lokaler Durchlauf mit einer quelloffenen Fremd-Wallet (`walt.id wallet-api2`) ist gelaufen, im Entwicklungsbetrieb, über `http`, ohne Sperr- und Statusprüfung und mit einem selbstsignierten Verifier-Zertifikat. Er ist kein Sandbox-Nachweis, siehe `docs/gegenstelle-waltid.md`. Alle übrigen Tests laufen gegen die Mock-Wallet dieses Repositorys.
- **Kein mdoc**: Der Prototyp unterstützt ausschließlich `dc+sd-jwt`; der mdoc-Pfad ist nicht umgesetzt.
- **Sperrprüfung nur gegen lokale Quellen erprobt.** OCSP- und CRL-Prüfung sind implementiert und laufen fail closed, wurden aber nur gegen lokale Test-Responder und selbst erzeugte CRLs getestet, nie gegen echte Sperrlisten oder Responder. Die Prüfbibliothek läuft zusätzlich mit `revocationPolicy: 'prefer'` und kann nur ablehnen, nie annehmen; die verbindliche Entscheidung trifft der eigene Sperrprüfer.
- **Keine ETSI-LOTL**: Das Trust-List-Monitoring im Prototyp verwendet eine TEST-JWS-Form, keine produktive ETSI-TS-119-612-XML-Signatur oder LoTE. Die Anker aus der Sandbox-Vertrauensliste lassen sich per Skript aus dem signierten JWT gewinnen (`docs/sandbox-runbook.md`); das ist keine Implementierung der Vertrauenslisten-Auswertung im Dienst.
- **Keine Produktionsbetriebsverifikation**: Persistenz (Sitzungen, Ergebnisse und Audit-Log liegen im Arbeitsspeicher), Schlüsselrotation, KMS/HSM, und ein externes Security-Audit fehlen. TLS endet an einem vorgeschalteten Proxy und wurde in diesem Repository nicht gegen einen echten Proxy mit Zertifikat geprüft.
- **DCQL-Feldnamen**: `pid_basis` und `age_over_18` verwenden die Namen der EU-PID (`birth_date`, `age_over_18`). Für die deutsche PID gelten laut offizieller PID-Referenz andere (`birthdate`, `age_equal_or_over.18`); dafür gibt es die Vorlagen `pid_de` und `age_over_18_de`. Wie die echte deutsche PID die Altersschwellen im SD-JWT verpackt, ist öffentlich nicht beschrieben und nicht geprüft.

## 3. Lokale Test- und Toolchain-Nachweise

Alle Zahlen sind am 08.10.2026 gemessen.

- `npm ci`: 218 Pakete im Lockfile, davon 41 produktiv; `npm audit --audit-level=high` 0 Schwachstellen (nach Aktualisierung von `source-map-js` im Lockfile, einer Entwicklungsabhängigkeit).
- `npm test`: 65 Testdateien, 1030 von 1030 Tests bestanden (Root-Suite dieses Repositorys).
- `npm run typecheck`: keine Fehler.
- `npm run lint`: für `src` und das Interop-Skript ohne Warnung.
- `npm run test:coverage`: 82,97 % Statements, 82,61 % Branches, 87,43 % Functions, 85,38 % Lines; die Schwellen in `vitest.config.ts` (79, 78, 84, 82) werden eingehalten. Prozessbasierte Tests (CLI, Dienststart) zählen in der Zeilenabdeckung nicht mit; die neuen CLI- und Mandantendatei-Pfade haben deshalb zusätzlich Tests im selben Prozess.
- `npm run test:flake`: wiederholt die zwölf zeitabhängigen Testdateien zehnmal, alle grün (53 s). Eigener CI-Job.
- Docker-Image: am 08.10.2026 lokal gebaut (Colima). Typecheck der Build-Stufe grün, 43 Laufzeitdateien im Image (Importabgleich: 43 erreichbar, 43 kopiert; seitdem als Test `src/dockerfile-dateiliste.test.ts`), keine Testdateien und kein Schlüsselmaterial, Start als Benutzer `node` mit `NODE_ENV=production` und Mandantendatei, `/live` antwortet, keine Entwicklungswarnung.
- SDK-Tests: im TypeScript-SDK (`sdk/typescript`) 8 Tests, Stand 08.10.2026. Die Zahlen für das Java/Kotlin-SDK (31 Tests, davon 4 in Java) und das Python-SDK stammen vom 27.09.2026 und wurden heute nicht neu gemessen.
- `npm run loadtest`: Szenarien für Betriebs- und Fachrouten mit eigenem Exit-Code, getrennt von der Unit-Suite. Ergebnisse und SLO-Vorschlag in `docs/lasttest.md`; heute nicht neu gemessen.
- `npm run site:url:check`: prüft, dass `site/robots.txt`, `site/sitemap.xml` und die hreflang-Einträge der Basis-URL aus `site.config.json` folgen.
- `npm run cli -- doctor`: liest dieselben Umgebungsvariablen und ruft dieselben Funktionen auf wie der Dienst beim Start. Der Befehl `tenant` ist der einzige Schreibbefehl und schreibt nur die Mandantendatei. Anleitung in `docs/cli-tool.md`.
- Interop mit einer Fremd-Wallet: `docs/gegenstelle-waltid.md` (lokal, Entwicklungsbetrieb).

Typecheck, Lint, Tests, Coverage und `npm audit` laufen in diesem Repository auch in GitHub Actions. Ein Interop-Lauf mit der Sandbox steht noch aus.

## 4. Bewertung

Der Prototyp erfüllt die eng begrenzte lokale Sicherheits- und Interop-Hypothese: signierte DCQL-Anfragen, SD-JWT-Präsentationen, direkte und JWE-verschlüsselte Antworten, Mandantentrennung sowie fail-closed Eingabe-, Sperr- und Ergebnisgrenzen sind implementiert und automatisiert getestet, und eine quelloffene Fremd-Wallet hat im Entwicklungsbetrieb eine Präsentation abgeschlossen. Die fehlenden produktiven Trust-, Betriebs- und Sandbox-Interop-Nachweise verhindern eine weitergehende Konformitätsaussage.
