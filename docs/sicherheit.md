# Sicherheitsdurchsicht (docs/sicherheit.md)

**Nachtrag 25.09.2026 (Branch `ocsp-sperrpruefung-2026-09-25`)**: Die
Aussteller-Zertifikatskette vorgelegter Credentials wird jetzt per OCSP
(RFC 6960) geprüft; der Platzhalter `revocationPolicy: 'skip'` ist entfernt.
Belege, Abgrenzung zu CRL und Token Status List sowie die freigegebene
Gnadenfrist von 24 Stunden stehen in Abschnitt 5a und in
`docs/entscheidung-ocsp-fail-modus.md`.

**Historischer Stand 22.09.2026 für Branch `phase1`.** Für den aktuellen Stand `vereinigung-2026-09-25` gelten `docs/konformitaet.md`, `docs/offene-fragen-vereinigung.md` und `docs/vereinigung-abschlussbericht.md`; insbesondere sind die dort genannten JWE-, DCQL- und Flow-Erweiterungen nicht in diesem historischen Bericht enthalten.

Stand: 22.09.2026 · Umfang: Schritt 4 des Auftrags (Prototyp, Branch `phase1`).

**Nachtrag (Branch `feature/interop-und-haertung`, Teil 1+2)**: der Dienst unterstützt jetzt `application/x-www-form-urlencoded` als zweites `direct_post`-Eingabeformat sowie JWE-verschlüsselte Antworten (`direct_post.jwt`, Entschlüsselung ausschließlich über die Bibliothek, ECDH-ES + A128GCM/A256GCM). Für Zugriffs-/Registrierungszertifikate existiert ein optionaler Sperrprüf-Erweiterungspunkt (`RevocationChecker`); der Prototyp liefert eine TEST-Mock-Sperrliste (Fingerprint-basiert). Beides ist abwärtskompatibel (Default unverändert) und durch 89 Tests abgedeckt. Alle Aussagen gelten für diesen Prototyp und sind keine Produktionszusage.

## 1. Zusammenfassung

- `npm audit`: **0 Schwachstellen** auf dem aufgelösten Abhängigkeitsbaum (Stand des Locks, Details siehe unten).
- Geheimnisse: **keine gefunden** — in Quelltext, Git-Historie oder (nicht vorhandenen) Logs liegen keine echten Schlüssel, Zertifikate oder Zugangsdaten.
- Grundsatz des Prototyps eingehalten: ausschließlich TEST-Material im Arbeitsspeicher, nie auf der Platte, nie in Logs. API-Schlüssel werden nur als SHA-256-Hash gespeichert (`src/service/tenant.ts`).
- **Ehrliche Einordnung**: Es gibt keine externe Sicherheitsprüfung dieser Codebasis und (Stand des Vergleichs) kein externes Audit von `@openeudi/openid4vp`. Der Prototyp ist ein Machbarkeitsnachweis, kein Produktivsystem.

## 2. `npm audit`

Ausführung: `npm audit` mit dem aktuellen `package-lock.json` (exakte Versionen, committet).

```
found 0 vulnerabilities
```

## 3. Suche nach Geheimnissen

Methode: regex-basierter Scan über alle Dateien inkl. Git-Historie, ausgeschlossen `node_modules/`, `.git/`, `package-lock.json`. Suchmuster u. a. `BEGIN … PRIVATE KEY`, `sk_live_/sk_test_`, `AKIA…`, `AIza…`, `aws_access_key`, `password=`, `ghp_…`, `Bearer <40+ Zeichen>`.

Ergebnis: **keine Treffer**.
- Es sind keine `.pem`, `.key`, `.env`- oder Secret-Dateien versioniert.
- `git ls-files` und `git log` enthalten keinen `node_modules/`.
- Logs existieren nicht persistent (STDOUT nur; Demo- und Servicelogs wurden beim Testlauf sofort gelöscht und sind nicht eingecheckt).
- Die im Prototyp verwendeten API-Schlüssel (`test-api-key-tenant-A/B`) und die in `src/decision-test/mock-wallet.ts` erzeugten Zertifikate sind eindeutig als TEST markiert; die API-Schlüssel stehen nirgends als Klartext im Code außer in `run.ts` (Bootstrap) und in den Tests — genau dort, wo sie als Dummy gebraucht werden.

## 4. Abhängigkeiten und Lizenzen (installierte, gehoistete Top-Level mit Transitivem)

45 eindeutige Pakete. Eine vollständige Liste wird hier nicht dupliziert; die prüfbare Quelle ist `package-lock.json` (committet) und `node_modules/<paket>/package.json`. Die direkten Abhängigkeiten des Projekts (diese Liste ist verantwortet):

| Paket | Version | Lizenz | Zweck |
|---|---|---|---|
| `@openeudi/openid4vp` | 0.11.1 | Apache-2.0 | OpenID4VP/DCQL/SD-JWT-/KB-Prüfung, signierte Request Objects |
| `@openeudi/core` | 0.8.0 | Apache-2.0 | Session-/Demomaterial der OpenEUDI-Organisation |
| `@openeudi/dcql` | 0.2.0 | Apache-2.0 | DCQL-Typen/Prüfung |
| `jose` (dev) | 6.1.3 | MIT | JWT-Erzeugung/-Prüfung (auch transitive Abhängigkeit der Bibliothek) |
| `@peculiar/x509` (dev) | 2.1.0 | MIT | TEST-Zertifikate (auch Abhängigkeit der Bibliothek) |
| `typescript`, `@types/node` (dev) | 5.7.2 / 22.10.2 | Apache-2.0 / MIT | Typecheck |

Wichtige transitive Pakete mit Lizenzen: `asn1js`/`bytestreamjs`/`pkijs`/`js-base64` (BSD-3-Clause), `@xmldom/xmldom`, `xadesjs`, `xmldsigjs`, `cbor-x`, `uuid`, `pvtsutils`, `pvutils`, `tslib` (0BSD), `reflect-metadata`, `tsyringe`, `@sd-jwt/*` (Apache-2.0), `detect-libc` (Apache-2.0). Vollständig per Befehl prüfbar (Abschnitt 7).

## 5. Bekannte Lücken und offene Punkte (ehrlich dokumentiert)

1. **Prototyp-Architektur**: Alle Zustände (Sitzungen, Ergebnisse, Mandanten, Audit-Log) liegen nur im Arbeitsspeicher. Neustart löscht alles. Für jede gehostete Umsetzung (Stufe 2 des Plans) sind Persistenz, Backup und Ablaufprozesse neu zu entwerfen.
2. **TLS/Deployment**: Der Dienst läuft roh über HTTP auf 127.0.0.1. Keine TLS-Terminierung, kein Reverse-Proxy, kein Container, keine Betriebskonfiguration.
3. **`direct_post`-Interop (Teil 1, jetzt verringert)**: Der Dienst akzeptiert zusätzlich zu `application/json` auch `application/x-www-form-urlencoded` (Envelope-Felder `vp_token`/`state`; `vp_token` als JSON-Objekt, JSON-Array oder roher SD-JWT-String — Roh-Werte werden in den DCQL-Envelope gewickelt, siehe `src/service/app.ts`) und JWE-verschlüsselte Antworten (`response=<JWE>` form- oder `{"response":"…"}` JSON). Die Entschlüsselung läuft über `decryptAuthorizationResponse` der Bibliothek; die Prüfung verschlüsselter Antworten ist nur mit `encryptionKey` aktiv, sonst bleibt der Altpfad intakt. **Offen bleibt**: Interop mit einer echten Sandbox-Wallet ist mangels Sandbox-Zugang nicht geprüft (siehe docs/offen.md).
4. **Verifier-Identität**: Request Objects werden mit selbstsignierten TEST-Zertifikaten signiert (`allowSelfSignedCertificate: true`). Profilkonforme Wallets (HAIP 1.0) würden diese Verifier-Identität ohne gültiges Zugriffs- und Registrierungszertifikat ablehnen. Der Live-Durchlauf hängt damit am Registry-/Zertifikatsthema (PLAN.md; Registrar ausstehend).
5. **Trust-Pfad und Sperrprüfung**: **Stand ocsp-sperrpruefung-2026-09-25**: Issuer-Zertifikate der vorgelegten Credentials werden per OCSP (RFC 6960) geprüft (`src/onboarding/ocsp-revocation.ts`, verdrahtet in `src/service/bootstrap.ts:80-88`); die Bibliothek läuft nur noch mit `revocationPolicy: 'prefer'` als Zweitinstanz (`src/service/service.ts:493`). Details, Abgrenzung und bekannte Nachteile: Abschnitt 5a. **Stand Haertung 1 (2026-09-25)**: Die Sperrprüfung für WRPAC/WRPRC ist Pflicht und fail closed (`src/onboarding/revocation.ts`, `enforceRevocation`); `NO_REVOCATION` ist nur mit `ATTACK_DEV_MODE=true` außerhalb von Produktion zulässig. Echte Quelle dort: `CrlRevocationChecker` (CRL nach RFC 5280). Credentials werden über eine Token Status List geprüft (`src/service/credential-status.ts`). Fehlercodes: `docs/fehlercodes.md`.
   **Weiterhin offen (ehrlich)**: (a) `CrlRevocationChecker` ist implementiert und getestet, aber im Dienststart nicht verdrahtet — das Onboarding-Gate ist standardmäßig nicht aktiv, die WRPAC/WRPRC-Sperrprüfung greift also erst, wenn ein Gate konfiguriert wird. (b) Für OCSP gibt es noch keinen Nachweis gegen einen echten produktiven Responder, alle Tests laufen gegen einen lokalen Mock. (c) Die Bibliothek schreibt bei OCSP-Fehlern Zertifikat-Subjects nach `console.warn`; das ist nicht abstellbar und in Abschnitt 5a als Nachteil festgehalten. (d) Es gibt keine CRL-Anbindung an den Issuer-Pfad; der Bibliothekspfad bietet sie, sie ist aber nicht der entscheidende Mechanismus.
6. **Keine Schutzmechanismen des Betriebs**: kein Rate-Limiting, keine CSRF/Token-Härtung für die Demo-Seite, keine separaten Prozessrechte, keine Secret-Verwaltung (KMS/HSM). Zugriffs- und Registrierungszertifikate sind bisher nur Platzhalter.
7. **`mso_mdoc`-Pfad fehlt**: Es wird ausschließlich der SD-JWT-VC-Pfad (Falster A) unterstützt. mdoc (Plan-Stufe 2) ist nicht umgesetzt.
8. **Transitive Deprecations**: `@sd-jwt/decode@0.19.0`, `@sd-jwt/types@0.19.0`, `@sd-jwt/utils@0.19.0` (als Abhängigkeit von `@openeudi/openid4vp`) sind als deprecated markiert (Merge zu `@sd-jwt/core` ≥ 0.20.0 mit Security-Hinweis GHSA-f9j6-8p6x-r9j6). Der Prototyp nutzt die Bibliothek, nicht `@sd-jwt/*` direkt; beim Wechsel auf eine neuere `@openeudi/*`-Version sollte die Deprecation mit verfolgt werden.
9. **Zweit-Journal `xadesjs`/`xmldsigjs`/`@xmldom/xmldom`**: XML-Signatur-Bibliotheken (LOTL-Verarbeitung der Bibliothek) sind Altlasten-Komponenten mit teils älteren Pfaden; hier nicht aktiv genutzt. Ohne Audit-Befund (npm audit: 0).
10. **Kein externes Audit / keine OIDF-CI-Replay im Repo**: Der Weg über die offizielle OIDF-Konformitätssuite der Bibliothek ist geprüft laut deren CI (docs/verifier_vergleich.md), aber nicht im eigenen Repo wiederholt. Ein eigener Replay-Lauf wäre eine Option für später (offen).

## 5a. Sperrprüfung: welcher Mechanismus wofür (Stand 2026-09-25)

Es gibt drei verschiedene Sperrmechanismen. Sie prüfen **nicht dasselbe** und
werden **nicht** für denselben Zertifikatstyp gleichzeitig herangezogen.

| Mechanismus | Gilt für | Implementierung | Quelle im Code |
| --- | --- | --- | --- |
| **OCSP** (RFC 6960) | Aussteller-Zertifikate der vorgelegten Credentials (Blatt und Intermediate bis zum Anker) | `OcspRevocationChecker` | `src/onboarding/ocsp-revocation.ts`, verdrahtet in `src/service/bootstrap.ts:80-88` |
| **CRL** (RFC 5280) | Onboarding-Zertifikate WRPAC/WRPRC (Blatt und Intermediate) | `CrlRevocationChecker` | `src/onboarding/crl-revocation.ts`, aufgerufen über `enforceRevocation` in `src/onboarding/wrpac.ts:140` und `src/onboarding/wrprc.ts:131` |
| **Token Status List** (IETF draft-ietf-oauth-status-list) | Der **Inhalt** eines Credentials (das Zertifikat selbst wird davon nicht berührt) | `TokenStatusListChecker` | `src/service/credential-status.ts:118`, aufgerufen in `src/service/service.ts:538` (Aufruf)  |

### Warum es keine Überschneidung zwischen OCSP und CRL gibt

OCSP und CRL prüfen **verschiedene Zertifikatstypen**, nicht dieselben:

- OCSP wird nur für die x5c-Kette des Issuer-JWT aufgerufen
  (`src/service/service.ts:520-531` -> `enforceIssuerChainRevocation` in
  `src/service/issuer-revocation.ts:40`). Diese Kette endet am konfigurierten
  Aussteller-Anker. Der Anker selbst wird nie geprüft, das ist der Vertrag von
  `RevocationChecker.checkRevoked` (`src/onboarding/revocation.ts:40`).
- CRL wird nur für die Onboarding-Kette aufgerufen (WRPAC-Zugriffszertifikat,
  WRPRC-Registrierungsnachweis). Diese Prüfung läuft im Onboarding-Gate, nicht
  im Präsentationspfad, und greift nur, wenn ein Gate konfiguriert ist
  (`src/onboarding/onboarding-gate.ts:81`).
- Die Token Status List prüft weder Zertifikate noch Issuer, sondern den
  Statuswert `status_list.idx` im Issuer-Payload (`credential-status.ts:162-170`).
  Sie ist damit auch keine Alternative zu OCSP, sondern eine Ergänzung: das
  Zertifikat kann gültig und ungesperrt sein, während das Credential selbst
  auf der Statusliste steht.

### Die einzige echte Überschneidung: die Prüfbibliothek

Es gibt genau eine Stelle, an der zwei Mechanismen auf dasselbe Zertifikat
treffen können: der Dienst ruft die Bibliothek mit
`revocationPolicy: 'prefer'` (`src/service/service.ts:493`), und die
Bibliothek prueft intern selbst OCSP **und** faellt auf CRL zurueck
(`node_modules/@openeudi/openid4vp/dist/index.js:7917-7927`).

**Vorrang: unser eigener OCSP-Checker entscheidet, die Bibliothek kann nur
ablehnen.**

Das ist so umgesetzt und belegt:

**Reihenfolge im Code** (belegt, nicht behauptet): Der Bibliotheksaufruf
`verifyAuthorizationResponse` steht in `processPresentation` bei
`src/service/service.ts:474`, der eigene OCSP-Check bei
`src/service/service.ts:526`, der Credential-Status bei
`src/service/service.ts:538`. Die Bibliothek laeuft also zuerst, die
verbindliche Entscheidung faellt danach.

**Warum der eigene Checker trotzdem den Vorrang hat:**

1. Die Bibliothek laeuft mit `'prefer'`, nicht `'require'`. Bei `'require' wuerde
   sie selbst `RevocationCheckFailedError` werfen, wenn ihr OCSP-Responder
   nicht erreichbar ist (`dist/index.js:7958-7961`) — das wuerde die
   freigegebene Option B (24 Stunden Gnadenfrist) wieder aushebeln. Mit
   `'prefer'` gibt sie bei Ausfall `unknown` zurueck, und `TrustEvaluator` wirft
   dann **nicht** (`dist/index.js:8169-8175` wirft nur bei `revoked`).
2. Eine Annahme kann deshalb nur aus dem eigenen Checker kommen: die
   Bibliothek kann durch `revoked` ablehnen, aber nicht freigeben. Ein
   `RevokedCertificateError` fuehrt weiterhin zur Ablehnung
   (`code = "certificate_revoked"`, `dist/index.js:98-100`, ->
   `issuer_certificate_revoked`, `src/service/limits.ts:76`).
3. Umgekehrt kann der eigene Checker die Bibliothek nicht ueberstimmen: er
   entscheidet danach und lehnt unabhaengig ab, unter anderem auch dann, wenn
   die Bibliothek `good` gemeldet hat. Testbeleg: "gesperrtes
   Aussteller-Zertifikat -> Praesentation abgelehnt
   (issuer_certificate_revoked)" in `src/service/issuer-revocation.test.ts`.
4. Die Reihenfolge ist bewusst so gewaehlt und nicht umgekehrt: der eigene
   Check steht hinter der Kettenpruefung der Bibliothek, damit OCSP nicht fuer
   Zertifikate aus einer noch nicht vertrauenswuerdigen Kette abgefragt wird.

Bekannte Nachteile dieser Zweitpruefung, bewusst in Kauf genommen und hier
festgehalten:

- **Doppelte Abfrage.** Beide Instanzen fragen beim Responder an. Eigener Cache
  (`nextUpdate`, 24-h-Obergrenze) auf der einen, `InMemoryCache` der
  Bibliothek auf der anderen Seite. Bei jeder Praesentation mit leerem
  Bibliothekscache kommt ein zweiter HTTP-Abruf hinzu.
- **Schwaecherer Zweitpfad.** Der Bibliotheks-OCSP-Client sendet keine Nonce
  (`dist/index.js:7602-7620`) und setzt keine Zeit- oder Groessengrenze. Er ist
  deshalb **nicht** die entscheidende Instanz, sondern nur ein zusaetzliches
  Ablehnungssignal.
- **`console.warn` der Bibliothek** — **gelöst** durch den Logfilter aus
  `src/lib/library-log-filter.ts`, siehe den Abschnitt "Logfilter für die
  Warnungen der Bibliothek" oben. Die dortige Formulierung "verstoesst gegen
  die eigene Regel" galt fuer das Betriebslog; sie ist mit dem Filter nicht mehr
  zutreffend.

### Logfilter für die Warnungen der Bibliothek (bewusster Eingriff)

Die Bibliothek meldet den Fehlschlag ihres eigenen OCSP-Versuchs selbst nach
`console.warn` und schreibt dabei Subject, Responder-URL und rohe
Fehlermeldung in den Prozesslog (`dist/index.js:7921`, `:7951`; die Meldung
bei `:7748` enthält zusätzlich die Seriennummer). Das verletzt die
Anforderung, dass keine Anspruchswerte im Log landen — und es geschieht
gerade dann, wenn ein Responder ausfällt, also im Betriebsfall, den die
Gnadenfrist abfedern soll.

Die Bibliothek bietet dafür **keinen** Schalter: kein Logger-Parameter, keine
`NODE_ENV`-Logik, nur ein einziger Export-Einstiegspunkt (geprüft in
`node_modules/@openeudi/openid4vp`). Deshalb gibt es
`src/lib/library-log-filter.ts`, installiert einmalig beim Prozessstart
(`src/service/run.ts`):

- Umhüllt wird ausschließlich `console.warn`; `error`, `log` und `info`
  bleiben unberührt (Test: "console.error und console.log werden nicht verändert").
- Unterdrückt wird ausschließlich, wenn das **erste** Argument eine
  Zeichenkette ist, die mit `[openid4vp]` beginnt. Alle sechs Warnstellen der
  Bibliothek schreiben genau so.
- Kein Zustand, kein Puffer: alle anderen Warnungen gehen unverändert und mit
  allen Argumenten weiter. Die eigenen Dev-Modus-Warnungen aus `src/config.ts`
  und `src/service/bootstrap.ts` bleiben sichtbar (Test: "die Dev-Modus-Warnungen
  aus config.ts erreichen das Log weiterhin").
- End-to-End belegt: "Gegenprobe: ohne Filter schreibt die Bibliothek bei
  OCSP-Ausfall nach console.warn" zeigt die echte Bibliothekszeile mit
  Subject im Log, "mit installiertem Filter bleibt von derselben Präsentation
  keine Bibliothekszeile im Log" zeigt, dass sie entfällt.

**Bewusste Grenze des Eingriffs:** Die Umhüllung gilt prozessweit, also auch
für Code, der den Filter nicht kennt, und ein gleichzeitiges Umschreiben von
`console.warn` durch Fremdcode würde nicht bemerkt. Deshalb wird der Filter
genau einmal beim Start installiert und `restore` stellt exakt dieselbe
Funktion wieder her (Test: "restore stellt den ursprünglichen Zustand wieder her").

### Überwachung: Präfixbindung des Logfilters (B11)

Der Filter ist an **zwei** Annahmen gebunden, und keine davon wird von einem Test abgesichert:

1. Alle Ausgaben der Prüfbibliothek gehen über `console.warn`.
2. Alle beginnen mit dem Präfix `[openid4vp]` (`src/lib/library-log-filter.ts:41`).

Beide können sich durch ein Update von `@openeudi/openid4vp` ändern. Der Filter
wird dann **nicht** zu breit, sondern zu **eng**: er greift stillschweigend
nicht mehr, und Subject, Responder-URL und Seriennummer landen wieder im
Prozesslog. Niemand bemerkt das ohne Nachsehen, weil kein Test die Bibliothek
liest.

**Deshalb: nach jedem Update von `@openeudi/openid4vp` ausführen.**

```bash
zsh docs/pruefmittel-ocsp-logfilter.sh
```

Das Werkzeug liest das Präfix aus dem Filter selbst, listet alle
`console.*`-Aufrufe der Bibliothek auf und vergleicht zeilenweise. Ausgabe
und Exit-Code:

| Exit | Bedeutung | Handlung |
|---|---|---|
| `0` | Filter deckt alle Ausgaben ab | nichts zu tun |
| `1` | Abweichung: N Ausgaben ohne Präfix | Präfix anpassen oder Meldung einzeln bewerten (enthält sie Zertifikatsdaten?) |
| `2` | Werkzeugfehler (Datei fehlt) | Dependencies installieren |

Aktueller Stand (Commit siehe `docs/gesamtstatus-2026-09-25.md`, B11):
6 Ausgaben, alle mit Präfix, 0 Abweichungen.

Das Werkzeug benutzt bewusst `grep -F` und nicht `grep -E`: mit `-E` wäre
`[openid4vp]` eine Zeichenklasse, der Vergleich wäre blind und würde jede
Änderung als „ok" melden. Genau dieser Fehler war in der ersten Fassung
vorhanden und wurde durch eine Negativprobe aufgedeckt (Präfix künstlich auf
`[openid4vp-core` gesetzt: korrektes Werkzeug meldet 6 Abweichungen und
Exit 1).

Bekannte, bewusst nicht abgesicherte Randfälle: Warnungen über
`process.emitWarning`, `process.stdout.write` oder `console.debug` fallen
ebenfalls durch das Raster. Das Werkzeug listet `console.debug` und
`console.trace` mit auf, erkennt aber keine anderen Kanäle; für
`process.emitWarning` gibt es bisher keinen Beleg in der Bibliothek
(`grep -c emitWarning` = 0).

### Bewusster Kompromiss: Nonce ist nicht verpflichtend (OCSP-Antwort)

Unser OCSP-Client sendet **immer** eine Nonce (16 Zufallsbytes,
`src/onboarding/ocsp-revocation.ts:217` und `:241`), und eine Antwort, die eine
Nonce **beantwortet**, muss exakt der gesendeten entsprechen — zeitkonstant,
sonst `revocation_list_malformed` (`:319`).

**Antwortet ein Responder nicht mit einer Nonce, wird das akzeptiert.** Das ist
eine bewusste Entscheidung, kein Versehen, und im Kopfkommentar von
`src/onboarding/ocsp-revocation.ts` (Schritt 6) festgehalten.

| | |
|---|---|
| **Begründung** | Nicht alle OCSP-Responder beantworten die Nonce-Erweiterung; RFC 6960 behandelt sie als optional. Eine Pflicht dazu hätte in der Praxis echte Interop-Ausfälle verursacht, weil eine große Zahl verbreiteter Responder sie ignoriert. |
| **Verbleibendes Risiko** | Bei Respondern ohne Nonce-Unterstützung bleibt eine **theoretische Replay-Lücke**: eine aufgezeichnete, echte `good`-Antwort kann zeitversetzt wieder eingespielt werden. Sie ist auf das Zeitfenster der Antwort begrenzt und nicht mit einer Fälschung verbunden. |
| **Kompensierende Kontrolle** | Strenge Zeitbindung: `thisUpdate` darf nicht in der Zukunft liegen, `nextUpdate` ist **Pflicht** (ohne sie `revocation_list_expired`), und ein überschrittenes `nextUpdate` wird abgelehnt (`assertFresh`, `:344-350`). Zusätzlich begrenzt der Cache die Wiederverwendung auf `min(nextUpdate, jetzt + 24 h)`. |
| **Test** | "Responder ohne Nonce -> akzeptiert, Zeitbindung gilt (Dokumentierte Ausnahme)" sowie "falsche Nonce in der Antwort -> revocation_list_malformed (Replay abgewehrt)" in `src/onboarding/ocsp-revocation.test.ts`. |
| **Wenn strenger gewünscht** | Eine Nonce-Antwort verpflichtend zu machen ist eine Einzeiler-Änderung (`:319` von `if (echoed && …)` auf `if (!echoed || …)`) — kostet aber die genannte Interop-Fähigkeit. Entscheidung liegt beim Betreiber. |

Abgrenzung: Das betrifft **unsere** Implementierung. Dass die Prüfbibliothek
gar keine Nonce sendet (`dist/index.js:7602-7620`), ist ein davon getrennter
Befund — siehe den Abschnitt zur Zweitprüfung weiter oben.

### Gnadenfrist: was genau gilt

Die freigegebene Entscheidung (Option B) steht in
`docs/entscheidung-ocsp-fail-modus.md`. Kurzfassung, jeweils mit Testbeleg in
`src/onboarding/ocsp-revocation.test.ts`:

| Situation | Ergebnis | Test |
| --- | --- | --- |
| `jetzt < nextUpdate` | gecachter Status, keine Abfrage | "Zustand A: innerhalb nextUpdate wird der Cache genutzt, keine zweite Anfrage" |
| `nextUpdate <= jetzt <= nextUpdate + 24 h`, letzter Status `good`, Abfrage scheitert | `good` | "Zustand B: nach nextUpdate, aber innerhalb der Frist, wird die veraltete good-Antwort genutzt" |
| exakt bei `nextUpdate + 24 h` | noch `good` | "Zustand C: exakt am Ende der 24-Stunden-Frist noch good, 1 ms spaeter Ablehnung" |
| 1 ms nach dem Fristende | Ablehnung `revocation_check_failed` | dieselbe Zeile, zweite Assertion |
| ohne vorherige verifizierte Antwort | Ablehnung | "Zustand C: ohne Vorabantwort gibt es keine Gnadenfrist" |
| `revoked` / `suspended` im Cache | nie `good`, auch nicht bei Ausfall | "Zustand C: revoked wird nie weich behandelt", "Zustand C: suspended wird nie weich behandelt" |
| `unavailableMode: 'fail-closed'` (Default) | Ablehnung trotz Cache | "fail-closed (Default) lehnt auch mit vorhandener Vorabantwort ab" |

Der Dienst startet mit `unavailableMode: 'bounded-soft-fail'`
(`src/service/bootstrap.ts:80-88`). Es gibt keinen Konfigurationsschalter, mit
dem sich die Frist verlaengern laesst; ein laengerer Wert als 24 Stunden ist
nicht vorgesehen.

## 6. Datenschutzbezogene Umsetzung vs. PLAN

- Die Planung sieht vor, nur pseudonymisierte/synthetische Daten loggen, keine Wallet-Identifikatoren, vp_token nur flüchtig verarbeiten. Umsetzung: Audit-Log ohne PII (`src/service/audit.ts`), vp_token wird in `handlePresentation` nur zur Verifikation genutzt und **nicht persistiert**; Ergebnisse (freigegebene Claim-Werte) werden flüchtig gehalten und nach Ablauf der Sitzungs-TTL gelöscht (`getResult`).

## 7. Reproduzierbare Check-Befehle

```bash
npm audit                     # 0 Schwachstellen
git ls-files | grep -E 'node_modules|\.env|\.pem|\.key|secret'   # keine Treffer
npm ls --all                  # Abhängigkeitsbaum (siehe Abschnitt 4)
npm test                      # 695 Tests in 47 Dateien grün
zsh docs/pruefmittel-ocsp-logfilter.sh   # Logfilter deckt alle Bibliotheks-Ausgaben ab (B11)
npm run typecheck             # fehlerfrei
```