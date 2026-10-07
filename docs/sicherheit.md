# Sicherheit

English version: [security.md](security.md)

Dieses Dokument beschreibt, welche Sicherheitseigenschaften der Dienst im Code
umsetzt, wie sie getestet sind und welche Lücken bekannt sind. Es richtet sich
an Entwicklerinnen und Entwickler sowie Sicherheitsverantwortliche, die den
Dienst vor einer Pilotierung bewerten.

Schwachstellen bitte vertraulich melden, siehe [SECURITY.md](../SECURITY.md).

## 1. Zusammenfassung

- **Prototyp, nicht für den Produktionsbetrieb.** Es gibt keine externe
  Sicherheitsprüfung dieser Codebasis, keinen Penetrationstest und keine
  Zertifizierung. Zum Zeitpunkt der Bibliotheksauswahl lag auch kein externes
  Audit der Protokollbibliothek `@openeudi/openid4vp` vor.
- **Teststand.** Der Dienst wurde Ende zu Ende ausschließlich gegen die
  Mock-Wallet dieses Repositorys getestet. Mit einer echten Wallet, einer
  Sandbox (auch nicht der SPRIND-Sandbox) oder einer nationalen Wallet wurde er
  noch nicht getestet. Einzelheiten: [Interoperabilitätsmatrix](interop-matrix.md).
- **Abhängigkeiten.** `npm audit` meldet für das committete `package-lock.json`
  0 Schwachstellen. Die CI führt `npm audit --audit-level=high` bei jedem Push
  und jedem Pull Request aus.
- **Geheimnisse.** Im Repository liegen keine echten Schlüssel, Zertifikate oder
  Zugangsdaten. Im Entwicklungsbetrieb entsteht sämtliches Schlüsselmaterial als
  TEST-Material im Arbeitsspeicher und wird weder gespeichert noch geloggt.

## 2. Was der Dienst umsetzt

| Eigenschaft | Umsetzung | Beleg |
|---|---|---|
| Start nur mit sicherer Konfiguration (fail closed) | Ohne echte Verifier-Identität (`ATTACK_VERIFIER_KEY_PEM`, `ATTACK_VERIFIER_CERT_CHAIN_PEM`) und ohne Aussteller-Anker (`ATTACK_ISSUER_TRUST_ANCHORS_PEM`) bricht der Start mit Exit Code 1 ab. Testmaterial, Testmandanten und abgeschaltete Prüfungen gibt es nur mit `ATTACK_DEV_MODE=true` außerhalb von `NODE_ENV=production`, jeweils mit deutlicher Warnung. `ATTACK_ALLOW_SELF_SIGNED=true` ist in Produktion verboten. | `bootstrapService` in `src/service/bootstrap.ts`, `loadConfig` in `src/config.ts`; Test `src/service/produktionsschalter.test.ts` |
| API-Schlüssel | Je Mandant ein serverseitiger Schlüssel als `authorization: Bearer`. Gespeichert wird nur der SHA-256-Hash. | `src/service/tenant.ts` |
| Mandantentrennung | Eine Sitzung eines fremden Mandanten ist nicht von einer unbekannten zu unterscheiden (`not_found`). | [Fehlercodes](fehlercodes.md) |
| Replay-Schutz | `state` und Nonce je Sitzung; eine Sitzung kann genau einmal eine Präsentation annehmen, ein zweiter Versuch endet mit `session_reused`. | `src/lib/session.ts`; Test `src/service/fehlerbilder.test.ts` |
| Ergebnis genau einmal | Ein fertiges Ergebnis wird genau einmal ausgeliefert und danach entfernt; ohne Abruf verfällt es nach 60 Sekunden (einstellbar). | Test `src/service/ergebnis-einmal.test.ts` |
| Datensparsamkeit | Das Ergebnis enthält nur die angefragten Claims, auch wenn das Credential mehr trägt. | `nurAngefragteClaims` in `src/service/profile.ts`; Test `src/service/e2e-vollablauf.test.ts` |
| Verschlüsselte Antworten | `direct_post.jwt` mit `ECDH-ES` und `A128GCM` oder `A256GCM`, frisches Schlüsselpaar je Sitzung. Die Entschlüsselung übernimmt die Bibliothek. | `src/onboarding/jar.ts`, `src/service/service.ts`; Test `src/service/jar-parity.test.ts` |
| Eingabegrenzen | Body höchstens 64 KiB, `vp_token` höchstens 32 KiB, JWE höchstens 48 KiB, höchstens 64 Disclosures, höchstens 32 Claims je Anfrage. | `src/service/limits.ts`; Test `src/service/fehlerbilder.test.ts` |
| Feste Fehlercodes | Antworten tragen feste Codes, nie Rohmeldungen aus Bibliotheken oder Ausnahmen. | `presentationErrorCode` in `src/service/limits.ts`, [Fehlercodes](fehlercodes.md) |
| Ratenbegrenzung | Je Prozess: 120 Anfragen je 60 Sekunden auf öffentlichen Routen, 60 je Mandant (Standardwerte, einstellbar über `ATTACK_RATE_LIMIT_*`). | `src/service/rate-limit.ts`, `src/config.ts`; Test `src/service/rate-limit.test.ts` |
| HTTP-Header | `x-content-type-options: nosniff`, `cache-control: no-store`, `x-frame-options: DENY` auf jeder Antwort; bewusst kein CORS. TLS und HSTS gehören in den Reverse Proxy. | `setzeSicherheitsHeader` in `src/service/app.ts`; Test `src/service/security-headers.test.ts`; [Deployment](deployment.md) |
| Logs ohne personenbezogene Daten | Strukturierte Logs ohne Claim-Werte; das Audit-Log enthält nur Zeitstempel, Mandant und Ereignisname. | `src/lib/logger.ts`, `src/service/audit.ts`; Tests `src/service/log-ohne-claims.test.ts`, `src/service/audit-inhalt.test.ts` |
| Container | Das `Dockerfile` startet den Dienst als Benutzer `node`, nicht als root. | `Dockerfile` |

## 3. Vertrauen und Sperrprüfung

### Welcher Mechanismus wofür

| Mechanismus | Gilt für | Stand |
|---|---|---|
| **Aussteller-Vertrauensanker** | Kette des Ausstellerzertifikats im Credential | Nur ausdrücklich konfigurierte Anker. Keine Trust List nach ETSI TS 119 612 (LOTL). |
| **OCSP** (RFC 6960) | Ausstellerzertifikate der vorgelegten Credentials, Blatt und Zwischenzertifikate bis zum Anker; der Anker selbst wird nicht geprüft | `OcspRevocationChecker` in `src/onboarding/ocsp-revocation.ts`, beim Start verdrahtet in `src/service/bootstrap.ts`. Getestet nur gegen einen lokalen Test-Responder. |
| **Token Status List** | Der Status des Credentials selbst, nicht des Zertifikats | `TokenStatusListChecker` in `src/service/credential-status.ts`, beim Start verdrahtet. Gegen echte Status-List-Aussteller nicht erprobt. |
| **CRL** (RFC 5280) | vorgesehen für Zugriffs- und Registrierungszertifikate (WRPAC, WRPRC) | `CrlRevocationChecker` in `src/onboarding/crl-revocation.ts` ist implementiert und getestet, **wird beim Start aber nirgends eingesetzt.** |
| **Onboarding-Gate** (WRPAC, WRPRC) | Zugriffs- und Registrierungszertifikate der Relying Party | Nur aktiv, wenn `ATTACK_ONBOARDING_ACCESS_CA_PEM` und `ATTACK_ONBOARDING_WRPRC_ISSUER_PEM` gesetzt sind. Ist das Gate aktiv, prüft es die Sperrung über denselben OCSP-Prüfer. Ohne Gate meldet `/ready` im Produktionsbetrieb `onboarding: failed`. |

Im Entwicklungsbetrieb (`ATTACK_DEV_MODE=true`) sind OCSP und Token Status List
abgeschaltet; der Dienst warnt beim Start ausdrücklich davor.

### Verhältnis zur Prüfung in der Bibliothek

Die Bibliothek `@openeudi/openid4vp` prüft beim Aufruf von
`verifyAuthorizationResponse` selbst die Sperrung (zuerst OCSP, dann CRL als
Rückfall). Der Dienst ruft sie mit `revocationPolicy: 'prefer'` auf und führt
danach seine eigene OCSP-Prüfung aus (`enforceIssuerChainRevocation` in
`src/service/issuer-revocation.ts`). Daraus folgt:

1. Mit `'prefer'` meldet die Bibliothek bei nicht erreichbarem Responder den
   Status `unknown` und lehnt nicht ab. Sie lehnt nur bei `revoked` ab. Die
   Bibliothek kann also ablehnen, aber nicht freigeben.
2. Die verbindliche Entscheidung trifft die eigene Prüfung danach. Sie lehnt
   auch dann ab, wenn die Bibliothek `good` gemeldet hat. Test: „gesperrtes
   Aussteller-Zertifikat -> Präsentation abgelehnt (issuer_certificate_revoked)“
   in `src/service/issuer-revocation.test.ts`.
3. Die eigene Prüfung läuft bewusst nach der Kettenprüfung der Bibliothek,
   damit OCSP nicht für Zertifikate aus einer nicht vertrauenswürdigen Kette
   abgefragt wird.

Bekannte Nachteile dieser doppelten Prüfung:

- **Doppelte Abfrage.** Bei leerem Cache der Bibliothek fragen beide Instanzen
  beim Responder an.
- **Schwächere Zweitprüfung.** Der OCSP-Client der Bibliothek sendet keine
  Nonce und setzt keine eigene Zeit- oder Größengrenze. Er ist deshalb nur ein
  zusätzliches Ablehnungssignal, nicht die entscheidende Instanz.

### Nonce in OCSP-Antworten ist nicht Pflicht

Der eigene OCSP-Client sendet immer eine Nonce (16 Zufallsbytes). Enthält die
Antwort eine Nonce, muss sie exakt passen (zeitkonstanter Vergleich), sonst
`revocation_list_malformed`. **Antwortet ein Responder ohne Nonce, wird das
akzeptiert.**

| | |
|---|---|
| **Begründung** | RFC 6960 behandelt die Nonce als optional, und viele verbreitete Responder beantworten sie nicht. Eine Pflicht würde den Betrieb mit diesen Respondern verhindern. |
| **Verbleibendes Risiko** | Bei Respondern ohne Nonce kann eine aufgezeichnete, echte `good`-Antwort innerhalb ihres Gültigkeitsfensters erneut eingespielt werden. |
| **Ausgleich** | `thisUpdate` darf nicht in der Zukunft liegen, `nextUpdate` ist Pflicht (sonst `revocation_list_expired`), ein überschrittenes `nextUpdate` wird abgelehnt. Der Cache gilt höchstens bis `min(nextUpdate, jetzt + 24 h)`. |
| **Tests** | „Responder ohne Nonce -> akzeptiert, Zeitbindung gilt (Dokumentierte Ausnahme)“ und „falsche Nonce in der Antwort -> revocation_list_malformed (Replay abgewehrt)“ in `src/onboarding/ocsp-revocation.test.ts` |
| **Strengere Variante** | Die Nonce zur Pflicht zu machen ist eine Änderung einer Bedingung in `evaluate` (`src/onboarding/ocsp-revocation.ts`). Sie kostet die Zusammenarbeit mit Respondern ohne Nonce. Die Entscheidung liegt beim Betreiber. |

### Gnadenfrist bei nicht erreichbarem OCSP-Responder

Der Dienst startet den OCSP-Prüfer im Modus `bounded-soft-fail`: Ist der
Responder nicht erreichbar, gilt eine zuvor verifizierte `good`-Antwort bis zu
24 Stunden über ihr `nextUpdate` hinaus weiter. Eine längere Frist ist nicht
konfigurierbar. Wird die Frist bei einer Präsentation genutzt, schreibt der
Dienst das Audit-Ereignis `issuer_revocation_grace_period`.

| Situation | Ergebnis | Test in `src/onboarding/ocsp-revocation.test.ts` |
|---|---|---|
| vor `nextUpdate` | Status aus dem Cache, keine Abfrage | „Zustand A: innerhalb nextUpdate wird der Cache genutzt, keine zweite Anfrage“ |
| nach `nextUpdate`, höchstens 24 h, letzter Status `good`, Abfrage scheitert | `good` | „Zustand B: nach nextUpdate, aber innerhalb der Frist, wird die veraltete good-Antwort genutzt“ |
| genau `nextUpdate + 24 h` | noch `good`; 1 ms später Ablehnung `revocation_check_failed` | „Zustand C: exakt am Ende der 24-Stunden-Frist noch good, 1 ms spaeter Ablehnung“ |
| keine zuvor verifizierte Antwort | Ablehnung | „Zustand C: ohne Vorabantwort gibt es keine Gnadenfrist“ |
| `revoked` oder `suspended` im Cache | nie `good`, auch nicht bei Ausfall | „Zustand C: revoked wird nie weich behandelt“, „Zustand C: suspended wird nie weich behandelt“ |
| Modus `fail-closed` (Standard der Klasse) | Ablehnung trotz Cache | „fail-closed (Default) lehnt auch mit vorhandener Vorabantwort ab“ |

## 4. Logfilter für Meldungen der Bibliothek

Die Bibliothek schreibt bei fehlgeschlagenen OCSP-, CRL- und Trust-List-Abrufen
Zertifikats-Subjects, Responder-URLs und Fehlertexte über `console.warn` in den
Prozesslog. Einen Schalter dafür bietet sie nicht. Das widerspricht der Regel,
dass keine Zertifikats- und Personendaten im Log landen, und tritt gerade im
Störungsfall auf.

Deshalb installiert der Dienst beim Start einen Filter
(`installLibraryLogFilter` in `src/lib/library-log-filter.ts`, aufgerufen in
`src/service/run.ts`):

- Er umhüllt nur `console.warn`; `error`, `log` und `info` bleiben unverändert.
- Er unterdrückt nur Meldungen, deren erstes Argument eine Zeichenkette ist,
  die mit `[openid4vp]` beginnt. Alle anderen Warnungen, auch die Warnungen des
  Entwicklungsbetriebs, gehen unverändert durch.
- Er gilt prozessweit und wird genau einmal installiert.

Tests: `src/lib/library-log-filter.test.ts` sowie „Gegenprobe: ohne Filter
schreibt die Bibliothek bei OCSP-Ausfall nach console.warn“ und „mit
installiertem Filter bleibt von derselben Praesentation keine Bibliothekszeile
im Log“ in `src/service/issuer-revocation.test.ts`.

**Grenze:** Der Filter hängt an zwei Annahmen über die Bibliothek: Alle
Meldungen gehen über `console.warn`, und alle beginnen mit `[openid4vp]`. In
Version 0.11.1 trifft das auf alle sechs Meldestellen zu. Ändert ein Update das
Präfix oder den Kanal, greift der Filter stillschweigend nicht mehr, und die
Daten erscheinen wieder im Log. Kein automatischer Test in diesem Repository
erkennt das. Nach jedem Update von `@openeudi/openid4vp` deshalb von Hand
prüfen:

```bash
grep -n -A1 -E "console\.(warn|log|error|info|debug|trace)\(" node_modules/@openeudi/openid4vp/dist/index.js
```

Jede gefundene Meldung muss mit `[openid4vp]` beginnen. Meldungen über
`process.emitWarning` oder `process.stdout.write` erfasst der Filter nicht; in
Version 0.11.1 kommen sie nicht vor.

## 5. Bekannte Lücken

1. **Keine Mandantenverwaltung für den Produktionsbetrieb.** Mandanten und
   ihre API-Schlüssel werden nur im Entwicklungsbetrieb angelegt
   (`DEV_TEST_TENANTS` in `src/service/bootstrap.ts`). Einen Weg, im
   Produktionsbetrieb Mandanten anzulegen, gibt es nicht; dort beantwortet der
   Dienst jede Anfrage auf Mandantenrouten mit 401.
2. **Keine Persistenz.** Sitzungen, Ergebnisse, Audit-Log und Ratenbegrenzung
   liegen im Arbeitsspeicher eines Prozesses. Ein Neustart löscht alles.
   Mehrere Instanzen teilen keinen Zustand.
3. **Audit-Log ohne Beweiskraft.** Die Einträge sind hash-verkettet, sodass
   eine nachträgliche Änderung erkennbar ist. Wer den Prozess kontrolliert,
   kann die Kette aber neu berechnen; Signatur, Zeitstempeldienst oder externer
   Speicher fehlen ([Bedrohungsmodell](bedrohungsmodell.md), S15).
4. **Kein TLS im Dienst.** Der Dienst spricht HTTP. TLS, HSTS und die
   Weiterleitung auf HTTPS muss ein Reverse Proxy übernehmen
   ([Deployment](deployment.md)).
5. **Keine Schlüsselverwaltung.** Der Verifier-Schlüssel wird aus einer
   PEM-Datei geladen. Es gibt keine Anbindung an KMS oder HSM und keine
   Schlüsselrotation.
6. **Keine Interoperabilität nachgewiesen.** Getestet wurde nur gegen die
   Mock-Wallet dieses Repositorys ([Interoperabilitätsmatrix](interop-matrix.md)).
7. **Verifier-Identität im Entwicklungsbetrieb.** Request Objects werden dort
   mit einem selbstsignierten TEST-Zertifikat signiert. Eine profilkonforme
   Wallet (HAIP) würde diese Identität ohne gültige Zugriffs- und
   Registrierungszertifikate ablehnen.
8. **Onboarding nicht vollständig.** Das Gate für WRPAC und WRPRC ist ohne
   zusätzliches Material aus; die CRL-Prüfung ist nicht verdrahtet; die
   Registrar-Anbindung fehlt.
9. **Sperrprüfung nur lokal getestet.** OCSP und Token Status List sind nur
   gegen lokale Testserver geprüft, nicht gegen produktive Responder oder
   Status-List-Aussteller.
10. **Kein mdoc.** Nur `dc+sd-jwt` wird unterstützt.
11. **Keine Konformitätsläufe.** In diesem Repository gibt es keinen Lauf der
    OIDF-Konformitätssuite und keinen externen HAIP-Konformitätstest.
12. **Hinweis zu `@sd-jwt/decode`.** Die Bibliothek bringt transitiv
    `@sd-jwt/decode`, `@sd-jwt/types` und `@sd-jwt/utils` in Version 0.19.0 mit.
    Diese Pakete sind als veraltet markiert; der Hinweistext nennt
    `GHSA-f9j6-8p6x-r9j6`. `npm audit` meldet dafür keinen Befund, und die
    Advisory war in der GitHub-Advisory-Datenbank nicht auffindbar. Ob Version
    0.19.0 betroffen ist, ist damit offen. Ein Wechsel setzt ein Update von
    `@openeudi/openid4vp` voraus.
13. **XML-Signaturbibliotheken.** `xadesjs`, `xmldsigjs` und `@xmldom/xmldom`
    kommen transitiv mit der Bibliothek (für deren LOTL-Verarbeitung). Der
    Dienst nutzt diesen Pfad nicht.
14. **Demo-Seite.** Die Demo (`npm run demo`) hat keinen CSRF-Schutz. Sie
    bindet nur an 127.0.0.1 und ist nicht für den Betrieb gedacht.

## 6. Datenschutz

- Der `vp_token` wird nur zur Prüfung verarbeitet und nicht gespeichert.
- Das Ergebnis enthält nur die angefragten Claim-Werte. Es liegt flüchtig im
  Arbeitsspeicher, wird genau einmal ausgeliefert und verfällt sonst nach der
  Ergebnis-TTL.
- Logs und Audit-Log enthalten keine Claim-Werte, keine Wallet-Kennungen und
  keine Zugangsdaten.
- Eine Datenschutz-Folgenabschätzung und eine fachliche Datenschutzfreigabe
  liegen nicht vor. Sie hängen vom Einsatz bei der jeweiligen Relying Party ab.

## 7. Abhängigkeiten

Laufzeitabhängigkeiten (exakte Versionen in `package.json` und
`package-lock.json`):

| Paket | Version | Lizenz | Zweck |
|---|---|---|---|
| `@openeudi/openid4vp` | 0.11.1 | Apache-2.0 | OpenID4VP, DCQL, signierte Request Objects, SD-JWT- und Key-Binding-Prüfung |
| `@openeudi/core` | 0.8.0 | Apache-2.0 | gemeinsame Typen und Hilfsfunktionen |
| `@openeudi/dcql` | 0.2.0 | Apache-2.0 | DCQL-Typen und Prüfung |
| `@peculiar/asn1-ocsp` | 2.9.5 | MIT | ASN.1-Strukturen für den eigenen OCSP-Client |

Entwicklungsabhängigkeiten sind unter anderem `jose`, `@peculiar/x509`
(TEST-Zertifikate), `typescript`, `eslint` und `vitest`. Die vollständige
Lizenzübersicht steht in [Lizenzen der Abhängigkeiten](lizenzen-abhaengigkeiten.md).

## 8. Selbst nachprüfen

```bash
npm ci
npm audit
npm ls --all
git ls-files | grep -E 'node_modules|\.env|\.pem|\.key|secret'
npm test
npm run typecheck
npm run lint
```

Der `git ls-files`-Befehl soll keine Treffer liefern. `npm ci`, `npm test`,
`npm run typecheck` und `npm run lint` laufen bei jedem Push auch in der CI,
dazu `npm run test:coverage` und `npm audit --audit-level=high`.
