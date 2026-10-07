# Fehlercodes

Verbindliche Liste der Fehlercodes, die der Verifier-Dienst nach außen gibt
(HTTP-Antwort `{"error": "<code>"}` bzw. `error` im Prüfergebnis) oder
intern im Audit-Log als Ursache führt. Codes sind stabile, kleingeschriebene
Bezeichner ohne Leerzeichen. Antworten enthalten **nie** Stacktraces, interne
Pfade oder Rohmeldungen aus Bibliotheken (Test: `src/service/fehlerbilder.test.ts`).

Grundsatz: Jeder Fehlerpfad führt zur Ablehnung. Kein Code steht für ein
positives Prüfergebnis.

## Sperrprüfung WRPAC/WRPRC (Onboarding-Gate)

Quelle: `src/onboarding/revocation.ts`, `src/onboarding/crl-revocation.ts`.
Nach außen erscheint am Dienst nur `tenant_registration_invalid` (HTTP 403,
siehe unten); der genaue Code steht im Audit-Log als `cause=<code>`.

| Code | Bedeutung |
|---|---|
| `certificate_revoked` | Zertifikat steht auf der Sperrliste (gesperrt). |
| `certificate_suspended` | Zertifikat ist ausgesetzt (CRL-Grund `certificateHold`). |
| `certificate_expired` | Ein Zertifikat der Kette (Blatt, Zwischenzertifikat, Anker) ist abgelaufen: `notAfter` + erlaubte Uhrabweichung liegt vor dem Prüfzeitpunkt (Haertung 9). |
| `certificate_not_yet_valid` | Ein Zertifikat der Kette ist noch nicht gültig: `notBefore` − erlaubte Uhrabweichung liegt nach dem Prüfzeitpunkt (Haertung 9). |
| `revocation_unavailable` | Sperrquelle nicht erreichbar, HTTP-Status ≠ 2xx oder Checker wirft eine unerwartete Ausnahme. |
| `revocation_timeout` | Sperrquelle antwortet nicht innerhalb der Zeitgrenze (Standard 5 s). |
| `revocation_list_too_large` | Sperrliste überschreitet die Größengrenze (Standard 1 MiB). |
| `revocation_list_signature_invalid` | Signatur der Sperrliste passt nicht zum ausstellenden Zertifikat. |
| `revocation_list_malformed` | Keine lesbare CRL, fremder Aussteller oder fehlendes `nextUpdate`. |
| `revocation_list_expired` | `nextUpdate` überschritten oder `thisUpdate` liegt in der Zukunft. |
| `revocation_status_unknown` | Checker liefert keinen ausdrücklichen Status oder einen unbekannten (auch `removeFromCRL` in einer Basis-CRL). |
| `revocation_source_missing` | Zertifikat nennt keine nutzbare Sperrquelle (kein http(s)-CRL-Distribution-Point). |

## Statusprüfung vorgelegter Credentials (Token Status List)

Quelle: `src/service/credential-status.ts`. Erscheint als `error` in der
Antwort von `POST /direct_post` (`valid: false`).

| Code | Bedeutung |
|---|---|
| `credential_revoked` | Statuswert 0x01 (INVALID). |
| `credential_suspended` | Statuswert 0x02 (SUSPENDED). |
| `credential_status_unknown` | Jeder andere Statuswert (0x03 und reservierte Werte). |
| `credential_status_missing` | Credential enthält keinen Statusverweis `status.status_list`. |
| `credential_status_reference_invalid` | Statusverweis unbrauchbar (Index, URI, http ohne Freigabe, Index außerhalb der Liste). |
| `status_list_unreachable` | Statusliste nicht erreichbar oder HTTP-Status ≠ 2xx. |
| `status_list_timeout` | Statusliste antwortet nicht innerhalb der Zeitgrenze (Standard 5 s). |
| `status_list_too_large` | Statusliste überschreitet die Größengrenze (Standard 1 MiB, entpackt 16 MiB). |
| `status_list_signature_invalid` | Unterzeichner nicht vertraut, Algorithmus nicht erlaubt oder Signatur ungültig. |
| `status_list_malformed` | Kein `statuslist+jwt`, `sub` ≠ URI, `iat`/`exp` fehlen, `bits`/`lst` ungültig. |
| `status_list_expired` | `exp` überschritten oder `iat` liegt in der Zukunft. |
| `certificate_expired` / `certificate_not_yet_valid` | Das Signaturzertifikat der Statusliste ist abgelaufen bzw. noch nicht gültig (Haertung 9). |

## HTTP-Schicht (alle Endpunkte)

Quelle: `src/service/app.ts`, `src/service/limits.ts`.

| Code | HTTP | Bedeutung |
|---|---|---|
| `unauthorized` | 401 | Kein oder unbekannter API-Schlüssel (auch für unbekannte Pfade ohne Schlüssel). Ausschließlich dieser Fall. Präsentationen auf `/direct_post`, die der Dienst **nicht verarbeiten konnte** (`ok: false`), tragen 422; inhaltlich abgelehnte (`ok: true, valid: false`) tragen 200. Siehe unten. |
| `not_found` | 404 | Sitzung/Route unbekannt, gelöscht, verbraucht, abgelaufen **oder** gehört einem fremden Mandanten – bewusst nicht unterscheidbar. |
| `rate_limited` | 429 | Zu viele Anfragen im Ratenfenster. Voreinstellung 60 je Mandant und 120 je IP-Adresse in 60 Sekunden, je Route und Identität getrennt gezählt. Einstellbar über `ATTACK_RATE_LIMIT_TENANT_PER_WINDOW`, `ATTACK_RATE_LIMIT_PUBLIC_PER_WINDOW` und `ATTACK_RATE_LIMIT_WINDOW_SECONDS`; `docs/deployment.md`. Die Antwort trägt `x-ratelimit-limit` (mit dem tatsächlich wirksamen Wert), `x-ratelimit-remaining` und `retry-after` in Sekunden. `/live`, `/health`, `/ready` und `/metrics` sind ausgenommen. |
| `payload_too_large` | 413 | Anfragekörper über 64 KiB (Content-Length oder beim Lesen gezählt). |
| `invalid_json` | 400 | Körper von `POST /v1/verification-requests` ist kein JSON-Objekt. |
| `invalid_request` | 400 | `POST /direct_post` ohne `state`/`vp_token` bzw. `response` oder kein lesbares JSON. |
| `internal_error` | 500 | Unerwarteter interner Fehler; Details nur als Fehlertyp im Betriebslog. |

## Prüfanfrage (`POST /v1/verification-requests`)

| Code | HTTP | Bedeutung |
|---|---|---|
| `claims_invalid` | 400 | `claims` kein Array, leer, mehr als 32 Einträge, Name außerhalb `[A-Za-z0-9_.-]{1,64}` oder nicht im Mandantenprofil. |
| `vct_invalid` | 400 | `vct` leer, länger als 256 Zeichen, mit Leer-/Steuerzeichen oder außerhalb des Mandantenprofils. |
| `registration_ref_invalid` | 400 | `registration_ref` hat nicht die erwartete Form. |
| `registration_ref_mismatch` | 400 | `registration_ref` passt nicht zur WRPRC des Mandanten. |
| `tenant_not_registered` | 403 | Eigener Mandant hat kein Registrierungsmaterial (nur mit Onboarding-Gate). |
| `tenant_registration_invalid` | 403 | Registrierungsmaterial des eigenen Mandanten ungültig (Ursache im Audit-Log, siehe Onboarding unten). |

## Onboarding-Gate (interne Ursachen, keine HTTP-Codes)

Diese Codes verlassen den Dienst **nicht**. `RelyingPartyOnboardingGate.verifyTenant`
verpackt sie in `ErrTenantRegistrationInvalid` mit `reason`, und der Client sieht
dann nur `403 {"error":"tenant_registration_invalid"}`. Sie stehen im Audit-Log
als `reason=<code>`, damit der Betrieb die Ursache belegen kann, statt sie zu
raten. Quelle: `src/onboarding/errors.ts`, `src/onboarding/onboarding-gate.ts:119-122`.

| Code | Bedeutung |
|---|---|
| `entitlement_unknown` | Policy-OID des WRPAC liegt unter dem Entitlement-Arc, aber nicht in der konfigurierten Karte. Siehe `docs/entitlement-betrieb.md`. |
| `wrpac_policy_missing` | WRPAC trägt keine EUDIWRP-Policy-OID. |
| `wrpac_contact_san_missing` | WRPAC hat keine Kontakt-SAN. |
| `wrpac_key_usage_invalid` | WRPAC ohne `digitalSignature` in der KeyUsage. |
| `wrpac_ext_key_usage_invalid` | WRPAC ohne `clientAuth` und ohne `anyEKU`. |
| `trust_path_not_found` | WRPAC- oder WRPRC-Kette führt zu keinem konfigurierten Anker. |
| `wrprc_malformed` | WRPRC ist kein lesbares JWT. |
| `wrprc_type_invalid` | WRPRC-`typ` ist nicht `rc-wrp+jwt`. |
| `wrprc_unsupported_alg` | WRPRC-Algorithmus ist nicht `ES256` oder `ES384`. |
| `wrprc_header_invalid` | `x5c` fehlt oder ist unbrauchbar. |
| `wrprc_signature_invalid` | JWS-Signatur des WRPRC ungültig. |
| `wrprc_claims_missing` | Pflicht-Claim fehlt oder hat den falschen Typ (`sub`, `iat`, `exp`, `registry_uri`, `entitlements`, `policy_id`). |
| `wrprc_policy_id_missing` | `policy_id` enthält die WRPRC-Policy-OID nicht. |
| `wrprc_not_yet_valid` | `iat` liegt in der Zukunft. |
| `wrprc_expired` | `exp` ist überschritten. |
| `wrprc_validity_window_invalid` | `exp` ≤ `iat` oder Fenster länger als 12 Monate. |
| `wrprc_entitlement_missing` | Kein Entitlement des WRPRC steht in `allowedEntitlements` des Verifiers. |
| `unspecified` | Kein benannter Code, zum Beispiel ein WRPAC ganz ohne Entitlement. |
| `certificate_expired` / `certificate_not_yet_valid` | Zertifikat der geprüften Kette zeitlich ungültig. |
| `certificate_revoked` / `certificate_suspended` | Statuswert 0x01 / 0x02. |
| `revocation_status_unknown` | Anderer Statuswert, auch `undefined`. |
| `revocation_timeout` | Sperrquelle antwortet nicht innerhalb der Grenze (Standard 5 s). |
| `revocation_unavailable` | Sperrquelle nicht erreichbar. |
| `revocation_list_expired` / `revocation_list_malformed` / `revocation_list_signature_invalid` / `revocation_list_too_large` / `revocation_source_missing` | Sperrliste nicht auswertbar, im Vertrauensmodus weitergereicht. |
| `registrar_*` (`not_found`, `unavailable`, `timeout`, `status_invalid`, `signature_invalid`, `stale_response`, `response_malformed`, `intended_use_not_found`, `intended_use_not_active`) | Abfrage am Registrar. Im Dienst derzeit **nicht aktiv**, `RegistrarClient` ist ungenutzt. |

## Präsentation (`POST /direct_post`)

Antwort `{"ok": ..., "valid": false, "error": "<code>"}`. `ok=true` → HTTP 200,
ggf. mit `valid=false` (die Präsentation kam an, das Credential wurde
abgelehnt). `ok=false` → HTTP 422, die Präsentation selbst wurde nicht
angenommen.

**Die beiden Fälle sind nicht dasselbe, und der Status sagt nur das eine.**
`ok` sagt, ob der Dienst die Präsentation verarbeiten konnte. `valid` sagt, ob
sie gültig ist. Eine Präsentation kann also gut verarbeitet (`ok: true`) und
inhaltlich abgelehnt sein (`valid: false`) — das ist HTTP **200**. 422 bedeutet
ausdrücklich *nicht*, dass eine Präsentation abgelehnt wurde, sondern dass sie
nicht verarbeitet werden konnte: unbekannte oder abgelaufene Sitzung,
Formfehler, Replay, JWE-Problem.

Im Auditlog sind die beiden Fälle ebenfalls unterscheidbar: nicht angenommene
Präsentationen erzeugen `presentation_rejected`, inhaltlich abgelehnte
`presentation_invalid` (beide Ereignisnamen aus `src/service/service.ts`).

| Feld `ok` | Feld `valid` | HTTP | Bedeutung |
|---|---|---|---|
| `false` | `false` | 422 | nicht verarbeitbar: unbekannte Sitzung, Formfehler, Replay, JWE-Problem |
| `true` | `true` | 200 | gültig |
| `true` | `false` | 200 | verarbeitet und inhaltlich abgelehnt, Grund in `error` |

**401 ist für diese Route ausgeschlossen.** Die Route ist öffentlich, es gab
also nie etwas zu authentifizieren. 401 bleibt exklusiv für fehlenden oder
unbekannten API-Schlüssel, damit ein Client den beiden Fällen nicht
verwechselt. Betroffen von 422 sind die `ok: false`-Fälle, unter anderem
`unknown_state`, `state_invalid`, `vp_token_invalid`, `session_reused` und die
JWE-Fehlerpfade.

Bis zum 26.09.2026 trug jede abgelehnte Präsentation hier 401. Das war doppelt
belegt: die HTTP-Schicht-Tabelle führte 401 als „kein oder unbekannter
API-Schlüssel", dieser Abschnitt gleichzeitig als `ok=false`. Ein Client, der
der Doku folgte, hätte den Schlüssel erneuert, obwohl die Sitzung nicht mehr
existierte. `assertCleanError` in `src/service/fehlerbilder.test.ts` prüft die
Zuordnung seitdem als Invariante.

| Code | Bedeutung |
|---|---|
| `state_invalid` | `state` fehlt, ist leer oder länger als 128 Zeichen. |
| `vp_token_invalid` | `vp_token` nicht genau ein Credential mit genau einer Präsentation als Zeichenkette. |
| `vp_token_too_long` | Präsentation länger als 32 KiB. |
| `too_many_disclosures` | Mehr als 64 Disclosures. |
| `jwe_too_long` | JWE-Antwort länger als 48 KiB. |
| `malformed_jwe_header` | Protected Header der JWE-Antwort ist nicht lesbar. |
| `missing_kid` | JWE-Antwort ohne gültiges `kid`; das Feld muss der Sitzung entsprechen. |
| `jwe_not_supported` | JWE-Antwort, aber für die Sitzung ist kein Entschlüsselungsschlüssel verfügbar. |
| `jwe_decrypt_failed` | JWE nicht entschlüsselbar (Algorithmus, Schlüssel, Manipulation). |
| `missing_state_in_jwe` | Entschlüsselte Antwort ohne `state`. |
| `unknown_state` | Kein offener Auftrag zu diesem `state`. |
| `session_expired` | Sitzung abgelaufen. |
| `session_reused` | Sitzung bereits verbraucht (Replay-Schutz). |
| `unknown_session` | Sitzung unbekannt. |
| `state_mismatch` | Sitzung passt nicht zum Auftrag. |
| `issuer_trust_anchors_empty` | Keine Aussteller-Vertrauensanker konfiguriert (leere Liste zur Laufzeit). |
| `issuer_not_trusted` | Kein konfigurierter Anker steht auf der Trust List. |
| `issuer_certificate_revoked` | Ein Zertifikat der Aussteller-Kette ist gesperrt (OCSP `revoked` oder Bibliotheksbefund). Quelle: `src/onboarding/ocsp-revocation.ts`, `src/service/service.ts`. |
| `issuer_certificate_suspended` | Ein Zertifikat der Aussteller-Kette ist ausgesetzt (OCSP `revoked` mit Grund `certificateHold`). |
| `issuer_revocation_check_failed` | Die Sperrprüfung der Aussteller-Kette ist nicht zu einem verwertbaren Ergebnis gekommen: Sperrquelle nicht erreichbar, Zeitüberschreitung, unbrauchbare oder abgelaufene Antwort, fehlende Sperrquelle oder unbekannter Status. Der genaue Grund steht im Audit-Log. Details zur Gnadenfrist: `docs/entscheidung-ocsp-fail-modus.md`. |
| `certificate_expired` | Ein Aussteller-Zertifikat im `x5c` des Credentials ist abgelaufen, oder alle konfigurierten Aussteller-Anker sind abgelaufen (Haertung 9). |
| `certificate_not_yet_valid` | Wie oben, aber noch nicht gültig (Haertung 9). |
| `credential_signature_invalid` | Signatur des Credentials ungültig. |
| `credential_expired` | Credential abgelaufen. |
| `credential_malformed` | Credential nicht lesbar oder Aussteller nicht vertraut (Bibliothek). |
| `credential_format_unsupported` | Format nicht unterstützt. |
| `nonce_invalid` | Nonce/Key-Binding passt nicht. |
| `query_invalid` | DCQL-Anfrage ungültig. |
| `issuer_trust_anchor_not_found`, `issuer_chain_invalid` | Trust-/Kettenfehler der Bibliothek (nur mit `trustStore`). `issuer_certificate_revoked` und `issuer_revocation_check_failed` entstehen auch aus der eigenen Sperrprüfung, siehe oben. |
| `multi_credential_unsupported` | Mehrere Credentials in einer Antwort. |
| `presentation_invalid` | Jede andere Ablehnung durch die Prüfbibliothek (Freitext wird nie ausgegeben). |

## Audit-Ereignisse (nur Audit-Log, nie HTTP-Antwort)

Quelle: `src/service/audit.ts`. Diese Ereignisse erscheinen **ausschließlich** im Audit-Log des
Dienstes, nicht in Antworten an Mandanten.

| Ereignis | Bedeutung |
|---|---|
| `issuer_revocation_grace_period` | Für die Issuer-Zertifikatskette wurde eine veraltete `good`-OCSP-Antwort aus der begrenzten Gnadenfrist verwendet (Option B aus `docs/entscheidung-ocsp-fail-modus.md`). Der `detail` folgt dem Dienstformat `session=<uuid> reason=stale_good_reused` und nennt bewusst **keine** Zertifikats-, Claim- oder Responder-Daten. |

## Zeitangaben und Uhrabweichung (Haertung 9)

Alle Gültigkeitszeiträume (Zertifikate, WRPRC-`iat`/`exp`, Statuslisten-`iat`/`exp`)
werden mit einer erlaubten Uhrabweichung geprüft: `ATTACK_CLOCK_SKEW_SECONDS`,
0..300, Standard 60. Gültig ist ein Zertifikat, solange
`notBefore − Abweichung ≤ jetzt ≤ notAfter + Abweichung`.

Nicht nach außen, nur im Audit-Log und als 500 `internal_error`:
`verifier_certificate_expired` / `verifier_certificate_not_yet_valid` (Audit
`request_rejected`), wenn das eigene Verifier-Zertifikat zur Laufzeit abläuft.
Beim Start bricht der Dienst in diesem Fall mit klarer Meldung ab.
