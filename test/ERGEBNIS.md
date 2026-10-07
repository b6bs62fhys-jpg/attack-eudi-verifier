# ERGEBNIS – Verifier-Kandidaten-Test (WP2, je max. 4 h)

Kriterien: lokal < 1 h startbar · erzeugt signiertes Request Object mit DCQL für SD-JWT-VC · nimmt Test-vp_token an und validiert · Lizenz/Pflege passen.

| Kandidat | Version / Stand | Lokal startbar | Signiertes req. object (DCQL, SD-JWT) | Test-vp_token validiert | Lizenz / Pflege | Ergebnis |
|---|---|---|---|---|---|---|
| **waltid verifier-api2** | Docker `latest`, Release v1.0.0 (24.08.2026) | ✅ ~13 min | ✅ x509_hash, ES256+x5c, DCQL | ✅ `SUCCESSFUL`, 8 vp-Policies + vc_signature grün | Apache-2.0, aktiv | **BESTANDEN** |
| **eudi verify Kit** (`eudi-verify`) | Workspace 24.09.2026-Git, `@openeudi/openid4vp 0.10.0` | ✅ ~45 min | ✅ HAIP `createSignedAuthorizationRequest` (JWS, x5c, DCQL PID) | ✅ `verified`, claims `age_over_18`, token mintet | Apache-2.0, aktiv gepflegt | **BESTANDEN** |
| **miEUDIverifier** (Mibuw) | .NET 8, README-Update 10.09.2026, Einzelautor | ✅ (dotnet 10, ~25 min) | ❌ erzeugt KEIN Request Object selbst – delegiert per `POST /ui/presentations` an externes EUDI-Verifier-Backend (eudiw.dev bzw. Docker; JAR + Validierung dort) | ❌ hier liegt KEINE Krypto-Validierung; liest nur Backend-Antworten (auch SD-JWT ohne Signaturprüfung) | Apache-2.0 | **NICHT BESTANDEN** (Kriterium 2+3 nicht im Kandidaten) |

## Trust-Anchor-Prüfung je Kandidat (echte vs. übersprungene Vertrauensliste)

- **waltid verifier-api2:** echte krypto-Policy-Prüfungen (Signature, audience, nonce, KB-JWT-/sd_hash-/exp-/nbf-checks, `vc_policies.signature`) liefen **gegen die did:key-Issuer-Signatur**, **KEINE Vertrauensliste/Trust-Anchor** konfiguriert → Issuer-Signatur echt geprüft, **Vertrauensliste übersprungen (keine angebunden)**. Produktiv wäre (wie in deren Doku) `TrustedIssuers`/X.509-Anker zu setzen.
- **eudi verify Kit (Openid4vpEngine, Lab-Run):** Issuer-Signatur wurde **echt gegen das x5c-Zertifikat** geprüft, die **Ketten-Absicherung (Trust Anchor) war explizit ÜBERSPRUNGEN** – `EUDI_TRUST=skip` → `skipTrustCheck: true, acknowledgeInsecureTrust: true` (Server-Log: „issuer trust anchoring is DISABLED"). In Produktion bietet der Engine-Parameter `trustStore`/`trustedCerts` (StaticTrustStore) eine echte Ankerprüfung.
- **miEUDIverifier:** Trust-Anchor-Prüfung findet im Kandidaten **gar nicht statt (n. v.)**; die Entscheidung liegt im externen EUDI-Verifier-Backend. Dessen Local-Compose-Run nutzt `SPRING_PROFILES_ACTIVE=self-signed` und offene `VERIFIER_ATTESTATIONCLASSIFICATIONS` (alle Issuer akzeptiert) → im lokalen Lab **übersprungene/offene Vertrauensliste**.

## Empfehlung

**Basis: eudi verify Kit.** Erfüllt alle vier Kriterien, ist eine TypeScript-Bibliothek (Zielsprache des Projekts), lässt sich als Kern in den Verifier einbetten (kein Fremd-Server im Produktkern), baut via `@openeudi/openid4vp` ein HAIP-konformes signiertes Request Object (x509_hash, DCQL mit SD-JWT-VC + mdoc) und validiert den vp_token inkl. Trust-Store-Option. In Produktion muss die Trust-Anchor-Prüfung über `trustStore`/`trustedCerts` scharfgeschaltet werden (im Lab mit `skip` getestet).

**Alternative:** waltid verifier-api2 – ebenso bestanden, sofort lauffähig via Docker, volle Verifier-Server-API inkl. Policy-Suite; dafür Serverarchitektur im Kern (Fremdabhängigkeit) und keine Vertrauensliste im Test.

**miEUDIverifier:** trotz grüner 48/48 Unit-Tests und funktionierender App nicht als Basis geeignet – es ist ein Client für die EU-Referenz-Backend-API; signiertes Request Object und vp_token-Validierung liegen außerhalb des Kandidaten (eigenes Risiko, Einzelautor). Nicht in jedem Winkel für den deutschen Durchlauf nützlich, aber nur als Referenz/Wiederverwendung.

Evidence: `test/waltid/evidence/waltid-run.txt`, `test/evidence/mieudi-verify.txt`. The eudi-verify run log is not included in the public copy.