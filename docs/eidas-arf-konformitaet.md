# eIDAS 2.0 / ARF-Mapping für Attack

Stand: 27. September 2026. Dieses Dokument ist ein präzises Capability-
Mapping für regulierte Kunden, keine Konformitätserklärung, keine
Zertifizierung und keine rechtliche Bewertung. `Erfüllt` bedeutet hier nur,
dass die konkrete Fähigkeit durch den genannten Code und Tests belegt ist.

## Statuslegende

- **Erfüllt**: im Code vorhanden und durch automatisierte Tests belegt.
- **Teilweise erfüllt**: ein belastbarer Teil ist vorhanden, aber mindestens
  ein Produktions- oder Ökosystemnachweis fehlt.
- **Nicht erfüllt/nicht nachgewiesen**: keine ausreichende Implementierung oder
  kein geeigneter Nachweis im Repository.

## Mapping

| ARF-Fähigkeitsbereich für Relying Parties | Status | Beleg und genaue Einschränkung |
|---|---|---|
| OpenID4VP Authorization Request mit DCQL | **Erfüllt** | `src/service/service.ts`, `src/onboarding/jar.ts`, `src/service/service.test.ts`, `src/service/jar-parity.test.ts` |
| Signiertes Request Object / JAR | **Erfüllt** | `src/onboarding/jar.ts`, `src/service/jar-parity.test.ts`; Signatur- und Header-Paritätsprüfungen sind automatisiert. |
| HAIP-orientierte Request- und Response-Profile | **Teilweise erfüllt** | `src/onboarding/jar.ts`, `src/service/direct-post-interop.test.ts`, `src/service/service.ts`; ein offizieller externer HAIP-/ARF-Konformitätstestlauf ist nicht enthalten. |
| `direct_post` und verschlüsselte `direct_post.jwt`-Antworten | **Erfüllt** | `src/service/app.ts`, `src/service/service.ts`, `src/service/direct-post-interop.test.ts`; die unterstützten Formate und Größenlimits sind begrenzt. |
| Nonce-, State- und Replay-Schutz | **Erfüllt** | `src/lib/session.ts`, `src/service/service.ts`, `src/service/erweiterung.test.ts`, `src/service/fehlerbilder.test.ts`. |
| VP-/SD-JWT-Validierung und Key Binding | **Teilweise erfüllt** | `src/service/service.ts` und `src/decision-test/*.test.ts` belegen die implementierten SD-JWT-Pfade. Eine vollständige ARF-/Wallet-Matrix für alle Credential-Formate ist nicht enthalten. |
| Credential-Statusprüfung | **Teilweise erfüllt** | `src/service/credential-status.ts`, `src/service/credential-status.test.ts`; reale Status-List-Aussteller und Produktionsdaten sind deploymentabhängig. |
| Issuer-Zertifikatskette, OCSP/CRL und Fail-Closed-Verhalten | **Teilweise erfüllt** | `src/onboarding/ocsp-revocation.ts`, `src/onboarding/crl-revocation.ts`, `src/service/issuer-revocation.test.ts`; reale Responder, Trust Lists und Produktionszertifikate wurden nicht nachgewiesen. |
| Verifier-Identität und Issuer-Trust-Anker | **Teilweise erfüllt** | `src/service/verifier-identity.ts`, `src/service/issuer-anchors.ts`, `src/service/bootstrap.ts`; produktive PKI-Konfiguration ist erforderlich, Testmaterial ist in Produktion verboten. |
| Relying-Party-Onboarding / WRPAC / WRPRC | **Teilweise erfüllt** | `src/onboarding/onboarding-gate.ts`, `src/onboarding/wrpac.ts`, `src/onboarding/wrprc.ts`, `src/service/onboarding-gate.test.ts`; das Gate ist strukturell vorhanden, echte Registrar-/Access-CA-Profile fehlen. |
| Datenminimierung und begrenzte Claim-Anfragen | **Teilweise erfüllt** | `src/service/profile.ts`, `src/service/limits.ts`, `src/service/log-ohne-claims.test.ts`; fachliche Datenschutzfreigabe, DPIA und kundenspezifische Zweckbindung sind nicht im Code beweisbar. |
| Sensible-Daten-Schutz in Fehlern und Logs | **Erfüllt** | `src/lib/library-log-filter.ts`, `src/lib/logger.ts`, `src/service/fehlerbilder.test.ts`, `src/service/log-ohne-claims.test.ts`; der Filter ist eine gezielte Prozessmaßnahme gegen bekannte Bibliothekslogs. |
| Abuse-Schutz und Eingabegrenzen | **Teilweise erfüllt** | `src/service/rate-limit.ts`, `src/service/limits.ts`, `src/service/rate-limit.test.ts`; Rate Limits und Sessions sind aktuell pro Prozess, nicht verteilt. |
| Liveness, Readiness und Betriebsmetriken | **Teilweise erfüllt** | `src/service/app.ts`, `src/service/metrics.ts`, `docs/observability.md`; die Metriken sind in-memory und es gibt keine formale SLO-/Alerting-Konfiguration. |
| Auditierbarkeit | **Teilweise erfüllt** | `src/service/audit.ts` und die Service-Tests enthalten stabile Ereigniscodes ohne Claims; unveränderliche, zentrale und revisionssichere Audit-Aufbewahrung ist nicht implementiert. |
| Verfügbarkeit und horizontale Skalierung | **Nicht nachgewiesen** | Sessions, Ergebnisse, Rate Limits, Audit und Metriken liegen in-memory; `docs/deployment.md` dokumentiert diese Grenze. |
| TLS, Secret Management und Produktionsbetrieb | **Teilweise erfüllt** | Fail-Closed-Konfiguration in `src/config.ts`/`src/service/bootstrap.ts` und `Dockerfile`; TLS-Terminierung und Secret Rotation müssen durch die Plattform erfolgen. |
| Offizieller ARF-/eIDAS-Konformitätsnachweis | **Nicht erfüllt/nicht nachgewiesen** | Es gibt keine akkreditierte Konformitätsprüfung, kein formales Testlabor-Ergebnis und keine rechtliche Freigabe im Repository. |

## Kundenrelevante Schlussfolgerung

Attack enthält belastbare Implementierungen für zentrale OpenID4VP-
Verifierpfade und defensive Prüfungen. Daraus folgt keine pauschale
eIDAS-2.0- oder ARF-Konformität. Vor einem regulierten Einsatz müssen
mindestens echte Trust- und Access-Zertifikate, Credential-Statusquellen,
produktive Wallet-Interoperabilität, externe Sicherheitsprüfung,
Datenschutzfreigabe, zentrale Zustands-/Rate-Limit-Speicherung und ein
offizieller Konformitätsnachweis ergänzt werden.
