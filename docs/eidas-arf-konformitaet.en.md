# eIDAS 2.0 / ARF Mapping for Attack

Status: 27 September 2026. This is a precise capability mapping for regulated
customers. It is not a conformity declaration, certification, legal opinion or
security assurance. `Fulfilled` means only that the capability is implemented
and supported by the cited code and tests.

## Status legend

- **Fulfilled**: implemented and covered by automated tests.
- **Partially fulfilled**: a meaningful part exists, but a production or ecosystem proof is missing.
- **Not fulfilled/not demonstrated**: the repository does not contain sufficient implementation or evidence.

## Mapping

| ARF relying-party capability area | Status | Evidence and precise limitation |
|---|---|---|
| OpenID4VP Authorization Request with DCQL | **Fulfilled** | `src/service/service.ts`, `src/onboarding/jar.ts`, `src/service/service.test.ts`, `src/service/jar-parity.test.ts` |
| Signed request object / JAR | **Fulfilled** | `src/onboarding/jar.ts`, `src/service/jar-parity.test.ts`; signature and header parity checks are automated. |
| HAIP-oriented request and response profiles | **Partially fulfilled** | `src/onboarding/jar.ts`, `src/service/direct-post-interop.test.ts`, `src/service/service.ts`; no official external HAIP/ARF conformance run is included. |
| `direct_post` and encrypted `direct_post.jwt` responses | **Fulfilled** | `src/service/app.ts`, `src/service/service.ts`, `src/service/direct-post-interop.test.ts`; supported formats and size limits are bounded. |
| Nonce, state and replay protection | **Fulfilled** | `src/lib/session.ts`, `src/service/service.ts`, `src/service/erweiterung.test.ts`, `src/service/fehlerbilder.test.ts`. |
| VP/SD-JWT validation and key binding | **Partially fulfilled** | `src/service/service.ts` and `src/decision-test/*.test.ts` cover the implemented SD-JWT paths. A complete ARF/wallet matrix for every credential format is not included. |
| Credential status checking | **Partially fulfilled** | `src/service/credential-status.ts`, `src/service/credential-status.test.ts`; real status-list issuers and production data are deployment-specific. |
| Issuer chains, OCSP/CRL and fail-closed behavior | **Partially fulfilled** | `src/onboarding/ocsp-revocation.ts`, `src/onboarding/crl-revocation.ts`, `src/service/issuer-revocation.test.ts`; real responders, trust lists and production certificates were not demonstrated. |
| Verifier identity and issuer trust anchors | **Partially fulfilled** | `src/service/verifier-identity.ts`, `src/service/issuer-anchors.ts`, `src/service/bootstrap.ts`; production PKI configuration is required and test material is forbidden in production. |
| Relying-party onboarding / WRPAC / WRPRC | **Partially fulfilled** | `src/onboarding/onboarding-gate.ts`, `src/onboarding/wrpac.ts`, `src/onboarding/wrprc.ts`, `src/service/onboarding-gate.test.ts`; the gate is structurally present, but real registrar/access-CA profiles are missing. |
| Data minimization and bounded claim requests | **Partially fulfilled** | `src/service/profile.ts`, `src/service/limits.ts`, `src/service/log-ohne-claims.test.ts`; legal privacy approval, DPIA and purpose limitation cannot be proven by code alone. |
| Sensitive-data protection in errors and logs | **Fulfilled** | `src/lib/library-log-filter.ts`, `src/lib/logger.ts`, `src/service/fehlerbilder.test.ts`, `src/service/log-ohne-claims.test.ts`; the filter is a targeted process control for known dependency logs. |
| Abuse protection and input limits | **Partially fulfilled** | `src/service/rate-limit.ts`, `src/service/limits.ts`, `src/service/rate-limit.test.ts`; limits and sessions are currently process-local, not distributed. |
| Liveness, readiness and operational metrics | **Partially fulfilled** | `src/service/app.ts`, `src/service/metrics.ts`, `docs/observability.md`; metrics are in-memory and no formal SLO/alerting configuration exists. |
| Auditability | **Partially fulfilled** | `src/service/audit.ts` and service tests contain stable events without claims; immutable centralized and retention-controlled audit storage is not implemented. |
| Availability and horizontal scaling | **Not demonstrated** | Sessions, results, rate limits, audit and metrics are in-memory; the boundary is documented in `docs/deployment.md`. |
| TLS, secret management and production operations | **Partially fulfilled** | Fail-closed configuration in `src/config.ts`/`src/service/bootstrap.ts` and `Dockerfile`; TLS termination and secret rotation are platform responsibilities. |
| Official ARF/eIDAS conformity evidence | **Not fulfilled/not demonstrated** | The repository contains no accredited conformity assessment, formal laboratory result or legal approval. |

## Customer conclusion

Attack contains substantial OpenID4VP verifier paths and defensive controls.
That does not establish blanket eIDAS 2.0 or ARF conformity. Before regulated
production use, the deployment needs real trust/access certificates, production
credential-status sources, wallet interoperability evidence, independent
security review, privacy approval, centralized state/rate-limit storage and an
official conformity assessment.
