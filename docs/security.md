# Security

Deutsche Fassung: [sicherheit.md](sicherheit.md)

This document describes which security properties the service implements in
code, how they are tested and which gaps are known. It is written for
developers and security officers who assess the service before a pilot.

Please report vulnerabilities privately, see [SECURITY.md](../SECURITY.md).

## 1. Summary

- **Prototype, not for production use.** There is no external security review
  of this code base, no penetration test and no certification. When the
  protocol library `@openeudi/openid4vp` was selected, no external audit of it
  was available either.
- **Test status.** The service has been tested end to end only against the
  mock wallet in this repository. It has not yet been tested with a real
  wallet, a sandbox (including the SPRIND sandbox) or a national wallet.
  Details: [interoperability matrix](interop-matrix.md) (German).
- **Dependencies.** `npm audit` reports 0 vulnerabilities for the committed
  `package-lock.json`. CI runs `npm audit --audit-level=high` on every push and
  every pull request.
- **Secrets.** The repository contains no real keys, certificates or
  credentials. In dev mode all key material is TEST material created in memory;
  it is never persisted or logged.

## 2. What the service implements

| Property | Implementation | Evidence |
|---|---|---|
| Fail closed startup | Without a real verifier identity (`ATTACK_VERIFIER_KEY_PEM`, `ATTACK_VERIFIER_CERT_CHAIN_PEM`) and issuer trust anchors (`ATTACK_ISSUER_TRUST_ANCHORS_PEM`) startup aborts with exit code 1. Test material, test tenants and disabled checks exist only with `ATTACK_DEV_MODE=true` outside `NODE_ENV=production`, each with a prominent warning. `ATTACK_ALLOW_SELF_SIGNED=true` is forbidden in production. | `bootstrapService` in `src/service/bootstrap.ts`, `loadConfig` in `src/config.ts`; test `src/service/produktionsschalter.test.ts` |
| API keys | One server side key per tenant, sent as `authorization: Bearer`. Only the SHA 256 hash is stored. | `src/service/tenant.ts` |
| Tenant isolation | A session that belongs to another tenant cannot be told apart from an unknown one (`not_found`). | [Error codes](fehlercodes.md) (German) |
| Replay protection | `state` and nonce per session; a session accepts exactly one presentation, a second attempt fails with `session_reused`. | `src/lib/session.ts`; test `src/service/fehlerbilder.test.ts` |
| Result delivered once | A finished result is delivered exactly once and then removed; if it is not fetched it expires after 60 seconds (configurable). | test `src/service/ergebnis-einmal.test.ts` |
| Data minimisation | The result contains only the requested claims, even if the credential carries more. | `nurAngefragteClaims` in `src/service/profile.ts`; test `src/service/e2e-vollablauf.test.ts` |
| Encrypted responses | `direct_post.jwt` with `ECDH-ES` and `A128GCM` or `A256GCM`, a fresh key pair per session. Decryption is done by the library. | `src/onboarding/jar.ts`, `src/service/service.ts`; test `src/service/jar-parity.test.ts` |
| Input limits | Body at most 64 KiB, `vp_token` at most 32 KiB, JWE at most 48 KiB, at most 64 disclosures, at most 32 claims per request. | `src/service/limits.ts`; test `src/service/fehlerbilder.test.ts` |
| Fixed error codes | Responses carry fixed codes, never raw messages from libraries or exceptions. | `presentationErrorCode` in `src/service/limits.ts`, [error codes](fehlercodes.md) |
| Rate limiting | Per process: 120 requests per 60 seconds on public routes, 60 per tenant (defaults, configurable through `ATTACK_RATE_LIMIT_*`). | `src/service/rate-limit.ts`, `src/config.ts`; test `src/service/rate-limit.test.ts` |
| HTTP headers | `x-content-type-options: nosniff`, `cache-control: no-store`, `x-frame-options: DENY` on every response; deliberately no CORS. TLS and HSTS belong in the reverse proxy. | `setzeSicherheitsHeader` in `src/service/app.ts`; test `src/service/security-headers.test.ts`; [deployment](deployment.md) |
| Logs without personal data | Structured logs without claim values; the audit log holds only timestamp, tenant and event name. | `src/lib/logger.ts`, `src/service/audit.ts`; tests `src/service/log-ohne-claims.test.ts`, `src/service/audit-inhalt.test.ts` |
| Container | The `Dockerfile` runs the service as user `node`, not as root. | `Dockerfile` |

## 3. Trust and revocation

### Which mechanism covers what

| Mechanism | Applies to | Status |
|---|---|---|
| **Issuer trust anchors** | Chain of the issuer certificate in the credential | Explicitly configured anchors only. No trusted list processing according to ETSI TS 119 612 (LOTL). |
| **OCSP** (RFC 6960) | Issuer certificates of presented credentials, leaf and intermediates up to the anchor; the anchor itself is not checked | `OcspRevocationChecker` in `src/onboarding/ocsp-revocation.ts`, wired at startup in `src/service/bootstrap.ts`. Tested only against a local test responder. |
| **Token Status List** | The status of the credential itself, not of the certificate | `TokenStatusListChecker` in `src/service/credential-status.ts`, wired at startup. Not tried with real status list issuers. |
| **CRL** (RFC 5280) | intended for access and registration certificates (WRPAC, WRPRC) | `CrlRevocationChecker` in `src/onboarding/crl-revocation.ts` is implemented and tested, **but is not used anywhere at startup.** |
| **Onboarding gate** (WRPAC, WRPRC) | Access and registration certificates of the relying party | Active only when `ATTACK_ONBOARDING_ACCESS_CA_PEM` and `ATTACK_ONBOARDING_WRPRC_ISSUER_PEM` are set. When active, it checks revocation through the same OCSP checker. Without the gate, `/ready` reports `onboarding: failed` in production. |

In dev mode (`ATTACK_DEV_MODE=true`) OCSP and the Token Status List are
switched off; the service warns about this explicitly at startup.

### Relation to the checks inside the library

When `verifyAuthorizationResponse` is called, the library `@openeudi/openid4vp`
checks revocation itself (OCSP first, CRL as fallback). The service calls it
with `revocationPolicy: 'prefer'` and then runs its own OCSP check
(`enforceIssuerChainRevocation` in `src/service/issuer-revocation.ts`). As a
result:

1. With `'prefer'` the library reports `unknown` when the responder cannot be
   reached and does not reject. It rejects only on `revoked`. The library can
   therefore reject, but it cannot accept.
2. The binding decision is made by the service's own check afterwards. It also
   rejects when the library reported `good`. Test: "gesperrtes
   Aussteller-Zertifikat -> Präsentation abgelehnt (issuer_certificate_revoked)"
   in `src/service/issuer-revocation.test.ts`.
3. The own check deliberately runs after the library's chain validation, so
   that OCSP is not queried for certificates from an untrusted chain.

Known downsides of this double check:

- **Duplicate queries.** With an empty library cache both instances query the
  responder.
- **Weaker second check.** The library's OCSP client sends no nonce and sets no
  time or size limit of its own. It is therefore only an additional rejection
  signal, not the deciding instance.

### Nonce in OCSP responses is not mandatory

The service's OCSP client always sends a nonce (16 random bytes). If the
response contains a nonce, it must match exactly (constant time comparison),
otherwise `revocation_list_malformed`. **A response without a nonce is
accepted.**

| | |
|---|---|
| **Reason** | RFC 6960 treats the nonce as optional and many common responders do not answer it. Making it mandatory would prevent operation with those responders. |
| **Remaining risk** | With responders that do not support the nonce, a recorded genuine `good` response can be replayed within its validity window. |
| **Compensation** | `thisUpdate` must not lie in the future, `nextUpdate` is mandatory (otherwise `revocation_list_expired`), an exceeded `nextUpdate` is rejected. The cache is valid at most until `min(nextUpdate, now + 24 h)`. |
| **Tests** | "Responder ohne Nonce -> akzeptiert, Zeitbindung gilt (Dokumentierte Ausnahme)" and "falsche Nonce in der Antwort -> revocation_list_malformed (Replay abgewehrt)" in `src/onboarding/ocsp-revocation.test.ts` |
| **Stricter option** | Making the nonce mandatory means changing one condition in `evaluate` (`src/onboarding/ocsp-revocation.ts`). It costs interoperability with responders that do not send a nonce. The operator decides. |

### Grace period when the OCSP responder is unreachable

The service starts the OCSP checker in `bounded-soft-fail` mode: if the
responder cannot be reached, a previously verified `good` response stays valid
for up to 24 hours beyond its `nextUpdate`. A longer period cannot be
configured. When the grace period is used for a presentation, the service
writes the audit event `issuer_revocation_grace_period`.

| Situation | Result | Test in `src/onboarding/ocsp-revocation.test.ts` |
|---|---|---|
| before `nextUpdate` | status from cache, no query | "Zustand A: innerhalb nextUpdate wird der Cache genutzt, keine zweite Anfrage" |
| after `nextUpdate`, at most 24 h, last status `good`, query fails | `good` | "Zustand B: nach nextUpdate, aber innerhalb der Frist, wird die veraltete good-Antwort genutzt" |
| exactly `nextUpdate + 24 h` | still `good`; 1 ms later rejection `revocation_check_failed` | "Zustand C: exakt am Ende der 24-Stunden-Frist noch good, 1 ms spaeter Ablehnung" |
| no previously verified response | rejection | "Zustand C: ohne Vorabantwort gibt es keine Gnadenfrist" |
| `revoked` or `suspended` in cache | never `good`, not even during an outage | "Zustand C: revoked wird nie weich behandelt", "Zustand C: suspended wird nie weich behandelt" |
| mode `fail-closed` (class default) | rejection despite cache | "fail-closed (Default) lehnt auch mit vorhandener Vorabantwort ab" |

## 4. Log filter for library messages

When OCSP, CRL or trusted list fetches fail, the library writes certificate
subjects, responder URLs and error texts to the process log through
`console.warn`. It offers no switch for this. That violates the rule that no
certificate or personal data ends up in the log, and it happens exactly when
something is already going wrong.

The service therefore installs a filter at startup
(`installLibraryLogFilter` in `src/lib/library-log-filter.ts`, called in
`src/service/run.ts`):

- It wraps only `console.warn`; `error`, `log` and `info` are unchanged.
- It suppresses only messages whose first argument is a string starting with
  `[openid4vp]`. All other warnings, including the dev mode warnings, pass
  through unchanged.
- It applies to the whole process and is installed exactly once.

Tests: `src/lib/library-log-filter.test.ts` as well as "Gegenprobe: ohne Filter
schreibt die Bibliothek bei OCSP-Ausfall nach console.warn" and "mit
installiertem Filter bleibt von derselben Praesentation keine Bibliothekszeile
im Log" in `src/service/issuer-revocation.test.ts`.

**Limit:** The filter depends on two assumptions about the library: all
messages go through `console.warn`, and all start with `[openid4vp]`. In
version 0.11.1 this holds for all six places that emit messages. If an update
changes the prefix or the channel, the filter silently stops working and the
data appears in the log again. No automated test in this repository detects
that. After every update of `@openeudi/openid4vp`, check by hand:

```bash
grep -n -A1 -E "console\.(warn|log|error|info|debug|trace)\(" node_modules/@openeudi/openid4vp/dist/index.js
```

Every message found must start with `[openid4vp]`. Messages through
`process.emitWarning` or `process.stdout.write` are not covered by the filter;
version 0.11.1 contains none.

## 5. Known gaps

1. **No tenant management for production.** Tenants and their API keys are
   created only in dev mode (`DEV_TEST_TENANTS` in `src/service/bootstrap.ts`).
   There is no way to create tenants in production mode; there the service
   answers every request on tenant routes with 401.
2. **No persistence.** Sessions, results, audit log and rate limits live in
   the memory of one process. A restart deletes everything. Multiple instances
   share no state.
3. **Audit log without evidential value.** Entries are hash chained, so a
   later change is detectable. Whoever controls the process can recompute the
   chain, though; a signature, timestamping service or external storage is
   missing ([threat model](bedrohungsmodell.md), S15, German).
4. **No TLS in the service.** The service speaks HTTP. TLS, HSTS and the
   redirect to HTTPS must be handled by a reverse proxy
   ([deployment](deployment.md)).
5. **No key management.** The verifier key is loaded from a PEM file. There is
   no KMS or HSM integration and no key rotation.
6. **No interoperability evidence.** Tested only against the mock wallet in
   this repository ([interoperability matrix](interop-matrix.md)).
7. **Verifier identity in dev mode.** Request objects are signed there with a
   self signed TEST certificate. A profile compliant wallet (HAIP) would reject
   this identity without valid access and registration certificates.
8. **Onboarding incomplete.** The WRPAC and WRPRC gate is off without
   additional material; the CRL check is not wired; the registrar integration
   is missing.
9. **Revocation tested locally only.** OCSP and Token Status List are tested
   only against local test servers, not against production responders or
   status list issuers.
10. **No mdoc.** Only `dc+sd-jwt` is supported.
11. **No conformance runs.** This repository contains no run of the OIDF
    conformance suite and no external HAIP conformance test.
12. **Note on `@sd-jwt/decode`.** The library pulls in `@sd-jwt/decode`,
    `@sd-jwt/types` and `@sd-jwt/utils` version 0.19.0 transitively. These
    packages are marked deprecated; the notice names `GHSA-f9j6-8p6x-r9j6`.
    `npm audit` reports no finding for them, and the advisory could not be
    found in the GitHub advisory database. Whether version 0.19.0 is affected
    is therefore open. Switching requires an update of `@openeudi/openid4vp`.
13. **XML signature libraries.** `xadesjs`, `xmldsigjs` and `@xmldom/xmldom`
    come in transitively with the library (for its LOTL processing). The
    service does not use that path.
14. **Demo page.** The demo (`npm run demo`) has no CSRF protection. It binds
    to 127.0.0.1 only and is not meant for operation.

## 6. Data protection

- The `vp_token` is processed only for verification and is not stored.
- The result contains only the requested claim values. It is held in memory,
  delivered exactly once and otherwise expires after the result TTL.
- Logs and audit log contain no claim values, no wallet identifiers and no
  credentials.
- There is no data protection impact assessment and no data protection
  approval. Both depend on how the relying party uses the service.

## 7. Dependencies

Runtime dependencies (exact versions in `package.json` and
`package-lock.json`):

| Package | Version | License | Purpose |
|---|---|---|---|
| `@openeudi/openid4vp` | 0.11.1 | Apache-2.0 | OpenID4VP, DCQL, signed request objects, SD-JWT and key binding validation |
| `@openeudi/core` | 0.8.0 | Apache-2.0 | shared types and helpers |
| `@openeudi/dcql` | 0.2.0 | Apache-2.0 | DCQL types and validation |
| `@peculiar/asn1-ocsp` | 2.9.5 | MIT | ASN.1 structures for the service's own OCSP client |

Development dependencies include `jose`, `@peculiar/x509` (TEST
certificates), `typescript`, `eslint` and `vitest`. The full license overview
is in [dependency licenses](lizenzen-abhaengigkeiten.md) (German).

## 8. Check it yourself

```bash
npm ci
npm audit
npm ls --all
git ls-files | grep -E 'node_modules|\.env|\.pem|\.key|secret'
npm test
npm run typecheck
npm run lint
```

The `git ls-files` command should return nothing. `npm ci`, `npm test`,
`npm run typecheck` and `npm run lint` also run in CI on every push, together
with `npm run test:coverage` and `npm audit --audit-level=high`.
