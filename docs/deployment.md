# Deployment

The repository includes a multi-stage `Dockerfile` for the Attack verifier.
The final image contains only production dependencies, the application source,
and the non-root `node` user. The image runs Node.js 22 with TypeScript type
stripping and performs a strict typecheck in the build stage.

## Container

```bash
docker build -t attack-verifier:local .
docker run --rm -p 8080:8080 \
  -e NODE_ENV=production \
  -e ATTACK_VERIFIER_KEY_PEM=/run/secrets/verifier-key.pem \
  -e ATTACK_VERIFIER_CERT_CHAIN_PEM=/run/secrets/verifier-chain.pem \
  -e ATTACK_ISSUER_TRUST_ANCHORS_PEM=/run/secrets/issuer-anchors.pem \
  -v "$PWD/secrets:/run/secrets:ro" \
  attack-verifier:local
```

The service fails closed if the production identity or issuer trust anchors
are absent. Never set `ATTACK_DEV_MODE=true` or
`ATTACK_ALLOW_SELF_SIGNED=true` in production.

## Environment variables

Required for production:

- `NODE_ENV=production`
- `ATTACK_VERIFIER_KEY_PEM`: mounted PEM PKCS#8 verifier private key
- `ATTACK_VERIFIER_CERT_CHAIN_PEM`: mounted verifier certificate chain, leaf first
- `ATTACK_ISSUER_TRUST_ANCHORS_PEM`: mounted issuer trust anchors

Required when the onboarding gate is enabled:

- `ATTACK_ONBOARDING_ACCESS_CA_PEM`: Access-CA anchors
- `ATTACK_ONBOARDING_WRPRC_ISSUER_PEM`: WRPRC issuer anchors

Optional:

- `ATTACK_HOST`: bind address; Docker defaults to `0.0.0.0`, local execution defaults to `127.0.0.1`
- `PORT`: HTTP port, default `8080`
- `ATTACK_CLOCK_SKEW_SECONDS`: certificate/time skew, `0..300`, default `60`
- `ATTACK_RESULT_TTL_SECONDS`: completed-result retention, `1..3600`, default `60`
- `ATTACK_ENTITLEMENT_MAP_JSON`: validated entitlement-map extension file

Rate limiting:

- `ATTACK_RATE_LIMIT_PUBLIC_PER_WINDOW`: requests per window and IP address on
  public routes, `1..1000000`, default `120`
- `ATTACK_RATE_LIMIT_TENANT_PER_WINDOW`: requests per window and API key on
  tenant routes, `1..1000000`, default `60`
- `ATTACK_RATE_LIMIT_WINDOW_SECONDS`: window length, `1..3600`, default `60`

A non-numeric, fractional or out-of-range value aborts startup. This is
deliberate: a typo must not silently produce a service that accepts an
unlimited number of requests. The upper bound of 1,000,000 is a
misconfiguration brake, not a protective limit.

**Sizing matters.** The default tenant limit of 60 per 60 seconds means roughly
**one request per second and tenant** in steady state. That is a protection
default chosen for a local prototype, not a throughput figure. A deployment
with real traffic must raise `ATTACK_RATE_LIMIT_TENANT_PER_WINDOW` and
`ATTACK_RATE_LIMIT_WINDOW_SECONDS` deliberately. The operational routes
`/live`, `/health`, `/ready` and `/metrics` are exempt and are not affected.
`npm run cli -- ratelimit` reports the values actually in effect, including
whether they come from the environment or from the built-in defaults.

The limiter counts per process and in memory. With more than one instance the
effective limit is the per-instance limit times the number of instances, so a
shared store is required to hold a limit across a scaled deployment
(`docs/eidas-arf-konformitaet.md` records this as not yet demonstrated).

Development-only switches:

- `ATTACK_DEV_MODE=true`: enables test identity, test anchors, test tenants and disabled status checks
- `ATTACK_ALLOW_SELF_SIGNED=true`: only valid together with development mode

The verifier's OCSP responder URL is taken from the credential certificate's
AIA extension. Production egress must therefore allow the configured OCSP
responders, subject to the OCSP timeout, byte limit, nonce and signature
checks. No OCSP URL or response is configured through a secret variable.

## TLS and security headers

The service speaks plain HTTP and terminates nothing itself. In front of it sits
a reverse proxy that owns TLS and therefore also owns the transport-level
headers. The service sets `x-content-type-options: nosniff`, `cache-control:
no-store` and `x-frame-options: deny` on every response, because those are
application-level and hold regardless of the proxy
(`docs/security-headers-audit-2026-09-27.md`).

The reverse proxy must add:

- `Strict-Transport-Security: max-age=31536000; includeSubDomains` once the
  deployment is served exclusively over HTTPS. Setting it inside the application
  is wrong: the rule only takes effect over HTTPS, so a value sent on the first
  plain-HTTP request would push the client onto HTTPS before the proxy that
  terminates TLS is reached.
- A redirect from `http://` to `https://` for the same reason.

The service deliberately sends no `Content-Security-Policy` and no
`Referrer-Policy`. It serves no HTML documents, and the second governs document
navigation, which this API is not part of. Both belong on the static website in
`site/`, where they have their effect.

The service sends no CORS headers. It is called by servers and native wallets,
not by foreign browser origins, so the browser same-origin policy applies in
full. If browser-based callers are ever added, configure an explicit origin
allowlist — never a wildcard — and see the audit document.

## Secrets

Inject secrets as read-only files or through a secret manager. Do not place
private keys, certificate bundles, API keys or production entitlement files in
the image, repository, Docker build context or logs. Rotate mounted material
by replacing the secret and restarting the process; the current prototype
loads identity and anchors at startup.

## Production start, verified

Verified on 28.09.2026 against the built image: the service starts in production
configuration **without** `ATTACK_DEV_MODE`. Full log and evidence in
`docs/release-pruefung.md`, section 5.1.

Three variables are required. Derived from `src/config.ts` and enforced in
`src/service/verifier-identity.ts` and `src/service/issuer-anchors.ts`:

| Variable | Rule |
|---|---|
| `ATTACK_VERIFIER_KEY_PEM` | required, together with the next one |
| `ATTACK_VERIFIER_CERT_CHAIN_PEM` | required, together with the previous one |
| `ATTACK_ISSUER_TRUST_ANCHORS_PEM` | required |

```bash
docker build -t attack-verifier:local .

docker run -d --name attack -p 8080:8080 \
  -e NODE_ENV=production \
  -e ATTACK_VERIFIER_KEY_PEM=/run/secrets/verifier-key.pem \
  -e ATTACK_VERIFIER_CERT_CHAIN_PEM=/run/secrets/verifier-chain.pem \
  -e ATTACK_ISSUER_TRUST_ANCHORS_PEM=/run/secrets/issuer-anchors.pem \
  -v "$PWD/secrets:/run/secrets:ro" \
  attack-verifier:local
```

Confirmed on that container: `docker ps` reports `(healthy)`, `GET /live` and
`GET /health` return HTTP 200, the process runs as `uid=1000(node)`, and the
startup log contains **no** development warning. The known test tenant keys from
`DEV_TEST_TENANTS` are rejected with HTTP 401, indistinguishable from an unknown
key.

Each missing requirement aborts the start with exit code 1 and a message naming
the variable:

```text
Keine Verifier-Identität konfiguriert und kein Test-Rückfall erlaubt (Produktionsmodus). …
```

**Do not set `ATTACK_DEV_MODE` in production.** The image sets
`NODE_ENV=production`, so `ATTACK_DEV_MODE=true` alone aborts the start, and
setting both is rejected. That is intentional: a silent test mode would accept
unsigned material.

**The secrets directory must be readable by the container's `node` user**
(uid 1000). On a bind mount from macOS, `/tmp` is not shared into Colima's VM;
use a path under `$HOME` or use Docker secrets.

## Health and readiness

- `/live` is a dependency-free liveness check.
- `/ready` returns `503` until production trust anchors, OCSP configuration and
  required onboarding material are ready.
- `/health` returns the **same body as `/live`**, byte for byte
  (`src/service/app.ts:183-198`). It is a liveness-compatible alias and **not** a
  readiness check: a load balancer must not use it to decide where to send
  traffic. Use `/ready` for that.
- `/metrics` exposes bounded Prometheus text metrics.

The readiness check deliberately does not make an arbitrary OCSP request. OCSP
URLs are credential-specific. Add a controlled synthetic probe if a deployment
needs a network reachability check independent of traffic.

## Scaling

The current service stores sessions, results, rate-limit windows, audit entries
and metrics in process memory. Run one replica, or use ingress stickiness and
accept the associated failover limitations. For horizontal production scale,
move session/result state and rate-limit counters to a shared strongly
consistent store, and scrape metrics per replica or use an aggregation layer.

The public `direct_post` endpoint is rate-limited per source identity and the
tenant API endpoints per API key. This in-process protection is not a
replacement for an edge WAF or distributed rate limiter.

## Graceful shutdown

`SIGTERM` and `SIGINT` stop accepting new connections, close the HTTP server,
and allow up to 10 seconds for shutdown. The container orchestrator should
provide at least a 10-second termination grace period. Because state is
in-memory, an interrupted process loses pending sessions and local metrics;
clients must be able to retry safely.

## Verifying a build before release

A release-dry-run job in `.github/workflows/ci.yml` runs on every pull request. It
packs the three SDKs, inspects their contents and writes a CycloneDX SBOM, without
publishing anything. This section explains what it checks and what it currently
cannot.

### What the job does

| Schritt | Prüft |
|---|---|
| `npm pack --dry-run` (TypeScript) | that no `src/` and no `*.test.` file would be published, and that `dist/index.js` is present |
| `python -m build` (Python) | that sdist and wheel build, and that the wheel contains no test files |
| `publishToMavenLocal` (Kotlin) | that the local publication builds; the plugin is applied, so this always runs |
| `npm sbom` (Root and TypeScript SDK) | writes a CycloneDX 1.5 SBOM as a build artifact |

### What it cannot check yet

**The Kotlin SDK has no publication target.** `sdk/kotlin/build.gradle.kts`
applies the `maven-publish` plugin, so `publishToMavenLocal` exists and the job
runs it; the artifact lands in the local Maven repository only. Publishing to
Maven Central or to a private registry is a release decision and has not been
taken: the target registry, and the `group` coordinate it would carry, both wait
on the naming decision. A failure of this step now means the plugin was removed
or the build broke — that is the intended signal. See
`docs/release-pruefung.md`, section 3.

**The SBOM covers npm only.** npm generates CycloneDX natively, so no additional
dependency is needed. Python would need `cyclonedx-bom` and Kotlin a Gradle
plugin; both add a dependency to the respective toolchain. Until that is
decided, the job emits a notice rather than a partial SBOM that suggests more
coverage than exists.

**The root package cannot be published and does not need to be.** It is
`"private": true` — it is a service, not a library. Note that `npm pack` still
succeeds and reports 5840 files including `.git`, `src/` and the `test/eudi-verify`
submodule. That is expected: `pack` and `publish` differ, and `private` blocks
publication. For SBOM purposes the job therefore uses `--sbom-type application`.

### Local run

```bash
docker build -t attack-verifier:local .

# Production path. Without a real identity the service refuses to start.
docker run --rm -p 8080:8080 \
  -e NODE_ENV=production \
  -e ATTACK_VERIFIER_KEY_PEM=/run/secrets/verifier-key.pem \
  -e ATTACK_VERIFIER_CERT_CHAIN_PEM=/run/secrets/verifier-chain.pem \
  -e ATTACK_ISSUER_TRUST_ANCHORS_PEM=/run/secrets/issuer-anchors.pem \
  -v "$PWD/secrets:/run/secrets:ro" \
  attack-verifier:local

# Local test path. Both variables are required together.
docker run --rm -p 8080:8080 \
  -e NODE_ENV=development -e ATTACK_DEV_MODE=true \
  attack-verifier:local

curl -s localhost:8080/live    # {"ok":true,"status":"live","app":"attack-service"}
```

`ATTACK_DEV_MODE=true` alone is not enough. The image sets `NODE_ENV=production`,
and the service refuses to start on the contradiction:

```text
NODE_ENV=production und ATTACK_DEV_MODE=true widersprechen sich. Der
Entwicklungsschalter ist nur in lokalen Umgebungen erlaubt. Start abgebrochen.
```

This is deliberate and must not be relaxed: a silent test mode in production
would accept unsigned material. Setting both variables is the only way in.

The image runs as `uid=1000(node)`, not root, and its `HEALTHCHECK` probes `/live`
every 30 seconds with a 10-second start period. `docker ps` reporting
`(healthy)` confirms it works.
