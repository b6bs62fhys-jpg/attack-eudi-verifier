# Observability

The service exposes bounded, privacy-preserving operational signals. Logs and
metrics must not be used to inspect credentials or presentations. Certificate
DER/PEM values, certificate subjects and serials, tokens, claims, nonces,
states and authorization values are intentionally excluded.

## Structured logs

The service uses `src/lib/logger.ts` for operational events. Each record is a
single JSON object with `ts`, `level`, `event` and a small set of stable fields.
The logger drops fields whose names indicate tokens, claims, certificates,
keys, secrets or presentation data. The existing
`src/lib/library-log-filter.ts` remains installed at process startup to suppress
known sensitive warnings emitted by the OpenID4VP dependency.

Examples of event names are `service_started`, `bootstrap_warning`,
`http_request_failed`, `dev_test_tenants_enabled` and
`service_shutdown_started`. HTTP errors contain only the method, route
template and error type, never the request URL, body or exception message.

Forward stdout/stderr to the platform log collector. Do not enable verbose
dependency logging in production and do not add request bodies to a log
formatter.

## Health and readiness

| Endpoint | Meaning | Dependency checks |
|---|---|---|
| `GET /live` | Process liveness | None; returns 200 while the HTTP process is serving |
| `GET /health` | Backwards-compatible liveness alias | None |
| `GET /ready` | Whether the instance should receive traffic | Configuration, issuer trust anchors, OCSP configuration and production onboarding state |
| `GET /metrics` | Prometheus text exposition | None |

Readiness returns 503 when a production issuer trust anchor, OCSP checker or
required onboarding material is unavailable. The service does not make an
unbounded OCSP network request from a health probe: OCSP responder URLs come
from the credential being checked. Runtime OCSP failures are fail-closed and
are visible in request/error metrics. A deployment may add an external
synthetic check using a dedicated test credential if responder reachability
itself must be probed.

## Prometheus metrics

The in-memory registry in `src/service/metrics.ts` exports:

- `attack_http_requests_total{method,route,status}`
- `attack_http_request_errors_total{method,route,status}`
- `attack_http_request_duration_ms_sum{method,route,status}`
- `attack_http_request_duration_ms_count{method,route,status}`
- `attack_ocsp_cache_hits_total`
- `attack_ocsp_cache_misses_total`
- `attack_onboarding_rejections_total{reason}`

Labels use route templates, not session IDs or raw paths. The registry is
process-local and resets on restart. A horizontally scaled deployment must
scrape every replica or replace the registry with a shared/sidecar metrics
implementation; request counts should not be summed across restarts without
accounting for counter resets.

## Security and retention

Keep logs and metrics access restricted to operators. Apply normal platform
retention and deletion policies. Audit events remain separate from operational
logs and contain only stable tenant/event codes as documented in
`src/service/audit.ts`.
