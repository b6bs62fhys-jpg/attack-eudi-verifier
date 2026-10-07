# Monitoring Runbook

This runbook covers the Prometheus alerts and Grafana panels for the Attack
verifier. The metrics registry is process-local and exposes bounded route and
reason labels. Logs are structured JSON from `src/lib/logger.ts`; never add
tokens, claims, certificate values or request bodies while diagnosing an
incident.

## First response

1. Check `up{job="attack-verifier"}` and query `/live` and `/ready`.
2. Check the Grafana time range against the first alert timestamp.
3. Correlate metric labels `route`, `status` and `reason` with structured log
   fields `ts`, `level`, `event`, `method`, `route` and `error_type`.
4. Do not log or copy authorization headers, VP tokens, claims, states,
   nonces, certificate subjects, serial numbers or DER/PEM data.

## Alerts

### `AttackHttpErrorRateHigh`

**Meaning:** One route has returned more than 5% errors for 10 minutes.

**Diagnose:**

- Open the `HTTP error rate by endpoint` panel and identify `route`.
- Break down `attack_http_requests_total` by `status` for that route.
- Search structured logs for `event="http_request_failed"` and compare
  `method`, `route` and `error_type` with the alert.
- Check whether the errors are expected client errors such as 400/401 or
  server-side 500 responses.
- If a deploy preceded the alert, roll back or compare the changed route and
  dependency health before retrying traffic.

**Mitigate:** Fix the failing dependency or input contract. Do not suppress
the alert by logging response bodies.

### `AttackOcspCacheHitRateLow`

**Meaning:** OCSP cache hit rate stayed below 80% for 15 minutes.

**Diagnose:**

- Inspect `attack_ocsp_cache_hits_total` and
  `attack_ocsp_cache_misses_total` and confirm there is real OCSP traffic.
- Check the request-latency panel for correlated latency growth.
- Check the OCSP responder reachability, timeouts and certificate `nextUpdate`
  behavior using a controlled synthetic credential.
- Search logs for `event="http_request_failed"` with the affected route and
  `error_type`; raw OCSP URLs and certificate values are intentionally not
  logged.
- Check whether a restart or replica change reset the process-local counters.

**Mitigate:** Restore responder reachability or investigate short-lived
responses and cache expiry. Keep fail-closed behavior; do not increase stale
acceptance just to clear the alert.

### `AttackOnboardingRejectionRateHigh`

**Meaning:** More than roughly six onboarding rejections per minute persisted
for 10 minutes.

**Diagnose:**

- Group `attack_onboarding_rejections_total` by `reason`.
- Check for `certificate_revoked`, `certificate_expired`, trust-path and
  malformed-registration reasons.
- Correlate with `event="http_request_failed"`, `method`, `route` and
  `error_type`; the stable rejection `reason` is the authoritative detail.
- Verify configured WRPAC/WRPRC anchors, certificate validity and revocation
  source status without copying certificate contents into logs.

**Mitigate:** Correct the affected onboarding material or registrar/trust
configuration. Do not disable the onboarding gate or revocation checks as an
operational shortcut.

### `AttackMetricsEndpointDown`

**Meaning:** Prometheus has been unable to scrape the verifier for two
minutes.

**Diagnose:**

- Check the container/process state and network path to `/metrics`.
- Query `/live` to distinguish a process outage from readiness failure.
- Query `/ready` and inspect its dependency checks.
- Search structured logs for `service_started`,
  `service_shutdown_started`, `service_shutdown_complete` and
  `http_request_failed`, using `ts`, `event` and `error_type`.
- Check recent configuration or secret-mount changes.

**Mitigate:** Restore the process or routing path. If `/live` is healthy but
`/ready` is not, fix the reported dependency before sending traffic back.

## Dashboard panels

`monitoring/grafana-dashboard.json` is importable into Grafana with a
Prometheus datasource. It contains panels for request latency, endpoint error
rate, OCSP cache hit rate, onboarding rejection rate and HTTP 429 rate-limit
responses.

## Operations limits

Sessions, metrics, audit entries and rate-limit state are process-local. In a
multi-replica deployment, scrape each replica and use a distributed rate-limit
and state store before treating aggregate alert rates as complete.
