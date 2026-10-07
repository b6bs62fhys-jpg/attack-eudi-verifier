# Monitoring-Runbook

Dieses Runbook beschreibt die Prometheus-Alerts und Grafana-Panels für den
Attack-Verifier. Die Metrik-Registry ist process-local und verwendet begrenzte
Route- und Reason-Labels. Logs sind strukturierte JSON-Einträge aus
`src/lib/logger.ts`. Bei der Diagnose niemals Tokens, Claims,
Zertifikatswerte oder Request-Bodies ergänzen.

## Erste Schritte

1. `up{job="attack-verifier"}` sowie `/live` und `/ready` prüfen.
2. Den Grafana-Zeitraum mit dem Zeitpunkt des Alerts abgleichen.
3. Metrik-Labels `route`, `status` und `reason` mit den strukturierten
   Log-Feldern `ts`, `level`, `event`, `method`, `route` und `error_type`
   korrelieren.
4. Keine Authorization-Header, VP-Tokens, Claims, States, Nonces,
   Zertifikats-Subjects, Seriennummern oder DER-/PEM-Inhalte loggen oder
   kopieren.

## Alerts

### `AttackHttpErrorRateHigh`

**Bedeutung:** Eine Route liefert länger als 10 Minuten mehr als 5% Fehler.

**Diagnose:**

- Im Panel `HTTP error rate by endpoint` die betroffene `route` ermitteln.
- `attack_http_requests_total` für diese Route nach `status` aufteilen.
- Strukturierte Logs nach `event="http_request_failed"` durchsuchen und
  `method`, `route` und `error_type` mit dem Alert vergleichen.
- Erwartete Clientfehler wie 400/401 von serverseitigen 500-Fehlern trennen.
- Bei zeitlichem Zusammenhang mit einem Deploy Änderungen und Abhängigkeiten
  prüfen oder den Deploy zurückrollen.

**Maßnahme:** Abhängigkeit oder Eingabevertrag reparieren. Nicht durch das
Logging von Response-Bodies den Alert unterdrücken.

### `AttackOcspCacheHitRateLow`

**Bedeutung:** Die OCSP-Cache-Hitrate liegt mindestens 15 Minuten unter 80%.

**Diagnose:**

- `attack_ocsp_cache_hits_total` und
  `attack_ocsp_cache_misses_total` prüfen und echten OCSP-Traffic bestätigen.
- Das Latenz-Panel auf parallele Latenzanstiege prüfen.
- OCSP-Erreichbarkeit, Timeouts und `nextUpdate` mit einem kontrollierten
  synthetischen Credential prüfen.
- Nach `event="http_request_failed"` mit `route` und `error_type` suchen;
  OCSP-URLs und Zertifikatswerte werden absichtlich nicht geloggt.
- Neustarts und Replica-Wechsel berücksichtigen, da die Counter process-local
  sind.

**Maßnahme:** Responder-Erreichbarkeit oder Antwortfristen reparieren.
Fail-Closed beibehalten und die Gnadenfrist nicht nur zum Alert-Löschen
erweitern.

### `AttackOnboardingRejectionRateHigh`

**Bedeutung:** Mehr als ungefähr sechs Onboarding-Ablehnungen pro Minute über
10 Minuten.

**Diagnose:**

- `attack_onboarding_rejections_total` nach `reason` gruppieren.
- Auf `certificate_revoked`, `certificate_expired`, Trust-Path- und
  Registration-Format-Fehler prüfen.
- Mit `event="http_request_failed"`, `method`, `route` und `error_type`
  korrelieren; `reason` ist das maßgebliche stabile Detail.
- WRPAC-/WRPRC-Anker, Zertifikatsgültigkeit und Sperrquelle prüfen, ohne
  Zertifikatsinhalte zu loggen.

**Maßnahme:** Onboarding-Material oder Registrar-/Trust-Konfiguration
reparieren. Gate und Sperrprüfung nicht als schnellen Workaround abschalten.

### `AttackMetricsEndpointDown`

**Bedeutung:** Prometheus kann den Verifier mindestens zwei Minuten nicht
scrapen.

**Diagnose:**

- Prozess/Container und Netzwerkpfad zu `/metrics` prüfen.
- `/live` abfragen, um Prozessausfall von Readiness-Problemen zu trennen.
- `/ready` abfragen und Dependency-Checks auswerten.
- Strukturierte Logs nach `service_started`,
  `service_shutdown_started`, `service_shutdown_complete` und
  `http_request_failed` durchsuchen; relevante Felder sind `ts`, `event` und
  `error_type`.
- Änderungen an Konfiguration oder Secret-Mounts prüfen.

**Maßnahme:** Prozess oder Routing wiederherstellen. Wenn `/live` gesund,
`/ready` aber nicht bereit ist, zuerst die gemeldete Abhängigkeit reparieren.

## Dashboard-Panels

`monitoring/grafana-dashboard.json` ist mit einer Prometheus-Datasource in
Grafana importierbar. Es enthält Panels für Request-Latenz, Fehlerquote pro
Endpoint, OCSP-Cache-Hitrate, Onboarding-Ablehnungen und HTTP-429-Rate-Limits.

## Betriebsgrenzen

Sessions, Metriken, Audit-Einträge und Rate-Limit-Status sind process-local.
Bei mehreren Replicas müssen alle Replicas gescrapt werden; für verlässliche
Aggregationen sind ein verteilter Rate-Limit- und State-Store erforderlich.
