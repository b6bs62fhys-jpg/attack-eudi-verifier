/** In-memory metrics registry. Exposes only bounded route/code labels. */
export interface ReadinessSnapshot {
  ready: boolean;
  checks: Record<string, 'ok' | 'degraded' | 'failed'>;
}

interface HttpMetric {
  count: number;
  errors: number;
  latencyMs: number;
}

function label(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

export class ServiceMetrics {
  private readonly http = new Map<string, HttpMetric>();
  private ocspHits = 0;
  private ocspMisses = 0;
  private readonly onboardingRejections = new Map<string, number>();

  recordHttpRequest(method: string, route: string, status: number, latencyMs: number): void {
    const key = `${method}|${route}|${status}`;
    const metric = this.http.get(key) ?? { count: 0, errors: 0, latencyMs: 0 };
    metric.count += 1;
    metric.errors += status >= 400 ? 1 : 0;
    metric.latencyMs += Math.max(0, latencyMs);
    this.http.set(key, metric);
  }

  recordOcspCacheHit(): void {
    this.ocspHits += 1;
  }

  recordOcspCacheMiss(): void {
    this.ocspMisses += 1;
  }

  recordOnboardingRejection(reason: string): void {
    this.onboardingRejections.set(reason, (this.onboardingRejections.get(reason) ?? 0) + 1);
  }

  toPrometheus(): string {
    const lines = [
      '# HELP attack_http_requests_total HTTP requests by route and status.',
      '# TYPE attack_http_requests_total counter',
    ];
    for (const [key, metric] of this.http) {
      const [method, route, status] = key.split('|');
      const labels = `method="${label(method)}",route="${label(route)}",status="${label(status)}"`;
      lines.push(`attack_http_requests_total{${labels}} ${metric.count}`);
      lines.push(`attack_http_request_errors_total{${labels}} ${metric.errors}`);
      lines.push(`attack_http_request_duration_ms_sum{${labels}} ${metric.latencyMs}`);
      lines.push(`attack_http_request_duration_ms_count{${labels}} ${metric.count}`);
    }
    lines.push('# HELP attack_ocsp_cache_hits_total Verified OCSP cache hits.', '# TYPE attack_ocsp_cache_hits_total counter', `attack_ocsp_cache_hits_total ${this.ocspHits}`);
    lines.push('# HELP attack_ocsp_cache_misses_total OCSP fetches after cache misses or expiry.', '# TYPE attack_ocsp_cache_misses_total counter', `attack_ocsp_cache_misses_total ${this.ocspMisses}`);
    lines.push('# HELP attack_onboarding_rejections_total Onboarding gate rejections by stable code.', '# TYPE attack_onboarding_rejections_total counter');
    for (const [reason, count] of this.onboardingRejections) lines.push(`attack_onboarding_rejections_total{reason="${label(reason)}"} ${count}`);
    return `${lines.join('\n')}\n`;
  }
}
