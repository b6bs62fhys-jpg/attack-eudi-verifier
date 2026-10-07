import assert from 'node:assert/strict';
import { describe, it } from 'vitest';

import { ServiceMetrics } from './metrics.ts';

describe('ServiceMetrics', () => {
  it('exports bounded HTTP, OCSP and onboarding counters as Prometheus text', () => {
    const metrics = new ServiceMetrics();
    metrics.recordHttpRequest('GET', '/ready', 200, 12);
    metrics.recordHttpRequest('POST', '/direct_post', 401, 8);
    metrics.recordOcspCacheHit();
    metrics.recordOcspCacheMiss();
    metrics.recordOnboardingRejection('certificate_revoked');
    const output = metrics.toPrometheus();
    assert.match(output, /attack_http_requests_total\{method="GET",route="\/ready",status="200"\} 1/);
    assert.match(output, /attack_http_request_errors_total\{method="POST",route="\/direct_post",status="401"\} 1/);
    assert.match(output, /attack_ocsp_cache_hits_total 1/);
    assert.match(output, /attack_ocsp_cache_misses_total 1/);
    assert.match(output, /attack_onboarding_rejections_total\{reason="certificate_revoked"\} 1/);
  });
});
