/**
 * Start des dünnen Verifier-Dienstes (nur 127.0.0.1).
 *
 * Start:  npm run service
 *
 * Alle Produktionsschalter entscheidet `bootstrapService` (bootstrap.ts),
 * fail closed:
 *   - Echte Identität via ATTACK_VERIFIER_KEY_PEM + ATTACK_VERIFIER_CERT_CHAIN_PEM.
 *   - Testmaterial (Identität, Aussteller-Anker, Test-Mandanten) und
 *     abgeschaltete Statusprüfung NUR mit ATTACK_DEV_MODE=true außerhalb von
 *     Produktion; dabei werden deutliche Warnungen ausgegeben.
 *   - In jedem anderen Fall wird der Start mit klarer Meldung (ohne
 *     Stacktrace, ohne Schlüsselinhalt) und Exit-Code 1 abgebrochen.
 *
 * Beim Start wird der Logfilter der Prüfbibliothek installiert
 * (`src/lib/library-log-filter.ts`): Die Bibliothek schreibt sonst
 * Zertifikat-Subjects, Responder-URLs und Seriennummern nach `console.warn`.
 * Eigene Warnungen, insbesondere die deutlichen Dev-Modus-Hinweise,
 * bleiben davon unberührt.
 */
import { createApp, ROUTES } from './app.ts';
import { RateLimiter } from './rate-limit.ts';
import { bootstrapService } from './bootstrap.ts';
import { startupFailureMessage } from '../config.ts';
import { installLibraryLogFilter } from '../lib/library-log-filter.ts';
import { logger } from '../lib/logger.ts';
import { NO_REVOCATION } from '../onboarding/revocation.ts';

installLibraryLogFilter();

let boot: Awaited<ReturnType<typeof bootstrapService>>;
try {
  boot = await bootstrapService(process.env, (message) => logger.warn('bootstrap_warning', { message }));
} catch (e) {
  // startupFailureMessage is deliberately sanitized and remains plain text so
  // supervisors can surface the actionable configuration error unchanged.
  console.error(startupFailureMessage(e));
  process.exit(1);
}

const { config, tenants, service, testTenants } = boot;
const readiness = () => {
  const checks = {
    config: 'ok' as const,
    issuer_trust: boot.issuerAnchors.length > 0 ? ('ok' as const) : ('failed' as const),
    ocsp: boot.issuerRevocation === NO_REVOCATION ? (config.isProduction ? ('failed' as const) : ('degraded' as const)) : ('ok' as const),
    onboarding: config.isProduction ? (boot.onboardingActive ? ('ok' as const) : ('failed' as const)) : ('degraded' as const),
  };
  return { ready: Object.values(checks).every((status) => status !== 'failed'), checks };
};
const server = createApp({
  appLabel: 'attack-service',
  tenants,
  service,
  metrics: boot.metrics,
  readiness,
  // Die Ratenbegrenzung kommt aus der Konfiguration (ATTACK_RATE_LIMIT_*).
  // Ohne diese Übergabe würden die fest verdrahteten Werte aus
  // src/service/rate-limit.ts gelten, also genau die ~1 Anfrage je Sekunde und
  // Mandant, die docs/lasttest.md als Obergrenze ausweist.
  rateLimits: config.rateLimits,
  rateLimiter: new RateLimiter({ windowMs: config.rateLimits.windowSeconds * 1000 }),
  ...(boot.trustedProxies ? { trustedProxies: boot.trustedProxies } : {}),
});

const host = config.host ?? '127.0.0.1';
server.listen(config.port, host, () => {
  // Request URI und Response URI kommen aus ATTACK_PUBLIC_BASE_URL (im
  // Produktionsmodus Pflicht). Nur ohne sie, also außerhalb von Produktion,
  // gilt die lokale Adresse.
  service.baseUrl = config.publicBaseUrl ?? `http://${host}:${config.port}`;
  logger.info('service_started', {
    app: 'attack-service',
    host,
    port: config.port,
    public_base_url: service.baseUrl,
    message: `Attack Verifier-Dienst (Prototyp) läuft auf http://${host}:${config.port}, öffentlich ${service.baseUrl}`,
  });
  logger.info('service_routes', { count: ROUTES.length });
  if (testTenants.length > 0) logger.warn('dev_test_tenants_enabled', { count: testTenants.length });
});

let shuttingDown = false;
function shutdown(signal: string): void {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info('service_shutdown_started', { signal });
  server.close(() => {
    logger.info('service_shutdown_complete');
    process.exit(0);
  });
  server.closeAllConnections();
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.once('SIGTERM', () => shutdown('SIGTERM'));
process.once('SIGINT', () => shutdown('SIGINT'));
