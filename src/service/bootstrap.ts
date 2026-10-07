/**
 * Aufbau des Verifier-Dienstes aus der Umgebung (fail closed).
 *
 * Eine Stelle entscheidet beim Start über alle Produktionsschalter; run.ts
 * ruft nur `bootstrapService` auf und bricht bei ConfigError mit klarer
 * Meldung ab. Tests prüfen hier alle Kombinationen ohne Prozessstart.
 *
 * Lockerungen nur mit ATTACK_DEV_MODE=true außerhalb von Produktion:
 *   - Test-Verifier-Identität (verifier-identity.ts)
 *   - selbstsignierte Verifier-Zertifikate (ATTACK_ALLOW_SELF_SIGNED)
 *   - Test-Aussteller-Anker (sonst ATTACK_ISSUER_TRUST_ANCHORS_PEM Pflicht),
 *     Test-Mandanten mit bekannten API-Schlüsseln
 *   - abgeschaltete Credential-Statusprüfung (NO_CREDENTIAL_STATUS)
 *   - abgeschaltete Aussteller-Sperrprüfung (NO_REVOCATION)
 *
 * Onboarding-Gate (B3, strukturell vorbereitet): Die WRPAC/WRPRC-Prüfung wird
 * über `resolveOnboardingGate` aufgelöst. Ohne echtes Material
 * (ATTACK_ONBOARDING_ACCESS_CA_PEM / ATTACK_ONBOARDING_WRPRC_ISSUER_PEM) bleibt
 * das Gate aus und der Start meldet das laut mit `describeOnboardingState` —
 * statt wie bisher viermal `undefined` still durchzureichen. Die Sperrquelle
 * wird unabhängig davon fail closed geprüft. Sobald das Material vorliegt, ist
 * die Verdrahtung ein reiner Konfigurationsakt.
 */
import {announceDevMode, announceSelfSignedCertificate, ConfigError, loadConfig, type AppConfig, type WarnFn} from '../config.ts';
import {generateTestKeyMaterial} from '../decision-test/mock-wallet.ts';
import {AuditLog} from './audit.ts';
import {NO_CREDENTIAL_STATUS, TokenStatusListChecker, type CredentialStatusChecker} from './credential-status.ts';
import {OcspRevocationChecker} from '../onboarding/ocsp-revocation.ts';
import {NO_REVOCATION, type RevocationChecker} from '../onboarding/revocation.ts';
import {createEntitlementMapProvider} from '../onboarding/entitlement-source.ts';
import {describeOnboardingState, resolveOnboardingGate, type OnboardingMaterial} from '../onboarding/onboarding-wiring.ts';
import {resolveIssuerAnchors} from './issuer-anchors.ts';
import {VerifierService} from './service.ts';
import {TenantStore} from './tenant.ts';
import {resolveVerifierIdentity} from './verifier-identity.ts';
import {ServiceMetrics} from './metrics.ts';

/** Nur mit Entwicklungsschalter angelegte Test-Mandanten (bekannte Schlüssel). */
export const DEV_TEST_TENANTS = Object.freeze([
  { id: 'tenant-a', name: 'Kunde A (TEST)', apiKey: 'test-api-key-tenant-A' },
  { id: 'tenant-b', name: 'Kunde B (TEST)', apiKey: 'test-api-key-tenant-B' },
]);

export interface Bootstrapped {
  config: AppConfig;
  tenants: TenantStore;
  audit: AuditLog;
  service: VerifierService;
  usedTestIdentity: boolean;
  usedTestAnchor: boolean;
  issuerAnchors: readonly Uint8Array[];
  credentialStatus: CredentialStatusChecker;
  /** Angelegte Test-Mandanten (leer ohne Entwicklungsschalter). */
  testTenants: ReadonlyArray<{ id: string; apiKey: string }>;
  /** Sperrprüfung der Aussteller-Zertifikatskette. */
  issuerRevocation: RevocationChecker;
  /** true, wenn das Onboarding-Gate (WRPAC/WRPRC) tatsächlich aktiv ist. */
  onboardingActive: boolean;
  /** Sprechender Zustand des Gates für Logs und Betrieb. */
  onboardingState: string;
  metrics: ServiceMetrics;
}

export interface BootstrapOptions {
  /** Nur für Tests: Onboarding-Material statt der PEM-Dateien injizieren. */
  onboardingMaterial?: () => Promise<OnboardingMaterial>;
}

export async function bootstrapService(
  env: Record<string, string | undefined> = process.env,
  warn: WarnFn = console.warn,
  options: BootstrapOptions = {},
): Promise<Bootstrapped> {
  const config = loadConfig(env, 8080);
  const metrics = new ServiceMetrics();
  announceDevMode(config, warn);
  announceSelfSignedCertificate(config, warn);

  const { keys, usedTestFallback } = await resolveVerifierIdentity(
    config,
    async () => {
      const verifier = await generateTestKeyMaterial('Service Verifier TEST');
      return { privateKey: verifier.privateKey, publicKey: verifier.publicKey, publicJwk: verifier.publicJwk, certificateChain: [verifier.certDerBytes] };
    },
    env,
  );
  if (usedTestFallback) warn('!!! Verifier-Identität: TEST-MATERIAL wird verwendet (ATTACK_DEV_MODE aktiv). !!!');

  const { anchors: issuerAnchors, usedTestAnchor } = await resolveIssuerAnchors(
    config,
    async () => (await generateTestKeyMaterial('Service Issuer TEST')).certDerBytes,
    env,
  );
  if (usedTestAnchor) warn('!!! Aussteller-Vertrauensanker: TEST-MATERIAL wird verwendet (ATTACK_DEV_MODE aktiv). !!!');

  // Credential-Statusprüfung (fail closed): ohne Entwicklungsschalter echte
  // Token-Status-List-Prüfung; NO_CREDENTIAL_STATUS nur mit ATTACK_DEV_MODE.
  const credentialStatus: CredentialStatusChecker = config.devMode
    ? NO_CREDENTIAL_STATUS
    : new TokenStatusListChecker({ trustedSigners: () => issuerAnchors, clockSkewSeconds: config.clockSkewSeconds });
  if (credentialStatus === NO_CREDENTIAL_STATUS) warn('!!! Credential-Statusprüfung ist ABGESCHALTET (ATTACK_DEV_MODE aktiv). !!!');

  // Sperrprüfung der Aussteller-Zertifikatskette über OCSP (fail closed, mit
  // der freigegebenen Gnadenfrist aus [interne Notiz, nicht veröffentlicht]:
  // Option B, 24 Stunden). NO_REVOCATION nur mit Entwicklungsschalter.
  // Der Beobachter meldet dem Dienst, dass eine veraltete `good`-Antwort aus der
  // Gnadenfrist verwendet wurde. Der Dienst schreibt daraus ein Audit-Ereignis
  // mit Mandant und Sitzung (B8). Ohne Zertifikatsdaten. Der Zähler wird nach der
  // Service-Konstruktion an den Dienst gebunden (unten).
  // Zähler der Gnadenfrist-Verwendungen. Der Dienst wertet ihn beim Schreiben
  // des Audit-Ereignisses aus, weil nur er den Mandanten kennt (B8).
  const gracePeriodSeen = { count: 0 };
  const issuerRevocation: RevocationChecker = config.devMode
    ? NO_REVOCATION
    : new OcspRevocationChecker({
        clockSkewSeconds: config.clockSkewSeconds,
        unavailableMode: 'bounded-soft-fail',
        observer: {
          onGracePeriodUse: () => gracePeriodSeen.count += 1,
          onCacheHit: () => metrics.recordOcspCacheHit(),
          onCacheMiss: () => metrics.recordOcspCacheMiss(),
        },
      });
  if (issuerRevocation === NO_REVOCATION) warn('!!! Aussteller-Sperrprüfung ist ABGESCHALTET (ATTACK_DEV_MODE aktiv). !!!');

  const tenants = new TenantStore();
  const testTenants: Array<{ id: string; apiKey: string }> = [];
  if (config.devMode) {
    for (const t of DEV_TEST_TENANTS) {
      tenants.add(t);
      testTenants.push({ id: t.id, apiKey: t.apiKey });
    }
    warn('!!! Test-Mandanten mit bekannten API-Schlüsseln sind angelegt (ATTACK_DEV_MODE aktiv). !!!');
  }

  // Entitlement-Quelle (eigener fail-closed-Schritt, vor dem Onboarding-Material):
  // Eine konfigurierte, aber kaputte JSON-Datei bricht hier den Start ab. Der
  // Schritt steht bewusst außerhalb des `catch` unten, weil ein Fehler der
  // Karte sonst als "kein Gate" verschluckt würde und der Dienst scheinbar
  // sauber ohne Onboarding-Prüfung liefe.
  const entitlementProvider = createEntitlementMapProvider(config, env);
  const entitlementMap = await entitlementProvider.resolve();
  warn(`Entitlement-Quelle: ${entitlementProvider.label} (${Object.keys(entitlementMap).length} Einträge).`);

  // Onboarding-Gate (B3): ohne echtes WRPAC/WRPRC-Material bleibt es aus, der
  // Zustand wird aber laut gemeldet statt still durchgereicht.
  let onboardingMaterialError: ConfigError | undefined;
  const onboarding = await resolveOnboardingGate({
    config,
    env,
    revocation: config.devMode ? NO_REVOCATION : issuerRevocation,
    tenants,
    entitlementMap,
    clockSkewSeconds: config.clockSkewSeconds,
    ...(options.onboardingMaterial ? { loadMaterial: options.onboardingMaterial } : {}),
  }).catch((e: unknown) => {
    if (e instanceof ConfigError) {
      onboardingMaterialError = e;
      return undefined;
    }
    throw e;
  });
  const onboardingState = describeOnboardingState(onboarding ? { gate: onboarding } : { gate: undefined, ...(onboardingMaterialError ? { error: onboardingMaterialError } : {}) });
  if (!onboarding) warn(onboardingState);
  if (onboarding) {
    warn('!!! Onboarding-Gate ist AKTIV (WRPAC/WRPRC-Prüfung). !!!');
  }

  const audit = new AuditLog();
  const service = new VerifierService(
    tenants,
    audit,
    keys,
    issuerAnchors,
    undefined,
    undefined,
    undefined,
    onboarding,
    config.allowSelfSignedCertificate,
    { mode: config, credentialStatus, issuerRevocation, gracePeriodSeen, resultTtlMs: config.resultTtlSeconds * 1000, clockSkewSeconds: config.clockSkewSeconds },
  );

  return {
    config,
    tenants,
    audit,
    service,
    usedTestIdentity: usedTestFallback,
    usedTestAnchor,
    issuerAnchors,
    credentialStatus,
    issuerRevocation,
    onboardingActive: onboarding !== undefined,
    onboardingState,
    testTenants,
    metrics,
  };
}
