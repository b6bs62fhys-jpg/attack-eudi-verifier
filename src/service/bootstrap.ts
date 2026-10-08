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
import {ENV_ATTACK_REDIRECT_URI, announceDevMode, announceSelfSignedCertificate, ConfigError, loadConfig, type AppConfig, type WarnFn} from '../config.ts';
import {generateTestKeyMaterial} from '../decision-test/mock-wallet.ts';
import {AuditLog} from './audit.ts';
import {NO_CREDENTIAL_STATUS, TokenStatusListChecker, type CredentialStatusChecker} from './credential-status.ts';
import {OcspRevocationChecker} from '../onboarding/ocsp-revocation.ts';
import {CrlRevocationChecker} from '../onboarding/crl-revocation.ts';
import {
  buildRevocationChecker,
  COMBINED_CRL_TIMEOUT_MS,
  COMBINED_OCSP_TIMEOUT_MS,
  describeRevocationSources,
  ENV_ATTACK_ISSUER_REVOCATION_SOURCES,
  ENV_ATTACK_ONBOARDING_REVOCATION_SOURCES,
  parseRevocationSources,
  type RevocationSourceName,
} from '../onboarding/revocation-source.ts';
import {NO_REVOCATION, type RevocationChecker} from '../onboarding/revocation.ts';
import {createEntitlementMapProvider} from '../onboarding/entitlement-source.ts';
import {describeOnboardingState, resolveOnboardingGate, type OnboardingMaterial} from '../onboarding/onboarding-wiring.ts';
import {resolveIssuerAnchors} from './issuer-anchors.ts';
import {VerifierService} from './service.ts';
import {TenantStore} from './tenant.ts';
import {ENV_ATTACK_TRUSTED_PROXIES, parseTrustedProxies, type TrustedProxies} from '../lib/client-ip.ts';
import {applyTenantFile, ENV_ATTACK_TENANTS_FILE, loadTenantFile} from './tenant-file.ts';
import {ENV_ATTACK_REGISTRATION_CERTIFICATE_FILE, loadRegistrationCertificate, type VerifierInfoEntry} from './registration-certificate.ts';
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
  /** Vertrauenswürdige Reverse Proxys (ATTACK_TRUSTED_PROXIES), falls konfiguriert. */
  trustedProxies?: TrustedProxies;
  /** Mandanten aus ATTACK_TENANTS_FILE (undefined, wenn keine Datei konfiguriert ist). */
  tenantFile?: { active: number; revoked: number };
  /** Sperrprüfung der Aussteller-Zertifikatskette. */
  issuerRevocation: RevocationChecker;
  /** Konfigurierte Sperrquellen der Aussteller-Kette, in Vorrangreihenfolge. */
  issuerRevocationSources: readonly RevocationSourceName[];
  /** Sperrprüfung im Onboarding-Gate; eigene Instanz ohne geerbte Gnadenfrist. */
  onboardingRevocation: RevocationChecker;
  /** Konfigurierte Sperrquellen des Onboarding-Gates, in Vorrangreihenfolge. */
  onboardingRevocationSources: readonly RevocationSourceName[];
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
  // Sperrquellen je Prüfpfad (revocation-source.ts): Standard OCSP zuerst, CRL
  // als Rückfall; im Produktionsmodus ist CRL Pflicht. Die Variablen werden
  // auch im Entwicklungsbetrieb gelesen, damit ein Tippfehler nicht erst in
  // Produktion auffällt.
  const issuerRevocationSources = parseRevocationSources(env, ENV_ATTACK_ISSUER_REVOCATION_SOURCES, config);
  const onboardingRevocationSources = parseRevocationSources(env, ENV_ATTACK_ONBOARDING_REVOCATION_SOURCES, config);
  const issuerRevocation: RevocationChecker = config.devMode
    ? NO_REVOCATION
    : buildRevocationChecker(issuerRevocationSources, {
        ocsp: (combined) =>
          new OcspRevocationChecker({
            clockSkewSeconds: config.clockSkewSeconds,
            unavailableMode: 'bounded-soft-fail',
            ...(combined ? { timeoutMs: COMBINED_OCSP_TIMEOUT_MS } : {}),
            observer: {
              onGracePeriodUse: () => gracePeriodSeen.count += 1,
              onCacheHit: () => metrics.recordOcspCacheHit(),
              onCacheMiss: () => metrics.recordOcspCacheMiss(),
            },
          }),
        crl: (combined) =>
          new CrlRevocationChecker({ clockSkewSeconds: config.clockSkewSeconds, ...(combined ? { timeoutMs: COMBINED_CRL_TIMEOUT_MS } : {}) }),
      });
  if (issuerRevocation === NO_REVOCATION) warn('!!! Aussteller-Sperrprüfung ist ABGESCHALTET (ATTACK_DEV_MODE aktiv). !!!');
  else warn(`Sperrquellen Aussteller-Kette: ${describeRevocationSources(issuerRevocationSources)} (${ENV_ATTACK_ISSUER_REVOCATION_SOURCES}).`);

  // Credential-Statusprüfung (fail closed): ohne Entwicklungsschalter echte
  // Token-Status-List-Prüfung; NO_CREDENTIAL_STATUS nur mit ATTACK_DEV_MODE.
  // Der Unterzeichner einer Statusliste muss selbst ein Aussteller-Anker oder
  // von einem Anker signiert sein (Kette, Gültigkeit, Schlüsselverwendung); im
  // zweiten Fall wird seine Kette mit denselben Sperrquellen geprüft wie die
  // Aussteller-Kette eines Credentials. Die Sandbox-Vertrauensliste führt für
  // Statuslisten eine CA, nicht das Unterzeichner-Zertifikat selbst.
  const credentialStatus: CredentialStatusChecker = config.devMode
    ? NO_CREDENTIAL_STATUS
    : new TokenStatusListChecker({ trustedSigners: () => issuerAnchors, clockSkewSeconds: config.clockSkewSeconds, revocation: issuerRevocation });
  if (credentialStatus === NO_CREDENTIAL_STATUS) warn('!!! Credential-Statusprüfung ist ABGESCHALTET (ATTACK_DEV_MODE aktiv). !!!');


  // Eigene Sperrprüfung für das Onboarding-Gate. Bewusst eine eigene Instanz:
  // OCSP hier strikt, ohne die 24-Stunden-Gnadenfrist des Credential-Pfads. Die
  // Frist für Zugangs- und Registrierungszertifikate ist nicht festgelegt und
  // wird deshalb nicht geerbt.
  const onboardingRevocation: RevocationChecker = config.devMode
    ? NO_REVOCATION
    : buildRevocationChecker(onboardingRevocationSources, {
        ocsp: (combined) => new OcspRevocationChecker({ clockSkewSeconds: config.clockSkewSeconds, ...(combined ? { timeoutMs: COMBINED_OCSP_TIMEOUT_MS } : {}) }),
        crl: (combined) =>
          new CrlRevocationChecker({ clockSkewSeconds: config.clockSkewSeconds, ...(combined ? { timeoutMs: COMBINED_CRL_TIMEOUT_MS } : {}) }),
      });

  const tenants = new TenantStore();
  const testTenants: Array<{ id: string; apiKey: string }> = [];
  if (config.devMode) {
    for (const t of DEV_TEST_TENANTS) {
      tenants.add(t);
      testTenants.push({ id: t.id, apiKey: t.apiKey });
    }
    warn('!!! Test-Mandanten mit bekannten API-Schlüsseln sind angelegt (ATTACK_DEV_MODE aktiv). !!!');
  }

  // Mandantendatei (fail closed): Ist die Variable gesetzt, muss die Datei
  // vollständig gültig sein, sonst bricht der Start ab. Ohne Variable startet
  // der Dienst, kann aber ohne Entwicklungsschalter keine Prüfanfrage annehmen;
  // das wird laut gemeldet statt still hingenommen.
  let tenantFile: { active: number; revoked: number } | undefined;
  const tenantFilePath = env[ENV_ATTACK_TENANTS_FILE];
  if (tenantFilePath) {
    try {
      tenantFile = applyTenantFile(tenants, await loadTenantFile(tenantFilePath));
    } catch (e) {
      if (e instanceof ConfigError) throw new ConfigError(`${e.message} Start abgebrochen.`);
      throw e;
    }
    warn(`Mandantendatei: ${tenantFile.active} aktiv, ${tenantFile.revoked} gesperrt (${ENV_ATTACK_TENANTS_FILE}).`);
  } else if (!config.devMode) {
    warn(`Keine Mandantendatei konfiguriert (${ENV_ATTACK_TENANTS_FILE}). Ohne Mandanten lehnt der Dienst jede Prüfanfrage mit 401 ab.`);
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
    revocation: onboardingRevocation,
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

  // Registrierungszertifikat für verifier_info (fail closed, wenn gesetzt).
  // Ohne es lehnt die Wallet laut offizieller Doku die Anfrage ab; der Dienst
  // startet trotzdem, weil das keine Lockerung ist, meldet es aber laut.
  let verifierInfo: VerifierInfoEntry[] = [];
  const registrationCertificatePath = env[ENV_ATTACK_REGISTRATION_CERTIFICATE_FILE];
  if (registrationCertificatePath) {
    verifierInfo = [await loadRegistrationCertificate(registrationCertificatePath, new Date(), config.clockSkewSeconds)];
    warn(`Registrierungszertifikat geladen, wird als verifier_info in jede Presentation Request übernommen (${ENV_ATTACK_REGISTRATION_CERTIFICATE_FILE}).`);
  } else if (!config.devMode) {
    warn(
      `Kein Registrierungszertifikat konfiguriert (${ENV_ATTACK_REGISTRATION_CERTIFICATE_FILE}). ` +
        'Ohne verifier_info lehnt die EUDI-Wallet die Anfrage laut offizieller Doku ab.',
    );
  }

  // Vertrauenswürdige Proxys für die Ratenbegrenzung (fail closed bei
  // ungültigem Eintrag). Ohne Angabe zählt immer die direkte Gegenstelle.
  const trustedProxies = parseTrustedProxies(env[ENV_ATTACK_TRUSTED_PROXIES]);
  if (trustedProxies) warn(`Vertrauenswürdige Proxys: ${trustedProxies.entries.join(', ')}. X-Forwarded-For wird nur von dort ausgewertet (${ENV_ATTACK_TRUSTED_PROXIES}).`);

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
    {
      mode: config,
      credentialStatus,
      issuerRevocation,
      gracePeriodSeen,
      resultTtlMs: config.resultTtlSeconds * 1000,
      clockSkewSeconds: config.clockSkewSeconds,
      verifierInfo,
      ...(config.redirectUri ? { redirectUri: config.redirectUri } : {}),
      requestObjectTtlSeconds: config.requestObjectTtlSeconds,
    },
  );
  if (config.redirectUri) warn(`redirect_uri ist aktiv (${ENV_ATTACK_REDIRECT_URI}): nur für den Ablauf auf einem Gerät, nicht für QR-Codes auf einem zweiten Gerät.`);
  // Öffentliche Basis-URL: daraus leitet der Dienst Request URI und Response
  // URI ab. Ohne sie setzt run.ts nach dem Start die lokale Adresse (nur
  // außerhalb von Produktion, siehe loadConfig).
  if (config.publicBaseUrl) service.baseUrl = config.publicBaseUrl;

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
    issuerRevocationSources,
    onboardingRevocation,
    onboardingRevocationSources,
    onboardingActive: onboarding !== undefined,
    onboardingState,
    testTenants,
    ...(tenantFile ? { tenantFile } : {}),
    ...(trustedProxies ? { trustedProxies } : {}),
    metrics,
  };
}
