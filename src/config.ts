/**
 * Zentrale Konfiguration: Eine Datei, die beim Start alle Umgebungsvariablen
 * einliest, prüft und bei ungültigen Werten (oder einer gefährlichen
 * Kombination) den Start mit klarer Meldung abbricht. Der VerifierService
 * liest selbst keine Umgebungsvariablen – er bekommt die entschiedenen Werte
 * über diese Konfiguration. So bleiben Tests deterministisch.
 *
 * Fail-closed ist Absicht: Ohne Konfiguration wird nichts stillschweigend
 * „tolerant". Fehlermeldungen enthalten niemals Schlüssel- oder
 * Zertifikatsinhalt.
 */

export const ENV_NODE_ENV = 'NODE_ENV';
export const ENV_PORT = 'PORT';
/** Bind-Adresse des HTTP-Dienstes; standardmäßig nur lokal erreichbar. */
export const ENV_ATTACK_HOST = 'ATTACK_HOST';
/**
 * Ausdrücklicher Entwicklungsschalter. Nur mit ATTACK_DEV_MODE=true (und
 * NODE_ENV != production) sind Lockerungen erlaubt: Rückfall auf
 * Testmaterial (Verifier-Identität, Aussteller-Anker, Test-Mandanten),
 * selbstsigniertes Material, abgeschaltete Sperr-/Statusprüfung.
 * In Produktion verboten.
 */
export const ENV_ATTACK_DEV_MODE = 'ATTACK_DEV_MODE';
/** Erlaubt selbstsignierte Verifier-Zertifikate. Nur mit ATTACK_DEV_MODE=true, in Produktion verboten (Abbruch). */
export const ENV_ATTACK_ALLOW_SELF_SIGNED = 'ATTACK_ALLOW_SELF_SIGNED';
/** Pfad zu einer PEM-PKCS#8-Datei mit dem Verifier-Private-Key (ECDSA P-256). */
export const ENV_ATTACK_VERIFIER_KEY_PEM = 'ATTACK_VERIFIER_KEY_PEM';
/** Pfad zu einer PEM-Datei mit der Verifier-Zertifikatskette (Blatt zuerst). */
export const ENV_ATTACK_VERIFIER_CERT_CHAIN_PEM = 'ATTACK_VERIFIER_CERT_CHAIN_PEM';
/** Pfad zu einer PEM-Datei mit den Vertrauensankern der Credential-Aussteller. */
export const ENV_ATTACK_ISSUER_TRUST_ANCHORS_PEM = 'ATTACK_ISSUER_TRUST_ANCHORS_PEM';
/**
 * Öffentliche Basis-URL des Dienstes, so wie die Wallet ihn erreicht (z. B.
 * https://verifier.example.de). Request URI und Response URI werden daraus
 * abgeleitet. Muss https sein (http nur mit ATTACK_DEV_MODE=true), ohne
 * Query und Fragment. Im Produktionsmodus Pflicht; ohne sie gäbe der Dienst
 * Adressen wie http://0.0.0.0:8080 aus, die keine Wallet erreicht.
 */
export const ENV_ATTACK_PUBLIC_BASE_URL = 'ATTACK_PUBLIC_BASE_URL';
/**
 * Optional, standardmäßig aus. Adresse einer Seite des Betreibers, zu der die
 * Wallet nach der Antwort des Dienstes navigieren soll (`redirect_uri` in der
 * Antwort auf `direct_post`). Nur für den Ablauf auf einem einzigen Gerät: der
 * Link öffnet sich im Browser des Geräts, auf dem die Wallet läuft, bei einem
 * QR-Code auf einem zweiten Gerät wäre das das falsche Gerät. Der Dienst hängt
 * `session_id` an. Muss https sein (http nur mit ATTACK_DEV_MODE=true).
 */
export const ENV_ATTACK_REDIRECT_URI = 'ATTACK_REDIRECT_URI';
/**
 * Gültigkeit eines Request Objects in Sekunden (30..600, Standard 120). Das ist
 * das `exp` im signierten Request Object, also die Zeit, in der die Wallet es
 * annehmen soll.
 */
export const ENV_ATTACK_REQUEST_OBJECT_TTL_SECONDS = 'ATTACK_REQUEST_OBJECT_TTL_SECONDS';
export const DEFAULT_REQUEST_OBJECT_TTL_SECONDS = 120;
export const REQUEST_OBJECT_TTL_MIN_SECONDS = 30;
export const REQUEST_OBJECT_TTL_MAX_SECONDS = 600;
/**
 * Erlaubte Uhrabweichung in Sekunden für Gültigkeitszeiträume von
 * Zertifikaten und Zeitangaben signierter Objekte (0..300, Standard 60).
 */
  export const ENV_ATTACK_CLOCK_SKEW_SECONDS = 'ATTACK_CLOCK_SKEW_SECONDS';
  export const DEFAULT_CLOCK_SKEW_SECONDS_CONFIG = 60;
  /**
   * Obergrenze der Uhrabweichung in Sekunden.
   *
   * Ausgelagert, weil die Grenze nicht nur in der Konfiguration, sondern auch
   * an den Stellen gelten muss, die die Abweichung im Konstruktor bekommen
   * (`src/onboarding/registrar.ts`). Eine zweite Grenze mit derselben Zahl wäre
   * eine zweite Wahrheit und könnte von dieser hier abweichen.
   */
  export const CLOCK_SKEW_SECONDS_MAX = 300;
/** Lebensdauer eines fertigen Prüfergebnisses in Sekunden (1..3600, Standard 60). */
export const ENV_ATTACK_RESULT_TTL_SECONDS = 'ATTACK_RESULT_TTL_SECONDS';
export const DEFAULT_RESULT_TTL_SECONDS = 60;
/**
 * Ratenlimit der öffentlichen Routen je IP-Adresse im Fenster (Standard 120).
 * Gilt für `/direct_post` und das Request-Object; die Betriebsroutes sind
 * ausgenommen.
 */
export const ENV_ATTACK_RATE_LIMIT_PUBLIC = 'ATTACK_RATE_LIMIT_PUBLIC_PER_WINDOW';
export const DEFAULT_RATE_LIMIT_PUBLIC = 120;
/**
 * Ratenlimit der mandantenpflichtigen Routen je API-Schlüssel im Fenster
 * (Standard 60). Das ist die eigentliche Obergrenze des Dienstes: 60 je 60
 * Sekunden ergibt dauerhaft rund eine Anfrage je Sekunde und Mandant.
 */
export const ENV_ATTACK_RATE_LIMIT_TENANT = 'ATTACK_RATE_LIMIT_TENANT_PER_WINDOW';
export const DEFAULT_RATE_LIMIT_TENANT = 60;
/** Länge des Ratenfensters in Sekunden (1..3600, Standard 60). */
export const ENV_ATTACK_RATE_LIMIT_WINDOW = 'ATTACK_RATE_LIMIT_WINDOW_SECONDS';
export const DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60;

/** Wirksame Ratenbegrenzung, vom Dienst unverändert an den Limiter weitergegeben. */
export interface RateLimitConfig {
  publicPerWindow: number;
  tenantPerWindow: number;
  windowSeconds: number;
}

export interface AppConfig {
  /** true, wenn NODE_ENV === "production". */
  isProduction: boolean;
  /** true, wenn ATTACK_DEV_MODE exakt "true" ist. Alles andere ist aus. */
  devMode: boolean;
  /** true, wenn ATTACK_ALLOW_SELF_SIGNED exakt "true" ist (nie in Produktion). */
  allowSelfSignedCertificate: boolean;
  /** NODE_ENV, Standard "development". */
  nodeEnv: string;
  /** Port, Standard uebergeben via defaultPort. */
  port: number;
  /** Bind-Adresse des HTTP-Dienstes. */
  host?: string;
  /** Öffentliche Basis-URL ohne abschließenden Schrägstrich, falls gesetzt. */
  publicBaseUrl?: string;
  /** Adresse für `redirect_uri` an die Wallet, falls gesetzt (Standard: aus). */
  redirectUri?: string;
  /** Gültigkeit eines Request Objects in Sekunden. */
  requestObjectTtlSeconds?: number;
  /** Lebensdauer eines fertigen Ergebnisses in Sekunden. */
  resultTtlSeconds: number;
  /** Erlaubte Uhrabweichung in Sekunden (Zertifikate, signierte Listen). */
  clockSkewSeconds: number;
  /** Wirksame Ratenbegrenzung. */
  rateLimits: RateLimitConfig;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

/**
 * Liest und validiert die Konfiguration. Wirft ConfigError, wenn eine
 * verbotene Kombination vorliegt (Entwicklungsschalter in Produktion,
 * selbstsignierte Zertifikate in Produktion, unbrauchbarer Port).
 *
 * @param env Umgebung (Standard: process.env)
 * @param defaultPort Standard-Port, wenn PORT nicht gesetzt ist
 */
export function loadConfig(
  env: Record<string, string | undefined> = process.env,
  defaultPort = 8080,
): AppConfig {
  const nodeEnv = env[ENV_NODE_ENV] ?? 'development';
  const isProduction = nodeEnv === 'production';
  const devMode = env[ENV_ATTACK_DEV_MODE] === 'true';
  const allowSelfSignedCertificate = env[ENV_ATTACK_ALLOW_SELF_SIGNED] === 'true';

  if (isProduction && devMode) {
    throw new ConfigError(
      `${ENV_NODE_ENV}=production und ${ENV_ATTACK_DEV_MODE}=true widersprechen sich. ` +
        'Der Entwicklungsschalter ist nur in lokalen Umgebungen erlaubt. Start abgebrochen.',
    );
  }

  if (isProduction && allowSelfSignedCertificate) {
    throw new ConfigError(
      `${ENV_ATTACK_ALLOW_SELF_SIGNED}=true ist in ${ENV_NODE_ENV}=production verboten. ` +
        'Selbstsignierte Zertifikate heben die Vertrauenskette des Verifier auf. ' +
        'Start abgebrochen.',
    );
  }

  // Jede Lockerung hängt am Entwicklungsschalter: selbstsigniert nur mit
  // ATTACK_DEV_MODE=true (Haertung 4).
  if (allowSelfSignedCertificate && !devMode) {
    throw new ConfigError(
      `${ENV_ATTACK_ALLOW_SELF_SIGNED}=true ist nur zusammen mit ${ENV_ATTACK_DEV_MODE}=true erlaubt. ` +
        'Start abgebrochen.',
    );
  }

  let port = defaultPort;
  const portRaw = env[ENV_PORT];
  if (portRaw !== undefined && portRaw !== '') {
    const parsed = Number(portRaw);
    if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65_535) {
      throw new ConfigError(`${ENV_PORT} muss eine ganze Zahl zwischen 1 und 65535 sein. Start abgebrochen.`);
    }
    port = parsed;
  }

  const host = env[ENV_ATTACK_HOST]?.trim() || '127.0.0.1';

  const publicBaseUrl = parsePublicBaseUrl(env[ENV_ATTACK_PUBLIC_BASE_URL], devMode);
  const redirectUri = parseRedirectUri(env[ENV_ATTACK_REDIRECT_URI], devMode);
  const requestObjectTtlSeconds = zahlAusUmgebung(
    env,
    ENV_ATTACK_REQUEST_OBJECT_TTL_SECONDS,
    DEFAULT_REQUEST_OBJECT_TTL_SECONDS,
    REQUEST_OBJECT_TTL_MIN_SECONDS,
    REQUEST_OBJECT_TTL_MAX_SECONDS,
  );
  if (isProduction && !publicBaseUrl) {
    throw new ConfigError(
      `${ENV_ATTACK_PUBLIC_BASE_URL} ist im Produktionsmodus Pflicht (öffentliche https-Adresse, unter der die Wallet den Dienst erreicht). ` +
        'Start abgebrochen.',
    );
  }

  let resultTtlSeconds = DEFAULT_RESULT_TTL_SECONDS;
  const ttlRaw = env[ENV_ATTACK_RESULT_TTL_SECONDS];
  if (ttlRaw !== undefined && ttlRaw !== '') {
    const parsed = Number(ttlRaw);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > 3600) {
      throw new ConfigError(`${ENV_ATTACK_RESULT_TTL_SECONDS} muss eine ganze Zahl zwischen 1 und 3600 sein. Start abgebrochen.`);
    }
    resultTtlSeconds = parsed;
  }

  // Ueber den gemeinsamen Helfer, damit Grenze und Meldung nicht an zwei
  // Stellen gepflegt werden muessen. Die Meldung ist woertlich dieselbe wie
  // vorher: derselbe Aufbau, dieselbe Zahl aus CLOCK_SKEW_SECONDS_MAX.
  const clockSkewSeconds = zahlAusUmgebung(env, ENV_ATTACK_CLOCK_SKEW_SECONDS, DEFAULT_CLOCK_SKEW_SECONDS_CONFIG, 0, CLOCK_SKEW_SECONDS_MAX);

  // Ratenbegrenzung. Die Obergrenze liegt bewusst hoch (1_000_000), damit ein
  // Betrieb sie wirklich einstellen kann; sie ist keine sinnvolle Schutzgrenze,
  // sondern eine Fehlkonfigurationsbremse.
  const rateLimits: RateLimitConfig = {
    publicPerWindow: zahlAusUmgebung(env, ENV_ATTACK_RATE_LIMIT_PUBLIC, DEFAULT_RATE_LIMIT_PUBLIC, 1, 1_000_000),
    tenantPerWindow: zahlAusUmgebung(env, ENV_ATTACK_RATE_LIMIT_TENANT, DEFAULT_RATE_LIMIT_TENANT, 1, 1_000_000),
    windowSeconds: zahlAusUmgebung(env, ENV_ATTACK_RATE_LIMIT_WINDOW, DEFAULT_RATE_LIMIT_WINDOW_SECONDS, 1, 3600),
  };

  return {
    isProduction,
    devMode,
    allowSelfSignedCertificate,
    nodeEnv,
    port,
    host,
    ...(publicBaseUrl ? { publicBaseUrl } : {}),
    ...(redirectUri ? { redirectUri } : {}),
    requestObjectTtlSeconds,
    resultTtlSeconds,
    clockSkewSeconds,
    rateLimits,
  };
}

/**
 * Prüft ATTACK_REDIRECT_URI (fail closed): https (http nur mit
 * Entwicklungsschalter), keine Zugangsdaten, kein Fragment. Eine Query ist
 * erlaubt; der Dienst ergänzt `session_id`.
 */
function parseRedirectUri(raw: string | undefined, devMode: boolean): string | undefined {
  if (raw === undefined || raw.trim() === '') return undefined;
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new ConfigError(`${ENV_ATTACK_REDIRECT_URI} ist keine gültige URL. Start abgebrochen.`);
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && devMode)) {
    throw new ConfigError(`${ENV_ATTACK_REDIRECT_URI} muss mit https:// beginnen (http nur mit ${ENV_ATTACK_DEV_MODE}=true). Start abgebrochen.`);
  }
  if (url.hash || url.username || url.password) {
    throw new ConfigError(`${ENV_ATTACK_REDIRECT_URI} darf weder Fragment noch Zugangsdaten enthalten. Start abgebrochen.`);
  }
  return url.toString();
}

/**
 * Prüft die öffentliche Basis-URL (fail closed). Liefert sie ohne
 * abschließenden Schrägstrich oder `undefined`, wenn nichts gesetzt ist.
 */
function parsePublicBaseUrl(raw: string | undefined, devMode: boolean): string | undefined {
  if (raw === undefined || raw.trim() === '') return undefined;
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new ConfigError(`${ENV_ATTACK_PUBLIC_BASE_URL} ist keine gültige URL. Start abgebrochen.`);
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && devMode)) {
    throw new ConfigError(
      `${ENV_ATTACK_PUBLIC_BASE_URL} muss mit https:// beginnen (http nur mit ${ENV_ATTACK_DEV_MODE}=true). Start abgebrochen.`,
    );
  }
  if (url.search || url.hash || url.username || url.password) {
    throw new ConfigError(`${ENV_ATTACK_PUBLIC_BASE_URL} darf weder Query, Fragment noch Zugangsdaten enthalten. Start abgebrochen.`);
  }
  return `${url.origin}${url.pathname.replace(/\/+$/, '')}`;
}

/** Ganzzahl aus der Umgebung mit Grenzen, fail closed bei unbrauchbarem Wert. */
function zahlAusUmgebung(
  env: Record<string, string | undefined>,
  key: string,
  standard: number,
  min: number,
  max: number,
): number {
  const raw = env[key];
  if (raw === undefined || raw === '') return standard;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new ConfigError(`${key} muss eine ganze Zahl zwischen ${min} und ${max} sein. Start abgebrochen.`);
  }
  return parsed;
}

export type WarnFn = (message: string) => void;

/** Laute Warnung beim Start, wenn der Entwicklungsschalter aktiv ist. */
export function announceDevMode(config: AppConfig, warn: WarnFn = console.warn): void {
  if (config.devMode) {
    warn('!!! WARNUNG: ATTACK_DEV_MODE=true ist AKTIV !!!');
    warn('!!! Es kann Testmaterial statt einer echten Verifier-Identität verwendet werden. !!!');
    warn('!!! Sperr- und Statusprüfung können abgeschaltet sein. !!!');
    warn('!!! Nur fuer lokale Entwicklung und Tests, niemals in Produktion. !!!');
  }
}

/** Laute Warnung beim Start, wenn selbstsignierte Zertifikate erlaubt sind. */
export function announceSelfSignedCertificate(config: AppConfig, warn: WarnFn = console.warn): void {
  if (config.allowSelfSignedCertificate) {
    warn('!!! WARNUNG: ATTACK_ALLOW_SELF_SIGNED=true ist AKTIV !!!');
    warn('!!! Selbstsignierte Verifier-Zertifikate werden akzeptiert. !!!');
    warn('!!! Nur fuer lokale Demo/Tests, niemals in Produktion. !!!');
  }
}

/**
 * Einheitlicher Abbruch beim Start: nur die Meldung, kein Stacktrace, keine
 * Schlüsselinhalte. Unerwartete Fehler werden nur mit ihrem Typ genannt.
 */
export function startupFailureMessage(e: unknown): string {
  if (e instanceof ConfigError) return e.message;
  const name = e instanceof Error ? e.name : typeof e;
  return `Start abgebrochen: unerwarteter Fehler beim Start (${name}).`;
}
