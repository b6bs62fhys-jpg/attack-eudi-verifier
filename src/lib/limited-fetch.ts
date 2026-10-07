/**
 * Begrenzter HTTP-Abruf für Sperrquellen (CRL, OCSP, Token Status List).
 *
 * Jeder Abruf hat eine harte Zeitgrenze (gilt für Verbindungsaufbau UND das
 * Lesen des Körpers) und eine harte Größengrenze (Content-Length vorab und
 * mitgezählte Bytes beim Lesen). Fehler werden in feste Codes übersetzt;
 * Rohmeldungen der Laufzeit verlassen dieses Modul nicht.
 *
 * GET (CRL, Statusliste) und POST (OCSP-Anfrage) werden unterstützt; ein
 * POST ohne Inhaltstyp oder mit leerem Körper wird abgewiesen.
 */

export type LimitedFetchErrorCode = 'fetch_unreachable' | 'fetch_timeout' | 'fetch_too_large' | 'fetch_http_status' | 'fetch_url_invalid';

export class LimitedFetchError extends Error {
  readonly code: LimitedFetchErrorCode;
  constructor(code: LimitedFetchErrorCode) {
    super(code);
    this.name = 'LimitedFetchError';
    this.code = code;
  }
}

export interface FetchInit {
  signal: AbortSignal;
  headers: Record<string, string>;
  /** HTTP-Methode. Standard GET. */
  method?: string;
  /** Anfragekörper (z. B. DER-codierte OCSP-Anfrage). Nur bei POST. */
  body?: Uint8Array;
  /** Inhaltstyp des Körpers. Nur bei POST. */
  contentType?: string;
}

export type FetchImpl = (url: string, init: FetchInit) => Promise<Response>;

export interface LimitedFetchOptions {
  /** Zeitgrenze für den gesamten Abruf in Millisekunden. */
  timeoutMs: number;
  /** Maximale Größe des Antwortkörpers in Bytes. */
  maxBytes: number;
  accept?: string;
  /** HTTP-Methode. Standard GET. */
  method?: string;
  /** Anfragekörper (nur bei POST). */
  body?: Uint8Array;
  /** Inhaltstyp des Körpers (nur bei POST). */
  contentType?: string;
  fetchImpl?: FetchImpl;
}

export interface LimitedFetchResult {
  status: number;
  contentType: string;
  body: Uint8Array;
}

export const DEFAULT_FETCH_TIMEOUT_MS = 5_000;
export const DEFAULT_FETCH_MAX_BYTES = 1024 * 1024;

export async function fetchLimited(url: string, options: LimitedFetchOptions): Promise<LimitedFetchResult> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new LimitedFetchError('fetch_url_invalid');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') throw new LimitedFetchError('fetch_url_invalid');

  const fetchImpl: FetchImpl = options.fetchImpl ?? ((u, init) => fetch(u, init as unknown as RequestInit));
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, options.timeoutMs);

  // Die Zeitgrenze muss auch dann greifen, wenn eine (Mock-)Implementierung
  // das AbortSignal ignoriert.
  const timeout = new Promise<never>((_, reject) => {
    controller.signal.addEventListener('abort', () => reject(new LimitedFetchError(timedOut ? 'fetch_timeout' : 'fetch_unreachable')), { once: true });
  });

  try {
    return await Promise.race([readLimited(fetchImpl, url, controller, options), timeout]);
  } catch (e) {
    if (timedOut) throw new LimitedFetchError('fetch_timeout');
    if (e instanceof LimitedFetchError) throw e;
    throw new LimitedFetchError('fetch_unreachable');
  } finally {
    clearTimeout(timer);
    if (!controller.signal.aborted) controller.abort();
  }
}

async function readLimited(fetchImpl: FetchImpl, url: string, controller: AbortController, options: LimitedFetchOptions): Promise<LimitedFetchResult> {
  const method = options.method ?? 'GET';
  if (method !== 'GET' && method !== 'POST') throw new LimitedFetchError('fetch_url_invalid');
  const headers: Record<string, string> = {};
  if (options.accept) headers.accept = options.accept;
  if (options.body !== undefined && options.body.byteLength === 0) throw new LimitedFetchError('fetch_url_invalid');
  if (options.body !== undefined && method !== 'POST') throw new LimitedFetchError('fetch_url_invalid');
  if (options.body !== undefined) {
    if (!options.contentType) throw new LimitedFetchError('fetch_url_invalid');
    headers['content-type'] = options.contentType;
  }
  const init: FetchInit = { signal: controller.signal, headers };
  if (method === 'POST' && options.body) {
    init.method = method;
    init.body = options.body;
  }
  const res = await fetchImpl(url, init);
  if (res.status < 200 || res.status >= 300) throw new LimitedFetchError('fetch_http_status');

  const declared = Number(res.headers.get('content-length') ?? '');
  if (Number.isFinite(declared) && declared > options.maxBytes) throw new LimitedFetchError('fetch_too_large');

  const chunks: Uint8Array[] = [];
  let total = 0;
  if (res.body) {
    const reader = res.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > options.maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new LimitedFetchError('fetch_too_large');
      }
      chunks.push(value);
    }
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { status: res.status, contentType: res.headers.get('content-type') ?? '', body };
}
