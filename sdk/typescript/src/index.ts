import type { components } from './generated.ts';

export type CreateRequestInput = components['schemas']['CreateRequestInput'];
export type CreateRequestOutput = components['schemas']['CreateRequestOutput'];
export type RegistrationRef = components['schemas']['RegistrationRef'];
export type ResultStatus = components['schemas']['ResultStatus'];
export type PresentationResponse = components['schemas']['PresentationResponse'];
export type VerificationResult = components['schemas']['VerificationResult'];
export type ErrorCode = components['schemas']['Error']['error'];
export type LivenessResponse = components['schemas']['LivenessResponse'];
export type ReadinessResponse = components['schemas']['ReadinessResponse'];

/**
 * HTTP 422: die Präsentation kam an, wurde aber nicht angenommen. Der
 * Ablehnungsgrund steht im Body, deshalb ist das ein Ergebnis und kein Fehler.
 * 401 bleibt exklusiv für den API-Schlüssel, 413 für die Größengrenze.
 */
const REJECTED_PRESENTATION = 422;

export interface AttackClientOptions {
  baseUrl: string;
  apiKey?: string;
  fetch?: typeof globalThis.fetch;
}

export interface DirectPostEnvelope {
  vp_token: Record<string, Array<string | Record<string, unknown>>>;
  state: string;
}

export interface DirectPostJwe {
  response: string;
}

export class AttackApiError extends Error {
  readonly status: number;
  readonly code?: ErrorCode;

  constructor(status: number, code?: ErrorCode) {
    super(code ?? `http_${status}`);
    this.name = 'AttackApiError';
    this.status = status;
    this.code = code;
  }
}

export class AttackClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly fetchImpl: typeof globalThis.fetch;

  constructor(options: AttackClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.apiKey = options.apiKey;
    this.fetchImpl = options.fetch ?? globalThis.fetch;
  }

  /**
   * `GET /live`: Prozess läuft, unabhängig von externen Abhängigkeiten. Die
   * Betriebsrouten sind nicht rate-limitiert und brauchen keinen API-Schlüssel.
   */
  async liveness(): Promise<LivenessResponse> {
    return this.request('/live', { method: 'GET' }, false);
  }

  /** `GET /health`: Dienst läuft. */
  async health(): Promise<{ ok: boolean; app?: string }> {
    return this.request('/health', { method: 'GET' }, false);
  }

  /**
   * `GET /ready`: Abhängigkeiten je einzeln. `not_ready` ist eine gültige
   * Antwort und kein Fehler, deshalb wird sie nicht als Ausnahme geworfen.
   * Der Dienst antwortet in diesem Fall mit HTTP 503.
   */
  async readiness(): Promise<ReadinessResponse> {
    const response = await this.fetchImpl(`${this.baseUrl}/ready`, { method: 'GET' });
    const payload = (await this.json<ReadinessResponse>(response)) as ReadinessResponse | undefined;
    // 503 mit lesbarem Body ist genau der Gegenstand dieser Methode.
    if (response.status === 503 && payload) return payload;
    if (!response.ok) throw await this.errorFrom(response, payload);
    if (!payload) throw new AttackApiError(response.status, 'invalid_request');
    return payload;
  }

  /** `GET /metrics`: Prometheus-Text, kein JSON. */
  async metrics(): Promise<string> {
    const response = await this.fetchImpl(`${this.baseUrl}/metrics`, { method: 'GET' });
    const body = await response.text();
    if (!response.ok) throw new AttackApiError(response.status, 'not_found');
    return body;
  }

  async createPresentationRequest(input: CreateRequestInput = {}): Promise<CreateRequestOutput> {
    return this.request('/v1/verification-requests', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(input),
    });
  }

  async getRequestObject(sessionId: string): Promise<string> {
    const response = await this.fetchImpl(`${this.baseUrl}/v1/verification-requests/${encodeURIComponent(sessionId)}/request-object`);
    if (!response.ok) throw await this.errorFrom(response);
    return response.text();
  }

  async submitPresentation(body: DirectPostEnvelope | DirectPostJwe): Promise<PresentationResponse> {
    const response = await this.fetchImpl(`${this.baseUrl}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const payload = await this.json<PresentationResponse>(response);
    // /direct_post ist die öffentliche Wallet-Route, es gab dort nichts zu
    // authentifizieren. Zwei Status tragen ein Ergebnis und dürfen
    // zurückgegeben werden: 200 (angenommen, ggf. valid:false) und 422 (nicht
    // angenommen, Ablehnungsgrund im Body). Alles andere außerhalb 2xx ist ein
    // Fehler der Anfrage.
    //
    // Vorher wurde nur dann geworfen, wenn kein Body lesbar war. Der Dienst
    // antwortet auf 401 aber mit `{"error":"unauthorized"}`, also wurde genau
    // diese Antwort als PresentationResponse zurückgegeben — mit fehlendem
    // `ok` und `valid`. Die Prüfung musste an 422 ausgerichtet werden, damit
    // die Wallet-Route nicht länger Authentifizierungsfehler als Ergebnis
    // tarnt.
    if (response.status !== REJECTED_PRESENTATION && !response.ok) throw await this.errorFrom(response, payload);
    if (!payload) throw new AttackApiError(response.status, 'invalid_request');
    return payload;
  }

  async getResult(sessionId: string): Promise<ResultStatus> {
    return this.request(`/v1/verification-requests/${encodeURIComponent(sessionId)}`, { method: 'GET' });
  }

  async deleteSession(sessionId: string): Promise<void> {
    await this.request<undefined>(`/v1/verification-requests/${encodeURIComponent(sessionId)}`, { method: 'DELETE' });
  }

  private async request<T>(path: string, init: RequestInit, authenticated = true): Promise<T> {
    const headers = new Headers(init.headers);
    if (authenticated && this.apiKey) headers.set('authorization', `Bearer ${this.apiKey}`);
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, { ...init, headers });
    const payload = await this.json<T>(response);
    if (!response.ok) throw await this.errorFrom(response, payload);
    return payload as T;
  }

  private async json<T>(response: Response): Promise<T | undefined> {
    if (response.status === 204) return undefined;
    const value: unknown = await response.json().catch(() => undefined);
    return value as T | undefined;
  }

  private async errorFrom(response: Response, payload?: unknown): Promise<AttackApiError> {
    const code = isErrorPayload(payload) ? payload.error : undefined;
    return new AttackApiError(response.status, code);
  }
}

function isErrorPayload(value: unknown): value is components['schemas']['Error'] {
  return typeof value === 'object' && value !== null && typeof (value as { error?: unknown }).error === 'string';
}
