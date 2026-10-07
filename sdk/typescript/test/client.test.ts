import { describe, expect, it, vi } from 'vitest';

import { AttackApiError, AttackClient, type CreateRequestOutput } from '../src/index.ts';

function response(status: number, body: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('AttackClient', () => {
  it('creates a presentation request with bearer authentication', async () => {
    const output: CreateRequestOutput = {
      sessionId: 'vs_test',
      state: 'vs_test',
      expiresAt: 1_768_320_000,
      requestObject: 'eyJ.test',
      responseUri: 'https://verifier.example/direct_post',
      requestObjectUri: 'https://verifier.example/v1/verification-requests/vs_test/request-object',
    };
    const fetcher = vi.fn<typeof fetch>(async (_input, init) => {
      expect(new Headers(init?.headers).get('authorization')).toBe('Bearer test-api-key');
      return response(201, output);
    });
    const client = new AttackClient({ baseUrl: 'https://verifier.example/', apiKey: 'test-api-key', fetch: fetcher });

    await expect(client.createPresentationRequest({ claims: ['age_over_18'] })).resolves.toEqual(output);
  });

  it('submits a presentation and returns the verifier result', async () => {
    const fetcher = vi.fn<typeof fetch>(async () => response(200, { ok: true, valid: true }));
    const client = new AttackClient({ baseUrl: 'https://verifier.example', fetch: fetcher });

    await expect(client.submitPresentation({ response: 'compact-jwe' })).resolves.toEqual({ ok: true, valid: true });
  });

  it('covers the three operational routes', async () => {
    // Die Betriebsrouten /live, /ready und /metrics fehlten im Client, obwohl
    // die Spec sie seit Paket 1 fuehrt. generate:check bewacht nur
    // generated.ts, nicht die von Hand geschriebenen Methoden.
    let aufgerufen = '';
    let authorization: string | null = 'nicht gesetzt';
    const fetcher = vi.fn<typeof fetch>(async (input, init) => {
      aufgerufen = String(input);
      authorization = new Headers(init?.headers).get('authorization');
      return response(200, { ok: true, status: 'live', app: 'attack-service' });
    });
    const client = new AttackClient({ baseUrl: 'https://verifier.example', apiKey: 'test-key', fetch: fetcher });

    await expect(client.liveness()).resolves.toEqual({ ok: true, status: 'live', app: 'attack-service' });
    expect(aufgerufen).toBe('https://verifier.example/live');
    // Betriebsrouten sind oeffentlich: es darf kein Authorization-Header laufen.
    expect(authorization).toBeNull();
  });

  it('treats /ready answering 503 as an answer, not an error', async () => {
    // not_ready ist eine gueltige Antwort auf genau diese Frage. Der Dienst
    // antwortet dafuer mit 503; ein Aufrufer darf daran keinen AttackApiError
    // sehen, sonst ist die Abhaengigkeitspruefung nicht durchfuehrbar.
    const fetcher = vi.fn<typeof fetch>(async () => response(503, { ok: false, status: 'not_ready', checks: { ocsp: 'failed' } }));
    const client = new AttackClient({ baseUrl: 'https://verifier.example', fetch: fetcher });

    await expect(client.readiness()).resolves.toEqual({ ok: false, status: 'not_ready', checks: { ocsp: 'failed' } });
  });

  it('returns /metrics as Prometheus text', async () => {
    const fetcher = vi.fn<typeof fetch>(async () => new Response('# HELP attack_http_requests_total x\n', { status: 200 }));
    const client = new AttackClient({ baseUrl: 'https://verifier.example', fetch: fetcher });

    await expect(client.metrics()).resolves.toContain('attack_http_requests_total');
  });

  it('returns the rejection instead of throwing when /direct_post answers 422', async () => {
    // /direct_post ist die oeffentliche Wallet-Route: es gab dort nichts zu
    // authentifizieren. Eine abgelehnte Praesentation traegt 422 und den
    // konkreten Grund im Body, also ein Ergebnis und kein Fehler. 401 bleibt
    // exklusiv fuer den API-Schluessel.
    const fetcher = vi.fn<typeof fetch>(async () => response(422, { ok: false, valid: false, error: 'unknown_state' }));
    const client = new AttackClient({ baseUrl: 'https://verifier.example', fetch: fetcher });

    await expect(client.submitPresentation({ response: 'compact-jwe' })).resolves.toEqual({
      ok: false,
      valid: false,
      error: 'unknown_state',
    });
  });

  it('still throws on 401 and 413 for the wallet route', async () => {
    // Gegenprobe: 422 ist der einzige Status, der eine Ablehnung traegt.
    const client = (status: number, body: unknown) =>
      new AttackClient({
        baseUrl: 'https://verifier.example',
        fetch: vi.fn<typeof fetch>(async () => response(status, body)),
      });

    await expect(client(401, { error: 'unauthorized' }).submitPresentation({ response: 'j' })).rejects.toEqual(
      new AttackApiError(401, 'unauthorized'),
    );
    await expect(client(413, { error: 'payload_too_large' }).submitPresentation({ response: 'j' })).rejects.toEqual(
      new AttackApiError(413, 'payload_too_large'),
    );
  });

  it('maps API errors to typed AttackApiError', async () => {
    const fetcher = vi.fn<typeof fetch>(async () => response(401, { error: 'unauthorized' }));
    const client = new AttackClient({ baseUrl: 'https://verifier.example', apiKey: 'bad', fetch: fetcher });

    await expect(client.getResult('vs_missing')).rejects.toEqual(new AttackApiError(401, 'unauthorized'));
  });
});
