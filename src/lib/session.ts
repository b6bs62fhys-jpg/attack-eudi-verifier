/**
 * Flüchtiger, einmaliger Session-Store für OpenID4VP-Transaktionen.
 *
 * Bewusst keine Persistenz und keine echten Daten: Sessions leben nur im
 * Arbeitsspeicher, werden nach TTL ungültig und sind genau einmal nutzbar
 * (Replay-Schutz für die Nonce). TEST-Umgebung, kein Produktivcode.
 */
export interface VpSession {
  id: string;
  nonce: string;
  audience: string;
  clientId: string;
  responseUri: string;
  expiresAt: number;
  consumed: boolean;
  decryptionKey?: CryptoKey;
}

export type RejectReason = 'unknown_session' | 'session_expired' | 'session_reused';

export class VpSessionStore {
  private readonly sessions = new Map<string, VpSession>();
  private readonly ttlSeconds: number;

  constructor(ttlSeconds = 300) {
    this.ttlSeconds = ttlSeconds;
  }

  create(opts: { audience: string; clientId: string; responseUri: string; decryptionKey?: CryptoKey }): VpSession {
    const id = crypto.randomUUID();
    const session: VpSession = {
      id,
      nonce: crypto.randomUUID(),
      audience: opts.audience,
      clientId: opts.clientId,
      responseUri: opts.responseUri,
      expiresAt: Date.now() + this.ttlSeconds * 1000,
      consumed: false,
      decryptionKey: opts.decryptionKey,
    };
    this.sessions.set(id, session);
    return session;
  }

  get(id: string): VpSession | undefined {
    return this.sessions.get(id);
  }

  isExpired(id: string): boolean {
    const session = this.sessions.get(id);
    return session ? session.expiresAt <= Date.now() : true;
  }

  clearExpiredKeys(): void {
    const now = Date.now();
    for (const session of this.sessions.values()) {
      if (session.expiresAt <= now) session.decryptionKey = undefined;
    }
  }

  /** Löscht eine Sitzung (inkl. Ablauf). true, wenn sie existierte. */
  delete(id: string): boolean {
    const session = this.sessions.get(id);
    if (session) session.decryptionKey = undefined;
    return this.sessions.delete(id);
  }

  dropDecryptionKey(id: string): void {
    const session = this.sessions.get(id);
    if (session) session.decryptionKey = undefined;
  }

  /** Markiert eine Sitzung als verbraucht, wenn sie existiert, nicht abgelaufen und unbenutzt ist. */
  consume(id: string): { session: VpSession } | { reason: RejectReason } {
    const session = this.sessions.get(id);
    if (!session) return { reason: 'unknown_session' };
    if (session.expiresAt <= Date.now()) {
      session.decryptionKey = undefined;
      return { reason: 'session_expired' };
    }
    if (session.consumed) return { reason: 'session_reused' };
    session.consumed = true;
    return { session };
  }
}