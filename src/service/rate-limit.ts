/** Fixed-window rate limiter for one process. Use a shared store when scaling out. */
export const DEFAULT_RATE_LIMIT_WINDOW_MS = 60_000;
export const DEFAULT_PUBLIC_RATE_LIMIT = 120;
export const DEFAULT_TENANT_RATE_LIMIT = 60;

interface WindowState {
  startedAt: number;
  count: number;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  retryAfterSeconds: number;
}

export class RateLimiter {
  private readonly windowMs: number;
  private readonly maxKeys: number;
  private readonly now: () => number;
  private readonly windows = new Map<string, WindowState>();

  constructor(options: { windowMs?: number; maxKeys?: number; now?: () => number } = {}) {
    this.windowMs = options.windowMs ?? DEFAULT_RATE_LIMIT_WINDOW_MS;
    this.maxKeys = options.maxKeys ?? 10_000;
    this.now = options.now ?? Date.now;
  }

  consume(key: string, limit: number): RateLimitResult {
    const now = this.now();
    const current = this.windows.get(key);
    const state = !current || now - current.startedAt >= this.windowMs ? { startedAt: now, count: 0 } : current;
    state.count += 1;
    this.windows.set(key, state);
    this.prune(now);
    const allowed = state.count <= limit;
    return {
      allowed,
      limit,
      remaining: Math.max(0, limit - state.count),
      retryAfterSeconds: Math.max(1, Math.ceil((state.startedAt + this.windowMs - now) / 1000)),
    };
  }

  clear(): void {
    this.windows.clear();
  }

  private prune(now: number): void {
    for (const [key, state] of this.windows) {
      if (now - state.startedAt >= this.windowMs) this.windows.delete(key);
    }
    while (this.windows.size > this.maxKeys) {
      const oldest = this.windows.keys().next().value;
      if (oldest === undefined) break;
      this.windows.delete(oldest);
    }
  }
}
