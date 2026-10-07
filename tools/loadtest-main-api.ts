/**
 * Lasttest fuer die Haupt-API des Verifier-Dienstes.
 *
 * Start:  npm run loadtest  (setzt keine Dev-Schalter voraus, siehe --help)
 *
 * Bewusst KEIN Vitest-Test: ein Lasttest braucht Zeit und viele Verbindungen,
 * ein fehlgeschlagener Latenzwert soll die Unit-Suite nicht rot machen. Das
 * Skript hat seinen eigenen Exit-Code und schreibt optional JSON.
 *
 * Zwei getrennte Lastklassen, weil der Dienst die Betriebsrouten vom
 * Rate-Limit ausnimmt (src/service/app.ts, shouldRateLimit):
 *
 *   1. Betrieb (/live, /health, /ready, /metrics) - Dauerlast. Diese Routen
 *      sind limitfrei und zeigen die tatsaechliche Leistung des HTTP-Stacks.
 *   2. Fachrouten (create, read, request-object, /direct_post) - Burst. Die
 *      Voreinstellung betraegt 60 Anfragen je Mandant und 120 je IP-Adresse im
 *      60-Sekunden-Fenster (src/service/rate-limit.ts). Jeder dauerhafte
 *      Durchsatzversuch laeuft also in 429. Der Burst bleibt bewusst unter dem
 *      Limit und 429 wird als erwartetes Verhalten gezaehlt, nicht als Fehler.
 *
 * Ohne diese Trennung waere das Ergebnis wertlos: man messe entweder nur den
 * limitfreien Teil des Dienstes oder nur die Ratenbegrenzung.
 *
 * Aufruf-Beispiele:
 *   npm run loadtest
 *   npm run loadtest -- --duration 30000 --concurrency 50
 *   npm run loadtest -- --json docs/lasttest-ergebnis.json
 *   npm run loadtest -- --only operational
 */

import { writeFileSync } from 'node:fs';

interface Scenario {
  name: string;
  /** true = Dauerlast auf einer limitfreien Route. */
  sustained: boolean;
  /** true = limitfrei, false = unter dem Mandanten-/IP-Limit bleiben. */
  exempt: boolean;
  /**
   * Status, die das Szenario erwartet. Alles andere zaehlt als Fehler.
   * /direct_post beantwortet eine absichtlich unbrauchbare Praesentation mit
   * 400; das ist der erwartete Weg durch den Parsing- und Validierungspfad.
   */
  expect: number[];
  run(ctx: RunContext): Promise<void>;
}

interface Sample {
  scenario: string;
  ms: number;
  status: number;
}

interface RunContext {
  base: string;
  apiKey: string;
  /** Anzahl paralleler Verbindungen. */
  concurrency: number;
  /** Gesamtdauer der Lastphase in Millisekunden. */
  durationMs: number;
  /** Obergrenze je Fachroute, damit das Ratenfenster nicht überschritten wird. */
  maxPerRoute: number;
  samples: Sample[];
  /** IDs aus der Setup-Phase, fuer die GET-Szenarien. */
  sessionIds: string[];
}

interface Slo {
  p95Ms: number;
  p99Ms: number;
  errorRate: number;
  minRps: number;
}

interface ScenarioResult {
  scenario: string;
  sustained: boolean;
  exempt: boolean;
  requests: number;
  errors: number;
  /** Fehler ohne 429, also echte Fehlschlaege. */
  hardErrors: number;
  rateLimited: number;
  rps: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
  maxMs: number;
  statuses: Record<string, number>;
}

const SLO_DEFAULTS: Slo = { p95Ms: 50, p99Ms: 100, errorRate: 0.01, minRps: 100 };

function isFailure(status: number, expect: number[]): boolean {
  return !expect.includes(status);
}

function parseArgs(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]!;
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) out[key] = 'true';
    else {
      out[key] = next;
      i += 1;
    }
  }
  return out;
}

function num(args: Record<string, string>, key: string, fallback: number): number {
  const raw = args[key];
  if (raw === undefined) return fallback;
  const v = Number(raw);
  if (!Number.isFinite(v) || v <= 0) throw new Error(`--${key} braucht eine positive Zahl, bekam "${raw}"`);
  return v;
}

/** naechste Nachkommastelle, auf die ein Prozentwert passt */
function pct(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx]!;
}

function summarize(samples: Sample[], scenario: string, sustained: boolean, exempt: boolean, expect: number[], seconds: number): ScenarioResult {
  const own = samples.filter((s) => s.scenario === scenario);
  const sorted = own.map((s) => s.ms).sort((a, b) => a - b);
  const statuses: Record<string, number> = {};
  for (const s of own) {
    const k = String(s.status);
    statuses[k] = (statuses[k] ?? 0) + 1;
  }
  const rateLimited = statuses['429'] ?? 0;
  const errors = own.filter((s) => isFailure(s.status, expect)).length;
  const hardErrors = own.filter((s) => isFailure(s.status, expect) && s.status !== 429).length;
  return {
    scenario,
    sustained,
    exempt,
    requests: own.length,
    errors,
    hardErrors,
    rateLimited,
    rps: seconds > 0 ? Number((own.length / seconds).toFixed(1)) : 0,
    p50Ms: pct(sorted, 50),
    p95Ms: pct(sorted, 95),
    p99Ms: pct(sorted, 99),
    maxMs: sorted[sorted.length - 1] ?? 0,
    statuses,
  };
}

async function timed(ctx: RunContext, scenario: string, fn: () => Promise<Response>): Promise<void> {
  const start = performance.now();
  try {
    const res = await fn();
    // Body lesen, sonst bleibt die Verbindung belegt und der Test misst
    // Warteschlangen statt Latenz.
    await res.arrayBuffer();
    ctx.samples.push({ scenario, ms: performance.now() - start, status: res.status });
  } catch (e) {
    ctx.samples.push({ scenario, ms: performance.now() - start, status: 0 });
    void e;
  }
}

async function get(ctx: RunContext, path: string, scenario: string, auth = false): Promise<void> {
  await timed(ctx, scenario, () =>
    fetch(`${ctx.base}${path}`, {
      headers: auth ? { authorization: `Bearer ${ctx.apiKey}` } : {},
    }),
  );
}

async function postJson(ctx: RunContext, path: string, body: unknown, scenario: string, auth: boolean): Promise<void> {
  await timed(ctx, scenario, () =>
    fetch(`${ctx.base}${path}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(auth ? { authorization: `Bearer ${ctx.apiKey}` } : {}),
      },
      body: JSON.stringify(body),
    }),
  );
}

/** Fuehrt `total` Anfragen mit `concurrency` parallelen Verbindungen aus. */
async function burst(ctx: RunContext, scenario: string, total: number, fn: (i: number) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(ctx.concurrency, total)) }, async () => {
    for (;;) {
      const i = next;
      next += 1;
      if (i >= total) return;
      await fn(i);
    }
  });
  await Promise.all(workers);
}

/** Haelt `concurrency` Verbindungen fuer `durationMs` offen und feuert ungebremst. */
async function sustain(ctx: RunContext, scenario: string, path: string): Promise<void> {
  const deadline = performance.now() + ctx.durationMs;
  const workers = Array.from({ length: Math.max(1, ctx.concurrency) }, async () => {
    while (performance.now() < deadline) await get(ctx, path, scenario);
  });
  await Promise.all(workers);
}

const SCENARIOS: Scenario[] = [
  {
    name: 'operational',
    sustained: true,
    exempt: true,
    expect: [200],
    async run(ctx) {
      for (const path of ['/live', '/health', '/ready', '/metrics']) {
        await sustain(ctx, 'operational', path);
      }
    },
  },
  {
    name: 'create',
    sustained: false,
    exempt: false,
    expect: [201],
    async run(ctx) {
      await burst(ctx, 'create', ctx.maxPerRoute, async () => {
        await postJson(ctx, '/v1/verification-requests', { claims: ['given_name'] }, 'create', true);
      });
    },
  },
  {
    name: 'read',
    sustained: false,
    exempt: false,
    expect: [200],
    async run(ctx) {
      const ids = ctx.sessionIds;
      if (ids.length === 0) {
        process.stderr.write('Harness: keine Sitzung aus der Setup-Phase, Szenario "read" uebersprungen\n');
        return;
      }
      await burst(ctx, 'read', ctx.maxPerRoute, async (i) => {
        await get(ctx, `/v1/verification-requests/${ids[i % ids.length]}`, 'read', true);
      });
    },
  },
  {
    name: 'request-object',
    sustained: false,
    exempt: false,
    expect: [200],
    async run(ctx) {
      const ids = ctx.sessionIds;
      if (ids.length === 0) {
        process.stderr.write('Harness: keine Sitzung aus der Setup-Phase, Szenario "request-object" uebersprungen\n');
        return;
      }
      await burst(ctx, 'request-object', ctx.maxPerRoute, async (i) => {
        await get(ctx, `/v1/verification-requests/${ids[i % ids.length]}/request-object`, 'request-object', true);
      });
    },
  },
  {
    name: 'direct-post',
    sustained: false,
    exempt: false,
    expect: [400],
    async run(ctx) {
      // Bewusst keine echte Praesentation: /direct_post ist die oeffentliche
      // Wallet-Route und wuerde echte Signaturpruefung erfordern. Gemessen wird
      // der Parsing- und Validierungspfad, deshalb ist 400 hier das erwartete
      // Ergebnis und kein Fehlschlag. Ausserdem ist diese Route nicht
      // mandantenpflichtig und zaehlt gegen das IP-Limit von 120, darum die
      // niedrigere Obergrenze.
      await burst(ctx, 'direct-post', Math.min(ctx.maxPerRoute, 100), async () => {
        await postJson(ctx, '/direct_post', { state: 'lasttest', vp_token: 'lasttest' }, 'direct-post', false);
      });
    },
  },
];

async function setupSessions(ctx: RunContext, count: number): Promise<string[]> {
  const ids: string[] = [];
  for (let i = 0; i < count; i += 1) {
    try {
      const res = await fetch(`${ctx.base}/v1/verification-requests`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${ctx.apiKey}` },
        body: JSON.stringify({ claims: ['given_name'] }),
      });
      const body = (await res.json()) as { id?: string; sessionId?: string };
      const id = body.id ?? body.sessionId;
      if (res.status === 201 && typeof id === 'string') ids.push(id);
    } catch {
      // Setup ist best effort; fehlende IDs fuehren zu uebersprungenen Szenarien.
    }
  }
  return ids;
}

function fmt(r: ScenarioResult): string {
  const head = `${r.scenario.padEnd(16)}${r.sustained ? 'Dauerlast' : 'Burst    '}${r.exempt ? ' limitfrei' : ' unter Limit'}`;
  // Bei einem Burst aus wenigen Anfragen waere ein Durchsatzwert Rauschen und
  // wuerde nur falsche Grosse vortaeuschen, deshalb wird er nicht gedruckt.
  const throughput = r.sustained ? `  Durchsatz     ${r.rps} req/s\n` : '';
  return [
    head,
    `  Anfragen      ${r.requests}`,
    throughput.trim() === '' ? '' : throughput.trimEnd(),
    `  Latenz        p50 ${r.p50Ms.toFixed(1)} ms · p95 ${r.p95Ms.toFixed(1)} ms · p99 ${r.p99Ms.toFixed(1)} ms · max ${r.maxMs.toFixed(1)} ms`,
    `  Status        ${Object.entries(r.statuses).map(([k, v]) => `${k}:${v}`).join('  ') || '-'}`,
    `  Abweichungen  ${r.errors} (davon 429: ${r.rateLimited}, unerwartet: ${r.hardErrors})`,
  ]
    .filter((l) => l !== '')
    .join('\n');
}

function evaluate(results: ScenarioResult[], slo: Slo): { ok: boolean; lines: string[] } {
  const lines: string[] = [];
  let ok = true;
  for (const r of results) {
    const problems: string[] = [];
    if (r.p95Ms > slo.p95Ms) problems.push(`p95 ${r.p95Ms.toFixed(1)} ms > ${slo.p95Ms} ms`);
    if (r.p99Ms > slo.p99Ms) problems.push(`p99 ${r.p99Ms.toFixed(1)} ms > ${slo.p99Ms} ms`);
    if (r.hardErrors / Math.max(1, r.requests) > slo.errorRate)
      problems.push(`unerwartete Antworten ${r.hardErrors}/${r.requests} > ${slo.errorRate}`);
    if (r.sustained && r.rps < slo.minRps) problems.push(`Durchsatz ${r.rps} req/s < ${slo.minRps} req/s`);
    const failed = problems.length > 0;
    if (failed) ok = false;
    lines.push(`${failed ? 'NICHT ERFUELLT' : 'erfuellt         '}  ${r.scenario.padEnd(16)}${problems.join('; ')}`);
  }
  return { ok, lines };
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help === 'true') {
    process.stdout.write(
      [
        'Lasttest der Haupt-API. Keine Vitest-Suite, eigener Exit-Code.',
        '',
        '  --base <url>        Ziel, Standard http://127.0.0.1:8080',
        '  --api-key <key>     Bearer-Schluessel, noetig fuer die Fachrouten',
        '  --duration <ms>     Dauer der Lastphase, Standard 10000',
        '  --concurrency <n>   Parallele Verbindungen, Standard 20',
        '  --max-per-route <n> Burst-Grenze je Fachroute, Standard 50',
        '  --only <name>       Nur ein Szenario: operational, create, read, request-object, direct-post',
        '  --json <pfad>       Ergebnis als JSON schreiben',
        '  --slo-p95 <ms>      Standard 50',
        '  --slo-p99 <ms>      Standard 100',
        '  --slo-error <quote> Standard 0.01',
        '  --slo-rps <n>       Mindestdurchsatz limitfreier Routen, Standard 100',
        '',
        'Beispiel: npm run loadtest -- --api-key test-api-key-tenant-A --duration 30000',
        '',
      ].join('\n'),
    );
    return 0;
  }

  const base = args.base ?? process.env.LOADTEST_BASE_URL ?? 'http://127.0.0.1:8080';
  const apiKey = args['api-key'] ?? process.env.LOADTEST_API_KEY ?? '';
  const slo: Slo = {
    p95Ms: num(args, 'slo-p95', SLO_DEFAULTS.p95Ms),
    p99Ms: num(args, 'slo-p99', SLO_DEFAULTS.p99Ms),
    errorRate: Number(args['slo-error'] ?? SLO_DEFAULTS.errorRate),
    minRps: num(args, 'slo-rps', SLO_DEFAULTS.minRps),
  };

  const ctx: RunContext = {
    base: base.replace(/\/$/, ''),
    apiKey,
    concurrency: num(args, 'concurrency', 20),
    durationMs: num(args, 'duration', 10_000),
    maxPerRoute: num(args, 'max-per-route', 50),
    samples: [],
    sessionIds: [],
  };

  const selected = args.only
    ? SCENARIOS.filter((s) => s.name === args.only)
    : SCENARIOS;
  if (selected.length === 0) {
    process.stderr.write(`Harness: unbekanntes Szenario "${args.only}".\n`);
    return 2;
  }

  const needsAuth = selected.some((s) => !s.exempt);
  if (needsAuth && !apiKey) {
    process.stderr.write('Harness: --api-key fehlt. Die Fachrouten sind mandantenpflichtig.\n');
    return 2;
  }

  const live = await fetch(`${ctx.base}/live`).catch(() => null);
  if (!live || !live.ok) {
    process.stderr.write(`Harness: ${ctx.base}/live antwortet nicht. Dienst starten: npm run service\n`);
    return 2;
  }
  await live.arrayBuffer();

  if (needsAuth) ctx.sessionIds = await setupSessions(ctx, Math.max(1, Math.min(ctx.maxPerRoute, 10)));

  const header = [
    'Lasttest Haupt-API',
    `  Ziel              ${ctx.base}`,
    `  Verbindungen      ${ctx.concurrency}`,
    `  Dauer je Betriebsroute  ${ctx.durationMs} ms`,
    `  Burst je Fachroute      ${ctx.maxPerRoute} Anfragen`,
    `  Mandant           ${apiKey ? 'mit Bearer-Schluessel' : 'ohne (nur Betriebsrouten)'}`,
  ].join('\n');
  process.stdout.write(`${header}\n\n`);

  const results: ScenarioResult[] = [];
  for (const scenario of selected) {
    const before = performance.now();
    await scenario.run(ctx);
    const seconds = (performance.now() - before) / 1000;
    const r = summarize(ctx.samples, scenario.name, scenario.sustained, scenario.exempt, scenario.expect, seconds);
    results.push(r);
    process.stdout.write(`${fmt(r)}\n\n`);
  }

  const verdict = evaluate(results, slo);
  process.stdout.write('SLO\n');
  for (const line of verdict.lines) process.stdout.write(`${line}\n`);

  if (args.json) {
    writeFileSync(
      args.json,
      `${JSON.stringify(
        {
          base: ctx.base,
          concurrency: ctx.concurrency,
          durationMs: ctx.durationMs,
          maxPerRoute: ctx.maxPerRoute,
          slo,
          ok: verdict.ok,
          results,
        },
        null,
        2,
      )}\n`,
    );
    process.stdout.write(`\nJSON geschrieben: ${args.json}\n`);
  }

  return verdict.ok ? 0 : 1;
}

process.exitCode = await main();
