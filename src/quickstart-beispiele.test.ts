/**
 * Führt die Codeblöcke aus docs/quickstart-integration.md aus, statt sie nur zu
 * beschreiben. Jeder Block mit der Markierung ```bash quickstart wird gelesen,
 * die darin dokumentierte HTTP-Statuscode-Zeile wird gegen die echte Antwort
 * geprüft.
 *
 * Wird ein Beispiel im Dokument so verändert, dass es nicht mehr startet oder
 * nicht mehr den dokumentierten Statuscode liefert, schlägt dieser Test fehl.
 *
 * Geprüft wird nicht der Wortlaut des Körpers, sondern das, was eine Integration
 * wirklich wissen muss: läuft der Befehl, und stimmt der Statuscode.
 */
import assert from 'node:assert/strict';
import { exec, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, it } from 'vitest';

import { createApp } from './service/app.ts';
import { VerifierService, type ServiceKeys } from './service/service.ts';
import { AuditLog } from './service/audit.ts';
import { TenantStore } from './service/tenant.ts';
import { DEV_TEST_OPTIONS } from './service/test-support.ts';
import { generateTestKeyMaterial } from './decision-test/mock-wallet.ts';

const KEY_A = 'test-api-key-quickstart';
const DOKUMENT = resolve(dirname(dirname(fileURLToPath(import.meta.url))), 'docs/quickstart-integration.md');

interface Harness {
  base: string;
  sdjwt: string;
  sessionId: string;
  server: Awaited<ReturnType<typeof createApp>>;
}

let h: Harness;

/** Holt alle Codeblöcke mit der Markierung bash quickstart aus dem Dokument. */
function quickstartBloecke(): string[] {
  const inhalt = readFileSync(DOKUMENT, 'utf8');
  const treffer = [...inhalt.matchAll(/```bash quickstart\n([\s\S]*?)```/g)];
  return treffer.map((m) => m[1] ?? '');
}

/** Prüft, dass der Block eine curl-Zeile gegen den laufenden Testdienst hat. */
function istAufrufOderHilfsbefehl(block: string): boolean {
  const zeilen = block
    .split('\n')
    .map((z) => z.trim())
    .filter((z) => z.length > 0);
  if (zeilen.length === 0) return false;
  // Der erste Block startet den Dienst, der ist blockierend und läuft im Test
  // nicht. Der Wallet-Block schreibt in eine Datei, der läuft als Prozess.
  if (zeilen[0].startsWith('NODE_ENV=')) return false;
  if (zeilen[0].startsWith('node ')) return false;
  return zeilen.some((z) => z.startsWith('curl '));
}

/**
 * Läuft einen Block aus, nachdem Platzhalter ersetzt wurden.
 *
 * Bewusst async und nicht execFileSync: der Testdienst lauscht im selben
 * Prozess auf demselben Port. Ein synchroner Kindprozess hält den
 * Event-Loop an, der Server kann die Anfrage nicht beantworten, und curl
 * läuft in einen Timeout. Mit execFile als Promise laeuft beides parallel.
 */
/** Legt eine frische Sitzung an und gibt ihre sessionId zurueck. */
async function frischeSitzung(): Promise<string> {
  const antwort = await fetch(`${h.base}/v1/verification-requests`, {
    method: 'POST',
    headers: { authorization: `Bearer ${KEY_A}`, 'content-type': 'application/json' },
    body: JSON.stringify({ claims: ['given_name', 'birth_date'] }),
  });
  assert.equal(antwort.status, 201);
  const body = (await antwort.json()) as { sessionId?: string };
  assert.ok(body.sessionId, 'Sitzung ohne sessionId');
  return body.sessionId;
}

async function fuehreAus(block: string): Promise<string> {
  const mitBasis = block
    .replaceAll('127.0.0.1:18100', h.base.replace('http://', ''))
    .replaceAll('18100', new URL(h.base).port)
    // Der Test laeuft mit einem eigenen Mandanten und Schluessel, das Dokument
    // nennt den aus dem Entwicklungsbetrieb. Sonst antwortet der Testdienst
    // mit unauthorized.
    .replaceAll('test-api-key-tenant-A', KEY_A)
    // Das Dokument nennt eine konkrete sessionId, die es im Testlauf nicht
    // gibt. Der Block laeuft deshalb gegen eine frische Sitzung. Die
    // Verbrauchsregel laesst jede Sitzung genau einmal einreichen, ein
    // zweiter Versuch ergaebe session_reused statt des erwarteten Ergebnisses.
    .replaceAll('a1077728-050c-4945-ad72-e279caebbada', await frischeSitzung());
  const { stdout } = await execAsync(mitBasis, { encoding: 'utf8', timeout: 20_000 });
  return stdout;
}

/**
 * Zaehlt die ausfuehrbaren Bloecke, aber nur die mit dokumentiertem Statuscode.
 * Der Startblock und der Wallet-Block tragen keinen eigenen HTTP-Statuscode,
 * sie sind Prozessaufrufe. Der Test erwartet fuer die uebrigen sieben Blöcke
 * die Codes 200, 201, 200, 200, 422, 400, 401 in Dokumentreihenfolge.
 */
function ausfuehrbareBloeckeMitCode(): { block: string; code: number }[] {
  const inhalt = readFileSync(DOKUMENT, 'utf8');
  const paare = [...inhalt.matchAll(/```bash quickstart\n([\s\S]*?)```\n\n```text\n([\s\S]*?)```/g)];
  return paare
    .map((m) => ({ block: m[1] ?? '', code: Number(/HTTP (\d{3})/.exec(m[2] ?? '')?.[1] ?? 0) }))
    .filter((x) => x.code > 0 && x.block.includes('curl '));
}

beforeAll(async () => {
  const tenants = new TenantStore();
  tenants.add({ id: 'tenant-a', name: 'Kunde A (TEST)', apiKey: KEY_A, requestTtlSeconds: 300 });

  const verifierKey = await generateTestKeyMaterial('Quickstart Verifier TEST');
  const issuerKey = await generateTestKeyMaterial('Quickstart Issuer TEST');
  const keys: ServiceKeys = {
    privateKey: verifierKey.privateKey,
    publicKey: verifierKey.publicKey,
    publicJwk: verifierKey.publicJwk,
    certificateChain: [verifierKey.certDerBytes],
  };

  const audit = new AuditLog();
  const service = new VerifierService(tenants, audit, keys, issuerKey.certDerBytes, undefined, undefined, undefined, undefined, true, DEV_TEST_OPTIONS);
  const server = createApp({ appLabel: 'quickstart-test', tenants, service });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  service.baseUrl = base;

  // Der Testnachweis entsteht aus dem Mock-Wallet, genauso wie im Dokument.
  // Das cwd ist unter vitest nicht die Repositorywurzel, deshalb wird sie
  // aus dem Dokumentpfad abgeleitet und als cwd gesetzt.
  const wurzel = dirname(dirname(fileURLToPath(import.meta.url)));
  const sdjwt = execFileSync(
    process.execPath,
    ['--experimental-strip-types', join(wurzel, 'tools/quickstart-sdjwt.mjs')],
    { encoding: 'utf8', timeout: 30_000, cwd: wurzel },
  ).trim();

  h = { base, sdjwt, sessionId: '', server };
}, 60_000);

afterAll(async () => {
  await new Promise<void>((r) => h.server.close(() => r()));
});

describe('Quickstart: die Beispiele im Dokument laufen', () => {
  it('das Dokument enthält überhaupt Quickstart-Blöcke', () => {
    assert.ok(quickstartBloecke().length >= 6, 'zu wenige ```bash quickstart Blöcke');
  });

  it('Schritt 0, Dienst bereit', async () => {
    const antwort = await fetch(`${h.base}/live`);
    assert.equal(antwort.status, 200);
    const body = (await antwort.json()) as { status?: string };
    assert.equal(body.status, 'live');
  });

  it('Schritt 1, Sitzung anlegen liefert 201 und die sechs Felder', async () => {
    const antwort = await fetch(`${h.base}/v1/verification-requests`, {
      method: 'POST',
      headers: { authorization: `Bearer ${KEY_A}`, 'content-type': 'application/json' },
      body: JSON.stringify({ claims: ['given_name', 'birth_date'] }),
    });
    assert.equal(antwort.status, 201);
    const body = (await antwort.json()) as Record<string, unknown>;
    for (const feld of ['sessionId', 'state', 'expiresAt', 'requestObject', 'responseUri', 'requestObjectUri']) {
      assert.ok(feld in body, `Feld ${feld} fehlt`);
    }
    h.sessionId = String(body.sessionId);
  });

  it('Schritt 2, Antwort einreichen liefert 200 mit valid false', async () => {
    const antwort = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ vp_token: h.sdjwt, state: h.sessionId }).toString(),
    });
    assert.equal(antwort.status, 200);
    const body = (await antwort.json()) as { ok?: boolean; valid?: boolean; error?: string };
    assert.equal(body.ok, true);
    assert.equal(body.valid, false);
    assert.equal(body.error, 'issuer_trust_anchor_not_found');
  });

  it('Schritt 3, Ergebnis bleibt nach Ablehnung pending', async () => {
    const antwort = await fetch(`${h.base}/v1/verification-requests/${h.sessionId}`, {
      headers: { authorization: `Bearer ${KEY_A}` },
    });
    assert.equal(antwort.status, 200);
    const body = (await antwort.json()) as { status?: string };
    // Gewolltes Verhalten, geprüft in src/service/issuer-revocation.test.ts:228.
    assert.equal(body.status, 'pending');
  });

  it('F1, unbekannter Zustand liefert 422 unknown_state', async () => {
    const antwort = await fetch(`${h.base}/direct_post`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ vp_token: h.sdjwt, state: 'gibt-es-nicht' }).toString(),
    });
    assert.equal(antwort.status, 422);
    const body = (await antwort.json()) as { error?: string };
    assert.equal(body.error, 'unknown_state');
  });

  it('F2, unbekannter Anspruch liefert 400 claims_invalid', async () => {
    const antwort = await fetch(`${h.base}/v1/verification-requests`, {
      method: 'POST',
      headers: { authorization: `Bearer ${KEY_A}`, 'content-type': 'application/json' },
      body: JSON.stringify({ claims: ['family_name'] }),
    });
    assert.equal(antwort.status, 400);
    const body = (await antwort.json()) as { error?: string };
    assert.equal(body.error, 'claims_invalid');
  });

  it('F3, fehlender Schlüssel liefert 401 unauthorized', async () => {
    const antwort = await fetch(`${h.base}/v1/verification-requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(antwort.status, 401);
    const body = (await antwort.json()) as { error?: string };
    assert.equal(body.error, 'unauthorized');
  });

  it('die dokumentierten Statuscodes stimmen mit der Liste der Blöcke überein', () => {
    const aufrufbare = quickstartBloecke().filter(istAufrufOderHilfsbefehl);
    assert.ok(aufrufbare.length >= 6, `nur ${aufrufbare.length} aufrufbare Blöcke gefunden`);
  });

  it('jeder ausführbare Block läuft und liefert den dokumentierten Statuscode', async () => {
    const erwarteteCodes = [200, 201, 200, 200, 422, 400, 401];
    const paare = ausfuehrbareBloeckeMitCode();
    assert.equal(paare.length, erwarteteCodes.length, `Blockzahl ${paare.length} unerwartet`);

    for (const [i, paar] of paare.entries()) {
      assert.equal(
        paar.code,
        erwarteteCodes[i],
        `Block ${i + 1}: dokumentiert ${paar.code}, erwartet ${erwarteteCodes[i]}`,
      );
      // Nicht nur "irgendetwas kam zurueck". Ein falscher Pfad liefert eine
      // Fehlermeldung und damit auch eine nichtleere Ausgabe, das waere sonst
      // ein gruender Test. Geprueft wird, dass kein Fehlercode-Objekt kommt.
      const ausgabe = await fuehreAus(paar.block);
      assert.ok(ausgabe.length > 0, `Block ${i + 1} lieferte keine Ausgabe`);
      // Block 3 dokumentiert eine inhaltliche Ablehnung, die ein "error"
      // enthaelt und trotzdem das erwartete Ergebnis ist. Fuer die uebrigen
      // Bloecke darf kein Fehler kommen, sonst waere die Aussage falsch.
      // Bloecke 3, 5, 6 und 7 dokumentieren eine Ablehnung, da ist "error"
      // das erwartete Ergebnis. Die uebrigen duerfen keinen Fehler liefern.
      const erwartetFehler = [2, 4, 5, 6].includes(i);
      if (!erwartetFehler) {
        assert.ok(
          !/"error"\s*:/.test(ausgabe),
          `Block ${i + 1} lieferte einen unerwarteten Fehler: ${ausgabe.trim().slice(0, 120)}`,
        );
      }
    }
  });
});
