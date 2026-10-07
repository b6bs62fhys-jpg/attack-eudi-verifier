/**
 * Registrierungszertifikat (WRPRC) für `verifier_info` in der Presentation
 * Request.
 *
 * Belege:
 *   - Offizielle Developer-Doku, "Using Registrar Certificates in Presentation
 *     Requests": Der Registrar liefert das Registrierungszertifikat als
 *     `registration-certificate.json`, "containing a JWT". Es gehört in
 *     `verifier_info` mit `"format": "registration_cert"` und dem JWT in
 *     `data`.
 *   - Offizielle Developer-Doku, "Presenting a PID online", Checkliste: fehlt
 *     `verifier_info`, gilt "Wallet will reject untrusted verifier".
 *   - OpenID4VP 1.0 und die Referenzimplementierung EUDIPLO (die der
 *     EUDI-Playground aus der Doku verwendet) senden `verifier_info` als Liste
 *     von Objekten. Dieser Dienst folgt der Liste.
 *
 * Der genaue Aufbau der JSON-Datei ist in der öffentlichen Doku nicht
 * beschrieben. Der Lader nimmt deshalb entweder das JWT selbst als Datei oder
 * eine JSON-Datei, in der genau ein JWT steht (als JSON-String oder als Wert
 * irgendwo im Objekt). Mehrere oder kein JWT: Abbruch.
 *
 * Geprüft wird nur die Form (drei base64url-Teile, Kopf mit `alg`, nicht
 * `none`) und, falls vorhanden, dass `exp` noch nicht abgelaufen ist. Die
 * Signatur prüft die Wallet gegen den Registrar. Der Inhalt erscheint nie in
 * einer Meldung.
 */
import { readFile } from 'node:fs/promises';

import { ConfigError } from '../config.ts';

/** Pfad zur Datei mit dem Registrierungszertifikat (registration-certificate.json oder das JWT selbst). */
export const ENV_ATTACK_REGISTRATION_CERTIFICATE_FILE = 'ATTACK_REGISTRATION_CERTIFICATE_FILE';

export const REGISTRATION_CERT_FORMAT = 'registration_cert';

export interface VerifierInfoEntry {
  format: string;
  data: string;
}

const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const MAX_BYTES = 64 * 1024;

function fail(detail: string): never {
  throw new ConfigError(`${ENV_ATTACK_REGISTRATION_CERTIFICATE_FILE}: ${detail} Start abgebrochen.`);
}

function decodeJson(part: string): unknown {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

/** Sammelt alle Zeichenketten, die wie ein kompaktes JWS aussehen. */
function collectJws(value: unknown, found: string[], depth = 0): void {
  if (depth > 8) return;
  if (typeof value === 'string') {
    if (COMPACT_JWS.test(value.trim())) found.push(value.trim());
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectJws(item, found, depth + 1);
    return;
  }
  if (typeof value === 'object' && value !== null) {
    for (const item of Object.values(value)) collectJws(item, found, depth + 1);
  }
}

/** Findet das JWT im Dateiinhalt und prüft seine Form. */
export function parseRegistrationCertificate(text: string, now: Date = new Date(), clockSkewSeconds = 60): string {
  const trimmed = text.trim();
  let jwt: string;
  if (COMPACT_JWS.test(trimmed)) {
    jwt = trimmed;
  } else {
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      fail('weder ein JWT noch gültiges JSON.');
    }
    const found: string[] = [];
    collectJws(parsed, found);
    const unique = [...new Set(found)];
    if (unique.length === 0) fail('kein JWT in der Datei gefunden.');
    if (unique.length > 1) fail(`${unique.length} verschiedene JWTs in der Datei, erwartet genau eines. Das JWT selbst als Datei ablegen.`);
    jwt = unique[0] as string;
  }

  const [headerPart, payloadPart] = jwt.split('.') as [string, string, string];
  let header: unknown;
  let payload: unknown;
  try {
    header = decodeJson(headerPart);
    payload = decodeJson(payloadPart);
  } catch {
    fail('JWT-Kopf oder Nutzdaten sind kein JSON.');
  }
  if (typeof header !== 'object' || header === null || Array.isArray(header)) fail('JWT-Kopf ist kein Objekt.');
  const alg = (header as Record<string, unknown>).alg;
  if (typeof alg !== 'string' || alg === '' || alg.toLowerCase() === 'none') fail('JWT-Kopf ohne gültiges "alg".');
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) fail('JWT-Nutzdaten sind kein Objekt.');
  const exp = (payload as Record<string, unknown>).exp;
  if (exp !== undefined) {
    if (typeof exp !== 'number' || !Number.isFinite(exp)) fail('"exp" ist keine Zahl.');
    if (exp * 1000 + clockSkewSeconds * 1000 < now.getTime()) fail('das Registrierungszertifikat ist abgelaufen ("exp").');
  }
  return jwt;
}

/** Liest die Datei und liefert den Eintrag für `verifier_info`. */
export async function loadRegistrationCertificate(path: string, now: Date = new Date(), clockSkewSeconds = 60): Promise<VerifierInfoEntry> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    fail('Datei nicht lesbar (Pfad prüfen).');
  }
  if (Buffer.byteLength(text, 'utf8') > MAX_BYTES) fail(`Datei ist größer als ${MAX_BYTES} Bytes.`);
  return { format: REGISTRATION_CERT_FORMAT, data: parseRegistrationCertificate(text, now, clockSkewSeconds) };
}
