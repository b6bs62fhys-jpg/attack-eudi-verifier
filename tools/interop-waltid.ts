/**
 * Gegenstelle: walt.id wallet-api2 gegen den Attack Verifier-Dienst.
 *
 * Steuert von außen, was zwei Container tun: den Dienst (Image attack) und die
 * Wallet (waltid/wallet-api2), beide im selben Docker-Netz. Das Skript
 *   1. erzeugt Aussteller- und Halterschlüssel und schreibt Anker und Mandantendatei,
 *   2. legt Halterschlüssel und ein Test-Credential in der Wallet ab,
 *   3. erzeugt eine Prüfanfrage am Dienst,
 *   4. lässt die Wallet die Anfrage ansehen (preview) und beantworten (present),
 *   5. liest das Ergebnis am Dienst.
 * Jeder Schritt wird mit Status und gekürzter Antwort ausgegeben, auch wenn er
 * scheitert. Aufruf und Vorbereitung: docs/gegenstelle-waltid.md.
 *
 * Nur Test-Material. Der Dienst läuft im Entwicklungsbetrieb (selbstsigniertes
 * Verifier-Zertifikat); Sperr- und Statusprüfung sind dabei aus. Geprüft wird
 * also das Protokoll zwischen Wallet und Dienst, nicht die Vertrauenskette.
 */
import 'reflect-metadata';

import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { SignJWT } from 'jose';

import { buildSdJwtVc, generateTestKeyMaterial } from '../src/decision-test/mock-wallet.ts';
import { addTenantEntry, emptyTenantFile, writeTenantFile } from '../src/service/tenant-file.ts';

const dir = process.argv[2];
const verifierUrl = process.env.ATTACK_URL ?? 'http://127.0.0.1:18090';
const walletUrl = process.env.WALLET_URL ?? 'http://127.0.0.1:7006';
const profile = process.env.PROFILE ?? 'pid_basis';
const phase = process.argv[3] ?? 'run';
if (!dir) {
  console.error('Aufruf: node --experimental-strip-types tools/interop-waltid.ts <Verzeichnis> [prepare|run]');
  process.exit(2);
}

const pemOf = (der: Uint8Array) => `-----BEGIN CERTIFICATE-----\n${(Buffer.from(der).toString('base64').match(/.{1,64}/g) ?? []).join('\n')}\n-----END CERTIFICATE-----\n`;
const short = (value: unknown, n = 600) => {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  return text.length > n ? `${text.slice(0, n)} ... (${text.length} Zeichen)` : text;
};

async function call(label: string, method: string, url: string, body?: unknown, headers: Record<string, string> = {}): Promise<{ status: number; json: unknown; text: string }> {
  const res = await fetch(url, { method, headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  console.log(`\n[${label}] ${method} ${url.replace(/^https?:\/\/[^/]+/, '')} -> HTTP ${res.status}\n  ${short(json ?? text)}`);
  return { status: res.status, json, text };
}

mkdirSync(dir, { recursive: true });
const keysFile = join(dir, 'keys.json');

if (phase === 'prepare') {
  const issuer = await generateTestKeyMaterial('Interop Aussteller');
  const holder = await generateTestKeyMaterial('Interop Halter');
  writeFileSync(join(dir, 'issuer-anchors.pem'), pemOf(issuer.certDerBytes));
  // Verifier-Identität des Dienstes, damit die Wallet ihr Zertifikat als Anker
  // für x509_hash konfigurieren kann (wallet-service.conf, clientIdTrust).
  const verifier = await generateTestKeyMaterial('Interop Verifier');
  const verifierPkcs8 = Buffer.from(await crypto.subtle.exportKey('pkcs8', verifier.privateKey)).toString('base64');
  writeFileSync(join(dir, 'verifier-key.pem'), `-----BEGIN PRIVATE KEY-----\n${(verifierPkcs8.match(/.{1,64}/g) ?? []).join('\n')}\n-----END PRIVATE KEY-----\n`, { mode: 0o600 });
  writeFileSync(join(dir, 'verifier-chain.pem'), pemOf(verifier.certDerBytes));
  const tripleQuote = '"'.repeat(3);
  writeFileSync(
    join(dir, 'wallet-service.conf'),
    [
      'publicBaseUrl = "http://localhost:7006"',
      '',
      '# OpenID4VP x509_san_dns und x509_hash scheitern ohne Anker (fail closed).',
      '# Hier nur das Verifier-Zertifikat dieses Testlaufs.',
      'clientIdTrust {',
      '  x509TrustAnchors = [',
      `    ${tripleQuote}${pemOf(verifier.certDerBytes).trim()}${tripleQuote}`,
      '  ]',
      '}',
      'enableDidWebResolverHttps=false',
      '',
    ].join('\n'),
  );
  const withPid = addTenantEntry(emptyTenantFile(), { id: 'pid-basis', name: 'Interop PID', requestProfile: 'pid_basis' });
  const withAge = addTenantEntry(withPid.file, { id: 'alter', name: 'Interop Alter', requestProfile: 'age_over_18' });
  const withDe = addTenantEntry(withAge.file, { id: 'alter-de', name: 'Interop Alter DE', requestProfile: 'age_over_18_de' });
  await writeTenantFile(join(dir, 'tenants.json'), withDe.file);
  const holderPrivate = await crypto.subtle.exportKey('jwk', holder.privateKey);
  delete holderPrivate.key_ops;
  delete holderPrivate.ext;
  const issuerPrivate = await crypto.subtle.exportKey('pkcs8', issuer.privateKey);
  writeFileSync(
    keysFile,
    JSON.stringify({
      tenantKeys: { pid_basis: withPid.apiKey, age_over_18: withAge.apiKey, age_over_18_de: withDe.apiKey },
      holderPrivateJwk: holderPrivate,
      issuerPkcs8: Buffer.from(issuerPrivate).toString('base64'),
      issuerX5c: issuer.x5cBase64,
    }),
    { mode: 0o600 },
  );
  console.log(`Material in ${dir} geschrieben: issuer-anchors.pem, verifier-key.pem, verifier-chain.pem, wallet-service.conf, tenants.json, keys.json (nur Test-Schlüssel).`);
  process.exit(0);
}

// Phase run
const { readFileSync } = await import('node:fs');
const saved = JSON.parse(readFileSync(keysFile, 'utf8')) as { tenantKeys: Record<string, string>; holderPrivateJwk: JsonWebKey; issuerPkcs8: string; issuerX5c: string };
const apiKey = saved.tenantKeys[profile];
if (!apiKey) throw new Error(`kein Mandantenschlüssel für Profil ${profile}`);

const issuerPrivateKey = await crypto.subtle.importKey('pkcs8', Buffer.from(saved.issuerPkcs8, 'base64'), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
const holderPrivateKey = await crypto.subtle.importKey('jwk', saved.holderPrivateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
const holderPublicJwk: JsonWebKey = { ...saved.holderPrivateJwk };
delete holderPublicJwk.d;
delete holderPublicJwk.key_ops;
const holderPublicKey = await crypto.subtle.importKey('jwk', holderPublicJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
const issuerKey = { privateKey: issuerPrivateKey, publicKey: issuerPrivateKey, publicJwk: {}, x5cBase64: saved.issuerX5c, certDerBytes: new Uint8Array(Buffer.from(saved.issuerX5c, 'base64')) };
const holderKey = { privateKey: holderPrivateKey, publicKey: holderPublicKey, publicJwk: holderPublicJwk, x5cBase64: '', certDerBytes: new Uint8Array() };

// 1. Wallet, Schlüssel, Credential
const wallet = await call('Wallet anlegen', 'POST', `${walletUrl}/wallet`, {});
const walletId = (wallet.json as { walletId?: string } | undefined)?.walletId;
if (!walletId) throw new Error('Wallet konnte nicht angelegt werden');
const key = await call('Halterschlüssel importieren', 'POST', `${walletUrl}/wallet/${walletId}/keys/import`, { key: { type: 'jwk', jwk: saved.holderPrivateJwk } });
const keyId = (key.json as { keyId?: string } | undefined)?.keyId;

const German = profile === 'age_over_18_de';
const vct = German ? 'urn:eudi:pid:de:1' : 'urn:eu.europa.ec.eudi:pid:1';

/**
 * Deutsche PID mit Altersschwellen, so wie die PID-Referenz sie beschreibt: ein
 * Objekt `age_equal_or_over`, in dem jede Schwelle einzeln offenlegbar ist
 * (eigenes `_sd`). Wie die echte Sandbox-PID das tatsächlich verpackt, ist
 * öffentlich nicht beschrieben. Eine erste Testform, bei der das ganze Objekt
 * eine einzige Offenlegung war, legte die walt.id Wallet für den Pfad
 * ["age_equal_or_over","18"] gar nicht offen (siehe docs/gegenstelle-waltid.md).
 */
async function germanAgeCredential(): Promise<string> {
  const b64u = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
  const digest = (t: string) => createHash('sha256').update(t).digest('base64url');
  const under18 = process.env.UNDER18 === '1';
  const thresholds: Record<string, boolean> = { '12': true, '14': true, '16': true, '18': !under18, '21': false, '65': false };
  const ageDisclosures = Object.entries(thresholds).map(([k, v]) => b64u([`salz-${k}`, k, v]));
  const given = b64u(['salz-g', 'given_name', 'Erika']);
  const now = Math.floor(Date.now() / 1000);
  const jwt = await new SignJWT({
    iss: 'https://TEST-issuer.de',
    vct,
    iat: now,
    exp: now + 3600,
    _sd_alg: 'sha-256',
    _sd: [digest(given)],
    age_equal_or_over: { _sd: ageDisclosures.map(digest) },
    cnf: { jwk: holderPublicJwk },
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: [saved.issuerX5c] })
    .sign(issuerPrivateKey);
  return `${jwt}~${[given, ...ageDisclosures].map((d) => `${d}~`).join('')}`;
}

const rawCredential = German
  ? await germanAgeCredential()
  : (await buildSdJwtVc({ issuerKey, holderKey, vct, claimName: 'given_name', claimValue: 'Erika', additionalDisclosures: { birth_date: '1984-01-26', family_name: 'Mustermann', age_over_18: process.env.UNDER18 !== '1' } })).sdJwt;
await call('Credential importieren', 'POST', `${walletUrl}/wallet/${walletId}/credentials/import`, { rawCredential, label: `interop-${profile}` });
await call('Credentials der Wallet', 'GET', `${walletUrl}/wallet/${walletId}/credentials`);

// 2. Prüfanfrage am Dienst
const created = await call('Prüfanfrage erzeugen', 'POST', `${verifierUrl}/v1/verification-requests`, {}, { authorization: `Bearer ${apiKey}` });
const request = created.json as { sessionId?: string; walletUrl?: string; requestObjectUri?: string } | undefined;
if (!request?.walletUrl) throw new Error('Dienst hat keine Prüfanfrage erzeugt');
console.log(`\nwalletUrl: ${request.walletUrl}`);

// 3. Wallet: ansehen und beantworten
const keyField = keyId ? { keyId } : { key: { type: 'jwk', jwk: saved.holderPrivateJwk } };
await call('Wallet: preview', 'POST', `${walletUrl}/wallet/${walletId}/credentials/present/preview`, { requestUrl: request.walletUrl, ...keyField });
const present = await call('Wallet: present', 'POST', `${walletUrl}/wallet/${walletId}/credentials/present`, { requestUrl: request.walletUrl, ...keyField });

// 4. Ergebnis am Dienst
const result = await call('Ergebnis abrufen', 'GET', `${verifierUrl}/v1/verification-requests/${request.sessionId}`, undefined, { authorization: `Bearer ${apiKey}` });
const ok = (result.json as { status?: string; result?: { valid?: boolean } } | undefined)?.result?.valid === true;
console.log(`\nERGEBNIS: ${ok ? 'Dienst hat die Präsentation der walt.id Wallet angenommen' : 'NICHT angenommen'} (present: HTTP ${present.status})`);
process.exit(ok ? 0 : 1);
