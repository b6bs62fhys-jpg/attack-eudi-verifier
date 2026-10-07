import "reflect-metadata"

import { SignJWT, jwtVerify, importJWK } from 'jose'

function certPubKeyJwk(certDerB64: string): JsonWebKey {
  const der = Buffer.from(certDerB64, 'base64')
  const marker = Buffer.from([0x03, 0x42, 0x00, 0x04])
  const idx = der.indexOf(marker)
  if (idx < 0) throw new Error('P-256-Public-Key (uncompressedpoint) nicht im X.509-DER gefunden')
  const point = der.subarray(idx + 3, idx + 3 + 65)
  return {
    kty: 'EC',
    crv: 'P-256',
    x: point.subarray(1, 33).toString('base64url'),
    y: point.subarray(33, 65).toString('base64url'),
  }
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function base58btc(bytes: Uint8Array): string {
  let x = 0n
  for (const b of bytes) x = (x << 8n) | BigInt(b)
  let s = ''
  while (x > 0n) {
    const rem = x % 58n
    s = B58[Number(rem)] + s
    x /= 58n
  }
  const zeros = [...bytes].findIndex((b) => b !== 0)
  const lead = zeros < 0 ? bytes.length : zeros
  return '1'.repeat(lead) + s
}
function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
}
function didKeyFromEd25519(pub: Uint8Array): string {
  const code = new Uint8Array([0xed, 0x01])
  const out = new Uint8Array(code.length + pub.length)
  out.set(code)
  out.set(pub, code.length)
  return 'did:key:z' + base58btc(out)
}
function b64urlJson(v: unknown): string {
  return Buffer.from(JSON.stringify(v)).toString('base64url')
}
async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', typeof data === 'string' ? new TextEncoder().encode(data) : data))
}
function b64url(b: Uint8Array): string {
  return Buffer.from(b).toString('base64url')
}

const [, , sessionIdArg] = process.argv
const sessionId = sessionIdArg || process.env.SESSION_ID
if (!sessionId) {
  console.error('usage: node wallet.ts <sessionId>')
  process.exit(1)
}

const base = 'http://localhost:7004/verification-session'
const requestUrl = `${base}/${sessionId}/request`
const infoUrl = `${base}/${sessionId}/info`

// --- 1) fetch signed request object (request_uri_method=post per waltid URL) ---
const fetchReq = await fetch(requestUrl)
console.log('Request-URI HTTP', fetchReq.status)
const reqBody = await fetchReq.text()
let requestObject = reqBody
if (!reqBody.startsWith('eyJ')) {
  try {
    const j = JSON.parse(reqBody)
    requestObject = j.request ?? j
  } catch {
    /* keep raw */
  }
}
console.log('Request object (JWT) erhalten, Länge', requestObject.length)

// --- 2) verify signature + x509_hash client id ---
const [h, p, s] = requestObject.split('.')
const header = JSON.parse(Buffer.from(h, 'base64url').toString())
console.log('Request-Object-Header:', JSON.stringify({ alg: header.alg, typ: header.typ, kid: header.kid, x5cAnzahl: header.x5c?.length }))

const certDer = Buffer.from(header.x5c[0], 'base64')
console.log('X.509-Chain: 1 Zertifikat (CN=verifier.example.com) – public key extrahiert')
const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', certDer))
const hashB64 = Buffer.from(digest).toString('base64url')

const payload = JSON.parse(Buffer.from(p, 'base64url').toString())
const expectedClientId = 'x509_hash:' + hashB64
console.log('x509_hash prüfen:', expectedClientId === payload.client_id ? 'OK (Berechnung == client_id)' : `FEHLER (berechnet ${expectedClientId}, client_id ${payload.client_id})`)

const pubKeyJwk = certPubKeyJwk(header.x5c[0])
const { payload: verified } = await jwtVerify(requestObject, await importJWK(pubKeyJwk, 'ES256'), { algorithms: [header.alg] })
console.log('Request-Object-Signatur: GÜLTIG (ES256, Schlüssel aus x5c)')
console.log('payload.response_type:', verified.response_type, '| response_mode:', verified.response_mode, '| state:', verified.state)
console.log('dcql_query:', JSON.stringify(verified.dcql_query))

const clientId = String(verified.client_id)
const nonce = String(verified.nonce)
const responseUri = String(verified.response_uri)
const state = String(verified.state)
const vct = (verified.dcql_query as any).credentials[0].meta.vct_values[0]
const credId = (verified.dcql_query as any).credentials[0].id

// --- 3) issuer + holder TEST keys (nur im Speicher) ---
const issuerPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])
const holderPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])
const issuerPub = new Uint8Array(await crypto.subtle.exportKey('raw', issuerPair.publicKey))
const didKey = didKeyFromEd25519(issuerPub)
console.log('Issuer (TEST, im Speicher):', didKey)

const holderPubRaw = await crypto.subtle.exportKey('jwk', holderPair.publicKey)
const holderPubClean: JsonWebKey = { kty: 'EC', crv: 'P-256', x: holderPubRaw.x, y: holderPubRaw.y }

// --- 4) SD-JWT VC mit _sd disclosures (RFC 9901: Disclosures base64url-kodiert) ---
const salt1 = b64url(crypto.getRandomValues(new Uint8Array(8)))
const salt2 = b64url(crypto.getRandomValues(new Uint8Array(8)))
const givenDisclosure = JSON.stringify([salt1, 'given_name', 'Ada'])
const familyDisclosure = JSON.stringify([salt2, 'family_name', 'Zhao'])
const givenEnc = b64url(new TextEncoder().encode(givenDisclosure))
const familyEnc = b64url(new TextEncoder().encode(familyDisclosure))
const e1 = new TextEncoder().encode(givenEnc)
const e2 = new TextEncoder().encode(familyEnc)
const h1 = b64url(await sha256(e1))
const h2 = b64url(await sha256(e2))

const issuerJwt = await new SignJWT({
  iss: didKey,
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  vct,
  _sd_alg: 'sha-256',
  _sd: [h1, h2],
  cnf: { jwk: holderPubClean },
})
  .setProtectedHeader({ alg: 'EdDSA', typ: 'vc+sd-jwt', kid: didKey })
  .sign(issuerPair.privateKey)
console.log('SD-JWT (Issuer-Signatur EdDSA) erzeugt')

const sdJwt = [issuerJwt, givenEnc, familyEnc].join('~')
const sdHash = b64url(await sha256(new TextEncoder().encode(sdJwt + '~')))

const kbJwt = await new SignJWT({ iat: Math.floor(Date.now() / 1000), nonce, aud: clientId, sd_hash: sdHash })
  .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
  .sign(holderPair.privateKey)

const presentation = sdJwt + '~' + kbJwt

// --- 5) vp_token -> response_uri (direct_post) ---
const vpTokenJson = JSON.stringify({ [credId]: [presentation] })
const form = new URLSearchParams()
form.append('vp_token', vpTokenJson)
form.append('state', state)
const respPost = await fetch(responseUri, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: form.toString(),
})
console.log('POST vp_token ->', responseUri, '| HTTP', respPost.status)
console.log('Response-Body:', (await respPost.text()).slice(0, 200))

// --- 6) Ergebnis abholen ---
await new Promise((r) => setTimeout(r, 1500))
const info = await (await fetch(infoUrl)).json()
console.log('--- ERGEBNIS ---')
console.log('status:', info.status, '| attempted:', info.attempted, '| overallSuccess:', info.policy_results?.overallSuccess)
const cred = info.presented_credentials?.[credId]?.[0]
if (cred) console.log('vorgestellte Credential-Daten:', JSON.stringify({ vct: cred.credentialData?.vct, given_name: cred.credentialData?.given_name, family_name: cred.credentialData?.family_name, issuer: cred.issuer }))