# Attack Integration Guide

This guide is for engineers at banks, fintechs and insurers who are new to
EUDI Wallet verification. It describes the API contract in `openapi.yaml` and
the TypeScript/Python SDK candidates in `sdk/`.

## 1. Environments and access

### Local TEST mode

Local development uses only synthetic TEST keys, certificates, wallet data and
API keys:

```bash
ATTACK_DEV_MODE=true npm run service
```

The service listens on `http://127.0.0.1:8080` by default. This is not a real
wallet, a public sandbox or an authority endpoint.

### Sandbox access

The repository contains no real sandbox URL, credentials or customer data.
Obtain sandbox access from the responsible wallet programme/operator and put
the assigned endpoint and credentials into your deployment configuration.
Do not replace the local TEST URLs with guessed URLs.

Before using a sandbox, confirm:

1. the allowed wallet and credential formats;
2. the callback/redirect and encryption requirements;
3. the verifier trust anchors and certificate chain;
4. the tenant API-key provisioning process;
5. the data-retention and incident-reporting rules.

## 2. Create a presentation request

The application server creates a request for a tenant. The API key is a
server-side secret and must not be sent to browser code.

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/verification-requests \
  -H 'Authorization: Bearer test-api-key-tenant-A' \
  -H 'Content-Type: application/json' \
  -d '{"claims":["age_over_18"]}'
```

The response contains `sessionId`, `state`, `responseUri` and a signed
`requestObject`. Give the request object or its URI to the wallet integration.
The exact schema is in `openapi.yaml`.

### TypeScript

```ts
import { AttackClient } from '@eudi-verify-sdk/typescript';

const client = new AttackClient({
  baseUrl: process.env.ATTACK_URL ?? 'http://127.0.0.1:8080',
  apiKey: process.env.ATTACK_API_KEY,
});

const request = await client.createPresentationRequest({
  claims: ['age_over_18'],
});
console.log(request.requestObjectUri);
```

## 3. Receive and verify the wallet response

The wallet posts to the public `/direct_post` endpoint. The verifier service
checks the protocol state, signature, disclosure hashes, key binding, issuer
trust, issuer-certificate revocation and credential status. The application
must not treat a browser-side success signal as verification.

After the wallet response, read the result with the tenant API key:

```bash
curl -sS \
  -H 'Authorization: Bearer test-api-key-tenant-A' \
  http://127.0.0.1:8080/v1/verification-requests/SESSION_ID
```

The result is one of `pending`, `completed`, `expired` or `not_found`. A
completed result contains `valid`, verified claims, issuer country and an
optional stable error code. Completed results are intentionally readable only
once.

The SDK maps non-success API responses to `AttackApiError` with the HTTP status
and stable `code`. The public wallet response uses `ok` and `valid`; a
`valid: false` response is a verification rejection, not an SDK transport
failure.

### Wallet responses: not accepted (422) and rejected on content (200)

`/direct_post` is public, so there is never an API key to authenticate against
on that route. **The HTTP status says only whether the service was able to
process the presentation — not whether it is valid.** Those are two different
questions with two different answers.

A wallet response that the service does not accept is therefore
answered with **HTTP 422 Unprocessable Entity** and a readable reason in the
body:

```bash
curl -sS -i -X POST http://127.0.0.1:8080/direct_post \
-H 'content-type: application/json' \
-d '{"state":"STATE","vp_token":{"pid":["SD_JWT"]}}'
```

```
HTTP/1.1 422 Unprocessable Entity
content-type: application/json; charset=utf-8

{"ok":false,"valid":false,"error":"unknown_state"}
```

A wallet response that **was processed but rejected on content** carries
**HTTP 200** instead. The service evaluated the presentation and rejected it,
for example because the issuer certificate has expired. The reason is in the
`error` field:

```bash
curl -sS -i -X POST http://127.0.0.1:8080/direct_post \
-H 'content-type: application/json' \
-d '{"state":"STATE","vp_token":{"pid":["EXPIRED_SD_JWT"]}}'
```

```
HTTP/1.1 200 OK
content-type: application/json; charset=utf-8

{"ok":true,"valid":false,"error":"certificate_expired"}
```

So 422 does **not** mean "presentation rejected", it means "presentation could
not be processed": unknown or expired session, malformed body, replay, JWE
problem. A client seeing a 422 must check the payload or the session. A client
seeing 200 with `valid: false` is looking at a verification result and should
handle it on the merits, not retry it.

All three SDKs return that body as a `PresentationResponse` instead of raising.
Check `ok`, then `valid`, then `error`:

```ts
const outcome = await attack.submitPresentation({ response: walletJwe });
if (!outcome.ok) {
  // 422: could not be processed. unknown_state, state_invalid,
  // vp_token_invalid, session_reused, …  Check payload or session.
  console.error(outcome.error);
} else if (!outcome.valid) {
  // 200: processed and rejected on content, e.g. certificate_expired.
  console.error(outcome.error);
} else {
  // 200 and valid
}
```

**Checking `valid` alone is not enough**, because on a 422 `valid` is `false`
too. A client that evaluates only `valid` will mistake a presentation that
could not be processed for a verification result.

**401 is reserved for authentication.** It means a missing or unknown tenant
API key, on the tenant routes only. A wallet response never produces it.

## 4. Error handling

Handle errors by category, not by localized message text:

- `401 unauthorized`: missing or invalid tenant API key;
- `403 tenant_not_registered` or `tenant_registration_invalid`: active
  onboarding material rejected the tenant;
- `400 claims_invalid`, `vct_invalid` or `registration_ref_invalid`: request
  input does not match the tenant profile;
- `credential_revoked`, `credential_suspended` or
  `credential_status_*`: credential status failed;
- `issuer_certificate_revoked` or `issuer_revocation_check_failed`: issuer
  certificate-chain status failed;
- `unknown_state`, `state_invalid`, `vp_token_invalid`, `session_reused`,
  `session_expired` or the `malformed_jwe_header` / `jwe_decrypt_failed` family:
  the wallet response was not accepted. These arrive on `/direct_post` as
  **HTTP 422** with `ok: false`. Not a retry with the same payload;
- codes of a content rejection such as `certificate_expired`,
  `certificate_not_yet_valid`, `issuer_trust_anchors_empty` or
  `credential_revoked`: the wallet response **was processed** and rejected. They
  arrive as **HTTP 200** with `ok: true, valid: false`. Handle on the merits, do
  not retry.
- `500 internal_error`: retry only according to the application's idempotency
  and incident policy; never assume that verification succeeded.

### Migration: 401 to 422 for rejected wallet responses

Until 27.09.2026 `/direct_post` answered **401** for every **rejected** wallet
response, including `unknown_state`. That was a breaking change for integrators.

That migration only covers the cases where the service could **not process** the
presentation (`ok: false`, 422 today). Presentations that were processed and
rejected on content (`ok: true, valid: false`) were and still are 200, and were
not affected by the change.

The reason for the change: 401 is defined in `docs/fehlercodes.md` as a missing
or unknown API key, and it is the only status with that meaning now. Because
`/direct_post` is public, a 401 there could not be acted on correctly — a
client following the documentation would renew its key although the session
simply no longer exists.

What to check in existing code:

| Behaviour before | Expected now |
|---|---|
| `direct_post` returns 401 → read `error` from the body | Returns 422, same body shape |
| `direct_post` 401 → retry with a fresh API key | 422 is not an auth problem; inspect `error` |
| `direct_post` returns 200 with `valid: false` | unchanged; it was never a 401 case, `error` is the substantive rejection reason |
| `direct_post` 200 with `valid: false` → treated as processed | correct: processed and rejected, do not retry |
| SDK call raised on a rejected presentation | SDKs return the `PresentationResponse` |
| 401 on tenant routes | unchanged, still 401 `unauthorized` |

A robust check ignores the status and reads the body, which is correct before
and after the change:

```ts
const outcome = await attack.submitPresentation({ response: walletJwe });
if (!outcome.ok) {
  switch (outcome.error) {
    case 'unknown_state':
    case 'session_expired': /* start a new presentation request */ break;
    case 'state_invalid':
    case 'vp_token_invalid': /* the wallet sent something wrong */ break;
    default: /* do not retry automatically */ break;
  }
}
```

The complete list is maintained in `docs/fehlercodes.md` and the response
schemas are in `openapi.yaml`.

## 5. Production checklist

Before production, replace every TEST-only assumption:

1. provide a real verifier identity and certificate chain;
2. configure issuer trust anchors through a reviewed operational process;
3. configure the credential Token Status List trust policy and status source;
4. decide whether and how the WRPAC/WRPRC onboarding gate is activated;
5. obtain and validate the applicable national registrar profile;
6. use TLS, secret management, persistence, backups and monitoring;
7. define retention, deletion, access logging and incident response;
8. run wallet interoperability and security testing with approved test data.

The repository currently provides TEST infrastructure and local mocks. It does
not provide official registry access, official sandbox credentials or a
production deployment.
