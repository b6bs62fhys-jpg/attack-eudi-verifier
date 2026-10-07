# `@eudi-verify-sdk/typescript`

Typed TypeScript client for the Attack EUDI Verifier API. The package is a
repository-local SDK candidate and is not published yet.

## Install

```bash
npm install @eudi-verify-sdk/typescript
```

The API uses a tenant Bearer API key for tenant-scoped routes. Keep that key
server-side; do not embed it in browser code.

## Create a presentation request

```ts
import { AttackClient } from '@eudi-verify-sdk/typescript';

const attack = new AttackClient({
  baseUrl: process.env.ATTACK_URL ?? 'http://127.0.0.1:8080',
  apiKey: process.env.ATTACK_API_KEY,
});

const request = await attack.createPresentationRequest({ claims: ['age_over_18'] });
console.log(request.requestObjectUri, request.responseUri);
```

The requested claims must be part of the tenant's request profile. A tenant on
the default profile `pid_basis` gets `given_name` and `birth_date`, so the call
above answers `claims_invalid` until the tenant is configured with the
`age_over_18` profile. See `src/service/profile.ts` for the available profiles.

## Read the result

```ts
const result = await attack.getResult(request.sessionId);
if (result.status === 'completed') console.log(result.result?.claims);
```

## Submit a wallet response

```ts
const outcome = await attack.submitPresentation({ response: walletJwe });
if (!outcome.valid) console.error(outcome.error);
```

`AttackApiError` contains the HTTP status and the stable API error code when
the server returns an error response.

## Operational routes

The three service routes take no API key and are not rate limited.

```ts
await attack.liveness();  // GET /live   -> { ok, status: "live", app }
await attack.readiness(); // GET /ready  -> { ok, status, checks }
const text = await attack.metrics(); // GET /metrics -> Prometheus text
```

`readiness()` returns a value even when the service answers HTTP 503.
`not_ready` is a valid answer to that question, not a failure, so the per
dependency `checks` stay readable instead of arriving as `AttackApiError`.

## Rejected presentations

`submitPresentation` does not throw for a rejected presentation. Check `ok`
first, then `valid`, then `error`.

`/direct_post` is public, so 401 stays reserved for a missing or unknown API key
and 413 for the size limit; both still raise `AttackApiError`.

| `ok` | `valid` | HTTP | Meaning |
|---|---|---|---|
| `false` | `false` | 422 | not processed: unknown session, malformed body, replay, JWE problem |
| `true` | `false` | 200 | processed and rejected on content, e.g. `certificate_expired` |
| `true` | `true` | 200 | valid |

```ts
const outcome = await attack.submitPresentation({ response: walletJwe });
if (!outcome.ok) console.error(outcome.error); // 422: unknown_state, state_invalid, …
else if (!outcome.valid) console.error(outcome.error); // 200: processed, rejected on content
```

Checking `valid` alone is not sufficient: on a 422 `valid` is `false` as well.

## Generated code

`src/generated.ts` is generated from `openapi.yaml` in the repository root and
must not be edited by hand.

```bash
npm run generate        # regenerate from openapi.yaml
npm run generate:check  # fail if the committed file drifts from the spec
```

`generate:check` regenerates into a temporary directory and compares byte for
byte. It runs in CI, so a change to the spec without a matching regeneration
fails the build. Hand written client methods are not covered by it; each client
keeps its own tests for the routes it exposes.
