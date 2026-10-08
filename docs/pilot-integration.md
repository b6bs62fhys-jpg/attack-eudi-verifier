# Pilot integration guide

For the technical contact of a relying party that wants to try an age check or an
identity check with Attack. It covers one path end to end: get a tenant, create a
verification request, show it to the wallet user, read the result.

**What has and has not been run.** The flow below has run against the mock wallet in
this repository and against the open source wallet `walt.id wallet-api2`
(`docs/gegenstelle-waltid.md`). It has **not** been run against the German sandbox
wallet or with a real PID. Until it has, treat a pilot as an integration test of your
side, not as proof that real wallets work.

## 1. What you need

| You need | Why |
|---|---|
| A backend that can make HTTPS calls | the API key must never reach a browser or an app |
| The base URL of the Attack service and your API key | issued by the operator, see step 2 |
| A way to show a link and a QR code in your page | same device: a link, other device: a QR code |
| A way to ask for the result, for example a short poll | the result is read by your backend, not pushed |
| A wallet with a test credential | for the sandbox, the German sandbox wallet with a test PID |

Use test data only. Do not point a test setup at real people.

## 2. Tenant (done by the operator)

The operator creates your tenant and hands you the API key once. The service stores
only the hash of the key, so a lost key means a new tenant.

```bash
npm run cli -- tenant add --id acme-test --name "Acme test" --profile age_over_18_de \
  --file /etc/attack/tenants.json
```

`--profile` decides what is asked and what comes back:

| Profile | Asks for | Answer in the result |
|---|---|---|
| `age_over_18_de` | threshold 18 of the German PID, nothing else | `age_equal_or_over.18: true`, or a clear no |
| `age_over_18` | the claim `age_over_18` | `age_over_18: true`, or a clear no |
| `pid_de` | `given_name`, `family_name`, `birthdate` of the German PID | the three values |
| `pid_basis` | `given_name`, `birth_date` | the two values |

Your tenant can only ask for the claims of its profile. The service reads the tenant
file at start; a new tenant works after a restart.

## 3. Create a verification request

```bash
curl -s -X POST "$ATTACK_URL/v1/verification-requests" \
  -H "authorization: Bearer $ATTACK_API_KEY"
```

```json
{
  "sessionId": "9411ec8f-9eee-4e82-bf19-3181288d1e3a",
  "state": "9411ec8f-9eee-4e82-bf19-3181288d1e3a",
  "expiresAt": 1791439843684,
  "requestObject": "eyJ0eXAiOi...",
  "responseUri": "https://verifier.example.de/direct_post",
  "requestObjectUri": "https://verifier.example.de/v1/verification-requests/9411ec8f-.../request-object",
  "walletUrl": "openid4vp://?client_id=x509_hash%3A...&request_uri=https%3A%2F%2Fverifier.example.de%2F...&request_uri_method=get"
}
```

Keep `sessionId`. You need only `walletUrl` and `sessionId`; the other fields are for
the wallet. Each request is single use and valid for a limited time (the tenant
session time, 300 seconds by default). The signed request object inside it is valid
for 120 seconds by default, so show the code right after creating it and create a new
request if the user waits longer.

## 4. Show it to the wallet user

* **Same device** (the user is on the phone that has the wallet): make `walletUrl` a
  link. Opening it starts the wallet.
* **Other device** (the user is at a computer): show `walletUrl` as a QR code. The user
  scans it with the phone camera.

A QR code from the command line, for a quick test:

```bash
qrencode -o wallet-qr.png "$WALLET_URL" && open wallet-qr.png
```

In a web page, use any QR library and encode the `walletUrl` string unchanged.

Optional, same device only: if the operator set `ATTACK_REDIRECT_URI`, the service
answers the wallet with `redirect_uri`, and the wallet can return the user to your
page with `session_id` appended. Leave it unset for QR codes; on a second device the
user would be sent to the wrong screen.

## 5. Read the result

Poll from your backend, for example once a second for up to a minute:

```bash
curl -s "$ATTACK_URL/v1/verification-requests/$SESSION_ID" \
  -H "authorization: Bearer $ATTACK_API_KEY"
```

| Answer | Meaning |
|---|---|
| `{"status":"pending"}` | the user has not finished, or the wallet's answer was rejected (see below) |
| `{"status":"completed","result":{...}}` | the wallet answered; read `result`, once |
| `{"status":"expired"}` | the session timed out |
| HTTP 404 | unknown, expired, already read, or not yours (not distinguishable on purpose) |

A completed result for an age check:

```json
{ "status": "completed",
  "result": { "at": "2026-10-08T06:06:54Z", "valid": true,
              "claims": { "age_equal_or_over.18": true }, "issuerCountry": "DE", "error": "" } }
```

The result can be read **once**. After that it is gone (HTTP 404). Store the decision
you need in your own system. The default retention is 60 seconds.

**Read `valid` and `error`, not only `claims`.** An age check that fails is a
completed result with `valid: false` and `error: "age_requirement_not_met"`, with no
claim values. That is a clear no. Treat `valid: false` as "not verified" in every case.

A response that the service could not accept as genuine (wrong signature, revoked or
unknown issuer, tampered data, repeated use) does not produce a result. Your poll stays
`pending` until the session expires. Show the user a retry, not an error code from the
wallet side.

## 6. Errors you will see

Calls to the API (`docs/fehlercodes.md` has the full list):

| HTTP | `error` | Cause |
|---|---|---|
| 401 | `unauthorized` | missing, unknown or revoked API key |
| 400 | `invalid_json`, `claims_invalid`, `vct_invalid` | the request body, not needed for the default call |
| 403 | `tenant_not_registered`, `tenant_registration_invalid` | only if the operator turned on the onboarding gate |
| 404 | `not_found` | unknown, expired, read, or somebody else's session |
| 413 | `payload_too_large` | body over 64 KiB |
| 429 | `rate_limited` | too many calls; wait for `retry-after` seconds |

Reasons in a result (`result.error`) or in the wallet's answer:

| `error` | Meaning |
|---|---|
| `age_requirement_not_met` | genuine credential, the age threshold is not reached: a no |
| `age_claim_invalid` | the age claim is missing or has the wrong type |
| `credential_revoked`, `credential_suspended` | the credential status says so |
| `issuer_certificate_revoked`, `certificate_expired` | the issuer's certificate is revoked or expired |
| `issuer_trust_anchor_not_found`, `credential_malformed` | the issuer is not trusted, or the credential is unreadable or malformed |
| `presentation_invalid` | any other rejection |

## 7. A first test, in order

1. Operator creates your tenant (step 2) and tells you the base URL.
2. `curl` the create call (step 3). Expect HTTP 201 and a `walletUrl` that starts with
   `openid4vp://`.
3. Open the link on the phone with the sandbox wallet, or scan its QR code.
4. Confirm in the wallet. The wallet shows who asks and why, only if the operator has
   loaded a registration certificate.
5. Poll (step 5). Expect `completed` with `valid: true`.
6. Repeat with a test PID that is under the age limit. Expect `valid: false`,
   `age_requirement_not_met`.
7. Let a request time out. Expect `pending`, then `expired` or 404.

If step 3 fails before the wallet shows anything, check that `requestObjectUri` is
reachable from the internet over HTTPS (open it in a browser: it returns a long signed
text). The wallet fetches it itself.

## 8. What is not covered here

* Real PIDs and real people: the sandbox forbids real personal data.
* Operations: certificates, revocation sources, proxies and rate limits are the
  operator's side, see `docs/sandbox-runbook.md` and `docs/deployment.md`.
* The legal side of acting as a service provider for a relying party is open, see
  section 7 of `docs/sandbox-runbook.md`.
