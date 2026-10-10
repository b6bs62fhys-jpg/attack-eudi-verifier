# Attack: EUDI Wallet Verifier API

[![CI](https://github.com/b6bs62fhys-jpg/attack-eudi-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/b6bs62fhys-jpg/attack-eudi-verifier/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Accept the EU Digital Identity Wallet in your service through one small REST API, without building the relying party side of OpenID4VP yourself.**

Your backend asks for a check (for example "is this person over 18" or "first name and date of birth from the PID"), the user presents the credential from their EUDI Wallet (in Germany: d-you), and you receive only the result you asked for.

> **Status: prototype, not for production use.**
> Tested end to end against the mock wallet in this repository and, since 2026-10-08, in a local run against the open source walt.id wallet (development mode, plain http, self-signed verifier certificate, no revocation or status checks; see [docs/gegenstelle-waltid.md](docs/gegenstelle-waltid.md)). All keys and credentials are TEST material created in memory. Not yet tested with a real wallet: no sandbox (including the SPRIND sandbox), no national wallet, no production wallet. The walt.id run is not a sandbox proof. Three open source verifiers (walt.id, eudi-verify, miEUDIverifier) were also evaluated as possible building blocks. There is no certification, no external security review and no production deployment. All keys and certificates in dev mode are TEST material, created in memory only and never persisted or logged. Known gaps are listed in [What it does not do yet](#what-it-does-not-do-yet).

## What it does

* **OpenID4VP** with signed request objects and **DCQL** queries
* **SD-JWT VC** validation (PID, `urn:eu.europa.ec.eudi:pid:1`), including selective disclosure, expiry and **key binding** (ES256)
* Encrypted wallet responses (**JWE**), a fresh key per session
* Issuer trust anchors, **OCSP** revocation checks and credential status lists
* Relying party **onboarding gate** for access and registration certificates (WRPAC, WRPRC)
* Multi tenant: API keys stored only as SHA 256 hash, strict isolation between tenants
* Every result is delivered exactly once and expires after a short TTL
* Rate limits, `/live`, `/ready`, Prometheus `/metrics`, structured logs without personal data
* SDKs for TypeScript, Python and Kotlin in [`sdk/`](sdk/) (not published to a registry)

## Quickstart (about 10 minutes)

Requires Node.js 22.12 or newer.

```bash
git clone https://github.com/b6bs62fhys-jpg/attack-eudi-verifier.git
cd attack-eudi-verifier
npm ci
npm run demo
```

Open `http://127.0.0.1:3001` and run the full flow: the verifier creates a request, a mock wallet presents a test PID, and the result is shown. The demo binds to 127.0.0.1 only.

Run the verifier service with two TEST tenants (`test-api-key-tenant-A`, `test-api-key-tenant-B`):

```bash
ATTACK_DEV_MODE=true npm run service
```

Then create a verification request from a second terminal:

```bash
curl -s -X POST http://127.0.0.1:8080/v1/verification-requests \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer test-api-key-tenant-A' \
  -d '{"claims":["given_name","birth_date"]}'
```

A complete walk through with a simulated wallet response and all error cases is in [`docs/quickstart-integration.md`](docs/quickstart-integration.md) (German). The `curl` examples in that file are executed by a test.

## API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/v1/verification-requests` | API key (Bearer) | Create a verification request |
| GET | `/v1/verification-requests/:id/request-object` | public | Signed request object for the wallet |
| POST | `/direct_post` | public | Receive and validate the wallet presentation |
| GET | `/v1/verification-requests/:id` | API key (Bearer) | Fetch the result (once) |
| DELETE | `/v1/verification-requests/:id` | API key (Bearer) | Expire or delete a session |
| GET | `/live`, `/ready`, `/metrics` | public | Liveness, readiness, Prometheus metrics |

Full specification: [`openapi.yaml`](openapi.yaml). Error codes: [`docs/fehlercodes.md`](docs/fehlercodes.md).

## Use it in a pilot

How a relying party connects the service in its own test environment. The steps follow the [integration guide](docs/integration-guide.md) and the [integration quickstart](docs/quickstart-integration.md); nothing here goes beyond what those documents describe.

1. **Run the service in your test environment.** Locally with `ATTACK_DEV_MODE=true npm run service`, or as a container with the [`Dockerfile`](Dockerfile) as described in [`docs/deployment.md`](docs/deployment.md). Dev mode uses TEST tenants, TEST keys and TEST certificates only.
2. **Keep the API key on your server.** It is a server side secret per tenant and is sent as `authorization: Bearer <key>`. Never put it into browser or app code.
3. **Create a verification request** with `POST /v1/verification-requests`. The `claims` must be part of the tenant profile, for example `given_name` and `birth_date` (profile `pid_basis`) or `age_over_18` (profile `age_over_18`). The response contains `sessionId`, `state` and `requestObjectUri`.
4. **Hand the request to the wallet.** Pass `requestObjectUri` to your wallet integration. The wallet posts its answer to the public `/direct_post` endpoint of the service, not to your backend.
5. **Evaluate the wallet response by its body.** Check `ok`, then `valid`, then `error`. HTTP 422 with `ok: false` means the response could not be processed (for example `unknown_state`). HTTP 200 with `valid: false` means it was checked and rejected on content (for example `certificate_expired`); do not retry it.
6. **Fetch the result once** with `GET /v1/verification-requests/:id`. It is readable exactly once and expires quickly. After a rejection no result is stored and the status stays `pending` until the session expires.
7. **Before you point it at a sandbox**, confirm with the wallet operator: allowed credential formats, callback and encryption requirements, verifier trust anchors and certificate chain, how tenant API keys are provisioned, and the data retention and incident rules. The repository contains no real sandbox URL and no real credentials.

The [production checklist](docs/integration-guide.md#5-production-checklist) in the integration guide lists everything that has to be replaced before real use.

Want help with a pilot? Two weeks, one use case (for example age check or identification) in your test environment, about 2 to 3 hours of effort on your side, a short written result at the end, free of charge. Open an issue or write to yaf.wimhoefer@gmail.com.

## What it does not do yet

* No **test with a real wallet**, a sandbox or a national wallet; only the mock wallet in this repository
* No **tenant management** outside dev mode: tenants and API keys are only created in dev mode, so production mode has no usable tenant yet
* No **mdoc** (ISO/IEC 18013-5); only `dc+sd-jwt`
* No **LOTL** / trusted list processing; only explicitly configured trust anchors
* No **DCQL credential sets**
* No wiring to an official **registrar**; the client exists but is not connected
* No persistence: sessions and results live in memory only
* No certification, no penetration test, no external review

Details and evidence: [`docs/interop-matrix.md`](docs/interop-matrix.md) (German) and [`docs/security.md`](docs/security.md).

## Tests

```bash
npm test
npm run typecheck
npm run lint
npm run test:coverage
```

CI runs the same checks plus `npm audit` on every push and pull request, without any secrets.

## Documentation

Most documents are in German; English versions exist where marked.

* Integration guide: [English](docs/integration-guide.md), [Deutsch](docs/integration-guide.de.md)
* Integration quickstart (Deutsch): [`docs/quickstart-integration.md`](docs/quickstart-integration.md)
* eIDAS and ARF conformance mapping: [English](docs/eidas-arf-konformitaet.en.md), [Deutsch](docs/eidas-arf-konformitaet.md)
* Interoperability and test status (Deutsch): [`docs/interop-matrix.md`](docs/interop-matrix.md)
* Security: [English](docs/security.md), [Deutsch](docs/sicherheit.md)
* Threat model (Deutsch): [`docs/bedrohungsmodell.md`](docs/bedrohungsmodell.md)
* Deployment and operations: [`docs/deployment.md`](docs/deployment.md) (English), [`docs/betrieb.md`](docs/betrieb.md) (Deutsch)
* Monitoring: [English](docs/monitoring-runbook.md), [Deutsch](docs/monitoring-runbook.de.md)
* Diagnostic CLI: [`docs/cli-tool.md`](docs/cli-tool.md)

## Background

Regulated sectors in the EU must accept the EUDI Wallet from the end of 2027, and Germany's wallet d-you starts on 2 January 2027. Attack is a signatory of the Bitkom Memorandum of Understanding on the EUDI Wallet.

## Security

Please report vulnerabilities privately, see [`SECURITY.md`](SECURITY.md).

## License

Apache License 2.0, see [`LICENSE`](LICENSE). Third party notices in [`NOTICE`](NOTICE).
