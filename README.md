# Attack: EUDI Wallet Verifier API

Accept the EU Digital Identity Wallet (EUDI Wallet, in Germany: d-you) in your service without building the relying party side yourself.

Attack is a verifier service with a small REST API. Your backend asks for a check (for example "is this person over 18" or "first name and date of birth from the PID"), the user presents the credential from their wallet, and you receive only the result you asked for.

> **Status: prototype, not for production use.** It runs end to end against test wallets and the German EUDI Wallet sandbox. All keys and certificates in dev mode are TEST material, created in memory only and never persisted or logged.

## What it does

* **OpenID4VP** with signed request objects and **DCQL** queries
* **SD-JWT VC** validation (PID, `urn:eu.europa.ec.eudi:pid:1`), including selective disclosure, expiry and **key binding** (ES256)
* Encrypted wallet responses (**JWE**), a fresh key per session
* Issuer trust anchors, **OCSP** revocation checks and credential status lists
* Relying party **onboarding gate** for access and registration certificates (WRPAC, WRPRC)
* Multi tenant: API keys stored only as SHA 256 hash, strict isolation between tenants
* Every result is delivered exactly once and expires after a short TTL
* Rate limits, `/live`, `/ready`, Prometheus `/metrics`, structured logs without personal data
* SDKs for TypeScript, Python and Kotlin in `sdk/`

## Quickstart (local demo)

Requires Node.js 22.12 or newer.

```bash
npm ci
npm run demo
```

Open `http://127.0.0.1:3001` and run the full flow: the verifier creates a request, a mock wallet presents a test PID, and the result is shown. The demo only binds to 127.0.0.1.

Run the verifier service:

```bash
ATTACK_DEV_MODE=true npm run service
```

## API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/v1/verification-requests` | API key (Bearer) | Create a verification request |
| GET | `/v1/verification-requests/:id/request-object` | public | Signed request object for the wallet |
| POST | `/direct_post` | public | Receive and validate the wallet presentation |
| GET | `/v1/verification-requests/:id` | API key (Bearer) | Fetch the result (once) |
| DELETE | `/v1/verification-requests/:id` | API key (Bearer) | Expire or delete a session |

Full specification: [`openapi.yaml`](openapi.yaml). Error codes: [`docs/fehlercodes.md`](docs/fehlercodes.md).

## Tests

```bash
npm test
npm run typecheck
npm run lint
```

## Documentation

* Integration guide: [English](docs/integration-guide.md), [Deutsch](docs/integration-guide.de.md)
* Quickstart for integrators: [`docs/quickstart-integration.md`](docs/quickstart-integration.md)
* Interoperability matrix: [English](docs/interop-matrix.md), [Deutsch](docs/interop-matrix.de.md)
* eIDAS and ARF conformance: [English](docs/eidas-arf-konformitaet.en.md), [Deutsch](docs/eidas-arf-konformitaet.md)
* Security and threat model: [`docs/sicherheit.md`](docs/sicherheit.md), [`docs/bedrohungsmodell.md`](docs/bedrohungsmodell.md)
* Deployment, operations, monitoring: [`docs/deployment.md`](docs/deployment.md), [`docs/betrieb.md`](docs/betrieb.md), [`docs/monitoring-runbook.md`](docs/monitoring-runbook.md)

## Free pilot

Regulated sectors in the EU must accept the EUDI Wallet from the end of 2027, and Germany's wallet d-you starts on 2 January 2027.

I offer two free pilots: two weeks, one use case (for example age check or identification) in your test environment, about 2 to 3 hours of effort on your side, and a short written result at the end.

Interested? Open an issue in this repository or write to yaf.wimhoefer@gmail.com.

**Deutsch:** Zwei kostenlose Piloten über zwei Wochen in Ihrer Testumgebung, zum Beispiel für Altersprüfung oder Identifizierung. Einfach ein Issue eröffnen oder eine Mail schreiben.

## License

Apache License 2.0, see [`LICENSE`](LICENSE). Third party notices in [`NOTICE`](NOTICE).

Attack is a signatory of the Bitkom Memorandum of Understanding on the EUDI Wallet.
