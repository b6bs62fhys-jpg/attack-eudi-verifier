# Attack Verifier Demo

Minimal Node.js example using the local TypeScript SDK. It creates a
presentation request and displays the request/result JSON in a small local web
page.

## Start

From the repository root, start the local TEST verifier first:

```bash
ATTACK_DEV_MODE=true npm run service
```

In another terminal:

```bash
npm --prefix examples/verifier-demo start
```

Open `http://127.0.0.1:3001` and click **Create presentation request**. The
default tenant API key is not automatically inserted by the example; set it
explicitly when the service requires tenant authentication:

```bash
ATTACK_API_KEY=test-api-key-tenant-A npm --prefix examples/verifier-demo start
```

The service URL can be changed with `ATTACK_URL`. The example uses only TEST
values and makes no external or authority request by itself.
