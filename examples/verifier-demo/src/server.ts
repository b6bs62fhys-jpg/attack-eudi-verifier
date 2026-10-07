import http from 'node:http';

import { AttackApiError, AttackClient } from '../../../sdk/typescript/src/index.ts';

const port = Number(process.env.PORT ?? 3001);
const client = new AttackClient({
  baseUrl: process.env.ATTACK_URL ?? 'http://127.0.0.1:8080',
  ...(process.env.ATTACK_API_KEY ? { apiKey: process.env.ATTACK_API_KEY } : {}),
});

const html = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Attack SDK demo</title></head>
<body>
  <main>
    <h1>Attack SDK demo</h1>
    <p>Creates a TEST presentation request against the configured Attack service.</p>
    <button id="create">Create presentation request</button>
    <pre id="output">No request yet.</pre>
    <label>Session ID <input id="session" autocomplete="off"></label>
    <button id="result">Read result</button>
    <script>
      const output = document.querySelector('#output');
      document.querySelector('#create').onclick = async () => {
        const response = await fetch('/request', { method: 'POST' });
        const value = await response.json();
        output.textContent = JSON.stringify(value, null, 2);
        if (value.sessionId) document.querySelector('#session').value = value.sessionId;
      };
      document.querySelector('#result').onclick = async () => {
        const id = document.querySelector('#session').value;
        const response = await fetch('/result/' + encodeURIComponent(id));
        output.textContent = JSON.stringify(await response.json(), null, 2);
      };
    </script>
  </main>
</body>
</html>`;

function sendJson(response: http.ServerResponse, status: number, value: unknown): void {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(value));
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? '/', `http://${request.headers.host ?? '127.0.0.1'}`);
    if (request.method === 'GET' && url.pathname === '/') {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(html);
      return;
    }
    if (request.method === 'POST' && url.pathname === '/request') {
      const created = await client.createPresentationRequest({ claims: ['age_over_18'] });
      sendJson(response, 201, created);
      return;
    }
    if (request.method === 'GET' && url.pathname.startsWith('/result/')) {
      const sessionId = decodeURIComponent(url.pathname.slice('/result/'.length));
      sendJson(response, 200, await client.getResult(sessionId));
      return;
    }
    sendJson(response, 404, { error: 'not_found' });
  } catch (error) {
    if (error instanceof AttackApiError) {
      sendJson(response, error.status || 502, { error: error.code ?? 'api_error' });
      return;
    }
    sendJson(response, 500, { error: 'internal_error' });
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`Attack SDK demo läuft auf http://127.0.0.1:${port}`);
});
