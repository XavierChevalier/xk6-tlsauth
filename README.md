# xk6-tlsauth

xk6 extension: per-request TLS client certificates for HTTP and WebSocket on stock k6.

Stopgap until [grafana/k6#6506](https://github.com/grafana/k6/pull/6506) lands. Track the upstream issue [grafana/k6#4915](https://github.com/grafana/k6/issues/4915).

## Install xk6

```bash
go install go.k6.io/xk6/cmd/xk6@latest
```

## Build custom k6

From the published module:

```bash
xk6 build --with github.com/XavierChevalier/xk6-tlsauth@latest
```

Local development (this repo):

```bash
cd /path/to/xk6-tlsauth
xk6 build --with github.com/XavierChevalier/xk6-tlsauth=.
./k6 version
```

## Usage

### HTTP — `k6/x/tlsauth/http`

```javascript
import http from 'k6/x/tlsauth/http';

const cert = open('client.crt');
const key = open('client.key');

export default function () {
  const res = http.get(__ENV.URL, {
    tlsAuth: { cert, key },
    headers: { 'X-Test': '1' },
    timeout: '30s',
    tags: { name: 'mtls' },
  });
  // res.status, res.body, res.headers, res.error
}
```

Methods: `get(url, params?)`, `post(url, body?, params?)`, `request(method, url, body?, params?)`.

Run: `./k6 run examples/http.js -e URL=https://your-mtls-host/`

### WebSocket — `k6/x/tlsauth/ws`

```javascript
import ws from 'k6/x/tlsauth/ws';

const cert = open('client.crt');
const key = open('client.key');

export default function () {
  const res = ws.connect(__ENV.WSS_URL, {
    tlsAuth: { cert, key },
    tags: { name: 'mtls-ws' },
  }, function (socket) {
    socket.on('open', () => { socket.send('hi'); socket.close(); });
    socket.on('message', () => {});
    socket.on('close', () => {});
    socket.on('error', () => {});
  });
  // res.status — HTTP upgrade status
}
```

Blocking connect model matches `k6/ws`, not `k6/websockets`.

Run: `./k6 run examples/ws.js -e WSS_URL=wss://your-mtls-host/ws`

### Shared `tlsAuth` object

| Field      | Type   | Required | Notes                                      |
| ---------- | ------ | -------- | ------------------------------------------ |
| `cert`     | string | yes      | Client certificate (PEM)                   |
| `key`      | string | yes      | Private key (PEM)                          |
| `password` | string | no       | Encrypted PEM passphrase (same as stock k6) |

Parsing lives in `internal/tlsauth` (`Parse` for `{ cert, key, password? }`).

## Migration when upstream merges

1. Change imports: `k6/x/tlsauth/http` → `k6/http`, `k6/x/tlsauth/ws` → `k6/ws`.
2. Keep the same `tlsAuth` param objects on each request.
3. Stop building with this extension; use stock k6.

## v1 non-goals

- Full `k6/http` parity (batch, cookies/jar, redirects tuning, compression, digest/ntlm, forms).
- Full `k6/websockets` (WHATWG) API.
- Global `options.tlsAuth` integration inside the extension.
- Domain-based cert selection.
- AIA fetching.

Unknown param keys are ignored (minimal v1 behavior).

## Known limitations

- HTTP transports are pooled per VU by `tlsAuth` identity (cert/key/password hash), up to 16 entries, so repeated calls with the same client certificate reuse keep-alive connections. Switching among many distinct certificates still creates new transports (and handshakes) until older pool entries are evicted.
- PEM parsing still runs once per new pool entry (not on every request once pooled).
- HTTP/2 is not forced (`ForceAttemptHTTP2` is not set); behavior follows the default Go `http.Transport`.
- WebSocket `tags` in connect params are accepted but not applied to built-in WS metrics (limited metrics vs stock `k6/ws`).
- WebSocket dial does not yet mirror stock `k6/ws` `throw: false` handshake-error handling.
- WebSocket connections are not pooled; each `connect` dials fresh.

## Development

```bash
go test ./... -count=1 -timeout 120s
```
