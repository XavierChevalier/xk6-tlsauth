# xk6-tlsauth design

Date: 2026-09-29
Status: approved for implementation (pending user spec review)

## Problem

Upstream k6 only configures client certificates globally via `options.tlsAuth`.
Per-request selection is proposed in [grafana/k6#4915](https://github.com/grafana/k6/issues/4915) and implemented in [PR #6506](https://github.com/grafana/k6/pull/6506), but not merged yet.

Users need the same capability on **stock k6** via an xk6 extension until that PR lands.

## Goals

- Provide per-request `tlsAuth` for HTTP and WebSocket.
- Mirror upstream import shapes under `k6/x/tlsauth/...` so scripts can migrate later with mostly import changes.
- Keep the implementation minimal.

## Non-goals (v1)

- Full `k6/http` parity (batch, cookies/jar, redirects tuning, compression, digest/ntlm, forms).
- Full `k6/websockets` (WHATWG) API.
- Global `options.tlsAuth` integration inside the extension.
- Domain-based cert selection.
- AIA fetching.

## API

### HTTP — `k6/x/tlsauth/http`

```javascript
import http from 'k6/x/tlsauth/http';

const res = http.get(url, {
  tlsAuth: { cert, key, password },
  headers: { 'X-Test': '1' },
  timeout: '30s',
  tags: { name: 'mtls' },
});
// res.status, res.body, res.headers, res.error
```

Methods: `get(url, params?)`, `post(url, body?, params?)`, `request(method, url, body?, params?)`.

### WebSocket — `k6/x/tlsauth/ws`

```javascript
import ws from 'k6/x/tlsauth/ws';

const res = ws.connect(url, {
  tlsAuth: { cert, key, password },
  headers: { 'X-Test': '1' },
  tags: { name: 'mtls-ws' },
}, function (socket) {
  socket.on('open', () => { socket.send('hi'); socket.close(); });
  socket.on('message', (msg) => {});
  socket.on('close', () => {});
  socket.on('error', (e) => {});
});
// res.status (HTTP upgrade status)
```

Blocking connect model matches `k6/ws`, not `k6/websockets`.

### Shared `tlsAuth` object

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `cert` | string (PEM) | yes | Client certificate |
| `key` | string (PEM) | yes | Private key |
| `password` | string | no | Passphrase for encrypted PEM keys (RFC1423 / DecryptPEMBlock, same limitation as k6) |

Invalid or missing `cert`/`key` returns a clear Go/JS error before dialing.

## Architecture

```
xk6-tlsauth/
  register.go              # init: modules.Register both paths
  http/module.go           # k6/x/tlsauth/http
  ws/module.go             # k6/x/tlsauth/ws
  internal/tlsauth/parse.go
  examples/http.js
  examples/ws.js
  README.md
  go.mod
```

### Components

1. **`internal/tlsauth`** — parse JS `tlsAuth` map → `*tls.Certificate` (shared by HTTP and WS).
2. **`http` module** — one-shot `http.Client` per request with cloned TLS config containing that certificate; return a minimal response object.
3. **`ws` module** — gorilla/websocket dialer with `TLSClientConfig` from `tlsAuth`; event loop blocked until socket closes (same idea as `k6/ws`).

### Data flow (HTTP)

1. JS calls `http.get(url, params)`.
2. Extension parses `tlsAuth` → certificate.
3. Build `tls.Config` (InsecureSkipVerify follows VU `state.Options` when available, else false).
4. Dial via VU dialer when available, else net.Dialer.
5. Perform request; map status/body/headers/error to JS object.
6. Best-effort push `http_req` / duration samples from VU `BuiltinMetrics` when present.

### Data flow (WS)

1. JS calls `ws.connect(url, params, callback)`.
2. Parse `tlsAuth`; configure dialer TLS.
3. Dial; invoke callback with socket bindings.
4. Run until close; return upgrade response status.

## Error handling

- Bad `tlsAuth` shape → immediate error (no network).
- TLS handshake / dial failures → HTTP: `error` string + status 0 (or throw if VU `throw` is true when readable); WS: surface via connect error / `error` event.
- Unknown params keys → ignore for HTTP (k6/http style); for WS ignore unknown keys too in v1 to stay minimal (document this).

## Testing

- Unit: `internal/tlsauth` parse validation (missing cert/key, bad password type).
- Integration-style Go tests with local mTLS `httptest` / WSS server:
  - missing cert fails
  - correct cert succeeds
  - switching certs between two calls works
- Manual: `examples/*.js` against a local mTLS server after `xk6 build`.

## Build / use

```bash
go install go.k6.io/xk6/cmd/xk6@latest
xk6 build --with github.com/XavierChevalier/xk6-tlsauth@latest
./k6 run examples/http.js
```

Local replace while developing:

```bash
xk6 build --with github.com/XavierChevalier/xk6-tlsauth=.
```

## Migration when upstream merges

1. Change imports from `k6/x/tlsauth/http` → `k6/http` and `k6/x/tlsauth/ws` → `k6/ws`.
2. Keep the same `tlsAuth` param objects.
3. Stop building with this extension.

## Success criteria

- Custom k6 binary built with xk6 can run HTTP and WS scripts that authenticate with different client certs per call.
- Codebase stays small: shared parser + two thin modules + examples + README.
