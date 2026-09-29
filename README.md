# xk6-tlsauth

xk6 extension: per-request TLS client certificates for HTTP and WebSocket on stock k6.

Stopgap until [grafana/k6#6506](https://github.com/grafana/k6/pull/6506) lands.

## Build

```bash
xk6 build --with github.com/XavierChevalier/xk6-tlsauth@latest
```

## Modules

- `k6/x/tlsauth/http` — HTTP with per-request `tlsAuth`
- `k6/x/tlsauth/ws` — WebSocket (`k6/ws` style) with per-request `tlsAuth`

Shared PEM parsing lives in `internal/tlsauth` (`Parse` for `{ cert, key, password? }`).
