# vManage → Grafana Infinity Auth Proxy

A lightweight reverse proxy that handles the two-step Cisco vManage (Viptela SD-WAN) session authentication and forwards API calls from the Grafana Infinity datasource.

## Why this exists

vManage uses a non-standard form-based login flow that Grafana Infinity cannot perform natively:

1. `POST /j_security_check` with credentials → returns `JSESSIONID` cookie
2. `GET /dataservice/client/token` → returns XSRF token
3. Every subsequent request needs both `JSESSIONID` + `X-XSRF-TOKEN`

This proxy owns those credentials and handles re-authentication transparently when sessions expire.

## Files

```
.
├── main.go             # Go proxy application (stdlib only)
├── go.mod
├── Dockerfile
├── docker-compose.yml
├── .gitignore
└── secrets/            # Secret files — never committed to git
    ├── vmanage_host.txt
    ├── vmanage_user.txt
    ├── vmanage_pass.txt
    └── proxy_bearer_token.txt
```

## Setup

### 1. Populate secrets

```bash
echo "https://vmanage.example.com" > secrets/vmanage_host.txt
echo "admin"                        > secrets/vmanage_user.txt
echo "yourpassword"                 > secrets/vmanage_pass.txt
openssl rand -hex 32                > secrets/proxy_bearer_token.txt
```

Secret files are loaded at startup via Docker secrets (`/run/secrets/`). They are never passed as plain environment variables or baked into the image.

### 2. Build and start

```bash
docker compose up -d --build
```

The proxy binds to `127.0.0.1:8080` by default — it is not reachable from outside the host without explicit firewall rules.

### 3. Configure Grafana Infinity datasource

| Field | Value |
|---|---|
| Base URL | `http://localhost:8080` |
| Auth type | Bearer Token |
| Bearer Token | contents of `secrets/proxy_bearer_token.txt` |
| Allowed hosts | `http://localhost:8080/` |

### 4. Use in a panel

Set the URL field to the path **after** `/dataservice/`, for example:

```
device/vedgeinventory/detail
device/template/feature
statistics/interface
```

## Endpoints

| Path | Auth required | Description |
|---|---|---|
| `/{path}` | Yes (Bearer) | Proxied vManage API call |
| `/healthz` | No | Health check for Docker / load balancer |

## Building from source

The binary has no external dependencies, so cross-compilation is trivial:

```bash
# Linux (amd64 / arm64)
GOOS=linux GOARCH=amd64 go build -o proxy-linux-amd64 .
GOOS=linux GOARCH=arm64 go build -o proxy-linux-arm64 .

# macOS
GOOS=darwin GOARCH=arm64 go build -o proxy-darwin-arm64 .
GOOS=darwin GOARCH=amd64 go build -o proxy-darwin-amd64 .

# Windows
GOOS=windows GOARCH=amd64 go build -o proxy-windows-amd64.exe .
```

## Security notes

- **Credentials never enter Grafana** — only the proxy bearer token is stored there.
- **Docker secrets** keep passwords out of `docker inspect` and process listings.
- **Non-root container** — the app runs as `appuser`, not root.
- **Loopback binding** — port 8080 is exposed on `127.0.0.1` only.
- Rotate the proxy bearer token independently of vManage credentials with `openssl rand -hex 32`.
- In production, put TLS termination (e.g. nginx) in front of the proxy.

## Re-authentication behaviour

On every `401` or `403` response from vManage, the proxy re-authenticates once and retries the original request. A `sync.Mutex` prevents concurrent re-auth storms under high load.
