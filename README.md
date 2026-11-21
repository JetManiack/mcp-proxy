# mcp-proxy

An aggregating MCP proxy that exposes multiple upstream MCP servers to AI agents through a single endpoint. Agents authenticate once with a Bearer token; the proxy handles per-upstream authentication transparently — including OAuth2 browser flows that agents cannot perform themselves.

## Why

Many MCP servers require OAuth2 browser-based authorization, making them unusable from agents running in headless environments (Kubernetes pods, CI runners, etc.). mcp-proxy solves this by holding OAuth2 sessions on behalf of a human operator and re-exposing all upstream tools through a simple Bearer-token API.

```
[AI agent]  --Bearer mcp_xxxx-->  [mcp-proxy :8080]
                                        |
                     ┌──────────────────┼──────────────────┐
               [Upstream A]      [Upstream B]        [Upstream C]
              Bearer <token>    OAuth2 session       API key
```

## How it works for agents

The proxy presents itself as a single MCP server with five virtual tools. The agent discovers tools by keyword rather than receiving hundreds of schemas upfront:

| Tool | Purpose |
|---|---|
| `mcp_tool_search` | Keyword search over all upstream tools — returns tool names, descriptions, upstream IDs |
| `mcp_tool_call` | Call a specific tool on a specific upstream |
| `upstream_status` | List connectivity and auth state of all upstreams |
| `mcp_resource_list` | List documentation resources from all upstreams |
| `mcp_resource_read` | Read a resource by its namespaced URI |

Typical agent flow:

```
mcp_tool_search(query="run shell command")
→ [{"tool_name":"exec","upstream_id":"...","upstream_name":"sandbox"}]

mcp_tool_call(upstream_id="...", tool_name="exec", args={"command":"echo hi"})
→ "hi"
```

The proxy also exposes a `resource://mcp-proxy/guide` resource with a full usage guide that agents can read on first connect.

## Upstream auth types

| Type | Credentials stored | Shared? |
|---|---|---|
| `none` | — | yes |
| `bearer_static` | token | yes |
| `oauth2_authorization_code` | access + refresh tokens | **yes** |

For `oauth2_authorization_code`: one person authorizes via the web UI browser flow, and the resulting token is shared across all agents. No per-agent or per-user credential isolation — the proxy acts as a single OAuth2 client on behalf of everyone.

All credentials are encrypted at rest with AES-256-GCM.

## Running

### Prerequisites

- Go 1.22+
- PostgreSQL 14+

### Build

```sh
go build -o bin/mcp-proxy ./cmd/mcp-proxy
```

### Generate an encryption key

```sh
openssl rand -hex 32
```

### Start

```sh
mcp-proxy \
  --database-url "postgres://user:pass@localhost:5432/mcp_proxy?sslmode=disable" \
  --encryption-key <32-byte hex key> \
  --public-url https://mcp-proxy.example.com \
  --auth-mode open
```

Or via environment variables:

```sh
export MCP_PROXY_DATABASE_URL="postgres://..."
export MCP_PROXY_ENCRYPTION_KEY="..."
export MCP_PROXY_PUBLIC_URL="https://mcp-proxy.example.com"
export MCP_PROXY_AUTH_MODE="open"
mcp-proxy
```

Or with a config file (`--config mcp-proxy.yaml`):

```yaml
database_url: postgres://user:pass@localhost:5432/mcp_proxy?sslmode=disable
public_url:   https://mcp-proxy.example.com

auth:
  mode: oauth2_proxy
  header_email: X-Auth-Request-Email
  header_groups: X-Auth-Request-Groups
  allowlist:
    emails:
      - alice@example.com
    groups:
      - sre
```

### Ports

| Port | Purpose |
|---|---|
| `:8080` | MCP endpoint for agents (`/mcp`) |
| `:8081` | Web UI + OAuth2 callbacks |
| `:8082` | Liveness/readiness probes (`/health/alive`, `/health/ready`) |

Override with `--agent-addr`, `--listen-addr`, `--probe-addr`.

## Web UI

The UI (`:8081`) lets operators:

- Add and remove upstream MCP servers
- Authorize OAuth2 upstreams (opens the upstream's browser flow — resulting token is shared by all agents)
- Create and revoke agent Bearer tokens
- Enable or disable individual upstream tools per-upstream

## Authentication modes

**`open`** — all requests to the web UI are allowed. For local development.

**`oauth2_proxy`** — the proxy must run behind [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/). It reads user identity from injected headers (`X-Auth-Request-Email`, `X-Auth-Request-Groups`) and enforces an allowlist. The MCP endpoint is unaffected — it always requires a Bearer agent token.

## Configuration reference

| Flag | Env | Default | Description |
|---|---|---|---|
| `--config` | `MCP_PROXY_CONFIG` | — | Path to YAML config file |
| `--database-url` | `MCP_PROXY_DATABASE_URL` | — | PostgreSQL connection URL |
| `--encryption-key` | `MCP_PROXY_ENCRYPTION_KEY` | — | 32-byte hex key for AES-256-GCM |
| `--public-url` | `MCP_PROXY_PUBLIC_URL` | — | Base URL for OAuth2 callbacks |
| `--auth-mode` | `MCP_PROXY_AUTH_MODE` | `open` | `open` or `oauth2_proxy` |
| `--agent-addr` | `MCP_PROXY_AGENT_ADDR` | `:8080` | MCP endpoint listen address |
| `--listen-addr` | `MCP_PROXY_LISTEN_ADDR` | `:8081` | Web UI listen address |
| `--probe-addr` | `MCP_PROXY_PROBE_ADDR` | `:8082` | Probe listen address |
| `--header-email` | `MCP_PROXY_HEADER_EMAIL` | `X-Auth-Request-Email` | Header carrying user email |
| `--header-groups` | `MCP_PROXY_HEADER_GROUPS` | `X-Auth-Request-Groups` | Header carrying group list |
| `--log-format` | `MCP_PROXY_LOG_FORMAT` | `json` | `json` or `text` |

## Kubernetes

The container is designed to run with a locked-down security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

The binary writes nothing to the filesystem at runtime, so no extra volume mounts are required. If a future dependency needs `/tmp`, add a memory-backed emptyDir:

```yaml
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir:
      medium: Memory
```

## Deployment notes

- **Single replica** — session state is in-process. No distributed coordination required.
- **Database migrations** run automatically on startup (advisory lock `87430004` prevents races on multi-pod rollouts).
- **ENCRYPTION_KEY rotation** — if the key changes, all stored credentials become unreadable. Re-enter them via the UI. The proxy logs a clear error on startup if decryption fails.
- Designed to run behind a TLS-terminating reverse proxy; the `Secure` cookie flag is omitted intentionally.

## License

MIT
