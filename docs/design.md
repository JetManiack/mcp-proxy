# mcp-proxy Design

## Problem

Several MCP servers require OAuth2 browser-based authorization.
This makes them unusable by agents running in Kubernetes, where no browser is available.

**Solution:** A proxy that holds OAuth2 sessions on behalf of a human operator and exposes the
upstream MCPs to agents via a simple Bearer token — no browser required from the agent side.

## Architecture Overview

```
[AI agent / k8s agent]  --Bearer mcp_xxxx-->  [mcp-proxy /mcp :8080]
                                                      |
                                        ┌─────────────┴──────────────┐
                                        │   Tool Catalog (in-memory)  │
                                        │   mcp_tool_search           │
                                        │   mcp_tool_call             │
                                        │   upstream_status           │
                                        │   mcp_resource_list/read    │
                                        └─────────────┬──────────────┘
                                                      |
                            ┌─────────────────────────┼────────────────────────┐
                      [Upstream A]            [Upstream B]              [Upstream C]
                     Bearer <token>          OAuth2 session              no auth
```

The proxy presents itself to the agent as a single MCP server. All upstream tools are visible
to all agents regardless of auth state — isolation is enforced at call time, not discovery time.

## Components

### 1. MCP Server (downstream — for agents)

Exposes five virtual tools, always:

| Tool | Description |
|---|---|
| `mcp_tool_search(query, max_results)` | Keyword search over in-memory tool catalog. Returns tool name, description, upstream ID, and input schema. |
| `mcp_tool_call(upstream_id, tool_name, args)` | Routes the call to the specified upstream. |
| `upstream_status()` | Returns connectivity and auth status of every configured upstream. |
| `mcp_resource_list()` | Lists all documentation resources from all upstreams (namespaced URIs). |
| `mcp_resource_read(uri)` | Reads a resource by its namespaced URI. |

Also exposes a `resource://mcp-proxy/guide` resource with a full usage guide for agents.

Tool search uses keyword matching (lowercase, name + description scored). No embedding model required.

Typical agent flow:
```
mcp_tool_search(query="run shell command")
→ [{"tool_name":"exec","upstream_id":"...","upstream_name":"sandbox","input_schema":{...}}]

mcp_tool_call(upstream_id="...", tool_name="exec", args={"command":"echo hi"})
→ "hi"
```

### 2. MCP Client Pool (upstream — to each backend)

One reusable MCP client session per upstream (Streamable HTTP transport, go-sdk).
Session key: `(upstream_id, uuid.Nil)` — always shared, never per-user.

On connect: calls `tools/list`, populates the in-memory tool catalog.
Reconnects automatically on failure (session is invalidated and recreated on next call).

A background reconcile loop runs every 30 seconds to:
- Trigger OAuth discovery for new `oauth2_authorization_code` upstreams.
- Refresh the tool catalog from all upstreams.

### 3. Tool Catalog

All upstream tools are merged into one in-memory index used by `mcp_tool_search`.
The catalog is rebuilt by the reconcile loop and also computed live on the first request
(before the first reconcile cycle completes).

Tools disabled via the web UI (`tool_filters` table) are excluded from both the catalog
and `mcp_tool_call` (double enforcement).

### 4. OAuth Manager (`oauth2_authorization_code` only)

Handles the full browser-based OAuth flow:

1. **Discovery** — `GET {url}/.well-known/oauth-protected-resource` + `oauth-authorization-server`
2. **DCR** — `POST /register` → stores `client_id` / `client_secret` encrypted in DB.
   Stored durably because many upstreams lose DCR data on restart.
3. **Authorization** — user clicks "Authorize" in Web UI → browser redirects to upstream IdP
   with PKCE `code_challenge`. `redirect_uri` = `{PUBLIC_URL}/oauth/callback`.
4. **Callback** — `GET /oauth/callback?code=...&state=...` → token exchange → store token
   with `user_id = uuid.Nil` (shared token, not tied to the authorizing user).
5. **Auto-refresh** — a `persistingTokenSource` wraps the oauth2 token; refreshed tokens
   are written back to the DB automatically on each use.

**Shared token model:** one person authorizes via the UI; the resulting token is used by all
agents. The authorizing user's identity is irrelevant — `BeginAuth` and `storeToken` always
use `uuid.Nil` as the user key.

If no shared token exists, the proxy connects to the upstream unauthenticated. Tool listings
may still work (catalog is populated); actual tool calls will return an auth error from the
upstream if credentials are required.

### 5. Web UI

Server-rendered HTML (`:8081`). Routes:

| Route | Description |
|---|---|
| `GET /ui/upstreams` | List upstreams with live status |
| `GET /ui/upstreams/new` | Add upstream form |
| `POST /ui/upstreams` | Create upstream; triggers discovery |
| `GET /ui/upstreams/{id}` | View upstream details, tools, resources |
| `POST /ui/upstreams/{id}/auth` | Start OAuth PKCE flow (shared authorization) |
| `GET /oauth/callback` | OAuth callback (exchanges code, stores shared token) |
| `POST /ui/upstreams/{id}/tools/{tool}` | Enable/disable a tool |
| `POST /ui/upstreams/{id}/credential` | Update bearer_static token |
| `POST /ui/upstreams/{id}/delete` | Delete upstream |
| `GET /ui/tokens` | Manage agent tokens |
| `POST /ui/tokens` | Create agent token |
| `POST /ui/tokens/{id}/delete` | Revoke agent token |

### 6. Web UI Authentication

Two modes:

| Mode | Behaviour |
|---|---|
| `open` | All requests allowed. For local development. |
| `oauth2_proxy` | Must run behind [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/). Reads `X-Auth-Request-Email` / `X-Auth-Request-Groups` headers; enforces an allowlist. |

The MCP endpoint (`:8080`) is separate and always requires a Bearer agent token regardless of UI auth mode.

```yaml
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

## Upstream Auth Types

| Type | Credential storage | Shared |
|---|---|---|
| `none` | — | yes |
| `bearer_static` | token, encrypted | yes |
| `oauth2_authorization_code` | access + refresh tokens, encrypted | yes — `user_id = uuid.Nil` |

## Database Schema (PostgreSQL)

```sql
users
  id            uuid PK
  email         text UNIQUE NOT NULL
  display_name  text
  created_at    timestamptz

upstreams
  id                  uuid PK
  name                text NOT NULL
  url                 text NOT NULL
  auth_type           text NOT NULL   -- none | bearer_static | oauth2_authorization_code
  auth_endpoint       text            -- OAuth2 authorization endpoint
  token_endpoint      text            -- OAuth2 token endpoint
  dcr_endpoint        text            -- Dynamic Client Registration endpoint
  client_id_meta_doc  bool            -- use client_id_metadata_document flow
  created_at          timestamptz
  updated_at          timestamptz

upstream_credentials          -- static credentials (bearer_static; DCR client_id/secret)
  id           uuid PK
  upstream_id  uuid FK → upstreams
  data         bytea NOT NULL  -- AES-256-GCM encrypted
  updated_at   timestamptz

upstream_user_tokens          -- shared OAuth2 tokens (user_id always uuid.Nil)
  id              uuid PK
  upstream_id     uuid FK → upstreams
  user_id         uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'
  access_token    bytea NOT NULL   -- AES-256-GCM encrypted
  refresh_token   bytea            -- AES-256-GCM encrypted, nullable
  expires_at      timestamptz
  status          text NOT NULL    -- authorized | reauth_required
  updated_at      timestamptz
  UNIQUE (upstream_id, user_id)

agent_tokens
  id           uuid PK
  name         text NOT NULL
  token_hash   bytea NOT NULL UNIQUE  -- SHA-256 of the raw mcp_xxxx token
  user_id      uuid FK → users        -- which UI user created this token
  created_at   timestamptz
  last_used_at timestamptz

tool_filters
  upstream_id  uuid FK → upstreams
  tool_name    text NOT NULL
  enabled      bool NOT NULL
  PRIMARY KEY (upstream_id, tool_name)
```

Encryption: AES-256-GCM, 32-byte key from `--encryption-key` / `MCP_PROXY_ENCRYPTION_KEY`.
Migrations run automatically on startup with advisory lock `87430004`.

## Project Structure

```
cmd/mcp-proxy/
  main.go               Entry point, CLI flags, server wiring

internal/
  config/               Config struct, YAML loading, validation
  store/                PostgreSQL store, migrations (sqlc-style raw SQL)
  crypto/               AES-256-GCM encrypt/decrypt helpers
  upstream/             Upstream registry CRUD; OAuth manager (discovery, DCR, PKCE, refresh)
  mcpclient/            MCP client pool; tool catalog; keyword search
  mcpserver/            MCP server for agents: virtual tools, dispatch
  web/                  Web UI HTTP handlers, templates, CSRF middleware
  auth/                 oauth2-proxy header parsing; allowlist enforcement
  telemetry/            Prometheus metrics, structured logging setup

test/e2e/               End-to-end tests (require TEST_DATABASE_URL)
```

## Key Dependencies

| Package | Purpose |
|---|---|
| `github.com/modelcontextprotocol/go-sdk` | MCP client + server (Streamable HTTP) |
| `github.com/urfave/cli/v3` | CLI flags |
| `golang.org/x/oauth2` | OAuth2 token management and refresh |
| `github.com/google/uuid` | UUID generation and parsing |
| `github.com/prometheus/client_golang` | Metrics |

## Deployment Notes

- **Single replica** — session state is in-process. No distributed coordination required.
- **Database migrations** run automatically on startup (advisory lock `87430004`).
- **ENCRYPTION_KEY rotation** — if the key changes, all stored credentials become unreadable. Re-enter them via the UI.
- **Public URL** must match the ingress FQDN so OAuth callbacks resolve correctly.
- Designed to run behind a TLS-terminating reverse proxy; the proxy itself does not terminate TLS.
