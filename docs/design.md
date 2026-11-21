# mcp-proxy Design

## Problem

Several MCP servers require OAuth2 browser-based authorization.
This makes them unusable by agents running in Kubernetes, where no browser is available.

**Solution:** A proxy that holds OAuth2 sessions on behalf of a human operator and exposes the
upstream MCPs to k8s agents via a simple Bearer token — no browser required from the agent side.

## Architecture Overview

```
[AI agent / k8s agent]  --Bearer mcp_xxxx-->  [mcp-proxy /mcp]
                                                    |
                                    ┌───────────────┴────────────────┐
                                    │       ToolCatalog (in-memory)   │
                                    │  mcp_tool_search                │
                                    │  mcp_tool_call                  │
                                    │  upstream_status (always on)    │
                                    └───────────────┬────────────────┘
                                                    |
                              ┌─────────────────────┼──────────────────────┐
                        [Upstream A]         [Upstream B]           [Upstream C]
                     Bearer <token>       Bearer <token>          Bearer <token>
```

The proxy presents itself to the agent as a single MCP server with three virtual tools.
The real upstream tools are discovered via search, not advertised upfront, to avoid flooding
the agent's context window with hundreds of tool schemas.

## Components

### 1. MCP Server (downstream — for agents)

Exposes three tools, always:

| Tool | Description |
|---|---|
| `mcp_tool_search(query, top_k=5)` | Keyword search over in-memory tool index. Returns tool names and descriptions. |
| `mcp_tool_call(tool_name, arguments)` | Dispatch: routes the call to the upstream that owns the named tool. |
| `upstream_status()` | Returns the authorization status of every configured upstream. The agent calls this and notifies the operator if reauth is needed. |

Tool search uses keyword matching (lowercase, whitespace-split, name+description scored).
No embedding model required.

### 2. MCP Client Pool (upstream — to each backend)

One reusable MCP session per authorized upstream (Streamable HTTP transport, go-sdk v1.8.0).
Reconnects on failure. On connect: calls `tools/list`, updates the in-memory ToolCatalog.

### 3. Tool Catalog & Namespace

All upstream tools are merged into one in-memory index used by `mcp_tool_search`.

Namespace rule applied at ingestion:
1. Normalize upstream name: lowercase, spaces/hyphens → `_`
2. If the tool name already starts with `{upstream_name}_` → keep as-is
3. Otherwise prefix: e.g. an upstream named `issues` with tool `search` → `issues_search`

This ensures tools already prefixed with the upstream name are unchanged while others get a prefix.

### 4. OAuth Manager (per upstream, `oauth2_authorization_code` only)

Handles the full browser-based OAuth flow for a specific (upstream, user) pair:

1. **Discovery** — `GET {url}/.well-known/oauth-protected-resource` + `oauth-authorization-server`
2. **DCR** — `POST /register` → stores `client_id` / `client_secret` encrypted in DB.
   Many upstreams keep DCR data in-memory and lose it on restart; we store it durably. On `invalid_client` error → re-register.
3. **Authorization** — user clicks "Authorize" in Web UI → browser redirects to upstream IdP with PKCE `code_challenge`. `redirect_uri` = `{PUBLIC_URL}/oauth/callback`.
4. **Callback** — `GET /oauth/callback?upstream_id=...&code=...` → token exchange → store tokens.
5. **Refresh goroutine** — background worker checks all `upstream_user_tokens`; refreshes at `expires_at - 5min`.
   If no `refresh_token` or refresh fails → status becomes `reauth_required`.

### 5. Web UI

Server-rendered HTML. Routes:

| Route | Description |
|---|---|
| `GET /` | List of upstreams with auth status for the current user |
| `GET /upstreams/new` | Add upstream form |
| `POST /upstreams` | Create upstream; triggers discovery |
| `GET /upstreams/{id}/authorize` | Start OAuth PKCE flow for current user |
| `GET /oauth/callback` | OAuth callback (exchanges code, stores tokens) |
| `GET /upstreams/{id}/edit` | Edit upstream config |
| `DELETE /upstreams/{id}` | Delete upstream |
| `GET /tokens` | Manage agent tokens |
| `POST /tokens` | Create agent token |
| `DELETE /tokens/{id}` | Revoke agent token |
| `GET /admin/allowlist` | View current allowlist (read-only, from config file) |

### 6. Web UI Authentication (OAuth2-proxy compatible)

The proxy is designed to run behind [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/),
which injects user identity headers after authentication. The proxy itself has no login flow —
it only reads what oauth2-proxy provides.

Headers read (configurable):
- `X-Auth-Request-Email` → user email
- `X-Auth-Request-Groups` → comma-separated group list

Allowlist is defined in the **config file** (not the DB), so the UI is protected before the
database is initialized.

Two auth modes:

| Mode | Behaviour |
|---|---|
| `oauth2_proxy` | Headers required; request denied (403) if absent or not in allowlist |
| `open` | All requests allowed; intended for local dev without oauth2-proxy in front |

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
      - devops
```

A request is allowed if the email or at least one group is in the allowlist.

### 7. User Isolation

Each user sees and manages only their own upstream tokens:
- The Web UI upstream list shows authorization status **for the current logged-in user only**.
- User A cannot read or enumerate User B's tokens.
- User A can authorize any upstream, which creates or replaces **their own** token for it.
- All store-layer methods take a `userID` from the request context — raw cross-user queries exist
  only inside the refresh goroutine.

## Upstream Auth Types

| Type | Credential storage | Per-user? |
|---|---|---|
| `none` | — | no |
| `bearer_static` | token, encrypted global | no |
| `api_key` | header name + value, encrypted global | no |
| `basic_auth` | username + password, encrypted global | no |
| `oauth2_client_credentials` | client_id + secret, encrypted global, shared token | no |
| `oauth2_authorization_code` | access + refresh tokens, encrypted | **yes** |

## Database Schema (PostgreSQL)

```sql
users
  id            uuid PK
  email         text UNIQUE NOT NULL
  display_name  text
  created_at    timestamptz

upstreams
  id             uuid PK
  name           text NOT NULL
  url            text NOT NULL
  auth_type      text NOT NULL   -- enum: none | bearer_static | api_key | basic_auth
                                 --       oauth2_client_credentials | oauth2_authorization_code
  auth_endpoint  text
  token_endpoint text
  dcr_endpoint   text
  created_at     timestamptz
  updated_at     timestamptz

upstream_credentials          -- global credentials (all non-per-user auth types)
  id           uuid PK
  upstream_id  uuid FK → upstreams
  data         bytea NOT NULL  -- AES-256-GCM encrypted JSON; shape depends on auth_type
  updated_at   timestamptz

upstream_user_tokens          -- per-user OAuth tokens (oauth2_authorization_code only)
  id              uuid PK
  upstream_id     uuid FK → upstreams
  user_id         uuid FK → users
  access_token    bytea NOT NULL   -- AES-256-GCM encrypted
  refresh_token   bytea            -- AES-256-GCM encrypted, nullable
  expires_at      timestamptz
  status          text NOT NULL    -- authorized | reauth_required
  dcr_client_id   bytea            -- encrypted; stored durably against upstream restart
  updated_at      timestamptz
  UNIQUE (upstream_id, user_id)

agent_tokens
  id           uuid PK
  name         text NOT NULL
  token_hash   bytea NOT NULL UNIQUE  -- SHA-256 of the raw mcp_xxxx token
  user_id      uuid FK → users
  created_at   timestamptz
  last_used_at timestamptz
```

Encryption: AES-256-GCM, key from env `ENCRYPTION_KEY` (32-byte hex). Advisory lock key: `87430004`.

## Configuration File

```yaml
# mcp-proxy.yaml

database_url: postgres://...
listen_addr:  ":8080"
public_url:   https://mcp-proxy.example.com   # used as OAuth redirect_uri base

auth:
  mode: oauth2_proxy          # or "stub"
  header_email: X-Auth-Request-Email
  header_groups: X-Auth-Request-Groups
  allowlist:
    emails: []
    groups: []
```

All fields are also settable via environment variables and CLI flags (urfave/cli v3).

## Project Structure

```
cmd/mcp-proxy/
  main.go

internal/
  config/       CLI flags, env, config file loading
  store/        GORM models, migrations (Postgres only, advisory lock 87430004)
  crypto/       AES-256-GCM encrypt/decrypt helpers
  upstream/     Upstream registry CRUD; OAuth manager (discovery, DCR, PKCE flow, refresh)
  mcpclient/    MCP client pool; ToolCatalog; keyword search index
  mcpserver/    MCP server for agents: virtual tools, dispatch
  web/          Web UI HTTP handlers
  auth/         oauth2-proxy header parsing; allowlist enforcement

web/
  templates/    HTML templates (server-rendered)
  static/       CSS, JS assets
```

## Key Dependencies

| Package | Version | Purpose |
|---|---|---|
| `github.com/modelcontextprotocol/go-sdk` | v1.8.0 | MCP client + server |
| `github.com/go-chi/chi/v5` | v5.x | HTTP router |
| `gorm.io/gorm` + `gorm.io/driver/postgres` | latest | ORM + migrations |
| `github.com/urfave/cli/v3` | v3.x | CLI flags |
| `golang.org/x/oauth2` | latest | OAuth2 client |

No SQLite — Postgres only (deployed alongside the agent in k8s).

## Deployment Notes

- Runs as a single-replica Deployment in k8s (session state is in-process).
- Requires `ENCRYPTION_KEY` env var (32-byte hex).
- Requires `PUBLIC_URL` to match the ingress FQDN so OAuth callbacks resolve correctly.
- Designed to run behind `oauth2-proxy` for Web UI access control.
- The MCP endpoint (`/mcp`) is separate from the Web UI and authenticated via Bearer token only.
