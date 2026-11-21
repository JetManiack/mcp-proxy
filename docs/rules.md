# Development Rules

## Workflow

1. Every feature or fix is developed on a dedicated branch; merged into `main` via PR.
2. Write failing tests first (red), then implement (green). No non-trivial logic ships without a test written before the implementation.
3. Before committing: run `make ci` locally. All gates must pass.
4. After `make ci` passes: run an independent code review in a **fresh subagent** (not a fork). A fork inherits the parent's full tool set including `Edit`/`Write` and is not independent. Use `subagent_type: "general-purpose"` with an explicit instruction not to edit files. Fix any findings, then commit and push.

## CI Gates (`make ci`)

| Gate | Command |
|---|---|
| Build | `go build -trimpath` |
| Test | `go test ./... -race -count=1` |
| Lint | `go vet ./...` + `staticcheck ./...` |
| Security | `govulncheck ./...` + `gosec ./...` |
| Module consistency | `go mod tidy` + `git diff --exit-code go.mod go.sum` |
| Format | `gofmt -l` on tracked `.go` files |

## Code Style

- No comments unless the **why** is non-obvious (hidden constraint, subtle invariant, workaround for a specific bug). Never explain what the code does.
- No error handling, fallbacks, or validation for scenarios that cannot happen. Trust internal invariants.
- No features, abstractions, or refactors beyond what the current task requires.
- Validate only at system boundaries (HTTP handlers, config loading). Trust internal code.
- Use `context.Background()` for DB writes that must survive request cancellation (e.g. audit records, token saves).

## Testing

- Unit tests: pure logic, no I/O.
- Integration tests: real Postgres in a temp database, real HTTP via `httptest`. No mocks for the database.
- Tests must cover the negative path: missing token → 401, unauthorized user → 403, etc.
- Assert invariants, not implementation: test observable behaviour, not internal call sequences.
- Coverage gate: ≥60% (`make coverage`).

## Security

- Never store raw tokens. Always encrypt with AES-256-GCM before writing to DB.
- Never log token values, even at debug level.
- Agent tokens: store SHA-256 hash only.
- `gosec` and `govulncheck` are blocking CI gates. Suppressions (`#nosec`) are not allowed.

## Git

- Commit messages: short imperative subject line, body only when non-obvious context is needed.
- One logical change per commit.
- End every commit message with:
  ```
  Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
  ```
