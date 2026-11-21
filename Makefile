BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ || echo "1970-01-01T00:00:00Z")
VERSION    ?= $(shell git describe --tags --long --always 2>/dev/null || echo "dev")
LDFLAGS    ?= -s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)

STATICCHECK_VERSION   := v0.8.2
GOSEC_VERSION         := v2.30.0
GOVULNCHECK_VERSION   := v1.1.4

# Where `go install` puts tool binaries. Resolving each tool through `command
# -v` with this as the fallback keeps targets working on machines that have
# never added GOPATH/bin to PATH.
GOPATH_BIN := $(shell go env GOPATH)/bin
tool = $$(command -v $(1) 2>/dev/null || echo $(GOPATH_BIN)/$(1))

# Derive the Go version from go.mod so installed tools are always built with
# a toolchain new enough to load this module's packages.
MODULE_GO_VERSION := $(shell go list -m -f '{{.GoVersion}}')
TOOL_GOTOOLCHAIN  := GOTOOLCHAIN=go$(MODULE_GO_VERSION)$(if $(word 3,$(subst ., ,$(MODULE_GO_VERSION))),,.0)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@echo "Available targets:" && echo && \
	awk 'BEGIN {FS = ":.*?## "}; /^[a-zA-Z0-9_\-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

# ---- Build -------------------------------------------------------------------

.PHONY: build
build: ## Build the binary into bin/mcp-proxy
	@mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/mcp-proxy ./cmd/mcp-proxy

# ---- Run ---------------------------------------------------------------------

.PHONY: run
run: ## Run locally (configure via config file or env vars, use ARGS="--flag=value" for extra flags)
	go run ./cmd/mcp-proxy $(ARGS)

# ---- Test --------------------------------------------------------------------

.PHONY: test
test: ## Run all tests with the race detector
	go test ./... -race -count=1

.PHONY: e2e
e2e: ## Run end-to-end tests (requires TEST_DATABASE_URL)
	go test ./test/e2e/... -v -race -count=1 -timeout=120s

.PHONY: coverage
coverage: ## Run tests and check coverage gate (≥60%)
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out | awk '/^total:/ { if ($$3+0 < 60) { print "Coverage too low: " $$3; exit 1 } }'
	rm coverage.out

# ---- Format & Vet ------------------------------------------------------------

.PHONY: fmt
fmt: ## Format all Go source files
	go fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail if any tracked .go file is not gofmt-formatted
	@unformatted="$$(gofmt -l $$(git ls-files '*.go'))"; \
	test -z "$$unformatted" || (echo "Unformatted files:"; echo "$$unformatted"; exit 1)

.PHONY: vet
vet: ## Run go vet
	go vet ./...

# ---- Lint --------------------------------------------------------------------

.PHONY: staticcheck
staticcheck: ## Run staticcheck (installed automatically if missing)
	@command -v staticcheck >/dev/null 2>&1 || \
		$(TOOL_GOTOOLCHAIN) go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	$(call tool,staticcheck) ./...

.PHONY: lint
lint: vet staticcheck ## Run vet + staticcheck

# ---- Security ----------------------------------------------------------------

.PHONY: govulncheck
govulncheck: ## Scan dependencies for known vulnerabilities (installed automatically if missing)
	@command -v govulncheck >/dev/null 2>&1 || \
		$(TOOL_GOTOOLCHAIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(call tool,govulncheck) ./...

.PHONY: gosec
gosec: ## Run gosec code-vulnerability scan (installed automatically if missing)
	@command -v gosec >/dev/null 2>&1 || \
		$(TOOL_GOTOOLCHAIN) go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	$(call tool,gosec) ./...

.PHONY: security
security: govulncheck gosec ## Run all security checks

# ---- Module consistency ------------------------------------------------------

.PHONY: mod-tidy
mod-tidy: ## Tidy go.mod/go.sum and fail if there are uncommitted changes
	go mod tidy
	git diff --exit-code -- go.mod $(shell [ -f go.sum ] && echo go.sum)

# ---- Container ---------------------------------------------------------------

.PHONY: container
container: ## Build the Docker image locally (not pushed)
	DOCKER_BUILDKIT=1 docker build \
	  --build-arg VERSION="$(VERSION)" \
	  --build-arg BUILD_TIME="$(BUILD_TIME)" \
	  -t mcp-proxy:local .

# ---- CI gate -----------------------------------------------------------------

.PHONY: ci
ci: build test lint security mod-tidy fmt-check ## Run all CI gates (same checks as the pipeline)

# ---- Misc --------------------------------------------------------------------

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin/ coverage.out
