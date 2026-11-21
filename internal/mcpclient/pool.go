package mcpclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/JetManiack/mcp-proxy/internal/crypto"
	"github.com/JetManiack/mcp-proxy/internal/store"
	"github.com/JetManiack/mcp-proxy/internal/telemetry"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const reconcileInterval = 30 * time.Second

// ErrUpstreamUnreachable is returned by CallTool when a session cannot be
// established (wrong key, missing auth, network error). The agent should call
// upstream_status to diagnose the cause.
var ErrUpstreamUnreachable = errors.New("upstream unreachable")

// ErrUpstreamNotFound is returned by CallTool when the upstream_id is unknown.
var ErrUpstreamNotFound = errors.New("upstream not found")

// ErrToolDisabled is returned by CallTool when the tool has been disabled via the UI.
var ErrToolDisabled = errors.New("tool disabled")

// bearerTransport injects a Bearer token into every outgoing request.
type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	r2.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(r2)
}

type sessionKey struct {
	upstreamID uuid.UUID
	userID     uuid.UUID // uuid.Nil for non-per-user upstreams
}

type sessionEntry struct {
	session      *mcp.ClientSession
	tokenHash    [32]byte // SHA-256 of encrypted access token (zero for no-auth)
	upstreamName string
	authType     string
}

// UpstreamStatus describes the connectivity state of an upstream for one user.
type UpstreamStatus struct {
	UpstreamID   uuid.UUID
	UpstreamName string
	AuthType     string
	Status       string // "connected", "needs_auth", "unreachable", "pending_discovery"
	Error        string // non-empty when Status == "unreachable"
}

// Discoverer runs OAuth endpoint discovery for an upstream.
type Discoverer interface {
	Discover(ctx context.Context, id uuid.UUID) error
}

// Pool manages MCP client sessions for all configured upstreams.
type Pool struct {
	store      *store.Store
	encKey     []byte
	discoverer Discoverer // may be nil

	mu      sync.Mutex
	entries map[sessionKey]*sessionEntry

	// catalog caches the tool+resource catalog built during reconcile.
	// Populated after the first reconcile; nil before that.
	catalog atomic.Pointer[Catalog]

	// triggerCh signals the reconcile loop to run immediately.
	// Buffered (1) so callers never block; excess signals are coalesced.
	triggerCh chan struct{}
}

// NewPool creates a Pool.
func NewPool(s *store.Store, encKey []byte, discoverer Discoverer) *Pool {
	return &Pool{
		store:      s,
		encKey:     encKey,
		discoverer: discoverer,
		entries:    make(map[sessionKey]*sessionEntry),
		triggerCh:  make(chan struct{}, 1),
	}
}

// TriggerReconcile asks the reconcile loop to run on its next opportunity.
// It is non-blocking: if a trigger is already pending it is a no-op.
func (p *Pool) TriggerReconcile() {
	select {
	case p.triggerCh <- struct{}{}:
	default:
	}
}

// StartReconcileLoop runs a background goroutine that periodically:
//   - Runs OAuth discovery for any oauth2_authorization_code upstream whose
//     auth_endpoint is not yet populated.
//   - Attempts to connect to every upstream to verify reachability.
//
// It stops when ctx is cancelled.
func (p *Pool) StartReconcileLoop(ctx context.Context, discoverer Discoverer) {
	go func() {
		ticker := time.NewTicker(reconcileInterval)
		defer ticker.Stop()
		p.reconcile(ctx, discoverer) // run once immediately on start
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.reconcile(ctx, discoverer)
			case <-p.triggerCh:
				p.reconcile(ctx, discoverer)
			}
		}
	}()
}

func (p *Pool) reconcile(ctx context.Context, discoverer Discoverer) {
	upstreams, err := p.store.ListUpstreams(ctx)
	if err != nil {
		slog.Error("mcpclient: reconcile: list upstreams", "err", err)
		return
	}
	for _, up := range upstreams {
		if up.AuthType == "oauth2_authorization_code" && up.AuthEndpoint == "" {
			if err := discoverer.Discover(ctx, up.ID); err != nil {
				slog.Error("mcpclient: reconcile: discovery failed",
					"upstream", up.Name, "upstream_id", up.ID, "err", err)
				continue
			}
			slog.Info("mcpclient: reconcile: discovered upstream", "upstream", up.Name)
		}
	}
	// Re-list to pick up freshly discovered endpoints.
	upstreams, err = p.store.ListUpstreams(ctx)
	if err != nil {
		return
	}
	for _, up := range upstreams {
		if _, err := p.getSession(ctx, up, uuid.Nil); err != nil {
			// Not all upstreams have a shared session (oauth2 is per-user); skip those.
			if up.AuthType != "oauth2_authorization_code" {
				slog.Warn("mcpclient: reconcile: ping failed",
					"upstream", up.Name, "err", err)
				if errors.Is(err, crypto.ErrDecryptionFailed) {
					slog.Error("mcpclient: credential decryption failed — ENCRYPTION_KEY may have changed; re-enter credentials via the UI",
						"upstream", up.Name)
				}
			}
		}
	}

	// Refresh the shared tool/resource catalog so mcp_tool_search reflects the
	// current tool set without a live round-trip on every agent request.
	p.refreshCatalog(ctx)
}

// refreshCatalog rebuilds and caches the tool catalog for the shared (uuid.Nil)
// user. This covers all non-per-user upstreams (bearer, api_key, none, etc.).
// Per-user oauth2 sessions are excluded; they will add their tools when
// GetCatalog is called with a real userID.
func (p *Pool) refreshCatalog(ctx context.Context) {
	upstreams, err := p.store.ListUpstreams(ctx)
	if err != nil {
		return
	}
	var entries []*CatalogEntry
	for _, up := range upstreams {
		sess, err := p.getSession(ctx, up, uuid.Nil)
		if err != nil {
			continue
		}
		filters, _ := p.store.GetToolFilters(ctx, up.ID)
		for tool, err := range sess.Tools(ctx, nil) {
			if err != nil {
				slog.Warn("mcpclient: refreshCatalog: tools listing error", "upstream", up.Name, "err", err)
				break
			}
			if enabled, ok := filters[tool.Name]; ok && !enabled {
				continue
			}
			tc := *tool
			entries = append(entries, &CatalogEntry{
				Tool:         &tc,
				UpstreamID:   up.ID,
				UpstreamName: up.Name,
			})
		}
	}
	p.catalog.Store(NewCatalog(entries))
	slog.Debug("mcpclient: catalog refreshed", "tools", len(entries))
}

// NamespacedResource associates a resource with its upstream.
type NamespacedResource struct {
	Resource     mcp.Resource
	UpstreamID   uuid.UUID
	UpstreamName string
	// NamespacedURI is "upstream_name/original_path" (e.g. "docs-server/api-reference").
	NamespacedURI string
}

// ListUpstreamResources returns the resource list for one upstream on behalf of userID.
func (p *Pool) ListUpstreamResources(ctx context.Context, up *store.Upstream, userID uuid.UUID) ([]mcp.Resource, error) {
	sess, err := p.getSession(ctx, up, userID)
	if err != nil {
		return nil, err
	}
	var resources []mcp.Resource
	for r, err := range sess.Resources(ctx, nil) {
		if err != nil {
			return nil, err
		}
		resources = append(resources, *r)
	}
	return resources, nil
}

// ListAllResources returns all resources from all reachable upstreams, with namespaced URIs.
// Upstreams that are inaccessible (no token, unreachable) are silently skipped.
func (p *Pool) ListAllResources(ctx context.Context, userID uuid.UUID) ([]*NamespacedResource, error) {
	upstreams, err := p.store.ListUpstreams(ctx)
	if err != nil {
		return nil, fmt.Errorf("mcpclient: list upstreams: %w", err)
	}
	var out []*NamespacedResource
	for _, up := range upstreams {
		resources, err := p.ListUpstreamResources(ctx, up, userID)
		if err != nil {
			continue
		}
		for _, r := range resources {
			nr := &NamespacedResource{
				Resource:      r,
				UpstreamID:    up.ID,
				UpstreamName:  up.Name,
				NamespacedURI: up.Name + "/" + stripResourceScheme(r.URI),
			}
			out = append(out, nr)
		}
	}
	return out, nil
}

// ReadUpstreamResource reads a resource from the specified upstream.
func (p *Pool) ReadUpstreamResource(ctx context.Context, upstreamID uuid.UUID, userID uuid.UUID, uri string) (*mcp.ReadResourceResult, error) {
	up, err := p.store.GetUpstream(ctx, upstreamID)
	if err != nil {
		return nil, fmt.Errorf("mcpclient: get upstream: %w", err)
	}
	sess, err := p.getSession(ctx, up, userID)
	if err != nil {
		return nil, fmt.Errorf("mcpclient: session for upstream %s: %w", upstreamID, err)
	}
	res, err := sess.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
	if err != nil {
		return nil, fmt.Errorf("mcpclient: read resource %q from %s: %w", uri, upstreamID, err)
	}
	return res, nil
}

// stripResourceScheme removes "resource://" prefix if present.
func stripResourceScheme(uri string) string {
	const prefix = "resource://"
	if len(uri) > len(prefix) && uri[:len(prefix)] == prefix {
		return uri[len(prefix):]
	}
	return uri
}

// ListUpstreamTools returns the tool list for one upstream on behalf of userID.
// Returns an empty slice (not an error) when the session is unavailable.
func (p *Pool) ListUpstreamTools(ctx context.Context, up *store.Upstream, userID uuid.UUID) ([]mcp.Tool, error) {
	sess, err := p.getSession(ctx, up, userID)
	if err != nil {
		return nil, err
	}
	var tools []mcp.Tool
	for t, err := range sess.Tools(ctx, nil) {
		if err != nil {
			return nil, err
		}
		tools = append(tools, *t)
	}
	return tools, nil
}

// Close closes all cached sessions.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.entries {
		_ = e.session.Close()
	}
	p.entries = make(map[sessionKey]*sessionEntry)
}

// GetCatalog returns a searchable Catalog of tools available to userID.
//
// Non-per-user upstreams (bearer, api_key, none) are served from the in-memory
// cache built during the last reconcile cycle. Per-user oauth2 upstreams are
// queried live and their tools are merged on top of the cached entries.
//
// Upstreams that are inaccessible are silently skipped.
func (p *Pool) GetCatalog(ctx context.Context, userID uuid.UUID) (*Catalog, error) {
	cached := p.catalog.Load()

	// No cache yet (before first reconcile): fall back to a live query.
	if cached == nil {
		return p.getCatalogLive(ctx, userID)
	}

	// If the caller is the anonymous user, the cache is complete.
	if userID == uuid.Nil {
		return cached, nil
	}

	// For a real user, merge per-user oauth2 entries on top of the cache.
	upstreams, err := p.store.ListUpstreams(ctx)
	if err != nil {
		return cached, nil // degrade gracefully
	}
	extra := cached.All()
	for _, up := range upstreams {
		if up.AuthType != "oauth2_authorization_code" {
			continue
		}
		sess, err := p.getSession(ctx, up, userID)
		if err != nil {
			continue
		}
		filters, _ := p.store.GetToolFilters(ctx, up.ID)
		for tool, err := range sess.Tools(ctx, nil) {
			if err != nil {
				break
			}
			if enabled, ok := filters[tool.Name]; ok && !enabled {
				continue
			}
			tc := *tool
			extra = append(extra, &CatalogEntry{
				Tool:         &tc,
				UpstreamID:   up.ID,
				UpstreamName: up.Name,
			})
		}
	}
	return NewCatalog(extra), nil
}

// getCatalogLive builds the catalog by querying every upstream live (fallback
// used before the first reconcile cycle completes).
func (p *Pool) getCatalogLive(ctx context.Context, userID uuid.UUID) (*Catalog, error) {
	upstreams, err := p.store.ListUpstreams(ctx)
	if err != nil {
		return nil, fmt.Errorf("mcpclient: list upstreams: %w", err)
	}
	var entries []*CatalogEntry
	for _, up := range upstreams {
		sess, err := p.getSession(ctx, up, userID)
		if err != nil {
			continue
		}
		filters, _ := p.store.GetToolFilters(ctx, up.ID)
		for tool, err := range sess.Tools(ctx, nil) {
			if err != nil {
				break
			}
			if enabled, ok := filters[tool.Name]; ok && !enabled {
				continue
			}
			tc := *tool
			entries = append(entries, &CatalogEntry{
				Tool:         &tc,
				UpstreamID:   up.ID,
				UpstreamName: up.Name,
			})
		}
	}
	return NewCatalog(entries), nil
}

// CallTool calls the named tool on the given upstream on behalf of userID.
// If the session errors, it is invalidated so the next call reconnects.
func (p *Pool) CallTool(ctx context.Context, userID, upstreamID uuid.UUID, toolName string, args map[string]any) (*mcp.CallToolResult, error) {
	up, err := p.store.GetUpstream(ctx, upstreamID)
	if err != nil {
		return nil, fmt.Errorf("mcpclient: %w: %s: %w", ErrUpstreamNotFound, upstreamID, err)
	}
	// Enforce tool filter: a tool toggled off via the UI must not be callable.
	filters, _ := p.store.GetToolFilters(ctx, upstreamID)
	if enabled, ok := filters[toolName]; ok && !enabled {
		return nil, fmt.Errorf("mcpclient: %w: %q on upstream %q", ErrToolDisabled, toolName, up.Name)
	}
	sess, err := p.getSession(ctx, up, userID)
	if err != nil {
		return nil, fmt.Errorf("mcpclient: %w: upstream %q (%s): %w", ErrUpstreamUnreachable, up.Name, upstreamID, err)
	}
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      toolName,
		Arguments: args,
	})
	if err != nil {
		p.invalidate(upstreamID, userID)
		return nil, fmt.Errorf("mcpclient: call %q on %s: %w", toolName, upstreamID, err)
	}
	return res, nil
}

// UpstreamStatuses returns a status entry for every configured upstream.
func (p *Pool) UpstreamStatuses(ctx context.Context, userID uuid.UUID) ([]*UpstreamStatus, error) {
	upstreams, err := p.store.ListUpstreams(ctx)
	if err != nil {
		return nil, fmt.Errorf("mcpclient: list upstreams: %w", err)
	}

	out := make([]*UpstreamStatus, 0, len(upstreams))
	for _, up := range upstreams {
		st := &UpstreamStatus{
			UpstreamID:   up.ID,
			UpstreamName: up.Name,
			AuthType:     up.AuthType,
		}

		if up.AuthEndpoint == "" && up.AuthType == "oauth2_authorization_code" {
			st.Status = "pending_discovery"
			out = append(out, st)
			continue
		}

		if up.AuthType == "oauth2_authorization_code" {
			tok, err := p.store.GetUserToken(ctx, up.ID, userID)
			if err != nil || tok.Status != "authorized" {
				st.Status = "needs_auth"
				out = append(out, st)
				continue
			}
		}

		if _, err := p.getSession(ctx, up, userID); err != nil {
			st.Status = "unreachable"
			st.Error = err.Error()
		} else {
			st.Status = "connected"
		}
		out = append(out, st)
	}
	return out, nil
}

// getSession returns a cached session for (upstream, user), creating one if
// needed or if the access token has changed since the last connection.
// The lock is released before the network connect to avoid holding it during I/O.
// On a race (two goroutines connecting simultaneously), the first one to store wins
// and the other closes its session.
func (p *Pool) getSession(ctx context.Context, up *store.Upstream, userID uuid.UUID) (*mcp.ClientSession, error) {
	var (
		accessToken string
		tokenHash   [32]byte
		key         sessionKey
	)

	switch up.AuthType {
	case "oauth2_authorization_code":
		tok, err := p.store.GetUserToken(ctx, up.ID, userID)
		if err != nil {
			return nil, fmt.Errorf("get user token: %w", err)
		}
		if tok.Status != "authorized" {
			return nil, fmt.Errorf("token status %q for upstream %s", tok.Status, up.ID)
		}
		tokenHash = sha256.Sum256(tok.AccessToken)
		key = sessionKey{upstreamID: up.ID, userID: userID}

		plain, err := crypto.Decrypt(p.encKey, tok.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("decrypt access token: %w", err)
		}
		accessToken = string(plain)
	case "bearer_static":
		cred, err := p.store.GetCredential(ctx, up.ID)
		if err != nil {
			return nil, fmt.Errorf("bearer_static: get credential: %w", err)
		}
		plain, err := crypto.Decrypt(p.encKey, cred.Data)
		if err != nil {
			return nil, fmt.Errorf("bearer_static: decrypt credential: %w", err)
		}
		accessToken = string(plain)
		tokenHash = sha256.Sum256(cred.Data) // change detector: rotated token → reconnect
		key = sessionKey{upstreamID: up.ID, userID: uuid.Nil}
	default:
		key = sessionKey{upstreamID: up.ID, userID: uuid.Nil}
	}

	// Fast path: cached session with matching token.
	p.mu.Lock()
	if e, ok := p.entries[key]; ok && e.tokenHash == tokenHash {
		sess := e.session
		p.mu.Unlock()
		return sess, nil
	}
	// Remove stale entry before releasing the lock.
	var old *sessionEntry
	if e, ok := p.entries[key]; ok {
		old = e
		delete(p.entries, key)
	}
	p.mu.Unlock()

	// Close old session outside the lock.
	if old != nil {
		_ = old.session.Close()
	}

	// Build HTTP client with optional Bearer token.
	var httpClient *http.Client
	if accessToken != "" {
		httpClient = &http.Client{
			Transport: &bearerTransport{base: http.DefaultTransport, token: accessToken},
		}
	} else {
		httpClient = http.DefaultClient
	}

	client := mcp.NewClient(
		&mcp.Implementation{Name: "mcp-proxy", Version: "v0.1.0"},
		nil,
	)
	transport := &mcp.StreamableClientTransport{
		Endpoint:             up.URL,
		HTTPClient:           httpClient,
		DisableStandaloneSSE: true,
	}

	sess, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", up.URL, err)
	}
	slog.Info("mcpclient: session connected", "upstream", up.Name, "auth_type", up.AuthType)

	// Store the new session, handling a potential race with another goroutine.
	p.mu.Lock()
	if _, ok := p.entries[key]; ok {
		// Another goroutine stored a session first; close ours.
		p.mu.Unlock()
		_ = sess.Close()
		p.mu.Lock()
	}
	if _, ok := p.entries[key]; !ok {
		p.entries[key] = &sessionEntry{
			session:      sess,
			tokenHash:    tokenHash,
			upstreamName: up.Name,
			authType:     up.AuthType,
		}
		telemetry.SessionsActive.WithLabelValues(up.Name, up.AuthType).Inc()
	} else {
		sess = p.entries[key].session
	}
	p.mu.Unlock()

	return sess, nil
}

// invalidate closes and removes the cached session for (upstreamID, userID).
func (p *Pool) invalidate(upstreamID, userID uuid.UUID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := sessionKey{upstreamID: upstreamID, userID: userID}
	if e, ok := p.entries[key]; ok {
		_ = e.session.Close()
		delete(p.entries, key)
		telemetry.SessionsActive.WithLabelValues(e.upstreamName, e.authType).Dec()
	}
}
