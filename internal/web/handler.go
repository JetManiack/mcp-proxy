package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/JetManiack/mcp-proxy/internal/auth"
	"github.com/JetManiack/mcp-proxy/internal/mcpclient"
	"github.com/JetManiack/mcp-proxy/internal/store"
	"github.com/JetManiack/mcp-proxy/internal/upstream"
	"github.com/google/uuid"
)

// Handler holds the web UI dependencies.
type Handler struct {
	store    *store.Store
	registry *upstream.Registry
	oauth    *upstream.Manager
	pool     *mcpclient.Pool // may be nil in tests
}

// New creates a Handler.
func New(s *store.Store, reg *upstream.Registry, mgr *upstream.Manager, pool *mcpclient.Pool) *Handler {
	return &Handler{store: s, registry: reg, oauth: mgr, pool: pool}
}

// oauthClientMetadata serves the RFC 9728 §2.2 client metadata document.
// The document URL is used as the OAuth2 client_id when the upstream's AS
// supports client_id_metadata_document_supported (no DCR registration needed).
func (h *Handler) oauthClientMetadata(w http.ResponseWriter, r *http.Request) {
	if h.oauth == nil {
		http.NotFound(w, r)
		return
	}
	meta := map[string]any{
		"client_id":                  h.oauth.ClientMetadataURL(),
		"client_name":                "mcp-proxy",
		"redirect_uris":              []string{h.oauth.CallbackURL()},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meta)
}

// Routes returns an http.Handler covering all web UI and OAuth endpoints.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/ui/upstreams", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("GET /health/alive", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok")
	})

	// OAuth callback — no auth required (redirected from external auth server).
	mux.HandleFunc("GET /oauth/callback", h.oauthCallback)
	mux.HandleFunc("GET /oauth/client-metadata", h.oauthClientMetadata)

	// Web UI — requires auth middleware added by the caller.
	mux.HandleFunc("GET /ui/upstreams", h.listUpstreams)
	mux.HandleFunc("POST /ui/upstreams", h.createUpstream)
	mux.HandleFunc("GET /ui/upstreams/new", h.newUpstreamForm)
	mux.HandleFunc("GET /ui/upstreams/{id}", h.viewUpstream)
	mux.HandleFunc("POST /ui/upstreams/{id}/tools/{tool}", h.toggleTool)
	mux.HandleFunc("POST /ui/upstreams/{id}/credential", h.setCredential)
	mux.HandleFunc("POST /ui/upstreams/{id}/auth", h.beginAuth)
	mux.HandleFunc("POST /ui/upstreams/{id}/delete", h.deleteUpstream)

	mux.HandleFunc("GET /ui/tokens", h.listTokens)
	mux.HandleFunc("POST /ui/tokens", h.createToken)
	mux.HandleFunc("POST /ui/tokens/{id}/delete", h.deleteToken)

	return mux
}

// ---- upstream handlers ------------------------------------------------------

// UpstreamRow pairs an upstream record with its live status for the template.
type UpstreamRow struct {
	*store.Upstream
	Status string // "connected" | "needs_auth" | "unreachable" | "pending_discovery" | ""
	Error  string
}

func (h *Handler) listUpstreams(w http.ResponseWriter, r *http.Request) {
	upstreams, err := h.store.ListUpstreams(r.Context())
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	// Build a status index if pool is available.
	statusByID := map[uuid.UUID]*mcpclient.UpstreamStatus{}
	if h.pool != nil {
		user, _ := currentUser(r, h.store)
		userID := uuid.Nil
		if user != nil {
			userID = user.ID
		}
		if ss, err := h.pool.UpstreamStatuses(r.Context(), userID); err == nil {
			for _, s := range ss {
				statusByID[s.UpstreamID] = s
			}
		}
	}
	rows := make([]UpstreamRow, len(upstreams))
	for i, up := range upstreams {
		row := UpstreamRow{Upstream: up}
		if s, ok := statusByID[up.ID]; ok {
			row.Status = s.Status
			row.Error = s.Error
		}
		rows[i] = row
	}
	renderTemplate(w, r, listUpstreamsTmpl, map[string]any{"Upstreams": rows})
}

func (h *Handler) newUpstreamForm(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, r, newUpstreamTmpl, nil)
}

func (h *Handler) createUpstream(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpError(w, err, http.StatusBadRequest)
		return
	}
	up := &store.Upstream{
		Name:     strings.TrimSpace(r.FormValue("name")),
		URL:      strings.TrimSpace(r.FormValue("url")),
		AuthType: strings.TrimSpace(r.FormValue("auth_type")),
	}
	if up.Name == "" || up.URL == "" {
		httpError(w, fmt.Errorf("name and url are required"), http.StatusBadRequest)
		return
	}
	if err := upstream.ValidateUpstreamURL(up.URL); err != nil {
		httpError(w, err, http.StatusBadRequest)
		return
	}
	// Auto-detect auth type from server response headers.
	if up.AuthType == "" || up.AuthType == "auto" {
		probed, err := h.registry.Probe(r.Context(), up.URL)
		if err != nil {
			httpError(w, fmt.Errorf("probe upstream: %w", err), http.StatusBadGateway)
			return
		}
		up.AuthType = probed.AuthType
		if err := h.registry.Create(r.Context(), up); err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		if probed.Meta != nil {
			if err := h.registry.StoreDiscovered(r.Context(), up.ID, probed.Meta); err != nil {
				_ = h.store.DeleteUpstream(r.Context(), up.ID)
				httpError(w, fmt.Errorf("store discovered endpoints: %w", err), http.StatusInternalServerError)
				return
			}
		}
	} else {
		if err := h.registry.Create(r.Context(), up); err != nil {
			httpError(w, err, http.StatusInternalServerError)
			return
		}
		if up.AuthType == "oauth2_authorization_code" {
			if err := h.registry.Discover(r.Context(), up.ID); err != nil {
				_ = h.store.DeleteUpstream(r.Context(), up.ID)
				httpError(w, fmt.Errorf("OAuth discovery failed: %w", err), http.StatusBadGateway)
				return
			}
		}
	}
	if up.AuthType == "bearer_static" {
		token := strings.TrimSpace(r.FormValue("static_token"))
		if token == "" {
			_ = h.store.DeleteUpstream(r.Context(), up.ID)
			httpError(w, fmt.Errorf("static_token is required for bearer_static auth"), http.StatusBadRequest)
			return
		}
		if err := h.oauth.SetStaticCredential(r.Context(), up.ID, token); err != nil {
			_ = h.store.DeleteUpstream(r.Context(), up.ID)
			httpError(w, fmt.Errorf("store token: %w", err), http.StatusInternalServerError)
			return
		}
	}
	if h.pool != nil {
		h.pool.TriggerReconcile()
	}
	http.Redirect(w, r, "/ui/upstreams", http.StatusSeeOther)
}

func (h *Handler) viewUpstream(w http.ResponseWriter, r *http.Request) {
	up, ok := h.upstreamFromPath(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Upstream": up}
	if h.pool != nil {
		user, _ := currentUser(r, h.store)
		userID := uuid.Nil
		if user != nil {
			userID = user.ID
		}
		statuses, err := h.pool.UpstreamStatuses(r.Context(), userID)
		if err == nil {
			for _, s := range statuses {
				if s.UpstreamID == up.ID {
					data["Status"] = s
					break
				}
			}
		}
		if st, ok := data["Status"].(*mcpclient.UpstreamStatus); ok && st.Status == "connected" {
			tools, err := h.pool.ListUpstreamTools(r.Context(), up, userID)
			if err == nil {
				filters, _ := h.store.GetToolFilters(r.Context(), up.ID)
				type ToolRow struct {
					Name        string
					Description string
					Enabled     bool
				}
				rows := make([]ToolRow, len(tools))
				for i, t := range tools {
					enabled := true
					if v, ok := filters[t.Name]; ok {
						enabled = v
					}
					rows[i] = ToolRow{Name: t.Name, Description: t.Description, Enabled: enabled}
				}
				data["Tools"] = rows
			}
			resources, err := h.pool.ListUpstreamResources(r.Context(), up, userID)
			if err == nil && len(resources) > 0 {
				type ResourceRow struct {
					URI         string
					Name        string
					Description string
					MIMEType    string
				}
				rows := make([]ResourceRow, len(resources))
				for i, res := range resources {
					rows[i] = ResourceRow{
						URI:         res.URI,
						Name:        res.Name,
						Description: res.Description,
						MIMEType:    res.MIMEType,
					}
				}
				data["Resources"] = rows
			}
		}
	}
	renderTemplate(w, r, viewUpstreamTmpl, data)
}

func (h *Handler) toggleTool(w http.ResponseWriter, r *http.Request) {
	up, ok := h.upstreamFromPath(w, r)
	if !ok {
		return
	}
	toolName := r.PathValue("tool")
	if toolName == "" {
		httpError(w, fmt.Errorf("tool name required"), http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		httpError(w, err, http.StatusBadRequest)
		return
	}
	enabled := r.FormValue("enabled") == "1"
	if err := h.store.SetToolEnabled(r.Context(), up.ID, toolName, enabled); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if r.Header.Get("Accept") == "application/json" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/ui/upstreams/"+up.ID.String(), http.StatusSeeOther)
}

func (h *Handler) beginAuth(w http.ResponseWriter, r *http.Request) {
	up, ok := h.upstreamFromPath(w, r)
	if !ok {
		return
	}
	// OAuth2 tokens are shared — the authorizing user's identity doesn't matter,
	// the resulting token covers all agents.
	redirectURL, _, err := h.oauth.BeginAuth(r.Context(), up.ID, uuid.Nil)
	if err != nil {
		httpError(w, fmt.Errorf("begin auth: %w", err), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *Handler) setCredential(w http.ResponseWriter, r *http.Request) {
	up, ok := h.upstreamFromPath(w, r)
	if !ok {
		return
	}
	if up.AuthType != "bearer_static" {
		httpError(w, fmt.Errorf("credential update only supported for bearer_static upstreams"), http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(r.FormValue("static_token"))
	if token == "" {
		httpError(w, fmt.Errorf("static_token is required"), http.StatusBadRequest)
		return
	}
	if err := h.oauth.SetStaticCredential(r.Context(), up.ID, token); err != nil {
		httpError(w, fmt.Errorf("store token: %w", err), http.StatusInternalServerError)
		return
	}
	if h.pool != nil {
		h.pool.TriggerReconcile()
	}
	http.Redirect(w, r, "/ui/upstreams/"+up.ID.String(), http.StatusSeeOther)
}

func (h *Handler) deleteUpstream(w http.ResponseWriter, r *http.Request) {
	up, ok := h.upstreamFromPath(w, r)
	if !ok {
		return
	}
	if err := h.registry.Delete(r.Context(), up.ID); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	if h.pool != nil {
		h.pool.TriggerReconcile()
	}
	http.Redirect(w, r, "/ui/upstreams", http.StatusSeeOther)
}

func (h *Handler) oauthCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		httpError(w, fmt.Errorf("missing state or code"), http.StatusBadRequest)
		return
	}
	if err := h.oauth.CompleteAuth(r.Context(), state, code); err != nil {
		httpError(w, fmt.Errorf("complete auth: %w", err), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/ui/upstreams", http.StatusSeeOther)
}

// ---- token handlers ---------------------------------------------------------

func (h *Handler) listTokens(w http.ResponseWriter, r *http.Request) {
	user, err := currentUser(r, h.store)
	if err != nil {
		httpError(w, err, http.StatusUnauthorized)
		return
	}
	tokens, err := h.store.ListAgentTokens(r.Context(), user.ID)
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	renderTemplate(w, r, listTokensTmpl, map[string]any{"Tokens": tokens})
}

func (h *Handler) createToken(w http.ResponseWriter, r *http.Request) {
	user, err := currentUser(r, h.store)
	if err != nil {
		httpError(w, err, http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		httpError(w, err, http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		httpError(w, fmt.Errorf("token name is required"), http.StatusBadRequest)
		return
	}

	raw, hash, err := generateAgentToken()
	if err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}

	tok := &store.AgentToken{
		Name:      name,
		TokenHash: hash,
		UserID:    user.ID,
	}
	if err := h.store.CreateAgentToken(r.Context(), tok); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	renderTemplate(w, r, createdTokenTmpl, map[string]any{"Token": raw, "Name": name})
}

func (h *Handler) deleteToken(w http.ResponseWriter, r *http.Request) {
	user, err := currentUser(r, h.store)
	if err != nil {
		httpError(w, err, http.StatusUnauthorized)
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		httpError(w, fmt.Errorf("invalid token id"), http.StatusBadRequest)
		return
	}
	if err := h.store.DeleteAgentToken(r.Context(), id, user.ID); err != nil {
		httpError(w, err, http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/ui/tokens", http.StatusSeeOther)
}

// ---- helpers ----------------------------------------------------------------

func (h *Handler) upstreamFromPath(w http.ResponseWriter, r *http.Request) (*store.Upstream, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpError(w, fmt.Errorf("invalid upstream id"), http.StatusBadRequest)
		return nil, false
	}
	up, err := h.store.GetUpstream(r.Context(), id)
	if err != nil {
		if store.IsNotFound(err) {
			http.NotFound(w, r)
		} else {
			httpError(w, err, http.StatusInternalServerError)
		}
		return nil, false
	}
	return up, true
}

// currentUser resolves the authenticated identity from request headers to a
// store.User, creating one if this is the first login.
func currentUser(r *http.Request, s *store.Store) (*store.User, error) {
	id, ok := auth.IdentityFromContext(r.Context())
	if !ok || id.Email == "" {
		return nil, fmt.Errorf("no authenticated identity in context")
	}
	return s.FindOrCreateUser(r.Context(), id.Email, id.Email)
}

func httpError(w http.ResponseWriter, err error, code int) {
	if code >= 500 {
		slog.Error("http handler error", "code", code, "err", err)
		http.Error(w, http.StatusText(code), code)
		return
	}
	http.Error(w, err.Error(), code)
}

func renderTemplate(w http.ResponseWriter, r *http.Request, tmpl string, data any) {
	// Always inject the CSRF token so templates can embed it without individual
	// handlers having to pass it explicitly.
	m, ok := data.(map[string]any)
	if !ok || m == nil {
		m = make(map[string]any)
	}
	m["CSRFToken"] = csrfTokenFromContext(r.Context())

	t, err := template.New("base").Parse(baseTmpl)
	if err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err = t.New("page").Parse(tmpl); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, m); err != nil {
		fmt.Fprintf(w, "\n<!-- render error: %v -->", err)
	}
}
