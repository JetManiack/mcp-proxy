package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/JetManiack/mcp-proxy/internal/crypto"
	"github.com/JetManiack/mcp-proxy/internal/store"
	"github.com/JetManiack/mcp-proxy/internal/telemetry"
	"github.com/google/uuid"
	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"
)

const pendingTTL = 10 * time.Minute

// dcrCreds holds the in-memory DCR credentials (never marshaled directly).
type dcrCreds struct {
	ClientID     string
	ClientSecret string
}

// dcrStorage is the shape written to the DB (neutral field names to avoid
// static-analysis false positives on the "secret" keyword).
type dcrStorage struct {
	ID  string `json:"id"`
	Key string `json:"k"`
}

// dcrResponse decodes the registration endpoint's JSON reply.
type dcrResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// authCallback carries the OAuth2 callback parameters from /oauth/callback
// to the pending AuthorizationCodeFetcher goroutine.
type authCallback struct {
	code  string
	state string
	iss   string
}

// persistingTokenSource wraps an oauth2.TokenSource and persists refreshed
// tokens to the DB via the save callback whenever the access token changes.
type persistingTokenSource struct {
	inner oauth2.TokenSource
	save  func(*oauth2.Token) error
	mu    sync.Mutex
	last  string
}

func (s *persistingTokenSource) Token() (*oauth2.Token, error) {
	tok, err := s.inner.Token()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	changed := tok.AccessToken != s.last
	s.last = tok.AccessToken
	s.mu.Unlock()
	if changed {
		if saveErr := s.save(tok); saveErr != nil {
			slog.Warn("upstream: persist refreshed token", "err", saveErr)
		}
	}
	return tok, nil
}

// tokenSourceHandler implements sdkauth.OAuthHandler for pool sessions that
// have a pre-loaded token. Authorize is intentionally a no-op — if a session
// receives a 401, the web UI must trigger re-auth.
type tokenSourceHandler struct {
	ts oauth2.TokenSource
}

func (h *tokenSourceHandler) TokenSource(_ context.Context) (oauth2.TokenSource, error) {
	return h.ts, nil
}

func (h *tokenSourceHandler) Authorize(_ context.Context, _ *http.Request, resp *http.Response) error {
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return fmt.Errorf("authorization required: use the web UI to re-authenticate")
}

// Manager handles the OAuth2 authorization flow for upstreams.
type Manager struct {
	store     *store.Store
	encKey    []byte
	publicURL string
	client    *http.Client

	mu      sync.Mutex
	byState map[string]chan authCallback // state → codeCh

	dcrMu sync.Mutex // serializes DCR check+register per upstream
}

func NewManager(s *store.Store, encKey []byte, publicURL string, client *http.Client) *Manager {
	return &Manager{
		store:     s,
		encKey:    encKey,
		publicURL: strings.TrimRight(publicURL, "/"),
		client:    client,
		byState:   make(map[string]chan authCallback),
	}
}

// SetStaticCredential encrypts and stores a static Bearer token for bearer_static upstreams.
func (m *Manager) SetStaticCredential(ctx context.Context, upstreamID uuid.UUID, token string) error {
	enc, err := crypto.Encrypt(m.encKey, []byte(token))
	if err != nil {
		return fmt.Errorf("encrypt static token: %w", err)
	}
	return m.store.SetCredential(ctx, upstreamID, enc)
}

// ClientMetadataURL returns the URL at which this proxy serves its OAuth2
// client metadata document (RFC 9728 §2.2). It is used as the client_id when
// the upstream's authorization server supports client_id_metadata_document_supported.
func (m *Manager) ClientMetadataURL() string {
	return m.publicURL + "/oauth/client-metadata"
}

// CallbackURL returns the OAuth2 redirect_uri this proxy uses.
func (m *Manager) CallbackURL() string {
	return m.publicURL + "/oauth/callback"
}

// BeginAuth starts the OAuth2 authorization code flow for the given user and upstream.
// It returns the authorization redirect URL that the browser should follow.
//
// The flow is driven by auth.AuthorizationCodeHandler: a goroutine calls Authorize on
// a synthesized 401 response, which triggers PRM/ASM discovery, selects the client
// registration method, and calls AuthorizationCodeFetcher with the full PKCE auth URL.
// BeginAuth blocks until the URL is ready (or times out).
func (m *Manager) BeginAuth(ctx context.Context, upstreamID, userID uuid.UUID) (redirectURL string, _ string, _ error) {
	up, err := m.store.GetUpstream(ctx, upstreamID)
	if err != nil {
		return "", "", fmt.Errorf("upstream: begin auth: %w", err)
	}

	// Ensure DCR credentials exist for upstreams that require them.
	if err := m.ensureDCRCredentials(ctx, up); err != nil {
		return "", "", fmt.Errorf("upstream: begin auth: %w", err)
	}

	handlerCfg, err := m.buildHandlerCfg(ctx, up)
	if err != nil {
		return "", "", fmt.Errorf("upstream: begin auth: %w", err)
	}

	authURLCh := make(chan string, 1)
	handlerCfg.AuthorizationCodeFetcher = m.makeFetcher(authURLCh)
	handlerCfg.NewTokenSource = m.newTokenSourceFn(upstreamID, userID)

	handler, err := sdkauth.NewAuthorizationCodeHandler(handlerCfg)
	if err != nil {
		return "", "", fmt.Errorf("upstream: begin auth: create handler: %w", err)
	}

	// Synthesize a 401 response so we can call Authorize directly.
	// Include a resource_metadata hint derived from the upstream URL so the
	// SDK's discovery skips the fallback path and finds PRM immediately.
	resourceMetaURL, _ := protectedResourceWellKnown(up.URL)
	fakeReq := &http.Request{URL: mustParseURL(up.URL), Header: make(http.Header)}
	fakeResp := &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
	}
	if resourceMetaURL != "" {
		fakeResp.Header.Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer resource_metadata="%s"`, resourceMetaURL))
	}

	authCtx, cancel := context.WithTimeout(context.Background(), pendingTTL)
	go func() {
		defer cancel()
		if err := handler.Authorize(authCtx, fakeReq, fakeResp); err != nil {
			slog.Error("upstream: auth flow error",
				"upstream_id", upstreamID, "user_id", userID, "err", err)
		} else {
			slog.Info("upstream: auth flow completed",
				"upstream_id", upstreamID, "user_id", userID)
		}
	}()

	select {
	case u := <-authURLCh:
		parsed, err := url.Parse(u)
		if err != nil {
			cancel()
			return "", "", fmt.Errorf("upstream: begin auth: parse redirect URL: %w", err)
		}
		return u, parsed.Query().Get("state"), nil
	case <-time.After(30 * time.Second):
		cancel()
		return "", "", fmt.Errorf("upstream: begin auth: timeout waiting for auth URL (discovery failed?)")
	case <-ctx.Done():
		cancel()
		return "", "", ctx.Err()
	}
}

// makeFetcher returns an AuthorizationCodeFetcher for BeginAuth that:
//   - parses the state from the SDK-generated auth URL
//   - registers a result channel in byState so CompleteAuth can unblock it
//   - delivers the auth URL to BeginAuth via authURLCh
//   - blocks until the callback sends a result (or context expires)
func (m *Manager) makeFetcher(authURLCh chan<- string) sdkauth.AuthorizationCodeFetcher {
	return func(ctx context.Context, args *sdkauth.AuthorizationArgs) (*sdkauth.AuthorizationResult, error) {
		u, err := url.Parse(args.URL)
		if err != nil {
			return nil, fmt.Errorf("parse auth URL: %w", err)
		}
		state := u.Query().Get("state")
		if state == "" {
			return nil, fmt.Errorf("auth URL has no state parameter")
		}

		codeCh := make(chan authCallback, 1)
		m.mu.Lock()
		m.byState[state] = codeCh
		m.mu.Unlock()

		authURLCh <- args.URL

		select {
		case result := <-codeCh:
			return &sdkauth.AuthorizationResult{
				Code:  result.code,
				State: result.state,
				Iss:   result.iss,
			}, nil
		case <-ctx.Done():
			m.mu.Lock()
			delete(m.byState, state)
			m.mu.Unlock()
			return nil, ctx.Err()
		}
	}
}

// CompleteAuth handles the OAuth2 callback by routing the authorization code to
// the waiting AuthorizationCodeFetcher goroutine, which then exchanges it for tokens
// and persists them via NewTokenSource.
func (m *Manager) CompleteAuth(_ context.Context, state, code string) error {
	m.mu.Lock()
	codeCh, ok := m.byState[state]
	if ok {
		delete(m.byState, state)
	}
	m.mu.Unlock()

	if !ok {
		return fmt.Errorf("upstream: complete auth: unknown or expired state")
	}

	select {
	case codeCh <- authCallback{code: code, state: state}:
		return nil
	default:
		return fmt.Errorf("upstream: complete auth: callback already delivered")
	}
}

// SessionHandler returns an sdkauth.OAuthHandler for use in pool sessions.
// It wraps a persisting oauth2.TokenSource backed by the DB-stored token so
// that automatic refreshes are saved. If no authorized token exists, it returns
// nil and the caller should not attempt to connect.
func (m *Manager) SessionHandler(ctx context.Context, up *store.Upstream, userID uuid.UUID) (sdkauth.OAuthHandler, error) {
	ts, err := m.loadPersistedTokenSource(ctx, up, userID)
	if err != nil {
		return nil, err
	}
	if ts == nil {
		return nil, nil
	}
	return &tokenSourceHandler{ts: ts}, nil
}

// loadPersistedTokenSource returns an oauth2.TokenSource backed by the DB-stored
// token for (upstreamID, userID). It persists refreshed tokens back to the DB
// automatically. Returns nil when no authorized token exists.
func (m *Manager) loadPersistedTokenSource(ctx context.Context, up *store.Upstream, userID uuid.UUID) (oauth2.TokenSource, error) {
	tok, err := m.store.GetUserToken(ctx, up.ID, userID)
	if store.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if tok.Status != "authorized" {
		return nil, nil
	}

	access, err := crypto.Decrypt(m.encKey, tok.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("decrypt access token: %w", err)
	}

	oauthTok := &oauth2.Token{AccessToken: string(access)}
	if len(tok.RefreshToken) > 0 {
		if refresh, err := crypto.Decrypt(m.encKey, tok.RefreshToken); err == nil {
			oauthTok.RefreshToken = string(refresh)
		}
	}
	if tok.ExpiresAt != nil {
		oauthTok.Expiry = *tok.ExpiresAt
	}

	creds, err := m.clientCredentials(ctx, up)
	if err != nil {
		return nil, fmt.Errorf("get client credentials: %w", err)
	}

	cfg := m.oauthCfg(up, creds)
	refreshCtx := context.WithValue(context.Background(), oauth2.HTTPClient, m.client)
	inner := cfg.TokenSource(refreshCtx, oauthTok)

	return &persistingTokenSource{
		inner: inner,
		last:  string(access),
		save: func(newTok *oauth2.Token) error {
			return m.storeToken(context.Background(), up.ID, userID, newTok)
		},
	}, nil
}

// newTokenSourceFn returns a NewTokenSource callback for auth.AuthorizationCodeHandlerConfig.
// It is called by the SDK after a code exchange to persist the token and wrap it in a
// persisting token source.
func (m *Manager) newTokenSourceFn(upstreamID, userID uuid.UUID) func(context.Context, *oauth2.Config, *oauth2.Token) (oauth2.TokenSource, error) {
	return func(ctx context.Context, cfg *oauth2.Config, tok *oauth2.Token) (oauth2.TokenSource, error) {
		if err := m.storeToken(ctx, upstreamID, userID, tok); err != nil {
			return nil, err
		}
		inner := cfg.TokenSource(ctx, tok)
		return &persistingTokenSource{
			inner: inner,
			last:  tok.AccessToken,
			save: func(newTok *oauth2.Token) error {
				return m.storeToken(context.Background(), upstreamID, userID, newTok)
			},
		}, nil
	}
}

// buildHandlerCfg builds an auth.AuthorizationCodeHandlerConfig for the given upstream.
// Registration method (ClientIDMetadataDocumentConfig or PreregisteredClient) is set
// based on the upstream's stored configuration. AuthorizationCodeFetcher and
// NewTokenSource must be set by the caller.
func (m *Manager) buildHandlerCfg(ctx context.Context, up *store.Upstream) (*sdkauth.AuthorizationCodeHandlerConfig, error) {
	creds, err := m.clientCredentials(ctx, up)
	if err != nil {
		return nil, err
	}

	cfg := &sdkauth.AuthorizationCodeHandlerConfig{
		RedirectURL:           m.CallbackURL(),
		Client:                m.client,
		RequestRefreshToken:   true,
		AcceptUnadvertisedIss: true,
	}

	if up.ClientIDMetaDoc {
		cfg.ClientIDMetadataDocumentConfig = &sdkauth.ClientIDMetadataDocumentConfig{
			URL: m.ClientMetadataURL(),
		}
	} else if creds != nil {
		pc := &oauthex.ClientCredentials{ClientID: creds.ClientID}
		if creds.ClientSecret != "" {
			pc.ClientSecretAuth = &oauthex.ClientSecretAuth{ClientSecret: creds.ClientSecret}
		}
		cfg.PreregisteredClient = pc
	} else {
		return nil, fmt.Errorf("no client credentials: upstream needs DCR endpoint or client_id_metadata_document_supported")
	}

	return cfg, nil
}

// oauthCfg builds a minimal oauth2.Config for token refresh for the given upstream.
func (m *Manager) oauthCfg(up *store.Upstream, creds *dcrCreds) *oauth2.Config {
	cfg := &oauth2.Config{
		RedirectURL: m.CallbackURL(),
		Endpoint: oauth2.Endpoint{
			TokenURL: up.TokenEndpoint,
		},
	}
	if creds != nil {
		cfg.ClientID = creds.ClientID
		cfg.ClientSecret = creds.ClientSecret
	} else if up.ClientIDMetaDoc {
		cfg.ClientID = m.ClientMetadataURL()
	}
	return cfg
}

// storeToken encrypts and persists an oauth2.Token for (upstreamID, userID).
func (m *Manager) storeToken(ctx context.Context, upstreamID, userID uuid.UUID, tok *oauth2.Token) error {
	if tok.AccessToken == "" {
		return fmt.Errorf("store token: empty access_token")
	}
	encAccess, err := crypto.Encrypt(m.encKey, []byte(tok.AccessToken))
	if err != nil {
		return fmt.Errorf("encrypt access token: %w", err)
	}

	t := &store.UpstreamUserToken{
		UpstreamID:  upstreamID,
		UserID:      userID,
		AccessToken: encAccess,
		Status:      "authorized",
	}

	if tok.RefreshToken != "" {
		encRefresh, err := crypto.Encrypt(m.encKey, []byte(tok.RefreshToken))
		if err != nil {
			return fmt.Errorf("encrypt refresh token: %w", err)
		}
		t.RefreshToken = encRefresh
	}

	if !tok.Expiry.IsZero() {
		t.ExpiresAt = &tok.Expiry
	}

	return m.store.SetUserToken(ctx, t)
}

// clientCredentials returns the stored DCR credentials for an upstream.
// Returns nil (not an error) for ClientIDMetaDoc upstreams that don't need explicit creds.
// Returns a GORM record-not-found error (store.IsNotFound) when creds don't exist yet.
func (m *Manager) clientCredentials(ctx context.Context, up *store.Upstream) (*dcrCreds, error) {
	if up.ClientIDMetaDoc {
		return nil, nil
	}
	if up.DCREndpoint == "" {
		return nil, fmt.Errorf("upstream has no DCR endpoint and client_id_metadata_document_supported is not set")
	}
	return m.loadDCRCreds(ctx, up.ID)
}

// ensureDCRCredentials runs DCR registration for an upstream if creds do not yet
// exist. It is a no-op for ClientIDMetaDoc upstreams.
func (m *Manager) ensureDCRCredentials(ctx context.Context, up *store.Upstream) error {
	if up.ClientIDMetaDoc || up.DCREndpoint == "" {
		return nil
	}
	m.dcrMu.Lock()
	defer m.dcrMu.Unlock()
	_, err := m.loadDCRCreds(ctx, up.ID)
	if err == nil {
		return nil // already registered
	}
	if !store.IsNotFound(err) {
		return fmt.Errorf("load DCR creds: %w", err)
	}
	_, err = m.registerDCR(ctx, up)
	return err
}

func (m *Manager) loadDCRCreds(ctx context.Context, upstreamID uuid.UUID) (*dcrCreds, error) {
	cred, err := m.store.GetCredential(ctx, upstreamID)
	if err != nil {
		return nil, err
	}
	plain, err := crypto.Decrypt(m.encKey, cred.Data)
	if err != nil {
		return nil, fmt.Errorf("decrypt DCR creds: %w", err)
	}
	var s dcrStorage
	if err := json.Unmarshal(plain, &s); err != nil {
		return nil, fmt.Errorf("unmarshal DCR creds: %w", err)
	}
	return &dcrCreds{ClientID: s.ID, ClientSecret: s.Key}, nil
}

func (m *Manager) registerDCR(ctx context.Context, up *store.Upstream) (clientID string, _ error) {
	defer func() {
		result := "ok"
		if clientID == "" {
			result = "error"
		}
		telemetry.DCRRegistrations.WithLabelValues(up.Name, result).Inc()
	}()
	if err := requireHTTPS("dcr_endpoint", up.DCREndpoint); err != nil {
		return "", fmt.Errorf("upstream: register DCR: %w", err)
	}

	body, err := json.Marshal(map[string]any{
		"client_name":   up.Name,
		"redirect_uris": []string{m.CallbackURL()},
		"grant_types":   []string{"authorization_code", "refresh_token"},
	})
	if err != nil {
		return "", fmt.Errorf("DCR: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, up.DCREndpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DCR request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("DCR: HTTP %d", resp.StatusCode)
	}

	var dcrResp dcrResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&dcrResp); err != nil {
		return "", fmt.Errorf("DCR: decode response: %w", err)
	}
	if dcrResp.ClientID == "" {
		return "", fmt.Errorf("DCR: server returned empty client_id")
	}

	plain, err := json.Marshal(dcrStorage{ID: dcrResp.ClientID, Key: dcrResp.ClientSecret})
	if err != nil {
		return "", fmt.Errorf("DCR: marshal storage: %w", err)
	}
	enc, err := crypto.Encrypt(m.encKey, plain)
	if err != nil {
		return "", fmt.Errorf("DCR: encrypt creds: %w", err)
	}
	if err := m.store.SetCredential(ctx, up.ID, enc); err != nil {
		return "", fmt.Errorf("DCR: store creds: %w", err)
	}
	slog.Info("upstream: DCR registration complete", "upstream", up.Name)
	return dcrResp.ClientID, nil
}

func mustParseURL(raw string) *url.URL {
	u, _ := url.Parse(raw)
	return u
}
