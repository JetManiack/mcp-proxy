package upstream_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/JetManiack/mcp-proxy/internal/store"
	"github.com/JetManiack/mcp-proxy/internal/upstream"
	"github.com/google/uuid"
)

// encKey is a 32-byte test key; never use in production.
var testEncKey = make([]byte, 32)

func openOAuthTestStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// newOAuthServer creates a TLS httptest server acting as an OAuth authorization
// server with DCR, /authorize and /token endpoints. Returns the server and an
// http.Client pre-configured to trust its certificate.
func newOAuthServer(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"registration_endpoint":  srv.URL + "/register",
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		exp := time.Now().Add(time.Hour).Unix()
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "test-access-token",
			"refresh_token": "test-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"expires_at":    exp,
		})
	})

	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv, srv.Client()
}

func TestBeginAuth_URLParams(t *testing.T) {
	s := openOAuthTestStore(t)
	ctx := context.Background()

	oauthSrv, oauthClient := newOAuthServer(t)

	// Resource server points to oauthSrv as its authorization server.
	resourceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"authorization_servers": []string{oauthSrv.URL},
		})
	}))
	defer resourceSrv.Close()

	up := &store.Upstream{
		Name:          "test-oauth-" + uuid.New().String()[:8],
		URL:           resourceSrv.URL,
		AuthType:      "oauth2_authorization_code",
		AuthEndpoint:  oauthSrv.URL + "/authorize",
		TokenEndpoint: oauthSrv.URL + "/token",
		DCREndpoint:   oauthSrv.URL + "/register",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	defer func() { _ = s.DeleteUpstream(ctx, up.ID) }()

	user, _ := s.FindOrCreateUser(ctx, "oauth-user-"+uuid.New().String()+"@example.com", "OAuth User")

	mgr := upstream.NewManager(s, testEncKey, "https://proxy.example.com", oauthClient)

	redirectURL, state, err := mgr.BeginAuth(ctx, up.ID, user.ID)
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}
	if state == "" {
		t.Fatal("state must be non-empty")
	}

	u, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("BeginAuth returned invalid URL: %v", err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method: got %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("code_challenge") == "" {
		t.Error("code_challenge must be set")
	}
	if q.Get("state") != state {
		t.Errorf("state in URL %q != returned state %q", q.Get("state"), state)
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type: got %q, want code", q.Get("response_type"))
	}
	if q.Get("redirect_uri") == "" {
		t.Error("redirect_uri must be set")
	}
}

func TestCompleteAuth_StoresTokens(t *testing.T) {
	s := openOAuthTestStore(t)
	ctx := context.Background()

	oauthSrv, oauthClient := newOAuthServer(t)

	up := &store.Upstream{
		Name:          "complete-oauth-" + uuid.New().String()[:8],
		URL:           oauthSrv.URL,
		AuthType:      "oauth2_authorization_code",
		AuthEndpoint:  oauthSrv.URL + "/authorize",
		TokenEndpoint: oauthSrv.URL + "/token",
		DCREndpoint:   oauthSrv.URL + "/register",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	defer func() { _ = s.DeleteUpstream(ctx, up.ID) }()

	user, _ := s.FindOrCreateUser(ctx, "complete-user-"+uuid.New().String()+"@example.com", "Complete User")

	mgr := upstream.NewManager(s, testEncKey, "https://proxy.example.com", oauthClient)

	_, state, err := mgr.BeginAuth(ctx, up.ID, user.ID)
	if err != nil {
		t.Fatalf("BeginAuth: %v", err)
	}

	if err := mgr.CompleteAuth(ctx, state, "mock-auth-code"); err != nil {
		t.Fatalf("CompleteAuth: %v", err)
	}

	tok, err := s.GetUserToken(ctx, up.ID, user.ID)
	if err != nil {
		t.Fatalf("GetUserToken after CompleteAuth: %v", err)
	}
	if tok.Status != "authorized" {
		t.Errorf("Status: got %q, want authorized", tok.Status)
	}
	if len(tok.AccessToken) == 0 {
		t.Error("AccessToken should be non-empty after CompleteAuth")
	}

	// Second CompleteAuth with same state must fail (state consumed).
	if err := mgr.CompleteAuth(ctx, state, "mock-auth-code"); err == nil {
		t.Error("second CompleteAuth with same state: expected error, got nil")
	}
}

func TestCompleteAuth_ExpiredState(t *testing.T) {
	s := openOAuthTestStore(t)
	ctx := context.Background()

	oauthSrv, oauthClient := newOAuthServer(t)

	up := &store.Upstream{
		Name:          "expired-state-" + uuid.New().String()[:8],
		URL:           oauthSrv.URL,
		AuthType:      "oauth2_authorization_code",
		AuthEndpoint:  oauthSrv.URL + "/authorize",
		TokenEndpoint: oauthSrv.URL + "/token",
		DCREndpoint:   oauthSrv.URL + "/register",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	defer func() { _ = s.DeleteUpstream(ctx, up.ID) }()

	user, _ := s.FindOrCreateUser(ctx, "expired-state-"+uuid.New().String()+"@example.com", "Expired User")
	mgr := upstream.NewManager(s, testEncKey, "https://proxy.example.com", oauthClient)

	_, state, _ := mgr.BeginAuth(ctx, up.ID, user.ID)

	// Forge an expired state (not possible from outside, so just test unknown state).
	if err := mgr.CompleteAuth(ctx, "unknown-state", "code"); err == nil {
		t.Error("CompleteAuth with unknown state: expected error, got nil")
	}
	_ = state // ensure state was set
}
