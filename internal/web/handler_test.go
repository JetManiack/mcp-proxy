package web_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JetManiack/mcp-proxy/internal/auth"
	"github.com/JetManiack/mcp-proxy/internal/web"
)

// stubStore satisfies the minimum interface needed for handler tests that
// don't touch the database (auth/routing tests).
// The real store is exercised in integration tests (TEST_DATABASE_URL).

func newTestHandler() (*web.Handler, http.Handler) {
	h := web.New(nil, nil, nil, nil)
	return h, h.Routes()
}

func withIdentity(r *http.Request, email string) *http.Request {
	ctx := auth.WithIdentity(r.Context(), auth.Identity{Email: email})
	return r.WithContext(ctx)
}

func TestHealthz(t *testing.T) {
	_, routes := newTestHandler()
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, httptest.NewRequest("GET", "/health/alive", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if body, _ := io.ReadAll(rec.Body); string(body) != "ok" {
		t.Fatalf("want 'ok', got %q", body)
	}
}

func TestRootRedirect(t *testing.T) {
	_, routes := newTestHandler()
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/ui/upstreams" {
		t.Fatalf("want /ui/upstreams, got %q", loc)
	}
}

func TestOAuthCallback_MissingParams(t *testing.T) {
	_, routes := newTestHandler()
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, httptest.NewRequest("GET", "/oauth/callback", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestCreateUpstream_MissingFields(t *testing.T) {
	_, routes := newTestHandler()
	form := url.Values{"name": {"test"}} // missing url and auth_type
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/ui/upstreams", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withIdentity(req, "user@example.com")
	routes.ServeHTTP(rec, req)
	// nil store → will fail at validation before hitting store
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for missing fields, got %d", rec.Code)
	}
}

func TestAgentTokenAuth_MissingHeader(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	guarded := web.AgentTokenAuthHandler(nil, inner)

	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, httptest.NewRequest("POST", "/mcp", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}
