package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JetManiack/mcp-proxy/internal/auth"
	"github.com/JetManiack/mcp-proxy/internal/config"
)

func handler200(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func newRequest(email, groups string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	if email != "" {
		r.Header.Set("X-Auth-Request-Email", email)
	}
	if groups != "" {
		r.Header.Set("X-Auth-Request-Groups", groups)
	}
	return r
}

func TestOpenMode_AllowsAll(t *testing.T) {
	cfg := &config.AuthConfig{Mode: config.AuthModeOpen}
	mw := auth.Middleware(cfg)

	rr := httptest.NewRecorder()
	mw(handler200(t)).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("open mode without headers: got %d, want 200", rr.Code)
	}
}

func TestOpenMode_SetsIdentity(t *testing.T) {
	cfg := &config.AuthConfig{
		Mode:         config.AuthModeOpen,
		HeaderEmail:  "X-Auth-Request-Email",
		HeaderGroups: "X-Auth-Request-Groups",
	}
	mw := auth.Middleware(cfg)

	req := newRequest("alice@example.com", "sre,devops")
	var capturedIdentity auth.Identity
	var identityFound bool

	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedIdentity, identityFound = auth.IdentityFromContext(r.Context())
	})
	mw(inner).ServeHTTP(httptest.NewRecorder(), req)

	if !identityFound {
		t.Fatal("identity not set in context")
	}
	if capturedIdentity.Email != "alice@example.com" {
		t.Errorf("Email: got %q", capturedIdentity.Email)
	}
	if len(capturedIdentity.Groups) != 2 {
		t.Errorf("Groups: got %v", capturedIdentity.Groups)
	}
}

func TestOAuth2ProxyMode_MissingEmail_Returns403(t *testing.T) {
	cfg := &config.AuthConfig{
		Mode:        config.AuthModeOAuth2Proxy,
		HeaderEmail: "X-Auth-Request-Email",
	}
	mw := auth.Middleware(cfg)

	rr := httptest.NewRecorder()
	mw(handler200(t)).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != http.StatusForbidden {
		t.Errorf("missing email: got %d, want 403", rr.Code)
	}
}

func TestOAuth2ProxyMode_EmptyAllowlist_AllowsAll(t *testing.T) {
	// Empty allowlist means no restriction — every authenticated user is allowed.
	cfg := &config.AuthConfig{
		Mode:         config.AuthModeOAuth2Proxy,
		HeaderEmail:  "X-Auth-Request-Email",
		HeaderGroups: "X-Auth-Request-Groups",
		Allowlist:    config.Allowlist{},
	}
	mw := auth.Middleware(cfg)

	rr := httptest.NewRecorder()
	mw(handler200(t)).ServeHTTP(rr, newRequest("anyone@example.com", ""))
	if rr.Code != http.StatusOK {
		t.Errorf("empty allowlist: got %d, want 200", rr.Code)
	}
}

func TestOAuth2ProxyMode_EmailInAllowlist_Allowed(t *testing.T) {
	cfg := &config.AuthConfig{
		Mode:        config.AuthModeOAuth2Proxy,
		HeaderEmail: "X-Auth-Request-Email",
		Allowlist:   config.Allowlist{Emails: []string{"alice@example.com"}},
	}
	mw := auth.Middleware(cfg)

	rr := httptest.NewRecorder()
	mw(handler200(t)).ServeHTTP(rr, newRequest("alice@example.com", ""))
	if rr.Code != http.StatusOK {
		t.Errorf("email in allowlist: got %d, want 200", rr.Code)
	}
}

func TestOAuth2ProxyMode_GroupInAllowlist_Allowed(t *testing.T) {
	cfg := &config.AuthConfig{
		Mode:         config.AuthModeOAuth2Proxy,
		HeaderEmail:  "X-Auth-Request-Email",
		HeaderGroups: "X-Auth-Request-Groups",
		Allowlist:    config.Allowlist{Groups: []string{"sre"}},
	}
	mw := auth.Middleware(cfg)

	rr := httptest.NewRecorder()
	mw(handler200(t)).ServeHTTP(rr, newRequest("bob@example.com", "devops,sre"))
	if rr.Code != http.StatusOK {
		t.Errorf("group in allowlist: got %d, want 200", rr.Code)
	}
}

func TestOAuth2ProxyMode_NotInAllowlist_Returns403(t *testing.T) {
	cfg := &config.AuthConfig{
		Mode:         config.AuthModeOAuth2Proxy,
		HeaderEmail:  "X-Auth-Request-Email",
		HeaderGroups: "X-Auth-Request-Groups",
		Allowlist: config.Allowlist{
			Emails: []string{"alice@example.com"},
			Groups: []string{"sre"},
		},
	}
	mw := auth.Middleware(cfg)

	rr := httptest.NewRecorder()
	mw(handler200(t)).ServeHTTP(rr, newRequest("bob@example.com", "engineering"))
	if rr.Code != http.StatusForbidden {
		t.Errorf("not in allowlist: got %d, want 403", rr.Code)
	}
}

func TestOAuth2ProxyMode_SetsIdentity(t *testing.T) {
	cfg := &config.AuthConfig{
		Mode:         config.AuthModeOAuth2Proxy,
		HeaderEmail:  "X-Auth-Request-Email",
		HeaderGroups: "X-Auth-Request-Groups",
		Allowlist:    config.Allowlist{Emails: []string{"alice@example.com"}},
	}
	mw := auth.Middleware(cfg)

	var capturedIdentity auth.Identity
	var identityFound bool
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedIdentity, identityFound = auth.IdentityFromContext(r.Context())
	})

	mw(inner).ServeHTTP(httptest.NewRecorder(), newRequest("alice@example.com", "sre,devops"))

	if !identityFound {
		t.Fatal("identity not set in context")
	}
	if capturedIdentity.Email != "alice@example.com" {
		t.Errorf("Email: got %q", capturedIdentity.Email)
	}
	if len(capturedIdentity.Groups) != 2 {
		t.Errorf("Groups: got %v, want [sre devops]", capturedIdentity.Groups)
	}
}

func TestIdentityFromContext_WithoutMiddleware(t *testing.T) {
	_, ok := auth.IdentityFromContext(context.Background())
	if ok {
		t.Error("IdentityFromContext on plain context should return ok=false")
	}
}

func TestAllowlist_EmailCaseInsensitive(t *testing.T) {
	cfg := &config.AuthConfig{
		Mode:        config.AuthModeOAuth2Proxy,
		HeaderEmail: "X-Auth-Request-Email",
		Allowlist:   config.Allowlist{Emails: []string{"alice@example.com"}},
	}
	mw := auth.Middleware(cfg)

	rr := httptest.NewRecorder()
	mw(handler200(t)).ServeHTTP(rr, newRequest("ALICE@EXAMPLE.COM", ""))
	if rr.Code != http.StatusOK {
		t.Errorf("email case-insensitive allowlist: got %d, want 200", rr.Code)
	}
}

func TestAllowlist_GroupCaseInsensitive(t *testing.T) {
	cfg := &config.AuthConfig{
		Mode:         config.AuthModeOAuth2Proxy,
		HeaderEmail:  "X-Auth-Request-Email",
		HeaderGroups: "X-Auth-Request-Groups",
		Allowlist:    config.Allowlist{Groups: []string{"SRE"}},
	}
	mw := auth.Middleware(cfg)

	rr := httptest.NewRecorder()
	mw(handler200(t)).ServeHTTP(rr, newRequest("bob@example.com", "sre"))
	if rr.Code != http.StatusOK {
		t.Errorf("group case-insensitive allowlist: got %d, want 200", rr.Code)
	}
}

func TestGroupsParsing_BlankEntries(t *testing.T) {
	cfg := &config.AuthConfig{
		Mode:         config.AuthModeOAuth2Proxy,
		HeaderEmail:  "X-Auth-Request-Email",
		HeaderGroups: "X-Auth-Request-Groups",
		Allowlist:    config.Allowlist{Groups: []string{"sre"}},
	}
	mw := auth.Middleware(cfg)

	// Header with only blank/whitespace entries must not match any group.
	rr := httptest.NewRecorder()
	mw(handler200(t)).ServeHTTP(rr, newRequest("bob@example.com", " , , "))
	if rr.Code != http.StatusForbidden {
		t.Errorf("blank group entries: got %d, want 403", rr.Code)
	}

	// Trailing comma: only "sre" should be parsed.
	rr = httptest.NewRecorder()
	mw(handler200(t)).ServeHTTP(rr, newRequest("bob@example.com", "sre,"))
	if rr.Code != http.StatusOK {
		t.Errorf("trailing comma in groups: got %d, want 200", rr.Code)
	}
}

func TestOAuth2ProxyMode_CustomHeaders(t *testing.T) {
	cfg := &config.AuthConfig{
		Mode:         config.AuthModeOAuth2Proxy,
		HeaderEmail:  "X-User-Email",
		HeaderGroups: "X-User-Groups",
		Allowlist:    config.Allowlist{},
	}
	mw := auth.Middleware(cfg)

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-User-Email", "alice@example.com")
	r.Header.Set("X-User-Groups", "sre")

	rr := httptest.NewRecorder()
	mw(handler200(t)).ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Errorf("custom headers: got %d, want 200", rr.Code)
	}
}

func TestGroupsParsing_TrimsSpaces(t *testing.T) {
	cfg := &config.AuthConfig{
		Mode:         config.AuthModeOAuth2Proxy,
		HeaderEmail:  "X-Auth-Request-Email",
		HeaderGroups: "X-Auth-Request-Groups",
		Allowlist:    config.Allowlist{Groups: []string{"sre"}},
	}
	mw := auth.Middleware(cfg)

	rr := httptest.NewRecorder()
	mw(handler200(t)).ServeHTTP(rr, newRequest("bob@example.com", " devops , sre , infra "))
	if rr.Code != http.StatusOK {
		t.Errorf("spaces in groups header: got %d, want 200", rr.Code)
	}
}
