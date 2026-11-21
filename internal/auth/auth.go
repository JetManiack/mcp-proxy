package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/JetManiack/mcp-proxy/internal/config"
)

type Identity struct {
	Email  string
	Groups []string
}

type contextKey struct{}

// WithIdentity injects an Identity into ctx. Intended for tests that need
// to bypass the HTTP header parsing done by Middleware.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// IdentityFromContext returns the Identity stored by Middleware. ok is true
// whenever the middleware ran, including open mode with no headers present
// (in which case Email is empty). Callers that require a real authenticated
// user should check Email != "".
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(Identity)
	return id, ok
}

// Middleware returns an HTTP middleware that enforces the auth policy in cfg.
//
// In open mode, every request is allowed and any present headers are parsed
// into the request context. In oauth2_proxy mode, the email header is
// required; a missing header or a caller not in the allowlist gets a 403.
// An empty allowlist means no restriction beyond header presence.
func Middleware(cfg *config.AuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			email := r.Header.Get(cfg.HeaderEmail)
			groups := parseGroups(r.Header.Get(cfg.HeaderGroups))

			if cfg.Mode == config.AuthModeOAuth2Proxy {
				if email == "" {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				if !allowed(cfg.Allowlist, email, groups) {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
			}

			// In open mode with no header present, inject a default dev identity
			// so the UI is usable without a proxy.
			if cfg.Mode == config.AuthModeOpen && email == "" {
				email = "dev@localhost"
			}

			id := Identity{Email: email, Groups: groups}
			ctx := context.WithValue(r.Context(), contextKey{}, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// allowed reports whether email or any group appears in the allowlist.
// An empty allowlist (no emails and no groups configured) allows everyone.
func allowed(al config.Allowlist, email string, groups []string) bool {
	if len(al.Emails) == 0 && len(al.Groups) == 0 {
		return true
	}
	for _, e := range al.Emails {
		if strings.EqualFold(e, email) {
			return true
		}
	}
	for _, g := range groups {
		for _, ag := range al.Groups {
			if strings.EqualFold(ag, g) {
				return true
			}
		}
	}
	return false
}

func parseGroups(header string) []string {
	if header == "" {
		return nil
	}
	parts := strings.Split(header, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
