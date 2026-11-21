package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/JetManiack/mcp-proxy/internal/mcpserver"
	"github.com/JetManiack/mcp-proxy/internal/store"
)

// AgentTokenAuthHandler authenticates requests using an "Authorization: Bearer <token>"
// header. On success it injects the user UUID into the context and calls next.
// On failure it returns 401.
func AgentTokenAuthHandler(s *store.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, ok := parseBearerToken(r)
		if !ok {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		h := sha256.Sum256([]byte(bearer))
		tok, err := s.FindAgentToken(r.Context(), h[:])
		if err != nil {
			http.Error(w, "invalid or unknown token", http.StatusUnauthorized)
			return
		}

		// Update last-seen timestamp in background; ignore errors.
		// Use WithoutCancel so the goroutine outlives the HTTP request lifetime.
		touchCtx := context.WithoutCancel(r.Context())
		go func() {
			_ = s.TouchAgentToken(touchCtx, tok.ID)
		}()

		ctx := mcpserver.WithUserID(r.Context(), tok.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// InjectUser reads the authenticated user identity from the context (set by
// auth.Middleware) and injects the user's UUID from the store. If no identity
// is present, the request proceeds with uuid.Nil so the pool uses shared sessions.
func InjectUser(s *store.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := currentUser(r, s)
		if err == nil && user != nil {
			ctx := mcpserver.WithUserID(r.Context(), user.ID)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func parseBearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(h, "Bearer ")
	return strings.TrimSpace(token), ok && strings.TrimSpace(token) != ""
}

// generateAgentToken creates a fresh raw token and its SHA-256 hash.
// The raw token is returned once and never stored; only the hash is persisted.
func generateAgentToken() (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", nil, err
	}
	raw = "mcp-" + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	return raw, h[:], nil
}
