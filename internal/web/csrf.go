package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

type csrfCtxKey struct{}

const (
	csrfCookieName = "_csrf"
	csrfFormField  = "csrf_token"
)

func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func withCSRFToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, csrfCtxKey{}, token)
}

func csrfTokenFromContext(ctx context.Context) string {
	t, _ := ctx.Value(csrfCtxKey{}).(string)
	return t
}

// CSRFMiddleware implements the Double-Submit Cookie pattern.
//
// On safe methods (GET/HEAD/OPTIONS) it ensures a _csrf cookie is set and
// injects the token value into the request context so templates can embed it
// as a hidden field. On state-changing methods (POST, etc.) it verifies that
// the submitted csrf_token form field matches the _csrf cookie.
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			token := cookieCSRFToken(r)
			if token == "" {
				var err error
				token, err = generateCSRFToken()
				if err != nil {
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				// Secure is omitted intentionally: the proxy is typically deployed
				// behind an HTTPS-terminating reverse proxy, so TLS is external.
				// SameSite=Strict already prevents cross-site submission attacks.
				http.SetCookie(w, &http.Cookie{
					Name:     csrfCookieName,
					Value:    token,
					Path:     "/",
					HttpOnly: false, // must be readable by the form submission
					SameSite: http.SameSiteStrictMode,
					MaxAge:   3600,
				})
			}
			next.ServeHTTP(w, r.WithContext(withCSRFToken(r.Context(), token)))
		default:
			cookie := cookieCSRFToken(r)
			if cookie == "" {
				http.Error(w, "CSRF validation failed", http.StatusForbidden)
				return
			}
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if r.FormValue(csrfFormField) != cookie {
				http.Error(w, "CSRF validation failed", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		}
	})
}

func cookieCSRFToken(r *http.Request) string {
	c, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}
