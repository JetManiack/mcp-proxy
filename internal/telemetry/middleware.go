package telemetry

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// sensitiveQueryParams are always redacted from any logged query string.
var sensitiveQueryParams = map[string]bool{
	"code": true, "state": true, "token": true,
	"access_token": true, "client_secret": true,
	"refresh_token": true, "client_id": true,
}

// responseRecorder captures the status code written by the handler.
type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *responseRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// HTTPMiddleware records an access-log entry and Prometheus metrics for every
// request. server labels the listener: "agent", "ui", or "probe".
//
// What is logged:
//   - method, route pattern (not the concrete path), status, latency_ms
//
// What is never logged:
//   - path variables (covered by the route pattern)
//   - query parameters (can carry OAuth codes/tokens)
//   - Authorization, Cookie, Set-Cookie header values
func HTTPMiddleware(server string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		duration := time.Since(start)
		route := routeLabel(r)
		status := rec.status
		statusStr := fmt.Sprintf("%d", status)

		HTTPRequestsTotal.WithLabelValues(server, r.Method, route, statusStr).Inc()
		HTTPRequestDuration.WithLabelValues(server, r.Method, route).Observe(duration.Seconds())

		level := slog.LevelInfo
		if status >= 500 {
			level = slog.LevelError
		} else if status >= 400 {
			level = slog.LevelWarn
		}

		slog.Log(r.Context(), level, "http",
			"server", server,
			"method", r.Method,
			"route", route,
			"status", status,
			"latency_ms", duration.Milliseconds(),
		)
	})
}

// routeLabel returns the matched ServeMux pattern (e.g. "GET /ui/upstreams/{id}").
// For unmatched requests (404 fallthrough), it returns the raw path so the log
// entry is still useful without exposing path variable values.
func routeLabel(r *http.Request) string {
	if p := r.Pattern; p != "" {
		return p
	}
	return r.URL.Path
}

// HasSensitiveQuery reports whether the request URL contains any query
// parameter that should never be logged. Used in tests and debug helpers.
func HasSensitiveQuery(r *http.Request) bool {
	for k := range r.URL.Query() {
		if sensitiveQueryParams[strings.ToLower(k)] {
			return true
		}
	}
	return false
}
