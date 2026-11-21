package telemetry

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// HTTP

	HTTPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests.",
	}, []string{"server", "method", "route", "status"})

	HTTPRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "HTTP request latency.",
		Buckets: prometheus.DefBuckets,
	}, []string{"server", "method", "route"})

	// Upstream OAuth

	TokenRefreshes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "upstream_token_refreshes_total",
		Help: "OAuth token refresh attempts.",
	}, []string{"upstream", "result"}) // result: ok | error | reauth_required

	DCRRegistrations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "upstream_dcr_registrations_total",
		Help: "Dynamic Client Registration attempts.",
	}, []string{"upstream", "result"}) // result: ok | error

	// MCP sessions

	SessionsActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "upstream_sessions_active",
		Help: "Currently active MCP client sessions.",
	}, []string{"upstream", "auth_type"})
)

// Setup initialises the default slog logger.
// format: "json" (default) or "text".
func Setup(format string) {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	var h slog.Handler
	if format == "text" {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}

// MetricsHandler returns an HTTP handler that serves Prometheus metrics.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}
