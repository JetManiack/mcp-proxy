package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JetManiack/mcp-proxy/internal/auth"
	"github.com/JetManiack/mcp-proxy/internal/config"
	"github.com/JetManiack/mcp-proxy/internal/crypto"
	"github.com/JetManiack/mcp-proxy/internal/mcpclient"
	"github.com/JetManiack/mcp-proxy/internal/mcpserver"
	"github.com/JetManiack/mcp-proxy/internal/store"
	"github.com/JetManiack/mcp-proxy/internal/telemetry"
	"github.com/JetManiack/mcp-proxy/internal/upstream"
	"github.com/JetManiack/mcp-proxy/internal/web"
	"github.com/urfave/cli/v3"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	cmd := &cli.Command{
		Name:    "mcp-proxy",
		Usage:   "MCP aggregation proxy",
		Version: fmt.Sprintf("%s (built %s)", Version, BuildTime),
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "path to YAML config file",
				Sources: cli.EnvVars("MCP_PROXY_CONFIG"),
			},
			&cli.StringFlag{
				Name:    "log-format",
				Usage:   "log output format: json or text",
				Value:   "json",
				Sources: cli.EnvVars("MCP_PROXY_LOG_FORMAT"),
				Action: func(_ context.Context, _ *cli.Command, v string) error {
					if v != "json" && v != "text" {
						return fmt.Errorf("unknown --log-format %q: must be json or text", v)
					}
					return nil
				},
			},
			&cli.StringFlag{
				Name:    "listen-addr",
				Usage:   "UI + OAuth callback listen `address`",
				Value:   ":8081",
				Sources: cli.EnvVars("MCP_PROXY_LISTEN_ADDR"),
			},
			&cli.StringFlag{
				Name:    "agent-addr",
				Usage:   "agent MCP endpoint listen `address`",
				Value:   ":8080",
				Sources: cli.EnvVars("MCP_PROXY_AGENT_ADDR"),
			},
			&cli.StringFlag{
				Name:    "probe-addr",
				Usage:   "liveness/readiness probe listen `address`",
				Value:   ":8082",
				Sources: cli.EnvVars("MCP_PROXY_PROBE_ADDR"),
			},
			&cli.StringFlag{
				Name:    "database-url",
				Usage:   "PostgreSQL connection `URL`",
				Sources: cli.EnvVars("MCP_PROXY_DATABASE_URL"),
			},
			&cli.StringFlag{
				Name:    "public-url",
				Usage:   "public base `URL` used in OAuth2 callbacks",
				Sources: cli.EnvVars("MCP_PROXY_PUBLIC_URL"),
			},
			&cli.StringFlag{
				Name:    "encryption-key",
				Usage:   "32-byte hex `key` for encrypting stored secrets",
				Sources: cli.EnvVars("MCP_PROXY_ENCRYPTION_KEY"),
			},
			&cli.StringFlag{
				Name:    "auth-mode",
				Usage:   "authentication mode: open | oauth2_proxy",
				Value:   "open",
				Sources: cli.EnvVars("MCP_PROXY_AUTH_MODE"),
				Action: func(_ context.Context, _ *cli.Command, v string) error {
					switch config.AuthMode(v) {
					case config.AuthModeOpen, config.AuthModeOAuth2Proxy:
						return nil
					default:
						return fmt.Errorf("unknown --auth-mode %q: must be open or oauth2_proxy", v)
					}
				},
			},
			&cli.StringFlag{
				Name:    "header-email",
				Usage:   "request `header` containing the authenticated user email",
				Value:   "X-Auth-Request-Email",
				Sources: cli.EnvVars("MCP_PROXY_HEADER_EMAIL"),
			},
			&cli.StringFlag{
				Name:    "header-groups",
				Usage:   "request `header` containing authenticated group memberships",
				Value:   "X-Auth-Request-Groups",
				Sources: cli.EnvVars("MCP_PROXY_HEADER_GROUPS"),
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			telemetry.Setup(cmd.String("log-format"))
			cfg, err := buildConfig(cmd)
			if err != nil {
				return err
			}
			return run(cfg)
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// buildConfig merges sources in priority order: CLI/env > YAML file > flag defaults.
// Flag defaults live in Flag.Value above — no need to repeat them here.
func buildConfig(cmd *cli.Command) (*config.Config, error) {
	cfg := &config.Config{}

	// Overlay YAML file (lowest priority).
	if f := cmd.String("config"); f != "" {
		if err := config.LoadFile(f, cfg); err != nil {
			return nil, err
		}
	}

	// For each field: CLI/env wins unconditionally; fall back to flag default
	// only when YAML didn't supply a value.
	apply := func(flagName string, dst *string) {
		if cmd.IsSet(flagName) || *dst == "" {
			*dst = cmd.String(flagName)
		}
	}
	apply("listen-addr", &cfg.ListenAddr)
	apply("agent-addr", &cfg.AgentAddr)
	apply("probe-addr", &cfg.ProbeAddr)
	apply("database-url", &cfg.DatabaseURL)
	apply("public-url", &cfg.PublicURL)
	apply("header-email", &cfg.Auth.HeaderEmail)
	apply("header-groups", &cfg.Auth.HeaderGroups)

	if cmd.IsSet("auth-mode") || cfg.Auth.Mode == "" {
		cfg.Auth.Mode = config.AuthMode(cmd.String("auth-mode"))
	}

	if hex := cmd.String("encryption-key"); hex != "" {
		key, err := crypto.KeyFromHex(hex)
		if err != nil {
			return nil, fmt.Errorf("--encryption-key: %w", err)
		}
		cfg.EncryptionKey = key
	}

	return cfg, config.Validate(cfg)
}

func run(cfg *config.Config) error {
	slog.Info("mcp-proxy starting", "version", Version, "built", BuildTime)

	// Store.
	s, err := store.Open(context.Background(), cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer func() { _ = s.Close() }()

	// Upstream management.
	httpClient := &http.Client{Timeout: 30 * time.Second}
	registry := upstream.NewRegistry(s, httpClient)
	oauthMgr := upstream.NewManager(s, cfg.EncryptionKey, cfg.PublicURL, httpClient)

	// MCP client pool.
	pool := mcpclient.NewPool(s, cfg.EncryptionKey, nil, oauthMgr)
	defer pool.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	mcpSrv := mcpserver.New(pool)
	pool.StartReconcileLoop(ctx, registry)

	// Web UI handler.
	webHandler := web.New(s, registry, oauthMgr, pool)
	webRoutes := webHandler.Routes()

	// --- Probe server (:probe-addr) ---
	// Never behind any auth proxy. No access-log middleware — high-frequency probes
	// would flood the log; metrics are still recorded via the handlers themselves.
	probeMux := http.NewServeMux()
	probeMux.HandleFunc("GET /health/alive", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "ok")
	})
	probeMux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Ping(r.Context()); err != nil {
			http.Error(w, "db: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, "ok")
	})
	probeMux.Handle("GET /metrics", telemetry.MetricsHandler())

	// --- Agent server (:agent-addr) ---
	agentMux := http.NewServeMux()
	mcpHandler := web.AgentTokenAuthHandler(s, mcpSrv.Handler())
	agentMux.Handle("/mcp", mcpHandler)
	agentMux.Handle("/mcp/", mcpHandler)

	// --- UI server (:listen-addr) ---
	uiMux := http.NewServeMux()
	// /oauth/callback must bypass oauth2-proxy auth (--skip-auth-route in docker-compose).
	uiMux.HandleFunc("GET /oauth/callback", func(w http.ResponseWriter, r *http.Request) {
		webRoutes.ServeHTTP(w, r)
	})
	authMW := auth.Middleware(&cfg.Auth)
	uiMux.Handle("/", authMW(web.InjectUser(s, webRoutes)))

	servers := []*http.Server{
		{
			Addr:         cfg.ProbeAddr,
			Handler:      probeMux, // no access-log middleware: probe traffic is high-frequency noise
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  30 * time.Second,
		},
		{
			Addr:         cfg.AgentAddr,
			Handler:      telemetry.HTTPMiddleware("agent", agentMux),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
		{
			Addr:         cfg.ListenAddr,
			Handler:      telemetry.HTTPMiddleware("ui", web.CSRFMiddleware(uiMux)),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
	}

	for _, srv := range servers {
		srv := srv
		go func() {
			slog.Info("server listening", "addr", srv.Addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("server error", "addr", srv.Addr, "err", err)
			}
		}()
	}

	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutCtx)
	}
	return nil
}
