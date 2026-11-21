// Package e2e contains end-to-end tests that exercise the full HTTP stack:
// agent Bearer token auth → MCP server → upstream pool → mock upstream.
//
// Requires TEST_DATABASE_URL to be set; skipped otherwise.
package e2e_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/JetManiack/mcp-proxy/internal/mcpclient"
	"github.com/JetManiack/mcp-proxy/internal/mcpserver"
	"github.com/JetManiack/mcp-proxy/internal/store"
	"github.com/JetManiack/mcp-proxy/internal/web"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// proxyBearerTransport adds a Bearer token to every request.
type proxyBearerTransport struct{ token string }

func (t *proxyBearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.Header.Set("Authorization", "Bearer "+t.token)
	return http.DefaultTransport.RoundTrip(r2)
}

// makeAgentToken generates a raw agent token and its SHA-256 hash.
func makeAgentToken(t *testing.T) (raw string, hash []byte) {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal("rand.Read:", err)
	}
	raw = "mcp-" + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	return raw, h[:]
}

// openE2EStore opens the test database, skipping if TEST_DATABASE_URL is unset.
func openE2EStore(t *testing.T) *store.Store {
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

// newMockUpstreamMCP starts an httptest server running a minimal MCP server
// with a single "ping" tool that returns "pong".
func newMockUpstreamMCP(t *testing.T) *httptest.Server {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "e2e-mock", Version: "v0.1.0"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "ping", Description: "returns pong"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "pong"}},
			}, nil, nil
		},
	)
	hs := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return srv
	}, nil))
	t.Cleanup(hs.Close)
	return hs
}

// TestE2E_AgentTokenFullChain wires the complete HTTP stack and verifies that:
//  1. A request with no Bearer token is rejected with 401.
//  2. A valid Bearer token allows MCP tool calls to reach a real upstream.
//  3. mcp_tool_search, mcp_tool_call, and upstream_status all return correct data.
func TestE2E_AgentTokenFullChain(t *testing.T) {
	s := openE2EStore(t)
	ctx := context.Background()

	// Mock upstream MCP server.
	mockUpstream := newMockUpstreamMCP(t)

	// Create upstream in DB (none auth — no OAuth dance needed).
	up := &store.Upstream{
		Name:     "e2e-" + uuid.New().String()[:8],
		URL:      mockUpstream.URL,
		AuthType: "none",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteUpstream(context.Background(), up.ID) })

	// Create user and an agent token.
	user, err := s.FindOrCreateUser(ctx, "e2e@test.local", "e2e@test.local")
	if err != nil {
		t.Fatalf("FindOrCreateUser: %v", err)
	}

	rawToken, tokenHash := makeAgentToken(t)
	agentTok := &store.AgentToken{
		Name:      "e2e-token-" + uuid.New().String()[:8],
		TokenHash: tokenHash,
		UserID:    user.ID,
	}
	if err := s.CreateAgentToken(ctx, agentTok); err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}
	t.Cleanup(func() {
		_ = s.DeleteAgentToken(context.Background(), agentTok.ID, user.ID)
	})

	// Wire up the proxy.
	encKey := make([]byte, 32)
	pool := mcpclient.NewPool(s, encKey, nil)
	t.Cleanup(pool.Close)

	proxySrv := mcpserver.New(pool)
	proxyHandler := web.AgentTokenAuthHandler(s, proxySrv.Handler())
	proxySrvHTTP := httptest.NewServer(proxyHandler)
	t.Cleanup(proxySrvHTTP.Close)

	// --- sub-test: unauthenticated request is rejected ----------------------
	t.Run("unauthenticated_rejected", func(t *testing.T) {
		resp, err := http.Post(proxySrvHTTP.URL, "application/json", nil)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("want 401, got %d", resp.StatusCode)
		}
	})

	// Connect an MCP client using the agent Bearer token.
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "mcp-client-e2e", Version: "v0.1.0"}, nil)
	sess, err := mcpClient.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: proxySrvHTTP.URL,
		HTTPClient: &http.Client{
			Transport: &proxyBearerTransport{token: rawToken},
		},
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })

	// --- sub-test: mcp_tool_search ------------------------------------------
	t.Run("mcp_tool_search", func(t *testing.T) {
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      "mcp_tool_search",
			Arguments: map[string]any{"query": "ping"},
		})
		if err != nil {
			t.Fatalf("mcp_tool_search: %v", err)
		}
		if res.IsError {
			t.Fatalf("mcp_tool_search error: %v", res.Content)
		}
		text := res.Content[0].(*mcp.TextContent).Text
		var results []map[string]any
		if err := json.Unmarshal([]byte(text), &results); err != nil {
			t.Fatalf("unmarshal results: %v — raw: %s", err, text)
		}
		if len(results) == 0 {
			t.Fatal("expected ≥1 result, got none")
		}
		if results[0]["tool_name"] != "ping" {
			t.Errorf("want tool_name=ping, got %q", results[0]["tool_name"])
		}
	})

	// --- sub-test: mcp_tool_call --------------------------------------------
	t.Run("mcp_tool_call", func(t *testing.T) {
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{
			Name: "mcp_tool_call",
			Arguments: map[string]any{
				"upstream_id": up.ID.String(),
				"tool_name":   "ping",
				"args":        map[string]any{},
			},
		})
		if err != nil {
			t.Fatalf("mcp_tool_call: %v", err)
		}
		if res.IsError {
			t.Fatalf("mcp_tool_call error: %v", res.Content)
		}
		text := res.Content[0].(*mcp.TextContent).Text
		if text != "pong" {
			t.Errorf("want pong, got %q", text)
		}
	})

	// --- sub-test: upstream_status ------------------------------------------
	t.Run("upstream_status", func(t *testing.T) {
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      "upstream_status",
			Arguments: map[string]any{},
		})
		if err != nil {
			t.Fatalf("upstream_status: %v", err)
		}
		if res.IsError {
			t.Fatalf("upstream_status error: %v", res.Content)
		}
		text := res.Content[0].(*mcp.TextContent).Text
		var rows []map[string]any
		if err := json.Unmarshal([]byte(text), &rows); err != nil {
			t.Fatalf("unmarshal status: %v — raw: %s", err, text)
		}
		for _, row := range rows {
			if row["upstream_id"] == up.ID.String() {
				if row["status"] != "connected" {
					t.Errorf("want connected, got %q", row["status"])
				}
				return
			}
		}
		t.Fatalf("upstream %s not found in status output", up.ID)
	})
}
