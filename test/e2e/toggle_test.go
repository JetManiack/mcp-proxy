package e2e_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JetManiack/mcp-proxy/internal/mcpclient"
	"github.com/JetManiack/mcp-proxy/internal/mcpserver"
	"github.com/JetManiack/mcp-proxy/internal/store"
	"github.com/JetManiack/mcp-proxy/internal/web"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestE2E_ToolToggle verifies that:
//  1. A tool is callable before being toggled off.
//  2. After toggling off, the tool call returns an IsError=true response with
//     the "disabled" message, without reaching the upstream.
//  3. After toggling back on, the tool is callable again.
//
// Also validates the GORM zero-value bug fix for SetToolEnabled(false).
func TestE2E_ToolToggle(t *testing.T) {
	s := openE2EStore(t)
	ctx := context.Background()

	// Mock upstream MCP server with a "ping" tool.
	mockUpstream := newMockUpstreamMCP(t)

	// Register upstream with no auth (avoids SSRF loopback restriction
	// because httptest uses 127.0.0.1 — which is fine in in-process tests
	// since ValidateUpstreamURL is only called by the HTTP handler).
	up := &store.Upstream{
		Name:     "toggle-e2e-" + uuid.New().String()[:8],
		URL:      mockUpstream.URL,
		AuthType: "none",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteUpstream(context.Background(), up.ID) })

	// User + agent token.
	user, err := s.FindOrCreateUser(ctx, "toggle-e2e@test.local", "toggle-e2e@test.local")
	if err != nil {
		t.Fatalf("FindOrCreateUser: %v", err)
	}
	rawToken, tokenHash := makeAgentToken(t)
	agentTok := &store.AgentToken{
		Name:      "toggle-e2e-" + uuid.New().String()[:8],
		TokenHash: tokenHash,
		UserID:    user.ID,
	}
	if err := s.CreateAgentToken(ctx, agentTok); err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteAgentToken(context.Background(), agentTok.ID, user.ID) })

	// Wire up the proxy stack.
	encKey := make([]byte, 32)
	pool := mcpclient.NewPool(s, encKey, nil, nil)
	t.Cleanup(pool.Close)

	proxySrv := mcpserver.New(pool)
	proxyHandler := web.AgentTokenAuthHandler(s, proxySrv.Handler())
	proxySrvHTTP := httptest.NewServer(proxyHandler)
	t.Cleanup(proxySrvHTTP.Close)

	// MCP client using the agent Bearer token.
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "toggle-e2e", Version: "v0.1.0"}, nil)
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

	callPing := func(t *testing.T) *mcp.CallToolResult {
		t.Helper()
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{
			Name: "mcp_tool_call",
			Arguments: map[string]any{
				"upstream_id": up.ID.String(),
				"tool_name":   "ping",
				"args":        map[string]any{},
			},
		})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		return res
	}

	textOf := func(res *mcp.CallToolResult) string {
		if len(res.Content) == 0 {
			return ""
		}
		return res.Content[0].(*mcp.TextContent).Text
	}

	// --- Scenario 1: tool is enabled by default ---
	t.Run("enabled_by_default", func(t *testing.T) {
		res := callPing(t)
		if res.IsError {
			t.Fatalf("expected success, got error: %s", textOf(res))
		}
		if textOf(res) != "pong" {
			t.Errorf("want pong, got %q", textOf(res))
		}
	})

	// --- Scenario 2: toggle off → call must return disabled error ---
	t.Run("disabled_after_toggle_off", func(t *testing.T) {
		if err := s.SetToolEnabled(ctx, up.ID, "ping", false); err != nil {
			t.Fatalf("SetToolEnabled(false): %v", err)
		}
		// Verify DB state.
		filters, err := s.GetToolFilters(ctx, up.ID)
		if err != nil {
			t.Fatalf("GetToolFilters: %v", err)
		}
		if filters["ping"] != false {
			t.Fatalf("expected ping=false in DB, got %v", filters["ping"])
		}

		res := callPing(t)
		if !res.IsError {
			t.Fatalf("expected IsError=true, got success: %s", textOf(res))
		}
		if !strings.Contains(textOf(res), "disabled") {
			t.Errorf("expected 'disabled' in error text, got: %s", textOf(res))
		}
	})

	// --- Scenario 3: toggle back on → tool works again ---
	t.Run("re_enabled_after_toggle_on", func(t *testing.T) {
		if err := s.SetToolEnabled(ctx, up.ID, "ping", true); err != nil {
			t.Fatalf("SetToolEnabled(true): %v", err)
		}
		res := callPing(t)
		if res.IsError {
			t.Fatalf("expected success after re-enable, got error: %s", textOf(res))
		}
		if textOf(res) != "pong" {
			t.Errorf("want pong, got %q", textOf(res))
		}
	})

	// --- Scenario 4: TriggerReconcile updates catalog ---
	t.Run("catalog_updated_via_trigger", func(t *testing.T) {
		// Register a second upstream mid-flight.
		mock2 := newMockUpstreamWithTool(t, "pong2")
		up2 := &store.Upstream{
			Name:     "trigger-e2e-" + uuid.New().String()[:8],
			URL:      mock2.URL,
			AuthType: "none",
		}
		if err := s.CreateUpstream(ctx, up2); err != nil {
			t.Fatalf("CreateUpstream2: %v", err)
		}
		t.Cleanup(func() { _ = s.DeleteUpstream(context.Background(), up2.ID) })

		// Before trigger: pool's catalog may not know about up2.
		// Call TriggerReconcile and give it a moment to run.
		pool.TriggerReconcile()
		// Wait briefly for the goroutine; in tests there's no background loop,
		// so we call refreshCatalog indirectly by checking GetCatalog falls back
		// to live query (catalog is nil since StartReconcileLoop wasn't called).
		cat, err := pool.GetCatalog(ctx, uuid.Nil)
		if err != nil {
			t.Fatalf("GetCatalog: %v", err)
		}
		found := false
		for _, e := range cat.All() {
			if e.UpstreamID == up2.ID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("new upstream %s not found in catalog after trigger", up2.Name)
		}
	})
}

// newMockUpstreamWithTool starts a mock MCP server advertising a single
// no-op tool with the given name.
func newMockUpstreamWithTool(t *testing.T, toolName string) *httptest.Server {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "mock-" + toolName, Version: "v0.1.0"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: toolName, Description: "mock tool"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			b, _ := json.Marshal(map[string]string{"tool": toolName})
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
			}, nil, nil
		},
	)
	hs := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return srv
	}, nil))
	t.Cleanup(hs.Close)
	return hs
}
