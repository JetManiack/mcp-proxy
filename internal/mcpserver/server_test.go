package mcpserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/JetManiack/mcp-proxy/internal/mcpclient"
	"github.com/JetManiack/mcp-proxy/internal/mcpserver"
	"github.com/JetManiack/mcp-proxy/internal/store"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func openTestStore(t *testing.T) *store.Store {
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

// newMockUpstream creates an httptest.Server running an MCP server with one
// tool named "echo" that returns the "msg" argument as text.
func newMockUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "mock", Version: "v0.1.0"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "echo", Description: "echoes the msg argument"},
		func(_ context.Context, _ *mcp.CallToolRequest, args struct {
			Msg string `json:"msg"`
		}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: args.Msg}},
			}, nil, nil
		},
	)
	handler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return srv
	}, nil)
	hs := httptest.NewServer(handler)
	t.Cleanup(hs.Close)
	return hs
}

// connectProxyClient connects a go-sdk client to the proxy's MCP server handler,
// returning a ClientSession ready for tool calls.
func connectProxyClient(t *testing.T, proxyHandler http.Handler, userID uuid.UUID) *mcp.ClientSession {
	t.Helper()
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := mcpserver.WithUserID(r.Context(), userID)
		proxyHandler.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(hs.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.1.0"}, nil)
	sess, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             hs.URL,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func TestMCPToolSearch(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	hs := newMockUpstream(t)
	up := &store.Upstream{
		Name:     "search-mock-" + uuid.New().String()[:8],
		URL:      hs.URL,
		AuthType: "none",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteUpstream(ctx, up.ID) })

	pool := mcpclient.NewPool(s, make([]byte, 32), nil)
	t.Cleanup(pool.Close)

	proxySrv := mcpserver.New(pool)
	sess := connectProxyClient(t, proxySrv.Handler(), uuid.Nil)

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "mcp_tool_search",
		Arguments: map[string]any{"query": "echo"},
	})
	if err != nil {
		t.Fatalf("mcp_tool_search: %v", err)
	}
	if res.IsError {
		t.Fatalf("mcp_tool_search returned error: %v", res.Content)
	}
	if len(res.Content) == 0 {
		t.Fatal("mcp_tool_search: empty content")
	}
	text := res.Content[0].(*mcp.TextContent).Text

	var results []map[string]any
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		t.Fatalf("unmarshal search results: %v — raw: %s", err, text)
	}
	if len(results) == 0 {
		t.Fatal("mcp_tool_search: expected at least one result, got none")
	}
	if results[0]["tool_name"] != "echo" {
		t.Errorf("first result tool_name: got %q, want echo", results[0]["tool_name"])
	}
}

func TestMCPToolCall(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	hs := newMockUpstream(t)
	up := &store.Upstream{
		Name:     "call-mock-" + uuid.New().String()[:8],
		URL:      hs.URL,
		AuthType: "none",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteUpstream(ctx, up.ID) })

	pool := mcpclient.NewPool(s, make([]byte, 32), nil)
	t.Cleanup(pool.Close)

	proxySrv := mcpserver.New(pool)
	sess := connectProxyClient(t, proxySrv.Handler(), uuid.Nil)

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: "mcp_tool_call",
		Arguments: map[string]any{
			"upstream_id": up.ID.String(),
			"tool_name":   "echo",
			"args":        map[string]any{"msg": "proxy works"},
		},
	})
	if err != nil {
		t.Fatalf("mcp_tool_call: %v", err)
	}
	if res.IsError {
		t.Fatalf("mcp_tool_call returned error: %v", res.Content)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if text != "proxy works" {
		t.Errorf("mcp_tool_call: got %q, want %q", text, "proxy works")
	}
}

func TestMCPToolCall_InvalidUpstreamID(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	pool := mcpclient.NewPool(s, make([]byte, 32), nil)
	t.Cleanup(pool.Close)

	proxySrv := mcpserver.New(pool)
	sess := connectProxyClient(t, proxySrv.Handler(), uuid.Nil)

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name: "mcp_tool_call",
		Arguments: map[string]any{
			"upstream_id": "not-a-uuid",
			"tool_name":   "echo",
		},
	})
	if err != nil {
		t.Fatalf("unexpected protocol error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError=true for invalid upstream_id")
	}
}

func TestUpstreamStatus(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	hs := newMockUpstream(t)
	up := &store.Upstream{
		Name:     "status-mock-" + uuid.New().String()[:8],
		URL:      hs.URL,
		AuthType: "none",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteUpstream(ctx, up.ID) })

	pool := mcpclient.NewPool(s, make([]byte, 32), nil)
	t.Cleanup(pool.Close)

	proxySrv := mcpserver.New(pool)
	sess := connectProxyClient(t, proxySrv.Handler(), uuid.Nil)

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "upstream_status",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("upstream_status: %v", err)
	}
	if res.IsError {
		t.Fatalf("upstream_status returned error: %v", res.Content)
	}

	var rows []map[string]any
	text := res.Content[0].(*mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &rows); err != nil {
		t.Fatalf("unmarshal status: %v — raw: %s", err, text)
	}

	for _, row := range rows {
		if row["upstream_id"] == up.ID.String() {
			if row["status"] != "connected" {
				t.Errorf("expected connected, got %q", row["status"])
			}
			return
		}
	}
	t.Fatalf("upstream %s not found in status output", up.ID)
}
