package mcpserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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

// --- direct-tools mode tests --------------------------------------------------

// noopDiscoverer satisfies mcpclient.Discoverer for test reconcile loops that
// only deal with non-OAuth2 upstreams (Discover is never called).
type noopDiscoverer struct{}

func (noopDiscoverer) Discover(_ context.Context, _ uuid.UUID) error { return nil }

// TestDirectTools_Listed verifies that upstream tools appear in tools/list when
// direct-tools mode is enabled. Tools whose name does not already start with the
// upstream name get prefixed as "upstream__tool"; others are kept as-is.
func TestDirectTools_Listed(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	hs := newMockUpstream(t)
	upName := "dt-listed-" + uuid.New().String()[:8]
	up := &store.Upstream{Name: upName, URL: hs.URL, AuthType: "none"}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteUpstream(ctx, up.ID) })

	pool := mcpclient.NewPool(s, make([]byte, 32), nil, nil)
	t.Cleanup(pool.Close)

	proxySrv := mcpserver.New(pool, true) // direct-tools mode
	sess := connectProxyClient(t, proxySrv.Handler(), uuid.Nil)

	res, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}

	names := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}

	// "echo" does not start with "<upName>_", so it should be namespaced
	expectedNS := upName + "__echo"
	if !names[expectedNS] {
		t.Errorf("expected %s in tools/list; got: %v", expectedNS, res.Tools)
	}
	// meta-tools must still be present
	if !names["upstream_status"] {
		t.Errorf("expected upstream_status in tools/list; got: %v", res.Tools)
	}
	// search/call meta-tools must be absent in direct mode
	if names["mcp_tool_search"] {
		t.Error("mcp_tool_search must not appear in tools/list in direct mode")
	}
	if names["mcp_tool_call"] {
		t.Error("mcp_tool_call must not appear in tools/list in direct mode")
	}
}

// TestDirectTools_NamespacePrefix verifies that a tool whose name already starts
// with "<upstream>_" is kept as-is (no double-prefix).
func TestDirectTools_NamespacePrefix(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// upName and tool name share the same prefix so namespaceTool returns toolName unchanged.
	suffix := uuid.New().String()[:8]
	upName := "vendor" + suffix
	toolName := upName + "_greet" // already prefixed with upName+"_"

	srv := mcp.NewServer(&mcp.Implementation{Name: "srv", Version: "v0"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: toolName, Description: "greet"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "hi"}}}, nil, nil
		},
	)
	hs := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server { return srv }, nil))
	t.Cleanup(hs.Close)

	up := &store.Upstream{Name: upName, URL: hs.URL, AuthType: "none"}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteUpstream(ctx, up.ID) })

	pool := mcpclient.NewPool(s, make([]byte, 32), nil, nil)
	t.Cleanup(pool.Close)

	proxySrv := mcpserver.New(pool, true)
	sess := connectProxyClient(t, proxySrv.Handler(), uuid.Nil)

	res, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	names := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	if !names[toolName] {
		t.Errorf("expected %s kept as-is; got: %v", toolName, res.Tools)
	}
	if names[upName+"__"+toolName] {
		t.Errorf("%s must not be double-prefixed to %s", toolName, upName+"__"+toolName)
	}
}

// TestDirectTools_Call verifies that a tool can be called by its namespaced name.
func TestDirectTools_Call(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	hs := newMockUpstream(t)
	upName := "dt-call-" + uuid.New().String()[:8]
	up := &store.Upstream{Name: upName, URL: hs.URL, AuthType: "none"}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteUpstream(ctx, up.ID) })

	pool := mcpclient.NewPool(s, make([]byte, 32), nil, nil)
	t.Cleanup(pool.Close)

	proxySrv := mcpserver.New(pool, true)
	sess := connectProxyClient(t, proxySrv.Handler(), uuid.Nil)

	nsName := upName + "__echo"
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      nsName,
		Arguments: map[string]any{"msg": "hello direct"},
	})
	if err != nil {
		t.Fatalf("call %s: %v", nsName, err)
	}
	if res.IsError {
		t.Fatalf("%s returned error: %v", nsName, res.Content)
	}
	if len(res.Content) == 0 {
		t.Fatal("empty content")
	}
	if text := res.Content[0].(*mcp.TextContent).Text; text != "hello direct" {
		t.Errorf("got %q, want %q", text, "hello direct")
	}
}

// TestDirectTools_CatalogUpdate verifies that tools added after server creation
// appear in tools/list once the pool reconcile loop fires its catalog-change hook.
func TestDirectTools_CatalogUpdate(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	pool := mcpclient.NewPool(s, make([]byte, 32), nil, nil)
	t.Cleanup(pool.Close)

	// Create the server BEFORE starting the reconcile loop so the hook is
	// registered before the first reconcile goroutine runs.
	proxySrv := mcpserver.New(pool, true)

	rCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	pool.StartReconcileLoop(rCtx, noopDiscoverer{})

	sess := connectProxyClient(t, proxySrv.Handler(), uuid.Nil)

	// Add an upstream after the server and reconcile loop are running.
	hs := newMockUpstream(t)
	upName := "dt-update-" + uuid.New().String()[:8]
	up := &store.Upstream{Name: upName, URL: hs.URL, AuthType: "none"}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteUpstream(ctx, up.ID) })

	pool.TriggerReconcile()

	expectedName := upName + "__echo"
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		res, err := sess.ListTools(ctx, nil)
		if err == nil {
			for _, tool := range res.Tools {
				if tool.Name == expectedName {
					return // found — test passes
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("tool %s not found in tools/list within 5s after catalog update", expectedName)
}

// --- search-mode tests --------------------------------------------------------

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

	pool := mcpclient.NewPool(s, make([]byte, 32), nil, nil)
	t.Cleanup(pool.Close)

	proxySrv := mcpserver.New(pool, false)
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

func TestMCPToolSearch_IncludesInputSchema(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	hs := newMockUpstream(t)
	up := &store.Upstream{
		Name:     "schema-mock-" + uuid.New().String()[:8],
		URL:      hs.URL,
		AuthType: "none",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteUpstream(ctx, up.ID) })

	pool := mcpclient.NewPool(s, make([]byte, 32), nil, nil)
	t.Cleanup(pool.Close)

	proxySrv := mcpserver.New(pool, false)
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
	var results []map[string]json.RawMessage
	text := res.Content[0].(*mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		t.Fatalf("unmarshal: %v — raw: %s", err, text)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	raw, ok := results[0]["input_schema"]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		t.Fatalf("input_schema missing or null in result: %s", text)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("input_schema is not a valid JSON object: %v", err)
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

	pool := mcpclient.NewPool(s, make([]byte, 32), nil, nil)
	t.Cleanup(pool.Close)

	proxySrv := mcpserver.New(pool, false)
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

// TestMCPToolCall_ProxyToolRejected checks that calling a proxy-level tool via
// mcp_tool_call returns a clear error instead of forwarding to an upstream.
// This prevents agents from looping when they accidentally route proxy tools
// through mcp_tool_call with an upstream_id.
// No database needed: the proxy-tool guard fires before any pool/store call.
func TestMCPToolCall_ProxyToolRejected(t *testing.T) {
	ctx := context.Background()

	pool := mcpclient.NewPool(nil, make([]byte, 32), nil, nil)
	t.Cleanup(pool.Close)

	proxySrv := mcpserver.New(pool, false)
	sess := connectProxyClient(t, proxySrv.Handler(), uuid.Nil)

	proxyTools := []string{
		"upstream_status",
		"mcp_tool_search",
		"mcp_tool_call",
		"mcp_resource_list",
		"mcp_resource_read",
	}
	for _, toolName := range proxyTools {
		t.Run(toolName, func(t *testing.T) {
			res, err := sess.CallTool(ctx, &mcp.CallToolParams{
				Name: "mcp_tool_call",
				Arguments: map[string]any{
					"upstream_id": uuid.New().String(),
					"tool_name":   toolName,
					"args":        map[string]any{},
				},
			})
			if err != nil {
				t.Fatalf("unexpected protocol error: %v", err)
			}
			if !res.IsError {
				t.Fatalf("expected IsError=true for proxy tool %q routed via mcp_tool_call", toolName)
			}
			if len(res.Content) == 0 {
				t.Fatal("expected non-empty error content")
			}
			msg := res.Content[0].(*mcp.TextContent).Text
			// The error must guide the agent: explain this is a proxy tool and
			// must be called directly, not routed through mcp_tool_call.
			if !strings.Contains(msg, "proxy") {
				t.Errorf("error message must mention 'proxy' to guide the agent; got: %q", msg)
			}
		})
	}
}

func TestMCPToolCall_InvalidUpstreamID(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	pool := mcpclient.NewPool(s, make([]byte, 32), nil, nil)
	t.Cleanup(pool.Close)

	proxySrv := mcpserver.New(pool, false)
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

	pool := mcpclient.NewPool(s, make([]byte, 32), nil, nil)
	t.Cleanup(pool.Close)

	proxySrv := mcpserver.New(pool, false)
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
