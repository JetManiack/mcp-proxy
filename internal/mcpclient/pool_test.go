package mcpclient_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/JetManiack/mcp-proxy/internal/mcpclient"
	"github.com/JetManiack/mcp-proxy/internal/store"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func openPoolTestStore(t *testing.T) *store.Store {
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

// newMockMCPServer creates a httptest.Server running an MCP server with one tool:
// "echo" that returns its first argument as text.
func newMockMCPServer(t *testing.T) *httptest.Server {
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

func TestPoolCallTool(t *testing.T) {
	s := openPoolTestStore(t)
	ctx := context.Background()

	hs := newMockMCPServer(t)

	up := &store.Upstream{
		Name:     "mock-" + uuid.New().String()[:8],
		URL:      hs.URL,
		AuthType: "none",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteUpstream(ctx, up.ID) })

	pool := mcpclient.NewPool(s, make([]byte, 32), nil, nil)
	t.Cleanup(pool.Close)

	res, err := pool.CallTool(ctx, uuid.Nil, up.ID, "echo", map[string]any{"msg": "hello"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatal("CallTool: empty content")
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "hello" {
		t.Errorf("CallTool: got %v, want TextContent{hello}", res.Content[0])
	}
}

func TestPoolGetCatalog(t *testing.T) {
	s := openPoolTestStore(t)
	ctx := context.Background()

	hs := newMockMCPServer(t)

	up := &store.Upstream{
		Name:     "catalog-" + uuid.New().String()[:8],
		URL:      hs.URL,
		AuthType: "none",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteUpstream(ctx, up.ID) })

	pool := mcpclient.NewPool(s, make([]byte, 32), nil, nil)
	t.Cleanup(pool.Close)

	cat, err := pool.GetCatalog(ctx, uuid.Nil)
	if err != nil {
		t.Fatalf("GetCatalog: %v", err)
	}

	found := false
	for _, e := range cat.All() {
		if e.UpstreamID == up.ID && e.Tool.Name == "echo" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GetCatalog: 'echo' tool from upstream %s not in catalog", up.ID)
	}
}

func TestPoolUpstreamStatuses_NeedsAuth(t *testing.T) {
	s := openPoolTestStore(t)
	ctx := context.Background()

	up := &store.Upstream{
		Name:         "oauth-" + uuid.New().String()[:8],
		URL:          "http://127.0.0.1:1", // unreachable, but status check comes first
		AuthType:     "oauth2_authorization_code",
		AuthEndpoint: "http://127.0.0.1:1/authorize",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteUpstream(ctx, up.ID) })

	pool := mcpclient.NewPool(s, make([]byte, 32), nil, nil)
	t.Cleanup(pool.Close)

	user, err := s.FindOrCreateUser(ctx, "status-user-"+uuid.New().String()+"@example.com", "Status User")
	if err != nil {
		t.Fatalf("FindOrCreateUser: %v", err)
	}

	statuses, err := pool.UpstreamStatuses(ctx, user.ID)
	if err != nil {
		t.Fatalf("UpstreamStatuses: %v", err)
	}

	for _, st := range statuses {
		if st.UpstreamID == up.ID {
			if st.Status != "needs_auth" {
				t.Errorf("expected needs_auth, got %q", st.Status)
			}
			return
		}
	}
	t.Fatal("upstream not found in statuses")
}
