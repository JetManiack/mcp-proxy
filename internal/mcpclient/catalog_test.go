package mcpclient_test

import (
	"testing"

	"github.com/JetManiack/mcp-proxy/internal/mcpclient"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func testEntries() []*mcpclient.CatalogEntry {
	return []*mcpclient.CatalogEntry{
		{
			Tool:         &mcp.Tool{Name: "query_logs", Description: "Query log entries by label selector"},
			UpstreamName: "log-server",
			UpstreamID:   uuid.New(),
		},
		{
			Tool:         &mcp.Tool{Name: "query_metrics", Description: "Query time-series metrics via PromQL"},
			UpstreamName: "metrics-server",
			UpstreamID:   uuid.New(),
		},
		{
			Tool:         &mcp.Tool{Name: "search_issues", Description: "Search project issues by filter"},
			UpstreamName: "issue-tracker",
			UpstreamID:   uuid.New(),
		},
	}
}

func TestCatalogAll(t *testing.T) {
	cat := mcpclient.NewCatalog(testEntries())
	if len(cat.All()) != 3 {
		t.Fatalf("All: want 3, got %d", len(cat.All()))
	}
}

func TestCatalogSearch_Empty(t *testing.T) {
	cat := mcpclient.NewCatalog(testEntries())
	got := cat.Search("", 0)
	if len(got) != 3 {
		t.Fatalf("empty query: want 3, got %d", len(got))
	}
}

func TestCatalogSearch_SingleKeyword(t *testing.T) {
	cat := mcpclient.NewCatalog(testEntries())
	got := cat.Search("query", 0)
	if len(got) != 2 {
		t.Fatalf("'query': want 2, got %d", len(got))
	}
}

func TestCatalogSearch_MultiKeyword_OR(t *testing.T) {
	cat := mcpclient.NewCatalog(testEntries())
	// "logs metrics" matches both query_logs (via "logs") and query_metrics (via "metrics").
	got := cat.Search("logs metrics", 0)
	if len(got) != 2 {
		t.Fatalf("'logs metrics': want 2, got %d", len(got))
	}
}

func TestCatalogSearch_ByUpstreamName(t *testing.T) {
	cat := mcpclient.NewCatalog(testEntries())
	// "issue-tracker" is the upstream name, not part of tool name/description.
	got := cat.Search("issue-tracker", 0)
	if len(got) != 1 || got[0].Tool.Name != "search_issues" {
		t.Fatalf("'issue-tracker': want [search_issues], got %v", got)
	}
}

func TestCatalogSearch_CrossUpstream(t *testing.T) {
	cat := mcpclient.NewCatalog(testEntries())
	// "log-server metrics-server" spans two upstreams by upstream name.
	got := cat.Search("log-server metrics-server", 0)
	if len(got) != 2 {
		t.Fatalf("'log-server metrics-server': want 2, got %d", len(got))
	}
}

func TestCatalogSearch_CaseInsensitive(t *testing.T) {
	cat := mcpclient.NewCatalog(testEntries())
	got := cat.Search("PROMQL", 0)
	if len(got) != 1 {
		t.Fatalf("'PROMQL': want 1, got %d", len(got))
	}
}

func TestCatalogSearch_NoMatch(t *testing.T) {
	cat := mcpclient.NewCatalog(testEntries())
	got := cat.Search("kubernetes", 0)
	if len(got) != 0 {
		t.Fatalf("'kubernetes': want 0, got %d", len(got))
	}
}

func TestCatalogSearch_MaxResults(t *testing.T) {
	cat := mcpclient.NewCatalog(testEntries())
	got := cat.Search("", 2)
	if len(got) != 2 {
		t.Fatalf("maxResults=2: want 2, got %d", len(got))
	}
}

func TestCatalogSearch_EmptyCatalog(t *testing.T) {
	cat := mcpclient.NewCatalog(nil)
	got := cat.Search("anything", 0)
	if len(got) != 0 {
		t.Fatalf("empty catalog: want 0, got %d", len(got))
	}
}
