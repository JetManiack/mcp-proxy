// Package mcpserver exposes virtual MCP tools to downstream agents.
//
// Initial tool set (all sessions):
//   - mcp_tool_search   — keyword search; activates found tools natively for the session
//   - upstream_status   — list connectivity/auth state for all upstreams
//   - mcp_resource_list — list documentation resources across all upstreams
//   - mcp_resource_read — read a documentation resource by namespaced URI
//
// Lazy activation: calling mcp_tool_search activates the matched upstream tools
// as native MCP tools with their original inputSchema. Subsequent calls go
// directly to the upstream without any wrapping.
package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/JetManiack/mcp-proxy/internal/mcpclient"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// sessionState holds a per-session mcp.Server and the set of already-activated
// native tool names (to avoid redundant AddTool calls).
type sessionState struct {
	srv            *mcp.Server
	activatedTools map[string]bool
}

// Server manages per-session MCP servers with lazy native-tool activation.
type Server struct {
	pool *mcpclient.Pool

	mu       sync.Mutex
	sessions map[string]*sessionState // sessionID → state
}

// New creates the proxy MCP server.
func New(pool *mcpclient.Pool) *Server {
	return &Server{
		pool:     pool,
		sessions: make(map[string]*sessionState),
	}
}

// Handler returns an http.Handler serving the MCP protocol.
func (s *Server) Handler() http.Handler {
	return mcp.NewStreamableHTTPHandler(s.getServer, nil)
}

// getServer is called by the streamable HTTP handler once per new client
// session. It creates a fresh mcp.Server with a predetermined session ID,
// registers the base tools, and stores the session in the registry so the
// mcp_tool_search handler can add native tools to it later.
func (s *Server) getServer(_ *http.Request) *mcp.Server {
	newID := uuid.New().String()

	srv := mcp.NewServer(
		&mcp.Implementation{Name: "mcp-proxy", Version: "v0.1.0"},
		&mcp.ServerOptions{
			GetSessionID: func() string { return newID },
		},
	)

	state := &sessionState{
		srv:            srv,
		activatedTools: make(map[string]bool),
	}

	mcp.AddTool(srv, toolSearch, s.makeSearchHandler(newID))
	mcp.AddTool(srv, toolStatus, s.handleStatus)
	mcp.AddTool(srv, toolResourceList, s.handleResourceList)
	mcp.AddTool(srv, toolResourceRead, s.handleResourceRead)
	srv.AddResource(proxyGuideResource, handleProxyGuide)

	s.mu.Lock()
	s.sessions[newID] = state
	s.mu.Unlock()

	go s.watchSession(newID, srv)

	return srv
}

// watchSession removes the session state from the registry once the client
// disconnects. It polls srv.Sessions() every 30 seconds:
//   - once a client connects (everConnected=true) and then goes away → clean up
//   - if no client ever connects within 5 minutes → clean up (aborted connect)
func (s *Server) watchSession(id string, srv *mcp.Server) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	created := time.Now()
	everConnected := false

	for range ticker.C {
		hasActive := false
		for range srv.Sessions() {
			hasActive = true
			break
		}
		switch {
		case hasActive:
			everConnected = true
		case everConnected:
			s.mu.Lock()
			delete(s.sessions, id)
			s.mu.Unlock()
			slog.Debug("mcpserver: session cleaned up", "session", id)
			return
		case time.Since(created) > 5*time.Minute:
			s.mu.Lock()
			delete(s.sessions, id)
			s.mu.Unlock()
			slog.Debug("mcpserver: session cleaned up (never connected)", "session", id)
			return
		}
	}
}

// ---- tool definitions -------------------------------------------------------

var toolSearch = &mcp.Tool{
	Name:        "mcp_tool_search",
	Description: "Search for tools across all connected upstream MCP servers by keyword. Activates matched tools as native MCP tools for this session — subsequent calls use the tool name directly without any wrapper.",
}

var toolStatus = &mcp.Tool{
	Name:        "upstream_status",
	Description: "List the connectivity and authorization status of all configured upstream MCP servers.",
}

var proxyGuideResource = &mcp.Resource{
	URI:         "resource://mcp-proxy/guide",
	Name:        "MCP Proxy — Agent Guide",
	Description: "How to discover and call tools and resources from upstream MCP servers through this proxy.",
	MIMEType:    "text/markdown",
}

const proxyGuideText = `# MCP Proxy — Agent Guide

This proxy aggregates multiple upstream MCP servers behind a single endpoint. You authenticate once with an agent token; the proxy handles per-upstream authentication transparently.

## Discovering and calling tools

Tools are loaded lazily per session. Use ` + "`mcp_tool_search`" + ` to discover and activate them:

1. ` + "`mcp_tool_search`" + ` with keywords → returns tool names, descriptions, and input schemas
2. After the search, found tools appear directly in your tool list with their original JSON Schema
3. Call the tool by its original name — no wrapper needed

Example:
` + "```" + `
mcp_tool_search(query="prometheus query")
→ [{"tool_name":"thanos_query_instant","input_schema":{"required":["query"],...}}]

thanos_query_instant(query="up{job='mcp-proxy'}")
→ <prometheus result>
` + "```" + `

## Reading upstream documentation

` + "```" + `
mcp_resource_list()
→ [{"uri":"docs-server/api-reference","name":"api-reference"}, ...]

mcp_resource_read(uri="docs-server/api-reference")
→ <markdown content>
` + "```" + `

## Authorization states

Some upstreams require OAuth2 authorization (initiated via the web UI). The ` + "`upstream_status`" + ` tool shows:
- **connected** — ready, tools available
- **needs_auth** — user must authorize via the web UI
- **pending_discovery** — OAuth endpoints being discovered (retry in ~30s)
- **unreachable** — network or auth error
`

func handleProxyGuide(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{
			{URI: proxyGuideResource.URI, MIMEType: "text/markdown", Text: proxyGuideText},
		},
	}, nil
}

var toolResourceList = &mcp.Tool{
	Name:        "mcp_resource_list",
	Description: "List all documentation resources available across all connected upstream MCP servers. Each resource has a namespaced URI of the form 'upstream_name/resource_path'. Pass this URI to mcp_resource_read to retrieve the content.",
}

var toolResourceRead = &mcp.Tool{
	Name:        "mcp_resource_read",
	Description: "Read a documentation resource from an upstream MCP server. Use mcp_resource_list first to discover available resources and their namespaced URIs.",
}

// ---- handlers ---------------------------------------------------------------

type searchArgs struct {
	Query      string `json:"query"       jsonschema:"Keywords to search for in tool names and descriptions"`
	MaxResults *int   `json:"max_results,omitempty" jsonschema:"Maximum number of results to return (default 20)"`
}

type statusArgs struct{}

// makeSearchHandler returns the mcp_tool_search handler bound to sessionID.
// When called, it searches the catalog, activates newly found tools as native
// MCP tools in the session's server (triggering tools/list_changed), and
// returns the full search results so the agent knows what is now available.
func (s *Server) makeSearchHandler(sessionID string) func(context.Context, *mcp.CallToolRequest, searchArgs) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, args searchArgs) (*mcp.CallToolResult, any, error) {
		max := 20
		if args.MaxResults != nil && *args.MaxResults > 0 {
			max = *args.MaxResults
		}

		cat, err := s.pool.GetCatalog(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("mcp_tool_search: get catalog: %w", err)
		}

		entries := cat.Search(args.Query, max)

		// Determine which tools are newly found (not yet activated in this session).
		s.mu.Lock()
		state, ok := s.sessions[sessionID]
		toActivate := make([]*mcpclient.CatalogEntry, 0, len(entries))
		if ok {
			for _, e := range entries {
				if !state.activatedTools[e.Tool.Name] {
					state.activatedTools[e.Tool.Name] = true
					toActivate = append(toActivate, e)
				}
			}
		}
		s.mu.Unlock()

		// Add native tools outside the lock. mcp.AddTool sends
		// notifications/tools/list_changed to the session automatically.
		if ok {
			for _, e := range toActivate {
				upstreamID := e.UpstreamID
				toolName := e.Tool.Name
				nativeTool := &mcp.Tool{
					Name:        e.Tool.Name,
					Description: e.Tool.Description,
					InputSchema: e.Tool.InputSchema,
				}
				mcp.AddTool(state.srv, nativeTool,
					func(ctx context.Context, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, any, error) {
						return s.callUpstreamTool(ctx, upstreamID, toolName, args)
					},
				)
			}
			if len(toActivate) > 0 {
				slog.Debug("mcpserver: activated native tools",
					"session", sessionID, "count", len(toActivate))
			}
		}

		// Build response with tool metadata for the agent.
		type result struct {
			ToolName     string          `json:"tool_name"`
			Description  string          `json:"description"`
			UpstreamID   string          `json:"upstream_id"`
			UpstreamName string          `json:"upstream_name"`
			InputSchema  json.RawMessage `json:"input_schema,omitempty"`
		}
		out := make([]result, 0, len(entries))
		for _, e := range entries {
			var schema json.RawMessage
			if e.Tool.InputSchema != nil {
				if b, err := json.Marshal(e.Tool.InputSchema); err == nil {
					schema = b
				} else {
					slog.Warn("mcp_tool_search: marshal input_schema", "tool", e.Tool.Name, "err", err)
				}
			}
			out = append(out, result{
				ToolName:     e.Tool.Name,
				Description:  e.Tool.Description,
				UpstreamID:   e.UpstreamID.String(),
				UpstreamName: e.UpstreamName,
				InputSchema:  schema,
			})
		}

		b, _ := json.Marshal(out)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
		}, nil, nil
	}
}

// callUpstreamTool proxies a native tool call to the upstream. Called by
// handlers installed via mcp.AddTool for each lazily activated tool.
func (s *Server) callUpstreamTool(ctx context.Context, upstreamID uuid.UUID, toolName string, args map[string]any) (*mcp.CallToolResult, any, error) {
	userID := userIDFromContext(ctx)
	res, err := s.pool.CallTool(ctx, userID, upstreamID, toolName, args)
	if err != nil {
		slog.Warn("mcpserver: upstream tool call failed",
			"upstream_id", upstreamID, "tool", toolName, "err", err)
		switch {
		case errors.Is(err, mcpclient.ErrToolDisabled):
			return errorResult(fmt.Sprintf(
				"tool %q is disabled; it was turned off via the admin UI",
				toolName,
			)), nil, nil
		case errors.Is(err, mcpclient.ErrUpstreamUnreachable):
			return errorResult(fmt.Sprintf(
				"upstream %s is unreachable; call upstream_status to check authorization state",
				upstreamID,
			)), nil, nil
		case errors.Is(err, mcpclient.ErrUpstreamNotFound):
			return errorResult(fmt.Sprintf(
				"upstream %s not found",
				upstreamID,
			)), nil, nil
		}
		return errorResult(err.Error()), nil, nil
	}
	return res, nil, nil
}

func (s *Server) handleStatus(ctx context.Context, req *mcp.CallToolRequest, _ statusArgs) (*mcp.CallToolResult, any, error) {
	userID := userIDFromContext(ctx)

	statuses, err := s.pool.UpstreamStatuses(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("upstream_status: %w", err)
	}

	type row struct {
		UpstreamID   string `json:"upstream_id"`
		UpstreamName string `json:"upstream_name"`
		AuthType     string `json:"auth_type"`
		Status       string `json:"status"`
		Error        string `json:"error,omitempty"`
	}
	out := make([]row, 0, len(statuses))
	for _, st := range statuses {
		out = append(out, row{
			UpstreamID:   st.UpstreamID.String(),
			UpstreamName: st.UpstreamName,
			AuthType:     st.AuthType,
			Status:       st.Status,
			Error:        st.Error,
		})
	}

	b, _ := json.Marshal(out)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}, nil, nil
}

type resourceListArgs struct{}

type resourceReadArgs struct {
	NamespacedURI string `json:"uri" jsonschema:"Namespaced resource URI from mcp_resource_list (format: 'upstream_name/resource_path')"`
}

func (s *Server) handleResourceList(ctx context.Context, req *mcp.CallToolRequest, _ resourceListArgs) (*mcp.CallToolResult, any, error) {
	userID := userIDFromContext(ctx)

	resources, err := s.pool.ListAllResources(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("mcp_resource_list: %w", err)
	}

	type row struct {
		URI          string `json:"uri"`
		Name         string `json:"name"`
		Description  string `json:"description,omitempty"`
		MIMEType     string `json:"mime_type,omitempty"`
		UpstreamName string `json:"upstream_name"`
	}
	out := make([]row, 0, len(resources))
	for _, nr := range resources {
		out = append(out, row{
			URI:          nr.NamespacedURI,
			Name:         nr.Resource.Name,
			Description:  nr.Resource.Description,
			MIMEType:     nr.Resource.MIMEType,
			UpstreamName: nr.UpstreamName,
		})
	}

	b, _ := json.Marshal(out)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}, nil, nil
}

func (s *Server) handleResourceRead(ctx context.Context, req *mcp.CallToolRequest, args resourceReadArgs) (*mcp.CallToolResult, any, error) {
	if args.NamespacedURI == "" {
		return errorResult("uri is required"), nil, nil
	}

	userID := userIDFromContext(ctx)

	resources, err := s.pool.ListAllResources(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("mcp_resource_read: list resources: %w", err)
	}

	var found *mcpclient.NamespacedResource
	for _, nr := range resources {
		if nr.NamespacedURI == args.NamespacedURI {
			found = nr
			break
		}
	}
	if found == nil {
		return errorResult(fmt.Sprintf("resource %q not found", args.NamespacedURI)), nil, nil
	}

	result, err := s.pool.ReadUpstreamResource(ctx, found.UpstreamID, userID, found.Resource.URI)
	if err != nil {
		return errorResult(err.Error()), nil, nil
	}

	var parts []mcp.Content
	for _, c := range result.Contents {
		if c.Text != "" {
			parts = append(parts, &mcp.TextContent{Text: c.Text})
		} else if len(c.Blob) > 0 {
			parts = append(parts, &mcp.TextContent{Text: fmt.Sprintf("[binary resource, mime: %s, %d bytes]", c.MIMEType, len(c.Blob))})
		}
	}
	if len(parts) == 0 {
		return errorResult("resource returned no content"), nil, nil
	}
	return &mcp.CallToolResult{Content: parts}, nil, nil
}

// ---- helpers ----------------------------------------------------------------

func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}

// contextKeyUserID is the context key for the authenticated user's UUID.
// The web layer injects it via WithUserID before the MCP handler runs.
type contextKeyUserID struct{}

// WithUserID returns a context carrying the authenticated user's UUID.
// Called by the HTTP middleware that wraps the MCP handler.
func WithUserID(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, contextKeyUserID{}, userID)
}

// userIDFromContext extracts the caller's user UUID injected by the HTTP
// middleware. Falls back to uuid.Nil when not set (e.g. in unit tests).
func userIDFromContext(ctx context.Context) uuid.UUID {
	if uid, ok := ctx.Value(contextKeyUserID{}).(uuid.UUID); ok {
		return uid
	}
	return uuid.Nil
}
