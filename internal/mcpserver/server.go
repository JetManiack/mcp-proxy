// Package mcpserver exposes virtual MCP tools to downstream agents:
//
//   - mcp_tool_search   — keyword search over all upstream tools
//   - mcp_tool_call     — call a specific upstream tool on behalf of the caller
//   - upstream_status   — list connectivity/auth state for all upstreams
//   - mcp_resource_list — list documentation resources across all upstreams
//   - mcp_resource_read — read a documentation resource by namespaced URI
package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/JetManiack/mcp-proxy/internal/mcpclient"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server wraps an MCP server that proxies tool calls to upstream MCP servers.
type Server struct {
	pool   *mcpclient.Pool
	server *mcp.Server
}

// New creates and registers the virtual tools on a fresh MCP server.
func New(pool *mcpclient.Pool) *Server {
	s := &Server{pool: pool}
	s.server = mcp.NewServer(
		&mcp.Implementation{Name: "mcp-proxy", Version: "v0.1.0"},
		nil,
	)
	mcp.AddTool(s.server, toolSearch, s.handleSearch)
	mcp.AddTool(s.server, toolCall, s.handleCall)
	mcp.AddTool(s.server, toolStatus, s.handleStatus)
	mcp.AddTool(s.server, toolResourceList, s.handleResourceList)
	mcp.AddTool(s.server, toolResourceRead, s.handleResourceRead)
	s.server.AddResource(proxyGuideResource, handleProxyGuide)
	return s
}

// Handler returns an http.Handler serving the MCP protocol.
func (s *Server) Handler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return s.server
	}, nil)
}

// ---- tool definitions -------------------------------------------------------

var toolSearch = &mcp.Tool{
	Name:        "mcp_tool_search",
	Description: "Search for tools across all connected upstream MCP servers by keyword. Returns matching tool names, descriptions, and their upstream IDs.",
}

var toolCall = &mcp.Tool{
	Name:        "mcp_tool_call",
	Description: "Call a specific tool on a specific upstream MCP server. Use mcp_tool_search first to find the right upstream_id and tool_name.",
}

var toolStatus = &mcp.Tool{
	Name:        "upstream_status",
	Description: "List the connectivity and authorization status of all configured upstream MCP servers for the current user.",
}

var proxyGuideResource = &mcp.Resource{
	URI:         "resource://mcp-proxy/guide",
	Name:        "MCP Proxy — Agent Guide",
	Description: "How to discover and call tools and resources from upstream MCP servers through this proxy.",
	MIMEType:    "text/markdown",
}

const proxyGuideText = `# MCP Proxy — Agent Guide

This proxy aggregates multiple upstream MCP servers behind a single endpoint. You authenticate once with an agent token; the proxy handles per-upstream authentication transparently.

## Available tools

| Tool | Purpose |
|------|---------|
` + "`mcp_tool_search`" + ` | Search for tools across all connected upstreams by keyword |
` + "`mcp_tool_call`" + ` | Call a specific tool on a specific upstream |
` + "`upstream_status`" + ` | Check connectivity and auth status of all upstreams |
` + "`mcp_resource_list`" + ` | List all documentation resources from all upstreams |
` + "`mcp_resource_read`" + ` | Read the content of a specific resource |

## Discovering and calling a tool

1. Search: ` + "`mcp_tool_search`" + ` with keywords → returns tool_name + upstream_id pairs
2. Call: ` + "`mcp_tool_call`" + ` with the upstream_id and tool_name from step 1

Example flow:
` + "```" + `
mcp_tool_search(query="execute command")
→ [{"tool_name":"exec_command","upstream_id":"...","upstream_name":"sandbox"}]

mcp_tool_call(upstream_id="...", tool_name="exec_command", args={"command":"echo hi"})
` + "```" + `

## Reading upstream documentation

Upstreams can expose documentation as MCP resources. URIs are namespaced as ` + "`upstream_name/resource_path`" + ` to avoid conflicts.

` + "```" + `
mcp_resource_list()
→ [{"uri":"docs-server/api-reference","name":"api-reference"}, ...]

mcp_resource_read(uri="docs-server/api-reference")
→ <markdown content>
` + "```" + `

## Authorization states

Some upstreams require per-user OAuth2 authorization (initiated via the web UI). The ` + "`upstream_status`" + ` tool shows:
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
	Description: "List all documentation resources available across all connected upstream MCP servers. Each resource has a namespaced URI of the form 'upstream_name/resource_path' (e.g. 'docs-server/api-reference'). Pass this URI to mcp_resource_read to retrieve the content.",
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

type callArgs struct {
	UpstreamID string         `json:"upstream_id" jsonschema:"UUID of the upstream MCP server (from mcp_tool_search)"`
	ToolName   string         `json:"tool_name"   jsonschema:"Name of the tool to call"`
	Args       map[string]any `json:"args"        jsonschema:"Arguments to pass to the tool"`
}

type statusArgs struct{}

func (s *Server) handleSearch(ctx context.Context, req *mcp.CallToolRequest, args searchArgs) (*mcp.CallToolResult, any, error) {
	userID := userIDFromContext(ctx, req)

	max := 20
	if args.MaxResults != nil && *args.MaxResults > 0 {
		max = *args.MaxResults
	}

	cat, err := s.pool.GetCatalog(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("mcp_tool_search: get catalog: %w", err)
	}

	entries := cat.Search(args.Query, max)

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
			if b, err := json.Marshal(e.Tool.InputSchema); err != nil {
				slog.Warn("mcp_tool_search: marshal input_schema", "tool", e.Tool.Name, "err", err)
			} else {
				schema = b
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

// proxyToolNames lists tools provided by the proxy itself. Routing them through
// mcp_tool_call to an upstream is always wrong; return a clear error so agents
// don't loop on "unknown tool" responses.
var proxyToolNames = map[string]bool{
	"mcp_tool_search":   true,
	"mcp_tool_call":     true,
	"upstream_status":   true,
	"mcp_resource_list": true,
	"mcp_resource_read": true,
}

func (s *Server) handleCall(ctx context.Context, req *mcp.CallToolRequest, args callArgs) (*mcp.CallToolResult, any, error) {
	if args.ToolName == "" {
		return errorResult("tool_name is required"), nil, nil
	}

	if proxyToolNames[args.ToolName] {
		return errorResult(fmt.Sprintf(
			"%q is a proxy-level tool; call it directly without upstream_id (do not route it through mcp_tool_call)",
			args.ToolName,
		)), nil, nil
	}

	if args.UpstreamID == "" {
		return errorResult("upstream_id is required"), nil, nil
	}

	upstreamID, err := uuid.Parse(args.UpstreamID)
	if err != nil {
		return errorResult(fmt.Sprintf("invalid upstream_id: %v", err)), nil, nil
	}

	userID := userIDFromContext(ctx, req)

	res, err := s.pool.CallTool(ctx, userID, upstreamID, args.ToolName, args.Args)
	if err != nil {
		slog.Warn("mcp_tool_call failed", "upstream_id", upstreamID, "tool", args.ToolName, "err", err)
		switch {
		case errors.Is(err, mcpclient.ErrUpstreamNotFound):
			return errorResult(fmt.Sprintf(
				"upstream_id %q not found; call upstream_status to list valid upstream IDs",
				args.UpstreamID,
			)), nil, nil
		case errors.Is(err, mcpclient.ErrToolDisabled):
			return errorResult(fmt.Sprintf(
				"tool %q is disabled on this upstream; it was turned off via the admin UI",
				args.ToolName,
			)), nil, nil
		case errors.Is(err, mcpclient.ErrUpstreamUnreachable):
			return errorResult(fmt.Sprintf(
				"upstream %q is unreachable; call upstream_status to check authorization state",
				args.UpstreamID,
			)), nil, nil
		}
		return errorResult(err.Error()), nil, nil
	}
	return res, nil, nil
}

func (s *Server) handleStatus(ctx context.Context, req *mcp.CallToolRequest, _ statusArgs) (*mcp.CallToolResult, any, error) {
	userID := userIDFromContext(ctx, req)

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
	userID := userIDFromContext(ctx, req)

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

	userID := userIDFromContext(ctx, req)

	// Resolve namespaced URI → upstream ID + original URI.
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
// middleware. Falls back to uuid.Nil when not set (e.g. in unit tests),
// which causes the pool to use the shared (non-per-user) session.
func userIDFromContext(ctx context.Context, _ *mcp.CallToolRequest) uuid.UUID {
	if uid, ok := ctx.Value(contextKeyUserID{}).(uuid.UUID); ok {
		return uid
	}
	return uuid.Nil
}
