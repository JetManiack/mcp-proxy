package mcpclient

import (
	"strings"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CatalogEntry associates an MCP tool with the upstream that provides it.
type CatalogEntry struct {
	Tool         *mcp.Tool
	UpstreamID   uuid.UUID
	UpstreamName string
}

// Catalog is an in-memory index over tools from all reachable upstreams.
type Catalog struct {
	entries []*CatalogEntry
}

// NewCatalog creates a Catalog from a slice of entries.
func NewCatalog(entries []*CatalogEntry) *Catalog {
	return &Catalog{entries: entries}
}

// All returns all entries.
func (c *Catalog) All() []*CatalogEntry {
	return c.entries
}

// Search returns entries that match any whitespace-separated keyword in query
// (case-insensitive OR match across tool name, description, and upstream name).
// If maxResults > 0, at most that many entries are returned.
// An empty query returns all entries (up to maxResults).
func (c *Catalog) Search(query string, maxResults int) []*CatalogEntry {
	keywords := strings.Fields(strings.ToLower(query))

	var results []*CatalogEntry
	for _, e := range c.entries {
		if matchAny(e, keywords) {
			results = append(results, e)
			if maxResults > 0 && len(results) >= maxResults {
				break
			}
		}
	}
	return results
}

func matchAny(e *CatalogEntry, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	hay := strings.ToLower(e.Tool.Name + " " + e.Tool.Description + " " + e.UpstreamName)
	for _, kw := range keywords {
		if strings.Contains(hay, kw) {
			return true
		}
	}
	return false
}
