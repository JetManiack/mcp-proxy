package mcpclient

import (
	"math"
	"sort"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CatalogEntry associates an MCP tool with the upstream that provides it.
type CatalogEntry struct {
	Tool         *mcp.Tool
	UpstreamID   uuid.UUID
	UpstreamName string
}

// BM25 parameters.
const (
	bm25K1 = 1.5
	bm25B  = 0.75

	// Field weights: a match in the tool name matters more than in the description.
	fieldWeightName     = 3.0
	fieldWeightUpstream = 2.0
	fieldWeightDesc     = 1.0
)

// indexedEntry holds the pre-computed per-field term frequencies for one entry.
type indexedEntry struct {
	entry    *CatalogEntry
	nameFreq map[string]int
	upFreq   map[string]int
	descFreq map[string]int
	nameLen  float64
	upLen    float64
	descLen  float64
}

// Catalog is an in-memory BM25F index over tools from all reachable upstreams.
// It is built once at construction and is read-only after that.
type Catalog struct {
	entries    []*CatalogEntry
	indexed    []indexedEntry
	idf        map[string]float64 // term → IDF score
	avgNameLen float64
	avgUpLen   float64
	avgDescLen float64
}

// NewCatalog creates a Catalog and builds the BM25 index.
func NewCatalog(entries []*CatalogEntry) *Catalog {
	c := &Catalog{entries: entries}
	c.buildIndex()
	return c
}

// All returns all entries in insertion order.
func (c *Catalog) All() []*CatalogEntry {
	return c.entries
}

// Search scores every entry with BM25F over three weighted fields
// (name > upstreamName > description) and returns up to maxResults
// entries sorted by relevance. An empty query returns all entries.
func (c *Catalog) Search(query string, maxResults int) []*CatalogEntry {
	terms := tokenize(query)

	if len(terms) == 0 {
		if maxResults <= 0 || maxResults >= len(c.entries) {
			return c.entries
		}
		return c.entries[:maxResults]
	}

	type hit struct {
		entry *CatalogEntry
		score float64
	}
	var hits []hit
	for i := range c.indexed {
		s := c.score(&c.indexed[i], terms)
		if s > 0 {
			hits = append(hits, hit{c.indexed[i].entry, s})
		}
	}

	sort.Slice(hits, func(i, j int) bool { return hits[i].score > hits[j].score })

	if maxResults > 0 && len(hits) > maxResults {
		hits = hits[:maxResults]
	}
	out := make([]*CatalogEntry, len(hits))
	for i, h := range hits {
		out[i] = h.entry
	}
	return out
}

// buildIndex computes per-field term frequencies, IDF scores, and average
// field lengths across the whole catalog.
func (c *Catalog) buildIndex() {
	n := len(c.entries)
	if n == 0 {
		c.idf = make(map[string]float64)
		return
	}

	c.indexed = make([]indexedEntry, n)
	df := make(map[string]int) // document frequency: number of entries containing term

	var totalNameLen, totalUpLen, totalDescLen float64

	for i, e := range c.entries {
		ie := indexedEntry{
			entry:    e,
			nameFreq: termFreq(tokenize(e.Tool.Name)),
			upFreq:   termFreq(tokenize(e.UpstreamName)),
			descFreq: termFreq(tokenize(e.Tool.Description)),
		}
		ie.nameLen = float64(len(tokenize(e.Tool.Name)))
		ie.upLen = float64(len(tokenize(e.UpstreamName)))
		ie.descLen = float64(len(tokenize(e.Tool.Description)))

		totalNameLen += ie.nameLen
		totalUpLen += ie.upLen
		totalDescLen += ie.descLen

		// Count each term once per document regardless of field.
		seen := make(map[string]bool)
		for t := range ie.nameFreq {
			if !seen[t] {
				df[t]++
				seen[t] = true
			}
		}
		for t := range ie.upFreq {
			if !seen[t] {
				df[t]++
				seen[t] = true
			}
		}
		for t := range ie.descFreq {
			if !seen[t] {
				df[t]++
				seen[t] = true
			}
		}

		c.indexed[i] = ie
	}

	fn := float64(n)
	c.avgNameLen = totalNameLen / fn
	c.avgUpLen = totalUpLen / fn
	c.avgDescLen = totalDescLen / fn
	// Guard against zero-length averages to avoid division by zero in bm25TF.
	if c.avgNameLen == 0 {
		c.avgNameLen = 1
	}
	if c.avgUpLen == 0 {
		c.avgUpLen = 1
	}
	if c.avgDescLen == 0 {
		c.avgDescLen = 1
	}

	c.idf = make(map[string]float64, len(df))
	for term, freq := range df {
		// Robertson-Sparck Jones IDF: log((N+1)/(df+0.5))
		c.idf[term] = math.Log((fn + 1) / (float64(freq) + 0.5))
	}
}

// score computes the BM25F relevance of an entry for a set of query terms.
func (c *Catalog) score(ie *indexedEntry, terms []string) float64 {
	var total float64
	for _, t := range terms {
		idf, ok := c.idf[t]
		if !ok {
			continue
		}
		fieldScore := fieldWeightName*bm25TF(ie.nameFreq[t], ie.nameLen, c.avgNameLen) +
			fieldWeightUpstream*bm25TF(ie.upFreq[t], ie.upLen, c.avgUpLen) +
			fieldWeightDesc*bm25TF(ie.descFreq[t], ie.descLen, c.avgDescLen)
		total += idf * fieldScore
	}
	return total
}

// bm25TF computes the BM25 term-frequency component for one field.
func bm25TF(tf int, docLen, avgDocLen float64) float64 {
	if tf == 0 {
		return 0
	}
	f := float64(tf)
	return f * (bm25K1 + 1) / (f + bm25K1*(1-bm25B+bm25B*docLen/avgDocLen))
}

// tokenize lowercases text and splits on any non-alphanumeric character
// (spaces, underscores, hyphens, slashes, etc.).
// "thanos_query_instant" → ["thanos", "query", "instant"]
func tokenize(text string) []string {
	return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// termFreq counts how many times each token appears in a slice.
func termFreq(tokens []string) map[string]int {
	m := make(map[string]int, len(tokens))
	for _, t := range tokens {
		m[t]++
	}
	return m
}
