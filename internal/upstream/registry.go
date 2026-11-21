package upstream

import (
	"context"
	"fmt"
	"net/http"

	"github.com/JetManiack/mcp-proxy/internal/store"
	"github.com/google/uuid"
)

// Registry wraps store CRUD for upstreams and runs discovery on demand.
type Registry struct {
	store  *store.Store
	client *http.Client
}

func NewRegistry(s *store.Store, client *http.Client) *Registry {
	return &Registry{store: s, client: client}
}

func (r *Registry) Create(ctx context.Context, u *store.Upstream) error {
	return r.store.CreateUpstream(ctx, u)
}

func (r *Registry) List(ctx context.Context) ([]*store.Upstream, error) {
	return r.store.ListUpstreams(ctx)
}

func (r *Registry) Get(ctx context.Context, id uuid.UUID) (*store.Upstream, error) {
	return r.store.GetUpstream(ctx, id)
}

func (r *Registry) Update(ctx context.Context, u *store.Upstream) error {
	return r.store.UpdateUpstream(ctx, u)
}

func (r *Registry) Delete(ctx context.Context, id uuid.UUID) error {
	return r.store.DeleteUpstream(ctx, id)
}

// Probe probes the upstream URL to auto-detect its auth type and, for oauth2,
// runs the full discovery chain.
func (r *Registry) Probe(ctx context.Context, rawURL string) (*ProbeResult, error) {
	return ProbeAuthType(ctx, r.client, rawURL)
}

// Discover fetches OAuth metadata for the upstream and stores the discovered
// endpoints back into the upstream record.
func (r *Registry) Discover(ctx context.Context, id uuid.UUID) error {
	up, err := r.store.GetUpstream(ctx, id)
	if err != nil {
		return err
	}
	meta, err := Discover(ctx, r.client, up.URL)
	if err != nil {
		return fmt.Errorf("upstream: registry discover %s: %w", id, err)
	}
	return r.StoreDiscovered(ctx, id, meta)
}

// StoreDiscovered validates and persists discovered OAuth endpoints for an upstream.
func (r *Registry) StoreDiscovered(ctx context.Context, id uuid.UUID, meta *Meta) error {
	up, err := r.store.GetUpstream(ctx, id)
	if err != nil {
		return err
	}
	for _, ep := range []struct{ name, u string }{
		{"authorization_endpoint", meta.AuthorizationEndpoint},
		{"token_endpoint", meta.TokenEndpoint},
	} {
		if err := requireHTTPS(ep.name, ep.u); err != nil {
			return fmt.Errorf("upstream: registry discover %s: %w", id, err)
		}
	}
	if meta.DCREndpoint != "" {
		if err := requireHTTPS("registration_endpoint", meta.DCREndpoint); err != nil {
			return fmt.Errorf("upstream: registry discover %s: %w", id, err)
		}
	}
	up.AuthEndpoint    = meta.AuthorizationEndpoint
	up.TokenEndpoint   = meta.TokenEndpoint
	up.DCREndpoint     = meta.DCREndpoint
	up.ClientIDMetaDoc = meta.ClientIDMetadataDocumentSupported
	return r.store.UpdateUpstream(ctx, up)
}
