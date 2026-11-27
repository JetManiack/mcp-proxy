package upstream

import (
	"context"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

// StoreTestToken persists a token directly for testing ProactiveRefresh and
// related flows. Uses uuid.Nil as the userID (shared oauth2 token slot).
func (m *Manager) StoreTestToken(ctx context.Context, upstreamID uuid.UUID, access, refresh string, expiry time.Time) error {
	tok := &oauth2.Token{
		AccessToken:  access,
		RefreshToken: refresh,
		Expiry:       expiry,
	}
	return m.storeToken(ctx, upstreamID, uuid.Nil, tok)
}
