package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/JetManiack/mcp-proxy/internal/store"
	"github.com/google/uuid"
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

func TestFindOrCreateUser(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	email := "user-" + uuid.New().String() + "@example.com"

	u1, err := s.FindOrCreateUser(ctx, email, "Test User")
	if err != nil {
		t.Fatalf("FindOrCreateUser: %v", err)
	}
	if u1.Email != email {
		t.Errorf("Email: got %q, want %q", u1.Email, email)
	}
	if u1.ID == (uuid.UUID{}) {
		t.Error("ID should be non-zero after create")
	}

	// Idempotent: same email → same record, DisplayName not updated.
	u2, err := s.FindOrCreateUser(ctx, email, "Different Name")
	if err != nil {
		t.Fatalf("FindOrCreateUser (second call): %v", err)
	}
	if u1.ID != u2.ID {
		t.Errorf("second call returned different ID: %s vs %s", u1.ID, u2.ID)
	}
}

func TestUpstreamCRUD(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	up := &store.Upstream{
		Name:     "upstream-" + uuid.New().String()[:8],
		URL:      "https://mcp.example.com",
		AuthType: "none",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	if up.ID == (uuid.UUID{}) {
		t.Fatal("CreateUpstream: ID should be set after create")
	}
	defer func() { _ = s.DeleteUpstream(ctx, up.ID) }()

	// List includes the created upstream.
	list, err := s.ListUpstreams(ctx)
	if err != nil {
		t.Fatalf("ListUpstreams: %v", err)
	}
	found := false
	for _, u := range list {
		if u.ID == up.ID {
			found = true
		}
	}
	if !found {
		t.Error("ListUpstreams: created upstream not found")
	}

	// Get by ID.
	got, err := s.GetUpstream(ctx, up.ID)
	if err != nil {
		t.Fatalf("GetUpstream: %v", err)
	}
	if got.Name != up.Name {
		t.Errorf("GetUpstream Name: got %q, want %q", got.Name, up.Name)
	}

	// Update.
	up.URL = "https://mcp2.example.com"
	if err := s.UpdateUpstream(ctx, up); err != nil {
		t.Fatalf("UpdateUpstream: %v", err)
	}
	got, _ = s.GetUpstream(ctx, up.ID)
	if got.URL != "https://mcp2.example.com" {
		t.Errorf("after update URL: got %q", got.URL)
	}

	// Delete removes the record.
	if err := s.DeleteUpstream(ctx, up.ID); err != nil {
		t.Fatalf("DeleteUpstream: %v", err)
	}
	if _, err := s.GetUpstream(ctx, up.ID); err == nil {
		t.Error("GetUpstream after delete: expected error, got nil")
	}

	// Delete on non-existent ID returns an error.
	if err := s.DeleteUpstream(ctx, up.ID); err == nil {
		t.Error("DeleteUpstream on non-existent ID: expected error, got nil")
	}
}

func TestCredential(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	up := &store.Upstream{
		Name:     "cred-upstream-" + uuid.New().String()[:8],
		URL:      "https://mcp.example.com",
		AuthType: "bearer_static",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	defer func() { _ = s.DeleteUpstream(ctx, up.ID) }()

	data := []byte("encrypted-credential-payload")
	if err := s.SetCredential(ctx, up.ID, data); err != nil {
		t.Fatalf("SetCredential: %v", err)
	}

	cred, err := s.GetCredential(ctx, up.ID)
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if string(cred.Data) != string(data) {
		t.Errorf("Data: got %q, want %q", cred.Data, data)
	}

	// SetCredential is idempotent — second call replaces.
	newData := []byte("updated-credential-payload")
	if err := s.SetCredential(ctx, up.ID, newData); err != nil {
		t.Fatalf("SetCredential (update): %v", err)
	}
	cred, err = s.GetCredential(ctx, up.ID)
	if err != nil {
		t.Fatalf("GetCredential (after update): %v", err)
	}
	if string(cred.Data) != string(newData) {
		t.Errorf("after update Data: got %q, want %q", cred.Data, newData)
	}
}

func TestUserToken(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	up := &store.Upstream{
		Name:     "tok-upstream-" + uuid.New().String()[:8],
		URL:      "https://mcp.example.com",
		AuthType: "oauth2_authorization_code",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	defer func() { _ = s.DeleteUpstream(ctx, up.ID) }()

	user, err := s.FindOrCreateUser(ctx, "tok-"+uuid.New().String()+"@example.com", "Token User")
	if err != nil {
		t.Fatalf("FindOrCreateUser: %v", err)
	}

	exp := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	tok := &store.UpstreamUserToken{
		UpstreamID:  up.ID,
		UserID:      user.ID,
		AccessToken: []byte("access-encrypted"),
		ExpiresAt:   &exp,
		Status:      "authorized",
	}
	if err := s.SetUserToken(ctx, tok); err != nil {
		t.Fatalf("SetUserToken: %v", err)
	}
	firstID := tok.ID

	got, err := s.GetUserToken(ctx, up.ID, user.ID)
	if err != nil {
		t.Fatalf("GetUserToken: %v", err)
	}
	if string(got.AccessToken) != "access-encrypted" {
		t.Errorf("AccessToken: got %q", got.AccessToken)
	}
	if got.Status != "authorized" {
		t.Errorf("Status: got %q", got.Status)
	}

	// Second SetUserToken replaces the row; t.ID must reflect the existing row PK.
	tok.AccessToken = []byte("refreshed-access")
	if err := s.SetUserToken(ctx, tok); err != nil {
		t.Fatalf("SetUserToken (update): %v", err)
	}
	if tok.ID != firstID {
		t.Errorf("after update t.ID changed: got %s, want %s (the original row PK)", tok.ID, firstID)
	}
	got, err = s.GetUserToken(ctx, up.ID, user.ID)
	if err != nil {
		t.Fatalf("GetUserToken (after update): %v", err)
	}
	if string(got.AccessToken) != "refreshed-access" {
		t.Errorf("after update AccessToken: got %q", got.AccessToken)
	}
}

func TestUserTokenNilExpiry(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	up := &store.Upstream{
		Name:     "noexp-upstream-" + uuid.New().String()[:8],
		URL:      "https://mcp.example.com",
		AuthType: "oauth2_authorization_code",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	defer func() { _ = s.DeleteUpstream(ctx, up.ID) }()

	user, _ := s.FindOrCreateUser(ctx, "noexp-"+uuid.New().String()+"@example.com", "NoExp User")

	tok := &store.UpstreamUserToken{
		UpstreamID:  up.ID,
		UserID:      user.ID,
		AccessToken: []byte("access-no-expiry"),
		ExpiresAt:   nil,
		Status:      "authorized",
	}
	if err := s.SetUserToken(ctx, tok); err != nil {
		t.Fatalf("SetUserToken: %v", err)
	}

	got, err := s.GetUserToken(ctx, up.ID, user.ID)
	if err != nil {
		t.Fatalf("GetUserToken: %v", err)
	}
	if got.ExpiresAt != nil {
		t.Errorf("ExpiresAt should be nil, got %v", got.ExpiresAt)
	}
}

func TestListTokensNeedingRefresh(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	up := &store.Upstream{
		Name:     "refresh-upstream-" + uuid.New().String()[:8],
		URL:      "https://mcp.example.com",
		AuthType: "oauth2_authorization_code",
	}
	if err := s.CreateUpstream(ctx, up); err != nil {
		t.Fatalf("CreateUpstream: %v", err)
	}
	defer func() { _ = s.DeleteUpstream(ctx, up.ID) }()

	user, _ := s.FindOrCreateUser(ctx, "refresh-"+uuid.New().String()+"@example.com", "Refresh User")
	userNoExp, _ := s.FindOrCreateUser(ctx, "noexp2-"+uuid.New().String()+"@example.com", "NoExp User2")

	// Past-expiry token — should appear.
	past := time.Now().Add(-time.Hour).Truncate(time.Microsecond)
	expiredTok := &store.UpstreamUserToken{
		UpstreamID:  up.ID,
		UserID:      user.ID,
		AccessToken: []byte("old-access"),
		ExpiresAt:   &past,
		Status:      "authorized",
	}
	if err := s.SetUserToken(ctx, expiredTok); err != nil {
		t.Fatalf("SetUserToken (expired): %v", err)
	}

	// Token with nil expires_at — must NOT appear (never needs refresh).
	noExpTok := &store.UpstreamUserToken{
		UpstreamID:  up.ID,
		UserID:      userNoExp.ID,
		AccessToken: []byte("no-expiry-access"),
		ExpiresAt:   nil,
		Status:      "authorized",
	}
	if err := s.SetUserToken(ctx, noExpTok); err != nil {
		t.Fatalf("SetUserToken (no-expiry): %v", err)
	}

	tokens, err := s.ListTokensNeedingRefresh(ctx)
	if err != nil {
		t.Fatalf("ListTokensNeedingRefresh: %v", err)
	}

	foundExpired := false
	foundNoExp := false
	for _, tk := range tokens {
		if tk.UpstreamID == up.ID && tk.UserID == user.ID {
			foundExpired = true
		}
		if tk.UpstreamID == up.ID && tk.UserID == userNoExp.ID {
			foundNoExp = true
		}
	}
	if !foundExpired {
		t.Error("ListTokensNeedingRefresh: past-expiry token not returned")
	}
	if foundNoExp {
		t.Error("ListTokensNeedingRefresh: nil-expiry token must not be returned")
	}
}

func TestAgentToken(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	user, _ := s.FindOrCreateUser(ctx, "agent-"+uuid.New().String()+"@example.com", "Agent User")

	hash := []byte("sha256-" + uuid.New().String())
	tok := &store.AgentToken{
		Name:      "agent-token",
		TokenHash: hash,
		UserID:    user.ID,
	}
	if err := s.CreateAgentToken(ctx, tok); err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}
	if tok.ID == (uuid.UUID{}) {
		t.Error("ID should be set after create")
	}

	// Find by hash.
	found, err := s.FindAgentToken(ctx, hash)
	if err != nil {
		t.Fatalf("FindAgentToken: %v", err)
	}
	if found.Name != "agent-token" {
		t.Errorf("Name: got %q", found.Name)
	}

	// List by user.
	list, err := s.ListAgentTokens(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListAgentTokens: %v", err)
	}
	if len(list) != 1 || list[0].ID != tok.ID {
		t.Errorf("ListAgentTokens: got %d tokens, want 1 with ID %s", len(list), tok.ID)
	}

	// Touch updates last_used_at.
	if err := s.TouchAgentToken(ctx, tok.ID); err != nil {
		t.Fatalf("TouchAgentToken: %v", err)
	}
	touched, _ := s.FindAgentToken(ctx, hash)
	if touched.LastUsedAt == nil {
		t.Error("LastUsedAt should be non-nil after Touch")
	}

	// Touch on non-existent ID returns an error.
	if err := s.TouchAgentToken(ctx, uuid.New()); err == nil {
		t.Error("TouchAgentToken on non-existent ID: expected error, got nil")
	}

	// Delete removes the token.
	if err := s.DeleteAgentToken(ctx, tok.ID, user.ID); err != nil {
		t.Fatalf("DeleteAgentToken: %v", err)
	}
	if _, err := s.FindAgentToken(ctx, hash); err == nil {
		t.Error("FindAgentToken after delete: expected error, got nil")
	}

	// Delete with wrong user is rejected.
	other, _ := s.FindOrCreateUser(ctx, "other-"+uuid.New().String()+"@example.com", "Other")
	tok2 := &store.AgentToken{
		Name:      "not-mine",
		TokenHash: []byte("other-hash-" + uuid.New().String()),
		UserID:    user.ID,
	}
	if err := s.CreateAgentToken(ctx, tok2); err != nil {
		t.Fatalf("CreateAgentToken (tok2): %v", err)
	}
	if err := s.DeleteAgentToken(ctx, tok2.ID, other.ID); err == nil {
		t.Error("DeleteAgentToken: should fail when user does not own token")
	}
	_ = s.DeleteAgentToken(ctx, tok2.ID, user.ID)
}
