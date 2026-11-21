package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const advisoryLockKey = 87430004

type Store struct {
	db *gorm.DB
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("store: get sql.DB: %w", err)
	}

	// Acquire a session-level advisory lock on a pinned connection to serialize
	// migrations across instances. pg_advisory_lock blocks until available (up
	// to 30 s), so parallel test packages wait rather than immediately failing.
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: acquire connection: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "SET lock_timeout = '30s'"); err != nil {
		return nil, fmt.Errorf("store: set lock_timeout: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		return nil, fmt.Errorf("store: migration lock (key %d): %w", advisoryLockKey, err)
	}
	defer func() {
		if _, err := conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", advisoryLockKey); err != nil {
			slog.Error("store: advisory_unlock failed", "err", err)
		}
	}()

	if err := db.AutoMigrate(
		&User{},
		&Upstream{},
		&UpstreamCredential{},
		&UpstreamUserToken{},
		&AgentToken{},
		&UpstreamToolFilter{},
	); err != nil {
		return nil, fmt.Errorf("store: migrate: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Ping checks that the database connection is still alive.
func (s *Store) Ping(ctx context.Context) error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

// FindOrCreateUser returns the user with the given email, creating them if absent.
// DisplayName is set only on creation; subsequent calls with the same email
// return the existing record unchanged.
func (s *Store) FindOrCreateUser(ctx context.Context, email, displayName string) (*User, error) {
	u := &User{Email: email, DisplayName: displayName}
	result := s.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "email"}},
			DoNothing: true,
		}).
		Create(u)
	if result.Error != nil {
		return nil, fmt.Errorf("store: find-or-create user %q: %w", email, result.Error)
	}
	if result.RowsAffected == 0 {
		// Row existed; fetch the canonical record using a fresh struct so GORM
		// does not add the newly generated (wrong) ID to the WHERE clause.
		var existing User
		if err := s.db.WithContext(ctx).Where("email = ?", email).First(&existing).Error; err != nil {
			return nil, fmt.Errorf("store: find-or-create user %q (fetch): %w", email, err)
		}
		return &existing, nil
	}
	return u, nil
}

func (s *Store) CreateUpstream(ctx context.Context, u *Upstream) error {
	if err := s.db.WithContext(ctx).Create(u).Error; err != nil {
		return fmt.Errorf("store: create upstream: %w", err)
	}
	return nil
}

func (s *Store) ListUpstreams(ctx context.Context) ([]*Upstream, error) {
	var upstreams []*Upstream
	if err := s.db.WithContext(ctx).Order("name").Find(&upstreams).Error; err != nil {
		return nil, fmt.Errorf("store: list upstreams: %w", err)
	}
	return upstreams, nil
}

func (s *Store) GetUpstream(ctx context.Context, id uuid.UUID) (*Upstream, error) {
	var u Upstream
	if err := s.db.WithContext(ctx).First(&u, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("store: get upstream %s: %w", id, err)
	}
	return &u, nil
}

func (s *Store) UpdateUpstream(ctx context.Context, u *Upstream) error {
	if err := s.db.WithContext(ctx).Save(u).Error; err != nil {
		return fmt.Errorf("store: update upstream: %w", err)
	}
	return nil
}

func (s *Store) DeleteUpstream(ctx context.Context, id uuid.UUID) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&UpstreamCredential{}, "upstream_id = ?", id).Error; err != nil {
			return err
		}
		if err := tx.Delete(&UpstreamUserToken{}, "upstream_id = ?", id).Error; err != nil {
			return err
		}
		result := tx.Delete(&Upstream{}, "id = ?", id)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
}

func (s *Store) SetCredential(ctx context.Context, upstreamID uuid.UUID, data []byte) error {
	cred := UpstreamCredential{
		UpstreamID: upstreamID,
		Data:       data,
		UpdatedAt:  time.Now(),
	}
	err := s.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "upstream_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"data", "updated_at"}),
		}).
		Create(&cred).Error
	if err != nil {
		return fmt.Errorf("store: set credential: %w", err)
	}
	return nil
}

func (s *Store) GetCredential(ctx context.Context, upstreamID uuid.UUID) (*UpstreamCredential, error) {
	var cred UpstreamCredential
	if err := s.db.WithContext(ctx).First(&cred, "upstream_id = ?", upstreamID).Error; err != nil {
		return nil, fmt.Errorf("store: get credential: %w", err)
	}
	return &cred, nil
}

// SetUserToken upserts a per-user OAuth token. On conflict (same upstream+user),
// the existing row is updated and t.ID is set to the row's canonical PK.
func (s *Store) SetUserToken(ctx context.Context, t *UpstreamUserToken) error {
	t.UpdatedAt = time.Now()
	err := s.db.WithContext(ctx).
		Clauses(
			clause.OnConflict{
				Columns: []clause.Column{
					{Name: "upstream_id"},
					{Name: "user_id"},
				},
				DoUpdates: clause.AssignmentColumns([]string{
					"access_token", "refresh_token", "expires_at",
					"status", "updated_at",
				}),
			},
			clause.Returning{},
		).
		Create(t).Error
	if err != nil {
		return fmt.Errorf("store: set user token: %w", err)
	}
	return nil
}

func (s *Store) GetUserToken(ctx context.Context, upstreamID, userID uuid.UUID) (*UpstreamUserToken, error) {
	var t UpstreamUserToken
	err := s.db.WithContext(ctx).
		First(&t, "upstream_id = ? AND user_id = ?", upstreamID, userID).Error
	if err != nil {
		return nil, fmt.Errorf("store: get user token: %w", err)
	}
	return &t, nil
}

// ListTokensNeedingRefresh returns authorized tokens expiring within 5 minutes
// (including already-expired ones). Tokens with no expiry (expires_at IS NULL)
// are excluded because they never need a refresh.
func (s *Store) ListTokensNeedingRefresh(ctx context.Context) ([]*UpstreamUserToken, error) {
	var tokens []*UpstreamUserToken
	threshold := time.Now().Add(5 * time.Minute)
	err := s.db.WithContext(ctx).
		Where("status = ? AND expires_at IS NOT NULL AND expires_at < ?", "authorized", threshold).
		Find(&tokens).Error
	if err != nil {
		return nil, fmt.Errorf("store: list tokens needing refresh: %w", err)
	}
	return tokens, nil
}

func (s *Store) CreateAgentToken(ctx context.Context, t *AgentToken) error {
	if err := s.db.WithContext(ctx).Create(t).Error; err != nil {
		return fmt.Errorf("store: create agent token: %w", err)
	}
	return nil
}

func (s *Store) FindAgentToken(ctx context.Context, hash []byte) (*AgentToken, error) {
	var t AgentToken
	if err := s.db.WithContext(ctx).First(&t, "token_hash = ?", hash).Error; err != nil {
		return nil, fmt.Errorf("store: find agent token: %w", err)
	}
	return &t, nil
}

func (s *Store) ListAgentTokens(ctx context.Context, userID uuid.UUID) ([]*AgentToken, error) {
	var tokens []*AgentToken
	err := s.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&tokens).Error
	if err != nil {
		return nil, fmt.Errorf("store: list agent tokens: %w", err)
	}
	return tokens, nil
}

func (s *Store) DeleteAgentToken(ctx context.Context, id, userID uuid.UUID) error {
	result := s.db.WithContext(ctx).
		Delete(&AgentToken{}, "id = ? AND user_id = ?", id, userID)
	if result.Error != nil {
		return fmt.Errorf("store: delete agent token: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("store: agent token %s not found or not owned by user", id)
	}
	return nil
}

// IsNotFound reports whether err is a record-not-found error from GORM.
func IsNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound)
}

func (s *Store) TouchAgentToken(ctx context.Context, id uuid.UUID) error {
	result := s.db.WithContext(ctx).
		Model(&AgentToken{}).
		Where("id = ?", id).
		Update("last_used_at", time.Now())
	if result.Error != nil {
		return fmt.Errorf("store: touch agent token: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("store: agent token %s not found", id)
	}
	return nil
}

// SetToolEnabled enables or disables a specific tool for an upstream.
// Enabling a tool that has no filter row is a no-op (tools are enabled by default).
func (s *Store) SetToolEnabled(ctx context.Context, upstreamID uuid.UUID, toolName string, enabled bool) error {
	// Raw SQL avoids GORM's zero-value elision: a bool `false` is Go's zero value
	// and GORM silently drops it from the INSERT, causing excluded.enabled to
	// resolve to the column default (true) in the ON CONFLICT clause.
	return s.db.WithContext(ctx).Exec(
		`INSERT INTO upstream_tool_filters (upstream_id, tool_name, enabled)
		 VALUES (?, ?, ?)
		 ON CONFLICT (upstream_id, tool_name) DO UPDATE SET enabled = excluded.enabled`,
		upstreamID, toolName, enabled,
	).Error
}

// GetToolFilters returns a map of tool_name → enabled for all explicitly configured
// tools of an upstream. Tools absent from the map are enabled by default.
func (s *Store) GetToolFilters(ctx context.Context, upstreamID uuid.UUID) (map[string]bool, error) {
	var rows []UpstreamToolFilter
	if err := s.db.WithContext(ctx).
		Where("upstream_id = ?", upstreamID).
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("store: get tool filters: %w", err)
	}
	m := make(map[string]bool, len(rows))
	for _, r := range rows {
		m[r.ToolName] = r.Enabled
	}
	return m, nil
}
