package store

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey"`
	Email       string    `gorm:"uniqueIndex;not null"`
	DisplayName string
	CreatedAt   time.Time
}

func (u *User) BeforeCreate(_ *gorm.DB) error {
	if u.ID == (uuid.UUID{}) {
		u.ID = uuid.New()
	}
	return nil
}

type Upstream struct {
	ID              uuid.UUID `gorm:"type:uuid;primaryKey"`
	Name            string    `gorm:"not null"`
	URL             string    `gorm:"not null"`
	AuthType        string    `gorm:"not null"`
	AuthEndpoint    string
	TokenEndpoint   string
	DCREndpoint     string
	ClientIDMetaDoc bool `gorm:"default:false"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (u *Upstream) BeforeCreate(_ *gorm.DB) error {
	if u.ID == (uuid.UUID{}) {
		u.ID = uuid.New()
	}
	return nil
}

type UpstreamCredential struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey"`
	UpstreamID uuid.UUID `gorm:"type:uuid;uniqueIndex;not null"`
	Data       []byte    `gorm:"not null"`
	UpdatedAt  time.Time
}

func (c *UpstreamCredential) BeforeCreate(_ *gorm.DB) error {
	if c.ID == (uuid.UUID{}) {
		c.ID = uuid.New()
	}
	return nil
}

type UpstreamUserToken struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey"`
	UpstreamID   uuid.UUID `gorm:"type:uuid;uniqueIndex:upstream_user_unique;not null"`
	UserID       uuid.UUID `gorm:"type:uuid;uniqueIndex:upstream_user_unique;not null"`
	AccessToken  []byte    `gorm:"not null"`
	RefreshToken []byte
	ExpiresAt    *time.Time
	Status       string `gorm:"not null"`
	DCRClientID  []byte
	UpdatedAt    time.Time
}

func (t *UpstreamUserToken) BeforeCreate(_ *gorm.DB) error {
	if t.ID == (uuid.UUID{}) {
		t.ID = uuid.New()
	}
	return nil
}

// UpstreamToolFilter stores per-tool publish settings for an upstream.
// Absence of a row means the tool is enabled (opt-out model).
type UpstreamToolFilter struct {
	UpstreamID uuid.UUID `gorm:"type:uuid;primaryKey"`
	ToolName   string    `gorm:"primaryKey"`
	Enabled    bool      `gorm:"not null;default:true"`
}

type AgentToken struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey"`
	Name       string    `gorm:"not null"`
	TokenHash  []byte    `gorm:"uniqueIndex;not null"`
	UserID     uuid.UUID `gorm:"type:uuid;not null"`
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

func (t *AgentToken) BeforeCreate(_ *gorm.DB) error {
	if t.ID == (uuid.UUID{}) {
		t.ID = uuid.New()
	}
	return nil
}
