package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type AuthMode string

const (
	AuthModeOpen        AuthMode = "open"
	AuthModeOAuth2Proxy AuthMode = "oauth2_proxy"
)

type Allowlist struct {
	Emails []string `yaml:"emails"`
	Groups []string `yaml:"groups"`
}

type AuthConfig struct {
	Mode         AuthMode  `yaml:"mode"`
	HeaderEmail  string    `yaml:"header_email"`
	HeaderGroups string    `yaml:"header_groups"`
	Allowlist    Allowlist `yaml:"allowlist"`
}

type Config struct {
	ListenAddr    string     `yaml:"listen_addr"`
	AgentAddr     string     `yaml:"agent_addr"`
	ProbeAddr     string     `yaml:"probe_addr"`
	DatabaseURL   string     `yaml:"database_url"`
	PublicURL     string     `yaml:"public_url"`
	EncryptionKey []byte     `yaml:"-"`
	Auth          AuthConfig `yaml:"auth"`
}

// LoadFile overlays cfg with values from a YAML file. Only fields present in
// the file are updated; absent fields keep their current values.
func LoadFile(path string, cfg *Config) error {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("config: open %q: %w", path, err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && err != io.EOF {
		return fmt.Errorf("config: parse %q: %w", path, err)
	}
	return nil
}

// Validate checks the config for logical errors.
func Validate(cfg *Config) error {
	switch cfg.Auth.Mode {
	case AuthModeOpen, AuthModeOAuth2Proxy:
	default:
		return fmt.Errorf("config: unknown auth.mode %q (valid: open, oauth2_proxy)", cfg.Auth.Mode)
	}
	if cfg.DatabaseURL == "" {
		return fmt.Errorf("config: database_url is required")
	}
	return nil
}
