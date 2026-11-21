package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/JetManiack/mcp-proxy/internal/config"
)

func TestLoadFileBasic(t *testing.T) {
	yaml := `
listen_addr: ":9090"
database_url: "postgres://localhost/test"
public_url: "https://proxy.example.com"
auth:
  mode: oauth2_proxy
  allowlist:
    emails:
      - alice@example.com
    groups:
      - sre
`
	path := writeTemp(t, yaml)
	cfg := &config.Config{}
	if err := config.LoadFile(path, cfg); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.ListenAddr != ":9090" {
		t.Errorf("ListenAddr: got %q", cfg.ListenAddr)
	}
	if cfg.DatabaseURL != "postgres://localhost/test" {
		t.Errorf("DatabaseURL: got %q", cfg.DatabaseURL)
	}
	if cfg.PublicURL != "https://proxy.example.com" {
		t.Errorf("PublicURL: got %q", cfg.PublicURL)
	}
	if cfg.Auth.Mode != config.AuthModeOAuth2Proxy {
		t.Errorf("Auth.Mode: got %q", cfg.Auth.Mode)
	}
	if len(cfg.Auth.Allowlist.Emails) != 1 || cfg.Auth.Allowlist.Emails[0] != "alice@example.com" {
		t.Errorf("Auth.Allowlist.Emails: got %v", cfg.Auth.Allowlist.Emails)
	}
	if len(cfg.Auth.Allowlist.Groups) != 1 || cfg.Auth.Allowlist.Groups[0] != "sre" {
		t.Errorf("Auth.Allowlist.Groups: got %v", cfg.Auth.Allowlist.Groups)
	}
}

// LoadFile overlays: values not in the file keep their existing values.
func TestLoadFileOverlay(t *testing.T) {
	yaml := `listen_addr: ":9090"`
	path := writeTemp(t, yaml)
	cfg := &config.Config{
		DatabaseURL: "postgres://pre-existing/db",
		Auth: config.AuthConfig{
			HeaderEmail:  "X-Auth-Request-Email",
			HeaderGroups: "X-Auth-Request-Groups",
		},
	}
	if err := config.LoadFile(path, cfg); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.ListenAddr != ":9090" {
		t.Errorf("ListenAddr: got %q", cfg.ListenAddr)
	}
	if cfg.DatabaseURL != "postgres://pre-existing/db" {
		t.Errorf("DatabaseURL: file should not overwrite pre-existing value, got %q", cfg.DatabaseURL)
	}
	if cfg.Auth.HeaderEmail != "X-Auth-Request-Email" {
		t.Errorf("HeaderEmail: should be preserved, got %q", cfg.Auth.HeaderEmail)
	}
}

func TestLoadFileEmpty(t *testing.T) {
	path := writeTemp(t, "")
	cfg := &config.Config{ListenAddr: ":8080"}
	if err := config.LoadFile(path, cfg); err != nil {
		t.Fatalf("empty file should be valid, got %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr: defaults should be preserved, got %q", cfg.ListenAddr)
	}
}

func TestLoadFileMissing(t *testing.T) {
	cfg := &config.Config{}
	if err := config.LoadFile("/nonexistent/path/config.yaml", cfg); err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestValidateOK(t *testing.T) {
	cfg := &config.Config{
		DatabaseURL: "postgres://localhost/db",
		Auth:        config.AuthConfig{Mode: config.AuthModeOpen},
	}
	if err := config.Validate(cfg); err != nil {
		t.Errorf("Validate: unexpected error: %v", err)
	}
}

func TestValidateMissingDatabaseURL(t *testing.T) {
	cfg := &config.Config{Auth: config.AuthConfig{Mode: config.AuthModeOpen}}
	if err := config.Validate(cfg); err == nil {
		t.Fatal("expected error for missing database_url")
	}
}

func TestValidateInvalidAuthMode(t *testing.T) {
	cfg := &config.Config{
		DatabaseURL: "postgres://localhost/db",
		Auth:        config.AuthConfig{Mode: "bogus"},
	}
	if err := config.Validate(cfg); err == nil {
		t.Fatal("expected error for unknown auth mode")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return filepath.Clean(f.Name())
}
