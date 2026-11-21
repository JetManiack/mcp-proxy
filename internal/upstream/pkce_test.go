package upstream_test

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/JetManiack/mcp-proxy/internal/upstream"
)

func TestGenerateVerifier_Length(t *testing.T) {
	v, err := upstream.GenerateVerifier()
	if err != nil {
		t.Fatalf("GenerateVerifier: %v", err)
	}
	// RFC 7636: verifier must be 43–128 chars
	if len(v) < 43 || len(v) > 128 {
		t.Errorf("verifier length %d out of RFC 7636 range [43, 128]", len(v))
	}
}

func TestGenerateVerifier_Uniqueness(t *testing.T) {
	v1, _ := upstream.GenerateVerifier()
	v2, _ := upstream.GenerateVerifier()
	if v1 == v2 {
		t.Error("two calls must produce different verifiers")
	}
}

func TestGenerateVerifier_Base64URL(t *testing.T) {
	v, _ := upstream.GenerateVerifier()
	for _, c := range v {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", c) {
			t.Errorf("verifier contains non-base64url char %q", c)
		}
	}
}

func TestChallenge_S256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := upstream.Challenge(verifier)

	// S256: base64url(sha256(verifier))
	h := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(h[:])
	if challenge != want {
		t.Errorf("Challenge(%q) = %q, want %q", verifier, challenge, want)
	}
}
