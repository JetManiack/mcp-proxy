package crypto_test

import (
	"bytes"
	"testing"

	"github.com/JetManiack/mcp-proxy/internal/crypto"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("super-secret-oauth-token")

	ciphertext, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext must differ from plaintext")
	}

	got, err := crypto.Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt: got %q, want %q", got, plaintext)
	}
}

func TestEncryptProducesUniqueNonces(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("same input")

	c1, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c1, c2) {
		t.Fatal("two Encrypt calls with the same input must produce different ciphertexts")
	}
}

func TestDecryptTampered(t *testing.T) {
	key := make([]byte, 32)
	ciphertext, err := crypto.Encrypt(key, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xFF
	if _, err := crypto.Decrypt(key, ciphertext); err == nil {
		t.Fatal("Decrypt must fail on tampered ciphertext")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 0xFF

	ciphertext, err := crypto.Encrypt(key1, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Decrypt(key2, ciphertext); err == nil {
		t.Fatal("Decrypt must fail with the wrong key")
	}
}

func TestEncryptInvalidKeySize(t *testing.T) {
	if _, err := crypto.Encrypt([]byte("short"), []byte("data")); err == nil {
		t.Fatal("Encrypt must reject a key that is not 32 bytes")
	}
}

func TestKeyFromHex(t *testing.T) {
	key, err := crypto.KeyFromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatalf("KeyFromHex: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length: got %d, want 32", len(key))
	}
	for i, b := range key {
		if b != byte(i) {
			t.Fatalf("key[%d]: got %#x, want %#x", i, b, byte(i))
		}
	}
}

func TestKeyFromHexInvalid(t *testing.T) {
	cases := []string{
		"",
		"zzzz",
		"deadbeef",
	}
	for _, tc := range cases {
		if _, err := crypto.KeyFromHex(tc); err == nil {
			t.Errorf("KeyFromHex(%q): expected error, got nil", tc)
		}
	}
}
