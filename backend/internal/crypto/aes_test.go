package crypto

import (
	"strings"
	"testing"
)

const testKey = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	enc, err := NewEncryptor(testKey)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	plaintext := "super-secret-api-key-12345"
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ciphertext == plaintext {
		t.Error("ciphertext should differ from plaintext")
	}
	got, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != plaintext {
		t.Errorf("Decrypt = %q, want %q", got, plaintext)
	}
}

func TestEncryptDecrypt_EmptyString(t *testing.T) {
	enc, err := NewEncryptor(testKey)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	ct, err := enc.Encrypt("")
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}
	if ct != "" {
		t.Errorf("Encrypt('') = %q, want empty", ct)
	}
	pt, err := enc.Decrypt("")
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if pt != "" {
		t.Errorf("Decrypt('') = %q, want empty", pt)
	}
}

func TestEncrypt_ProducesUniqueCiphertexts(t *testing.T) {
	// Each call must produce a different ciphertext (random nonce).
	enc, err := NewEncryptor(testKey)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	ct1, _ := enc.Encrypt("same-plaintext")
	ct2, _ := enc.Encrypt("same-plaintext")
	if ct1 == ct2 {
		t.Error("two encryptions of the same plaintext should differ (random nonce)")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	enc, err := NewEncryptor(testKey)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	ct, _ := enc.Encrypt("value")
	// Flip the last byte of the hex string.
	tampered := ct[:len(ct)-2] + "ff"
	_, err = enc.Decrypt(tampered)
	if err == nil {
		t.Error("Decrypt should fail on tampered ciphertext")
	}
}

func TestNewEncryptor_InvalidKey(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"not hex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
		{"too short", "0102030405060708"},
		{"too long", strings.Repeat("01", 33)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEncryptor(tc.key)
			if err == nil {
				t.Errorf("NewEncryptor(%q) should return error", tc.key)
			}
		})
	}
}

func TestNoopEncryptor_PassThrough(t *testing.T) {
	var n NoopEncryptor
	ct, err := n.Encrypt("hello")
	if err != nil || ct != "hello" {
		t.Errorf("NoopEncryptor.Encrypt = %q, %v; want 'hello', nil", ct, err)
	}
	pt, err := n.Decrypt("hello")
	if err != nil || pt != "hello" {
		t.Errorf("NoopEncryptor.Decrypt = %q, %v; want 'hello', nil", pt, err)
	}
}
