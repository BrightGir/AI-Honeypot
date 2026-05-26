// Package crypto provides AES-256-GCM envelope encryption for sensitive values
// stored in Redis (e.g. integration API keys, webhook secrets).
//
// Usage:
//
//	enc, err := crypto.NewEncryptor(os.Getenv("SECRET_ENCRYPTION_KEY"))
//	ciphertext, err := enc.Encrypt("my-api-key")
//	plaintext,  err := enc.Decrypt(ciphertext)
//
// The encryption key must be a 32-byte (256-bit) hex-encoded string.
// Generate one with: openssl rand -hex 32
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// Encryptor performs AES-256-GCM authenticated encryption.
type Encryptor struct {
	aead cipher.AEAD
}

// NewEncryptor creates an Encryptor from a 32-byte hex-encoded key.
// The AES block cipher and GCM wrapper are created once at construction time
// and reused for all subsequent Encrypt/Decrypt calls.
// Returns an error if the key is missing or has the wrong length.
func NewEncryptor(hexKey string) (*Encryptor, error) {
	if hexKey == "" {
		return nil, errors.New("crypto: SECRET_ENCRYPTION_KEY is not set")
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes (got %d)", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return &Encryptor{aead: gcm}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM and returns a hex-encoded
// string of the form: nonce(12 bytes) || ciphertext || tag(16 bytes).
// Returns the plaintext unchanged if it is empty.
func (e *Encryptor) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("crypto: generate nonce: %w", err)
	}
	ciphertext := e.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a hex-encoded ciphertext produced by Encrypt.
// Returns the plaintext unchanged if it is empty.
func (e *Encryptor) Decrypt(hexCiphertext string) (string, error) {
	if hexCiphertext == "" {
		return "", nil
	}
	data, err := hex.DecodeString(hexCiphertext)
	if err != nil {
		return "", fmt.Errorf("crypto: decode hex: %w", err)
	}
	nonceSize := e.aead.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("crypto: ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := e.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("crypto: decrypt: %w", err)
	}
	return string(plaintext), nil
}

// NoopEncryptor is a pass-through implementation used when encryption is
// disabled (e.g. in tests or when SECRET_ENCRYPTION_KEY is not configured).
type NoopEncryptor struct{}

// NewNoopEncryptor creates a NoopEncryptor, panicking if APP_ENV=production.
// Call this instead of using NoopEncryptor{} directly in non-test code.
// The caller is responsible for logging an appropriate warning before calling
// this function (separation of concerns).
func NewNoopEncryptor() NoopEncryptor {
	if os.Getenv("APP_ENV") == "production" {
		panic("crypto: NoopEncryptor must not be used in production — set SECRET_ENCRYPTION_KEY")
	}
	return NoopEncryptor{}
}

func (NoopEncryptor) Encrypt(s string) (string, error) {
	return s, nil
}
func (NoopEncryptor) Decrypt(s string) (string, error) { return s, nil }

// SecretEncryptor is the interface satisfied by both Encryptor and NoopEncryptor.
type SecretEncryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}
