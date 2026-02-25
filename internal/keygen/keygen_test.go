package keygen_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/dlddu/my-auth/internal/keygen"
)

// ---------------------------------------------------------------------------
// GenerateRSAKeyPair — happy path
// ---------------------------------------------------------------------------

func TestGenerateRSAKeyPair_ReturnsKeyPair_WithDefaultBits(t *testing.T) {
	// Act
	key, err := keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)

	// Assert
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair() returned unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("GenerateRSAKeyPair() returned nil key")
	}
	if key.N.BitLen() != keygen.DefaultKeyBits {
		t.Errorf("key bit length = %d, want %d", key.N.BitLen(), keygen.DefaultKeyBits)
	}
}

func TestGenerateRSAKeyPair_ReturnsValidKey(t *testing.T) {
	// Act
	key, err := keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair() returned unexpected error: %v", err)
	}

	// Assert — key must pass the standard library's internal consistency checks
	if err := key.Validate(); err != nil {
		t.Errorf("key.Validate() failed: %v", err)
	}
}

func TestGenerateRSAKeyPair_ReturnsDifferentKeysEachCall(t *testing.T) {
	// Act
	key1, err := keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)
	if err != nil {
		t.Fatalf("first GenerateRSAKeyPair(): %v", err)
	}
	key2, err := keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)
	if err != nil {
		t.Fatalf("second GenerateRSAKeyPair(): %v", err)
	}

	// Assert — two independently generated keys must not be identical
	if key1.N.Cmp(key2.N) == 0 {
		t.Error("two generated keys have the same modulus — they are identical, which indicates a broken RNG")
	}
}

// ---------------------------------------------------------------------------
// GenerateRSAKeyPair — edge cases
// ---------------------------------------------------------------------------

func TestGenerateRSAKeyPair_Accepts4096Bits(t *testing.T) {
	// Act
	key, err := keygen.GenerateRSAKeyPair(4096)

	// Assert
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair(4096) returned unexpected error: %v", err)
	}
	if key.N.BitLen() != 4096 {
		t.Errorf("key bit length = %d, want 4096", key.N.BitLen())
	}
}

// ---------------------------------------------------------------------------
// GenerateRSAKeyPair — error cases
// ---------------------------------------------------------------------------

func TestGenerateRSAKeyPair_ReturnsError_WhenBitsTooSmall(t *testing.T) {
	// Act — RSA keys below 512 bits are rejected by the standard library
	_, err := keygen.GenerateRSAKeyPair(64)

	// Assert
	if err == nil {
		t.Error("GenerateRSAKeyPair(64) expected error for too-small key size, got nil")
	}
}

// ---------------------------------------------------------------------------
// SavePrivateKeyPEM — happy path
// ---------------------------------------------------------------------------

func TestSavePrivateKeyPEM_WritesValidPKCS1PEMFile(t *testing.T) {
	// Arrange
	key, err := keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair(): %v", err)
	}
	path := filepath.Join(t.TempDir(), "private.pem")

	// Act
	if err := keygen.SavePrivateKeyPEM(key, path); err != nil {
		t.Fatalf("SavePrivateKeyPEM() returned unexpected error: %v", err)
	}

	// Assert — file must exist and contain a PEM block of the correct type
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q): %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("SavePrivateKeyPEM() wrote no PEM block")
	}
	if block.Type != "RSA PRIVATE KEY" {
		t.Errorf("PEM type = %q, want %q", block.Type, "RSA PRIVATE KEY")
	}
	// The decoded bytes must be parseable as a PKCS#1 private key.
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Errorf("x509.ParsePKCS1PrivateKey: %v", err)
	}
}

func TestSavePrivateKeyPEM_FileHasRestrictivePermissions(t *testing.T) {
	// Arrange
	key, err := keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair(): %v", err)
	}
	path := filepath.Join(t.TempDir(), "private.pem")

	// Act
	if err := keygen.SavePrivateKeyPEM(key, path); err != nil {
		t.Fatalf("SavePrivateKeyPEM(): %v", err)
	}

	// Assert — private key must be readable only by the owner (0600)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat(%q): %v", path, err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions = %04o, want 0600", perm)
	}
}

// ---------------------------------------------------------------------------
// SavePrivateKeyPEM — error cases
// ---------------------------------------------------------------------------

func TestSavePrivateKeyPEM_ReturnsError_WhenPathUnwritable(t *testing.T) {
	// Arrange
	key, err := keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair(): %v", err)
	}

	// Act — target directory does not exist
	err = keygen.SavePrivateKeyPEM(key, "/nonexistent/dir/private.pem")

	// Assert
	if err == nil {
		t.Error("SavePrivateKeyPEM() expected error for unwritable path, got nil")
	}
}

// ---------------------------------------------------------------------------
// SavePublicKeyPEM — happy path
// ---------------------------------------------------------------------------

func TestSavePublicKeyPEM_WritesValidPKIXPEMFile(t *testing.T) {
	// Arrange
	key, err := keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair(): %v", err)
	}
	path := filepath.Join(t.TempDir(), "public.pem")

	// Act
	if err := keygen.SavePublicKeyPEM(key, path); err != nil {
		t.Fatalf("SavePublicKeyPEM() returned unexpected error: %v", err)
	}

	// Assert
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q): %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("SavePublicKeyPEM() wrote no PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		t.Errorf("PEM type = %q, want %q", block.Type, "PUBLIC KEY")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParsePKIXPublicKey: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("parsed key is not *rsa.PublicKey")
	}
	if rsaPub.N.Cmp(key.PublicKey.N) != 0 {
		t.Error("saved public key modulus does not match the original key")
	}
}

// ---------------------------------------------------------------------------
// SavePublicKeyPEM — error cases
// ---------------------------------------------------------------------------

func TestSavePublicKeyPEM_ReturnsError_WhenPathUnwritable(t *testing.T) {
	// Arrange
	key, err := keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair(): %v", err)
	}

	// Act
	err = keygen.SavePublicKeyPEM(key, "/nonexistent/dir/public.pem")

	// Assert
	if err == nil {
		t.Error("SavePublicKeyPEM() expected error for unwritable path, got nil")
	}
}

// ---------------------------------------------------------------------------
// LoadPrivateKeyPEM — happy path
// ---------------------------------------------------------------------------

func TestLoadPrivateKeyPEM_ReturnsOriginalKey_AfterSave(t *testing.T) {
	// Arrange
	original, err := keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair(): %v", err)
	}
	path := filepath.Join(t.TempDir(), "private.pem")
	if err := keygen.SavePrivateKeyPEM(original, path); err != nil {
		t.Fatalf("SavePrivateKeyPEM(): %v", err)
	}

	// Act
	loaded, err := keygen.LoadPrivateKeyPEM(path)

	// Assert
	if err != nil {
		t.Fatalf("LoadPrivateKeyPEM() returned unexpected error: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadPrivateKeyPEM() returned nil key")
	}
	if loaded.N.Cmp(original.N) != 0 {
		t.Error("loaded key modulus does not match the original key")
	}
	if loaded.E != original.E {
		t.Errorf("loaded key exponent = %d, want %d", loaded.E, original.E)
	}
}

// ---------------------------------------------------------------------------
// LoadPrivateKeyPEM — error cases
// ---------------------------------------------------------------------------

func TestLoadPrivateKeyPEM_ReturnsError_WhenFileNotFound(t *testing.T) {
	// Act
	_, err := keygen.LoadPrivateKeyPEM("/nonexistent/private.pem")

	// Assert
	if err == nil {
		t.Error("LoadPrivateKeyPEM() expected error for missing file, got nil")
	}
}

func TestLoadPrivateKeyPEM_ReturnsError_WhenFileContainsInvalidPEM(t *testing.T) {
	// Arrange
	path := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(path, []byte("not a pem file"), 0600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	// Act
	_, err := keygen.LoadPrivateKeyPEM(path)

	// Assert
	if err == nil {
		t.Error("LoadPrivateKeyPEM() expected error for invalid PEM content, got nil")
	}
}
