package testhelper

import (
	"crypto/rsa"
	"testing"

	"github.com/dlddu/my-auth/internal/keygen"
)

// NewTestRSAKey generates an in-memory RSA private key for use in tests.
// It fails the test immediately if key generation fails.
func NewTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)
	if err != nil {
		t.Fatalf("testhelper.NewTestRSAKey: %v", err)
	}
	return key
}
