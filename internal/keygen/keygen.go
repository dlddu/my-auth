// Package keygen provides RSA key-pair generation utilities for my-auth.
package keygen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// DefaultKeyBits is the recommended RSA key size for JWKS signing keys.
const DefaultKeyBits = 2048

// GenerateRSAKeyPair generates a new RSA key pair with the given bit size.
// Returns the private key (which contains the embedded public key) or an error.
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("keygen: generate RSA key (%d bits): %w", bits, err)
	}
	return key, nil
}

// SavePrivateKeyPEM encodes key as a PKCS#1 PEM block and writes it to path.
// The file is created with mode 0600 (owner read/write only).
func SavePrivateKeyPEM(key *rsa.PrivateKey, path string) error {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	data := pem.EncodeToMemory(block)

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("keygen: write private key to %q: %w", path, err)
	}
	return nil
}

// SavePublicKeyPEM encodes the public component of key as a PKIX PEM block
// and writes it to path. The file is created with mode 0644.
func SavePublicKeyPEM(key *rsa.PrivateKey, path string) error {
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("keygen: marshal public key: %w", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}

	data := pem.EncodeToMemory(block)

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("keygen: write public key to %q: %w", path, err)
	}
	return nil
}

// LoadPrivateKeyPEM reads and decodes a PKCS#1 PEM-encoded private key from path.
func LoadPrivateKeyPEM(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keygen: read private key file %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("keygen: no PEM block found in %q", path)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keygen: parse PKCS#1 private key from %q: %w", path, err)
	}

	return key, nil
}
