// Package handler provides HTTP handler constructors for the my-auth server.
package handler

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"

	jose "github.com/go-jose/go-jose/v3"
)

// NewOIDCDiscoveryHandler returns an http.HandlerFunc that serves the OIDC
// Discovery document at /.well-known/openid-configuration.
//
// issuer is the OIDC Issuer Identifier (e.g. "https://auth.example.com").
func NewOIDCDiscoveryHandler(issuer string) http.HandlerFunc {
	doc := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/auth",
		"token_endpoint":                        issuer + "/oauth2/token",
		"jwks_uri":                              issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}

	body, _ := json.Marshal(doc)

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}

// NewJWKSHandler returns an http.HandlerFunc that serves the JSON Web Key Set
// containing the RSA public key derived from privateKey.
//
// The handler never exposes private key components (d, p, q, dp, dq, qi).
func NewJWKSHandler(privateKey *rsa.PrivateKey) http.HandlerFunc {
	pubDER, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	hash := sha256.Sum256(pubDER)
	kid := base64.RawURLEncoding.EncodeToString(hash[:8])

	jwk := jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     kid,
		Use:       "sig",
		Algorithm: string(jose.RS256),
	}

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
	body, _ := json.Marshal(jwks)

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}
