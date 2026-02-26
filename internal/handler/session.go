package handler

import (
	"time"

	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// newFositeSession constructs a fosite openid.DefaultSession populated with
// the provided subject and issuer. This session type carries both standard
// OAuth2 claims and OIDC id_token claims required by fosite's OpenID Connect
// handler.
func newFositeSession(subject, issuer string) *openid.DefaultSession {
	now := time.Now().UTC()
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      issuer,
			Subject:     subject,
			IssuedAt:    now,
			RequestedAt: now,
			Extra:       make(map[string]interface{}),
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
		Subject: subject,
	}
}
