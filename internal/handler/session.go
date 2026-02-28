package handler

import (
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

// newOIDCSession creates an openid.DefaultSession for a successfully authenticated user.
// It populates the claims required for OIDC ID token generation.
func newOIDCSession(subject, clientID, issuer string, ar fosite.AuthorizeRequester) *openid.DefaultSession {
	now := time.Now().UTC()

	sess := &openid.DefaultSession{
		Subject: subject,
		Claims: &openid.IDTokenClaims{
			Issuer:      issuer,
			Subject:     subject,
			Audience:    []string{clientID},
			IssuedAt:    now,
			ExpiresAt:   now.Add(time.Hour),
			RequestedAt: now,
		},
		Headers: &openid.Headers{},
	}

	// Carry the nonce from the authorize request into the session.
	if ar != nil {
		// fosite.AuthorizeRequest embeds fosite.Request which has Form url.Values.
		// We try to access the form via type assertion to *fosite.AuthorizeRequest.
		if req, ok := ar.(*fosite.AuthorizeRequest); ok {
			if nonce := req.Form.Get("nonce"); nonce != "" {
				sess.Claims.Nonce = nonce
			}
		}
	}

	return sess
}

// newEmptyOIDCSession creates an openid.DefaultSession with minimal initialisation.
// fosite will populate the fields from the stored session during token exchange.
func newEmptyOIDCSession() *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims:  &openid.IDTokenClaims{},
		Headers: &openid.Headers{},
	}
}
