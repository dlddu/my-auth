package handler

import (
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// JWTOIDCSession extends openid.DefaultSession with the fields required by
// fosite's JWT access-token strategy. The strategy calls GetJWTClaims() and
// GetJWTHeader() on the session when it mints a JWT access token; without
// those methods fosite falls back to a plain opaque token (or panics,
// depending on the version). Embedding *openid.DefaultSession means the OIDC
// id_token pipeline continues to work unchanged.
type JWTOIDCSession struct {
	*openid.DefaultSession

	// JWTClaims carries the claims that will be embedded in the JWT access
	// token. They are populated separately from the OIDC IDTokenClaims so
	// that access-token and id-token lifetimes / audiences can diverge.
	JWTClaims *jwt.JWTClaims

	// JWTHeader carries the JOSE headers for the JWT access token.
	JWTHeader *jwt.Headers
}

// GetJWTClaims satisfies the fosite JWT access-token strategy interface
// (oauth2.JWTSessionContainer). It returns a non-nil JWTClaimsContainer,
// initialising the field lazily if necessary.
func (s *JWTOIDCSession) GetJWTClaims() jwt.JWTClaimsContainer {
	if s.JWTClaims == nil {
		s.JWTClaims = &jwt.JWTClaims{}
	}
	return s.JWTClaims
}

// SetSubject sets the subject on the embedded DefaultSession so that
// deserialization code in other packages can restore it without needing to
// know about the concrete JWTOIDCSession type.
func (s *JWTOIDCSession) SetSubject(subject string) {
	s.DefaultSession.Subject = subject
}

// GetJWTHeader satisfies the fosite JWT access-token strategy interface.
// It returns a non-nil *jwt.Headers, initialising the field lazily if
// necessary.
func (s *JWTOIDCSession) GetJWTHeader() *jwt.Headers {
	if s.JWTHeader == nil {
		s.JWTHeader = &jwt.Headers{}
	}
	return s.JWTHeader
}

// newOIDCSession creates a JWTOIDCSession for a successfully authenticated
// user. It populates both the OIDC id-token claims (via openid.DefaultSession)
// and the JWT access-token claims (via JWTClaims).
func newOIDCSession(subject, clientID, issuer string, ar fosite.AuthorizeRequester) *JWTOIDCSession {
	now := time.Now().UTC()

	defaultSess := &openid.DefaultSession{
		Subject: subject,
		Claims: &jwt.IDTokenClaims{
			Issuer:      issuer,
			Subject:     subject,
			Audience:    []string{clientID},
			IssuedAt:    now,
			ExpiresAt:   now.Add(time.Hour),
			RequestedAt: now,
		},
		Headers: &jwt.Headers{},
	}

	sess := &JWTOIDCSession{
		DefaultSession: defaultSess,
		JWTClaims: &jwt.JWTClaims{
			Subject:   subject,
			Issuer:    issuer,
			Audience:  []string{clientID},
			IssuedAt:  now,
			ExpiresAt: now.Add(time.Hour),
		},
		JWTHeader: &jwt.Headers{},
	}

	// Carry the nonce from the authorize request into the id-token claims.
	if ar != nil {
		// fosite.AuthorizeRequest embeds fosite.Request which has Form url.Values.
		// We try to access the form via type assertion to *fosite.AuthorizeRequest.
		if req, ok := ar.(*fosite.AuthorizeRequest); ok {
			if nonce := req.Form.Get("nonce"); nonce != "" {
				sess.DefaultSession.Claims.Nonce = nonce
			}
		}
	}

	return sess
}

// newEmptyOIDCSession creates a JWTOIDCSession with minimal initialisation.
// fosite will populate the fields from the stored session during token
// exchange.
func newEmptyOIDCSession() *JWTOIDCSession {
	return &JWTOIDCSession{
		DefaultSession: &openid.DefaultSession{
			Claims:  &jwt.IDTokenClaims{},
			Headers: &jwt.Headers{},
		},
		JWTClaims: &jwt.JWTClaims{},
		JWTHeader: &jwt.Headers{},
	}
}
