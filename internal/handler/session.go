package handler

import (
	"time"

	"github.com/mohae/deepcopy"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// fositeSession satisfies openid.Session (for ID tokens) and
// oauth2.JWTSessionContainer (for JWT access tokens) simultaneously.
type fositeSession struct {
	*openid.DefaultSession
	JWTClaims *jwt.JWTClaims `json:"jwt_claims"`
	JWTHeader *jwt.Headers   `json:"jwt_header"`
}

// GetJWTClaims implements oauth2.JWTSessionContainer.
func (s *fositeSession) GetJWTClaims() jwt.JWTClaimsContainer {
	if s.JWTClaims == nil {
		s.JWTClaims = &jwt.JWTClaims{}
	}
	return s.JWTClaims
}

// GetJWTHeader implements oauth2.JWTSessionContainer.
func (s *fositeSession) GetJWTHeader() *jwt.Headers {
	if s.JWTHeader == nil {
		s.JWTHeader = &jwt.Headers{}
	}
	return s.JWTHeader
}

// Clone implements fosite.Session.
func (s *fositeSession) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	return deepcopy.Copy(s).(fosite.Session)
}

// newFositeSession constructs a combined session populated with the provided
// subject and issuer. This session type carries both standard OAuth2 JWT
// claims and OIDC id_token claims required by fosite's handlers.
func newFositeSession(subject, issuer string) *fositeSession {
	now := time.Now().UTC()
	return &fositeSession{
		DefaultSession: &openid.DefaultSession{
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
		},
		JWTClaims: &jwt.JWTClaims{
			Subject:   subject,
			Issuer:    issuer,
			IssuedAt:  now,
			ExpiresAt: now.Add(time.Hour),
			Extra:     make(map[string]interface{}),
		},
		JWTHeader: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	}
}
