// Package session provides the composite OAuth2 session type used throughout
// the my-auth server. It satisfies both the OpenID Connect session interface
// (openid.Session) and the JWT access token interface
// (oauth2.JWTSessionContainer) so that fosite can issue both id_tokens and
// RS256-signed access tokens from the same session object.
package session

import (
	"github.com/mohae/deepcopy"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// Session is a composite session that satisfies both:
//   - openid.Session (for OIDC id_token generation via IDTokenClaims /
//     IDTokenHeaders, promoted from the embedded openid.DefaultSession)
//   - oauth2.JWTSessionContainer (for JWT access token generation via
//     GetJWTClaims / GetJWTHeader)
//
// Embedding openid.DefaultSession provides all fosite.Session lifecycle
// methods (GetExpiresAt, SetExpiresAt, GetUsername, GetSubject, …) as well as
// the OIDC-specific Claims and Headers fields. The JWTClaims and JWTHeader
// fields are the additional JWT access token data.
type Session struct {
	*openid.DefaultSession
	JWTClaims *jwt.JWTClaims `json:"jwt_claims"`
	JWTHeader *jwt.Headers   `json:"jwt_header"`
}

// NewSession creates a new composite Session for the given subject. It
// populates the OIDC side (DefaultSession) and the JWT access token side
// (JWTClaims / JWTHeader) with the subject and issuer so that both the
// id_token and the access token carry correct claims from the start.
func NewSession(subject string, issuer string) *Session {
	return &Session{
		DefaultSession: &openid.DefaultSession{
			Claims:  &jwt.IDTokenClaims{Subject: subject},
			Headers: &jwt.Headers{},
			Subject: subject,
		},
		JWTClaims: &jwt.JWTClaims{
			Subject: subject,
			Issuer:  issuer,
		},
		JWTHeader: &jwt.Headers{},
	}
}

// GetJWTClaims implements oauth2.JWTSessionContainer.
// fosite's DefaultJWTStrategy calls this to populate the JWT access token
// payload. A nil guard ensures the method is safe even if the session was
// deserialized from a database row that predates the JWTClaims field.
func (s *Session) GetJWTClaims() jwt.JWTClaimsContainer {
	if s.JWTClaims == nil {
		s.JWTClaims = &jwt.JWTClaims{}
	}
	return s.JWTClaims
}

// GetJWTHeader implements oauth2.JWTSessionContainer.
// fosite's DefaultJWTStrategy calls this to populate the JOSE header of the
// JWT access token (e.g. to set the "kid" key ID). A nil guard ensures the
// method is safe after deserialization.
func (s *Session) GetJWTHeader() *jwt.Headers {
	if s.JWTHeader == nil {
		s.JWTHeader = &jwt.Headers{}
	}
	return s.JWTHeader
}

// Clone implements fosite.Session. It overrides the Clone method promoted by
// the embedded openid.DefaultSession so that the outer Session struct
// (including JWTClaims and JWTHeader) is deep-copied rather than just the
// embedded DefaultSession.
func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	return deepcopy.Copy(s).(fosite.Session)
}
