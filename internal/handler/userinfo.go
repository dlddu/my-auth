package handler

import (
	"encoding/json"
	"net/http"

	"github.com/ory/fosite"

	"github.com/dlddu/my-auth/internal/config"
	"github.com/dlddu/my-auth/internal/session"
)

// userInfoClaims represents the JSON body returned by GET /oauth2/userinfo.
// Fields are pointers so that absent claims (due to missing scopes) are
// omitted from the JSON output rather than serialised as zero values.
type userInfoClaims struct {
	Sub           *string `json:"sub,omitempty"`
	Name          *string `json:"name,omitempty"`
	GivenName     *string `json:"given_name,omitempty"`
	FamilyName    *string `json:"family_name,omitempty"`
	Email         *string `json:"email,omitempty"`
	EmailVerified *bool   `json:"email_verified,omitempty"`
}

// NewUserInfoHandler returns an http.HandlerFunc that handles
// GET /oauth2/userinfo as specified by OIDC Core 1.0 §5.3.
//
// The handler validates the Bearer token supplied in the Authorization header
// via fosite's IntrospectToken (called directly, since NewIntrospectionRequest
// is POST-only and would always reject GET requests), then builds a claims
// response containing only the claims that correspond to the granted scopes:
//   - openid  → sub (always included when the token is valid)
//   - profile → name, given_name, family_name
//   - email   → email, email_verified
//
// Invalid or absent tokens result in HTTP 401 Unauthorized with the
// WWW-Authenticate: Bearer header as required by RFC 6750 §3.
func NewUserInfoHandler(provider fosite.OAuth2Provider, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Extract the Bearer token from the Authorization header (RFC 6750 §2.1).
		// fosite.AccessTokenFromRequest handles both "Authorization: Bearer <token>"
		// and "?access_token=<token>" query-parameter forms.
		token := fosite.AccessTokenFromRequest(r)
		if token == "" {
			// RFC 6750 §3.1: respond with 401 and WWW-Authenticate: Bearer.
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Validate the token directly via IntrospectToken, which works for any
		// HTTP method (unlike NewIntrospectionRequest which requires POST with a
		// form body containing the token parameter per RFC 7662 §2.1).
		mySession := session.NewSession("", "")
		_, ar, err := provider.IntrospectToken(ctx, token, fosite.AccessToken, mySession)
		if err != nil {
			// RFC 6750 §3.1: respond with 401 and WWW-Authenticate: Bearer.
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		sub := ar.GetSession().GetSubject()
		grantedScopes := ar.GetGrantedScopes()

		claims := &userInfoClaims{}

		// "sub" is always included for a valid openid token (OIDC Core §5.3).
		claims.Sub = &sub

		// "profile" scope → name, given_name, family_name (OIDC Core §5.1).
		if fosite.Arguments(grantedScopes).Has("profile") {
			username := cfg.Owner.Username
			claims.Name = &username
			// Derive given_name from the username for completeness.
			// For a single-owner server the username doubles as the display name.
			given := username
			claims.GivenName = &given
		}

		// "email" scope → email, email_verified (OIDC Core §5.1).
		if fosite.Arguments(grantedScopes).Has("email") {
			email := cfg.Owner.Username
			verified := true
			claims.Email = &email
			claims.EmailVerified = &verified
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(claims)
	}
}
