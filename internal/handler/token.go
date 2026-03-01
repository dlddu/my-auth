package handler

import (
	"net/http"

	"github.com/ory/fosite"

	"github.com/dlddu/my-auth/internal/session"
)

// NewTokenHandler returns an http.HandlerFunc that handles POST /oauth2/token.
//
// It implements the OAuth2 token endpoint for the authorization code grant.
// fosite validates the request (client credentials, code, redirect_uri), issues
// an access token, an id_token (OpenID Connect), and a refresh token, then
// writes the RFC 6749 §5.1 JSON response.
func NewTokenHandler(provider fosite.OAuth2Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Create a new session stub. fosite will populate it with the data
		// from the authorize request session that was stored in the database.
		// session.Session satisfies both openid.Session (id_token) and
		// oauth2.JWTSessionContainer (JWT access token).
		mySession := new(session.Session)

		// Validate client credentials, grant_type, code, redirect_uri, etc.
		ar, err := provider.NewAccessRequest(ctx, r, mySession)
		if err != nil {
			provider.WriteAccessError(ctx, w, ar, err)
			return
		}

		// Issue access_token, id_token, refresh_token.
		resp, err := provider.NewAccessResponse(ctx, ar)
		if err != nil {
			provider.WriteAccessError(ctx, w, ar, err)
			return
		}

		// Write the RFC 6749 §5.1 JSON response.
		provider.WriteAccessResponse(ctx, w, ar, resp)
	}
}
