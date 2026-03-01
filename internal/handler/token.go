package handler

import (
	"net/http"

	"github.com/ory/fosite"

	"github.com/dlddu/my-auth/internal/session"
)

// NewTokenHandler returns an http.HandlerFunc that handles POST /oauth2/token.
//
// It implements the OAuth2 token endpoint for both the authorization code grant
// and the client credentials grant. fosite validates the request and issues
// the appropriate tokens.
//
// For client_credentials grant, this handler additionally:
//   - Grants all requested scopes explicitly (fosite does not auto-grant).
//   - Sets the JWT session subject to the client ID (RFC 9068 §2: "sub" for
//     client credentials MUST be the client_id).
//
// fosite writes the RFC 6749 §5.1 JSON response.
func NewTokenHandler(provider fosite.OAuth2Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Create a new session stub. fosite will populate it with the data
		// from the authorize request session that was stored in the database.
		// session.Session satisfies both openid.Session (id_token) and
		// oauth2.JWTSessionContainer (JWT access token).
		mySession := session.NewSession("", "")

		// Validate client credentials, grant_type, code, redirect_uri, etc.
		ar, err := provider.NewAccessRequest(ctx, r, mySession)
		if err != nil {
			provider.WriteAccessError(ctx, w, ar, err)
			return
		}

		// client_credentials grant requires explicit scope granting and session
		// subject population, because there is no prior authorization request
		// session in the database to restore these from.
		if ar.GetGrantTypes().ExactOne("client_credentials") {
			// Grant all scopes that were validated by fosite's
			// ClientCredentialsGrantHandler.HandleTokenEndpointRequest.
			for _, scope := range ar.GetRequestedScopes() {
				ar.GrantScope(scope)
			}

			// RFC 9068 §2: for client_credentials, "sub" MUST identify the
			// client (i.e. the client_id). Set it on the JWT session so that
			// DefaultJWTStrategy.generate() can include it in the access token.
			clientID := ar.GetClient().GetID()
			if sess, ok := ar.GetSession().(*session.Session); ok {
				if sess.JWTClaims != nil {
					sess.JWTClaims.Subject = clientID
				}
				if sess.DefaultSession != nil {
					sess.DefaultSession.Subject = clientID
				}
			}
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
