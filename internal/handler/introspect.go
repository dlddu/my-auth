package handler

import (
	"net/http"

	"github.com/ory/fosite"

	"github.com/dlddu/my-auth/internal/session"
)

// NewIntrospectHandler returns an http.HandlerFunc that handles POST /oauth2/introspect.
//
// It implements RFC 7662 token introspection. The handler delegates to fosite:
// NewIntrospectionRequest validates the client and inspects the token,
// returning a response with active:true for valid tokens and active:false for
// invalid, expired, or revoked tokens.
func NewIntrospectHandler(provider fosite.OAuth2Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// An empty session is created because fosite's NewIntrospectionRequest
		// needs a session object to populate from the stored token data. If
		// custom claims are needed in introspection responses in the future,
		// pre-populate the session here before passing it to fosite.
		mySession := session.NewSession("", "")

		resp, err := provider.NewIntrospectionRequest(ctx, r, mySession)
		if err != nil {
			provider.WriteIntrospectionError(ctx, w, err)
			return
		}

		provider.WriteIntrospectionResponse(ctx, w, resp)
	}
}
