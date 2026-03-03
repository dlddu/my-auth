package handler

import (
	"net/http"

	"github.com/ory/fosite"
)

// NewRevokeHandler returns an http.HandlerFunc that handles POST /oauth2/revoke.
//
// It implements RFC 7009 token revocation. The handler delegates entirely to
// fosite: NewRevocationRequest validates the client and locates the token,
// and WriteRevocationResponse writes the appropriate HTTP response.
//
// Per RFC 7009 §2.2, a 200 OK is returned even when the presented token is
// invalid, expired, or was never issued — fosite handles this automatically.
func NewRevokeHandler(provider fosite.OAuth2Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		err := provider.NewRevocationRequest(ctx, r)

		provider.WriteRevocationResponse(ctx, w, err)
	}
}
