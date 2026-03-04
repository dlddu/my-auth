package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ory/fosite"

	"github.com/dlddu/my-auth/internal/session"
)

// RevokeChecker checks whether a token's jti has been blacklisted.
type RevokeChecker interface {
	IsJTIRevoked(ctx context.Context, jti string) (bool, error)
}

// NewIntrospectHandler returns an http.HandlerFunc that handles POST /oauth2/introspect.
//
// It implements RFC 7662 token introspection. The handler delegates to fosite
// for token validation, then checks the revoked_tokens blacklist. A revoked
// token returns active: false while still including metadata (client_id,
// scope, sub, exp) so callers can distinguish it from an unknown token.
func NewIntrospectHandler(provider fosite.OAuth2Provider, checker RevokeChecker) http.HandlerFunc {
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

		// If fosite says the token is active, check the jti blacklist.
		// A revoked token returns active: false with metadata preserved.
		if resp.IsActive() {
			jti := resp.GetAccessRequester().GetID()
			revoked, checkErr := checker.IsJTIRevoked(ctx, jti)
			if checkErr == nil && revoked {
				writeRevokedIntrospection(w, resp)
				return
			}
		}

		provider.WriteIntrospectionResponse(ctx, w, resp)
	}
}

// writeRevokedIntrospection writes an RFC 7662 response with active: false
// but includes metadata from the original token session, distinguishing a
// blacklisted token from one that never existed.
func writeRevokedIntrospection(w http.ResponseWriter, resp fosite.IntrospectionResponder) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	ar := resp.GetAccessRequester()
	response := map[string]interface{}{
		"active": false,
	}

	if ar.GetClient().GetID() != "" {
		response["client_id"] = ar.GetClient().GetID()
	}
	if len(ar.GetGrantedScopes()) > 0 {
		response["scope"] = strings.Join(ar.GetGrantedScopes(), " ")
	}
	if ar.GetSession().GetSubject() != "" {
		response["sub"] = ar.GetSession().GetSubject()
	}
	if !ar.GetSession().GetExpiresAt(fosite.AccessToken).IsZero() {
		response["exp"] = ar.GetSession().GetExpiresAt(fosite.AccessToken).Unix()
	}

	_ = json.NewEncoder(w).Encode(response)
}
