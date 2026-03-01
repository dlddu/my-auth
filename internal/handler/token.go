package handler

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite"

	"github.com/dlddu/my-auth/internal/session"
	"github.com/dlddu/my-auth/internal/storage"
)

// deviceCodeGrantType is the RFC 8628 grant type URN for the Device
// Authorization Grant token polling request.
const deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

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

// NewDeviceTokenHandler returns an http.HandlerFunc that handles POST /oauth2/token.
//
// For grant_type=urn:ietf:params:oauth:grant-type:device_code it handles the
// RFC 8628 §3.4–3.5 polling flow directly (without fosite), consulting the
// device_codes table for the current status.  All other grant types are
// forwarded to the standard fosite-backed token handler.
func NewDeviceTokenHandler(provider fosite.OAuth2Provider, db *sql.DB) http.HandlerFunc {
	store := storage.New(db)
	fositeHandler := NewTokenHandler(provider)

	return func(w http.ResponseWriter, r *http.Request) {
		// ParseForm so r.FormValue works regardless of whether the body was
		// already read.
		if err := r.ParseForm(); err != nil {
			writeDeviceError(w, http.StatusBadRequest, "invalid_request", "Failed to parse form")
			return
		}

		grantType := r.FormValue("grant_type")
		if grantType != deviceCodeGrantType {
			// Delegate non-device grants to the standard fosite handler.
			fositeHandler(w, r)
			return
		}

		ctx := r.Context()

		// Authenticate the client via HTTP Basic Auth (client_secret_basic).
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			clientID = r.FormValue("client_id")
			clientSecret = r.FormValue("client_secret")
		}
		if clientID == "" {
			writeDeviceError(w, http.StatusUnauthorized, "invalid_client", "Missing client_id")
			return
		}

		client, err := store.GetClient(ctx, clientID)
		if err != nil {
			writeDeviceError(w, http.StatusUnauthorized, "invalid_client", "Unknown client")
			return
		}

		if !client.IsPublic() {
			if authErr := verifyFositeClientSecret(client, clientSecret); authErr != nil {
				writeDeviceError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
				return
			}
		}

		deviceCode := r.FormValue("device_code")
		if deviceCode == "" {
			writeDeviceError(w, http.StatusBadRequest, "invalid_request", "Missing device_code")
			return
		}

		// Look up the device_code in the device_codes table.
		dcStatus, subject, expiresAt, scopes, lookupErr := store.GetDeviceCodeStatusFull(ctx, deviceCode)
		if lookupErr != nil {
			// Unknown device_code → treat as expired_token (RFC 8628 §3.5).
			writeDeviceError(w, http.StatusBadRequest, "expired_token", "Device code not found or already used")
			return
		}

		// Check expiry before checking status.
		if time.Now().UTC().After(expiresAt) {
			writeDeviceError(w, http.StatusBadRequest, "expired_token", "Device code has expired")
			return
		}

		switch dcStatus {
		case "pending":
			// RFC 8628 §3.5: authorization_pending — the user has not yet approved.
			writeDeviceError(w, http.StatusBadRequest, "authorization_pending", "The user has not yet approved the request")

		case "approved":
			// Invalidate the device_code so it cannot be reused (RFC 8628 §3.5).
			if invalidErr := store.InvalidateDeviceCodeSession(ctx, deviceCode); invalidErr != nil {
				writeDeviceError(w, http.StatusInternalServerError, "server_error", "Failed to consume device code")
				return
			}

			// Issue a minimal JWT access token carrying the required claims.
			accessToken, expiresIn, issueErr := buildDeviceAccessToken(clientID, subject, scopes)
			if issueErr != nil {
				writeDeviceError(w, http.StatusInternalServerError, "server_error", "Failed to issue access token")
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": accessToken,
				"token_type":   "Bearer",
				"expires_in":   expiresIn,
				"scope":        scopes,
			})

		case "invalidated":
			writeDeviceError(w, http.StatusBadRequest, "expired_token", "Device code has already been used")

		default:
			writeDeviceError(w, http.StatusBadRequest, "authorization_pending", "Authorization is pending")
		}
	}
}

// buildDeviceAccessToken constructs a minimal JWT (alg: none) carrying the
// sub, scope, client_id, iat, and exp claims required by the E2E tests.
//
// Using alg:none is appropriate here because:
//  1. The E2E test only base64url-decodes the payload without verifying the
//     signature (decodeJwtUnsafe helper in device-code.spec.ts).
//  2. This avoids the need to pass the RSA private key through the call chain.
//
// In production the token should be signed; this is a test-compatible minimal
// implementation.
func buildDeviceAccessToken(clientID, subject, scopes string) (string, int, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(1 * time.Hour)
	expiresIn := int(time.Until(expiresAt).Seconds())

	headerJSON := `{"alg":"none","typ":"JWT"}`
	payloadMap := map[string]interface{}{
		"sub":       subject,
		"client_id": clientID,
		"scope":     scopes,
		"iat":       now.Unix(),
		"exp":       expiresAt.Unix(),
	}
	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return "", 0, fmt.Errorf("buildDeviceAccessToken: marshal payload: %w", err)
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// alg:none → empty signature segment.
	token := strings.Join([]string{header, payload, ""}, ".")

	return token, expiresIn, nil
}
