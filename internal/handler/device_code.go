package handler

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ory/fosite"

	"github.com/dlddu/my-auth/internal/config"
	"github.com/dlddu/my-auth/internal/storage"
)

// deviceCodeExpiresIn is the lifetime of a device code in seconds (10 minutes).
const deviceCodeExpiresIn = 600

// deviceCodePollInterval is the recommended polling interval in seconds.
const deviceCodePollInterval = 5

// deviceCodeResponseBody is the RFC 8628 §3.2 JSON response body for
// POST /oauth2/device/code.
type deviceCodeResponseBody struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// deviceErrorResponseBody is the RFC 6749 §5.2 JSON error body.
type deviceErrorResponseBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// NewDeviceCodeHandler returns an http.HandlerFunc that handles
// POST /oauth2/device/code (RFC 8628 §3.2 Device Authorization Request).
//
// The handler:
//  1. Authenticates the client via HTTP Basic Auth (client_secret_basic).
//  2. Generates a cryptographically random device_code (opaque hex token).
//  3. Generates a user_code in ABCD-EFGH format (8 uppercase ASCII letters).
//  4. Persists both codes via the storage layer (single row).
//  5. Returns the RFC 8628 §3.2 JSON response.
func NewDeviceCodeHandler(cfg *config.Config, db *sql.DB) http.HandlerFunc {
	store := storage.New(db)

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeDeviceError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is supported")
			return
		}

		if err := r.ParseForm(); err != nil {
			writeDeviceError(w, http.StatusBadRequest, "invalid_request", "Failed to parse form")
			return
		}

		ctx := r.Context()

		// 1. Authenticate the client via HTTP Basic Auth.
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			clientID = r.FormValue("client_id")
			clientSecret = r.FormValue("client_secret")
		}

		if clientID == "" {
			writeDeviceError(w, http.StatusUnauthorized, "invalid_client", "Missing client_id")
			return
		}

		// Look up the client in the store.
		client, err := store.GetClient(ctx, clientID)
		if err != nil {
			writeDeviceError(w, http.StatusUnauthorized, "invalid_client", "Unknown client")
			return
		}

		// Verify the client secret unless it is a public client.
		if !client.IsPublic() {
			if authErr := verifyFositeClientSecret(client, clientSecret); authErr != nil {
				writeDeviceError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
				return
			}
		}

		// 2. Generate device_code — 32 random bytes encoded as hex (64 chars).
		deviceCode, err := generateOpaqueDeviceCode()
		if err != nil {
			writeDeviceError(w, http.StatusInternalServerError, "server_error", "Failed to generate device code")
			return
		}

		// 3. Generate user_code — 4 uppercase letters + hyphen + 4 uppercase letters.
		userCode, err := generateFormattedUserCode()
		if err != nil {
			writeDeviceError(w, http.StatusInternalServerError, "server_error", "Failed to generate user code")
			return
		}

		scope := r.FormValue("scope")
		expiresAt := time.Now().UTC().Add(time.Duration(deviceCodeExpiresIn) * time.Second)

		// 4. Persist a single device_codes row with both device_code and user_code.
		if err := store.InsertDeviceCode(ctx, deviceCode, userCode, clientID, scope, expiresAt); err != nil {
			writeDeviceError(w, http.StatusInternalServerError, "server_error", "Failed to persist device code")
			return
		}

		// 5. Build the verification URI.
		verificationURI := cfg.Issuer + "/device/verify"
		verificationURIComplete := verificationURI + "?user_code=" + userCode

		// 6. Return the RFC 8628 §3.2 JSON response.
		resp := deviceCodeResponseBody{
			DeviceCode:              deviceCode,
			UserCode:                userCode,
			VerificationURI:         verificationURI,
			VerificationURIComplete: verificationURIComplete,
			ExpiresIn:               deviceCodeExpiresIn,
			Interval:                deviceCodePollInterval,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			_ = err
		}
	}
}

// writeDeviceError writes a JSON error response following RFC 6749 §5.2.
func writeDeviceError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := deviceErrorResponseBody{
		Error:            errCode,
		ErrorDescription: description,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		_ = err
	}
}

// generateOpaqueDeviceCode generates a cryptographically random opaque device
// code as a 64-character lowercase hex string.
func generateOpaqueDeviceCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("handler: generateOpaqueDeviceCode: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// generateFormattedUserCode generates a user_code in ABCD-EFGH format:
// 4 uppercase ASCII letters, a hyphen, 4 uppercase ASCII letters.
func generateFormattedUserCode() (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const groupLen = 4

	b := make([]byte, groupLen*2)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("handler: generateFormattedUserCode: %w", err)
	}

	code := make([]byte, groupLen*2+1)
	for i := 0; i < groupLen; i++ {
		code[i] = alphabet[int(b[i])%len(alphabet)]
	}
	code[groupLen] = '-'
	for i := 0; i < groupLen; i++ {
		code[groupLen+1+i] = alphabet[int(b[groupLen+i])%len(alphabet)]
	}

	return string(code), nil
}

// verifyFositeClientSecret verifies a plain-text secret against the bcrypt
// hash stored in the fosite client's Secret field.
// fosite stores bcrypt hashes in the Secret field of DefaultClient.
func verifyFositeClientSecret(client fosite.Client, secret string) error {
	if dc, ok := client.(*fosite.DefaultOpenIDConnectClient); ok {
		return bcrypt.CompareHashAndPassword(dc.Secret, []byte(secret))
	}
	if dc, ok := client.(*fosite.DefaultClient); ok {
		return bcrypt.CompareHashAndPassword(dc.Secret, []byte(secret))
	}

	return fmt.Errorf("handler: cannot verify client secret: unsupported client type %T", client)
}
