// Package handler_test — Device Authorization Grant (RFC 8628) handler
// integration tests for POST /oauth2/device/code.
//
// These tests are written in the TDD Red Phase. They exercise the
// POST /oauth2/device/code endpoint and will fail until the following are
// implemented:
//
//  1. POST /oauth2/device/code handler (handler.NewDeviceCodeHandler) that:
//     - Generates a cryptographically random device_code (opaque token)
//     - Generates a user_code in ABCD-EFGH format (8 uppercase letters + hyphen)
//     - Persists both codes in the device_codes table via the storage layer
//     - Returns JSON: {"device_code", "user_code", "verification_uri", "expires_in"}
//
//  2. Route registered in testhelper/server.go buildRouter():
//     r.Post("/oauth2/device/code", handler.NewDeviceCodeHandler(...))
//
//  3. Device code client seeded by seedTestClient() in testhelper/server.go
//     with grant_types=["urn:ietf:params:oauth:grant-type:device_code"]
//
// Test coverage:
//   - Happy path: valid client → 200 JSON with device_code, user_code,
//     verification_uri, expires_in
//   - user_code format: 8 uppercase letters with a hyphen in the middle (XXXX-XXXX)
//   - device_code is non-empty and opaque (not a JWT)
//   - verification_uri points to /device/verify (or server-relative path)
//   - expires_in is a positive integer
//   - Unknown client_id → non-200 error response
//   - Missing client credentials → non-200 error response
//   - Repeated requests produce distinct device_code and user_code values
package handler_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Device Code test constants
// ---------------------------------------------------------------------------

// deviceClientID is the OAuth2 client ID used for device code flow tests.
// The client must be seeded by testhelper.NewTestServer with:
//   - grant_types: ["urn:ietf:params:oauth:grant-type:device_code"]
//   - scopes:      ["openid", "profile", "email"]
const deviceClientID = "device-client"

// deviceClientSecret is the plain-text secret for deviceClientID.
const deviceClientSecret = "device-secret"

// deviceScope is the scope string requested in device code requests.
const deviceScope = "openid profile"

// userCodePattern matches the required ABCD-EFGH format:
// exactly 4 uppercase ASCII letters, a hyphen, 4 uppercase ASCII letters.
var userCodePattern = regexp.MustCompile(`^[A-Z]{4}-[A-Z]{4}$`)

// ---------------------------------------------------------------------------
// deviceCodeResponse represents the JSON body returned by
// POST /oauth2/device/code per RFC 8628 §3.2.
// ---------------------------------------------------------------------------
type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// ---------------------------------------------------------------------------
// requestDeviceCode is a shared helper that posts a device authorization
// request and returns the raw *http.Response.
//
// The caller is responsible for closing resp.Body.
// ---------------------------------------------------------------------------
func requestDeviceCode(
	t *testing.T,
	srvURL string,
	clientID string,
	clientSecret string,
	scope string,
) *http.Response {
	t.Helper()

	form := url.Values{
		"client_id": {clientID},
		"scope":     {scope},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srvURL+"/oauth2/device/code",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("requestDeviceCode: http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// RFC 6749 §2.3.1: client_secret_basic via HTTP Basic Auth.
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("requestDeviceCode: POST /oauth2/device/code: %v", err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// 1. TestDeviceCodeHandler_ReturnsRequiredFields
//    Happy path: valid device client → 200 JSON with all required RFC 8628
//    §3.2 fields: device_code, user_code, verification_uri, expires_in.
// ---------------------------------------------------------------------------

func TestDeviceCodeHandler_ReturnsRequiredFields(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act
	resp := requestDeviceCode(t, srv.URL, deviceClientID, deviceClientSecret, deviceScope)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — HTTP 200 OK.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth2/device/code status = %d, want 200; body = %s",
			resp.StatusCode, body)
	}

	// Assert — Content-Type is application/json.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want it to contain \"application/json\"", ct)
	}

	var dcr deviceCodeResponse
	if err := json.Unmarshal(body, &dcr); err != nil {
		t.Fatalf("json.Unmarshal deviceCodeResponse: %v — body: %s", err, body)
	}

	// Assert — device_code is present and non-empty.
	if dcr.DeviceCode == "" {
		t.Error("device_code is empty, want a non-empty opaque token")
	}

	// Assert — user_code is present and non-empty.
	if dcr.UserCode == "" {
		t.Error("user_code is empty, want a non-empty code")
	}

	// Assert — verification_uri is present and non-empty.
	if dcr.VerificationURI == "" {
		t.Error("verification_uri is empty, want a non-empty URI")
	}

	// Assert — expires_in is a positive number.
	if dcr.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want a positive value", dcr.ExpiresIn)
	}
}

// ---------------------------------------------------------------------------
// 2. TestDeviceCodeHandler_UserCodeFormat
//    The user_code must match the ABCD-EFGH format required by the
//    acceptance criteria: 8 uppercase ASCII letters split by a hyphen.
//
//    RFC 8628 §6.1 recommends using characters that are easy to type and
//    visually distinct. The project spec requires the XXXX-XXXX form.
// ---------------------------------------------------------------------------

func TestDeviceCodeHandler_UserCodeFormat(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act
	resp := requestDeviceCode(t, srv.URL, deviceClientID, deviceClientSecret, deviceScope)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth2/device/code status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	var dcr deviceCodeResponse
	if err := json.Unmarshal(body, &dcr); err != nil {
		t.Fatalf("json.Unmarshal: %v — body: %s", err, body)
	}

	// Assert — user_code must match XXXX-XXXX (4 uppercase letters, hyphen,
	// 4 uppercase letters). Total length = 9 characters.
	if !userCodePattern.MatchString(dcr.UserCode) {
		t.Errorf("user_code = %q, want format matching %s (e.g. ABCD-EFGH)",
			dcr.UserCode, userCodePattern.String())
	}
}

// ---------------------------------------------------------------------------
// 3. TestDeviceCodeHandler_DeviceCodeIsOpaque
//    The device_code must not be a JWT (three dot-separated base64url
//    segments). RFC 8628 §3.2 states it is an opaque credential.
// ---------------------------------------------------------------------------

func TestDeviceCodeHandler_DeviceCodeIsOpaque(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act
	resp := requestDeviceCode(t, srv.URL, deviceClientID, deviceClientSecret, deviceScope)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth2/device/code status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	var dcr deviceCodeResponse
	if err := json.Unmarshal(body, &dcr); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Assert — device_code must NOT look like a JWT.
	if isJWT(dcr.DeviceCode) {
		t.Errorf("device_code = %q looks like a JWT; want an opaque token", dcr.DeviceCode)
	}
}

// ---------------------------------------------------------------------------
// 4. TestDeviceCodeHandler_VerificationURIPointsToDeviceVerify
//    The verification_uri must point to the /device/verify endpoint so that
//    users can visit it to enter their user_code.
// ---------------------------------------------------------------------------

func TestDeviceCodeHandler_VerificationURIPointsToDeviceVerify(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act
	resp := requestDeviceCode(t, srv.URL, deviceClientID, deviceClientSecret, deviceScope)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth2/device/code status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	var dcr deviceCodeResponse
	if err := json.Unmarshal(body, &dcr); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Assert — verification_uri must contain "/device/verify".
	if !strings.Contains(dcr.VerificationURI, "/device/verify") {
		t.Errorf("verification_uri = %q, want it to contain \"/device/verify\"", dcr.VerificationURI)
	}
}

// ---------------------------------------------------------------------------
// 5. TestDeviceCodeHandler_ExpiresInIsPositive
//    expires_in must be a positive integer (seconds until expiry).
//    RFC 8628 §3.2 requires this field.
// ---------------------------------------------------------------------------

func TestDeviceCodeHandler_ExpiresInIsPositive(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act
	resp := requestDeviceCode(t, srv.URL, deviceClientID, deviceClientSecret, deviceScope)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth2/device/code status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	var dcr deviceCodeResponse
	if err := json.Unmarshal(body, &dcr); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Assert — expires_in must be greater than zero.
	if dcr.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want a positive value", dcr.ExpiresIn)
	}
}

// ---------------------------------------------------------------------------
// 6. TestDeviceCodeHandler_UnknownClient_ReturnsError
//    A request with an unregistered client_id must be rejected.
//    RFC 8628 §3.2 inherits error handling from RFC 6749 §5.2.
// ---------------------------------------------------------------------------

func TestDeviceCodeHandler_UnknownClient_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act — use a client_id that was never registered.
	resp := requestDeviceCode(t, srv.URL, "nonexistent-device-client", "any-secret", deviceScope)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — must not be 200.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("POST /oauth2/device/code with unknown client: status = 200, want non-200")
	}
}

// ---------------------------------------------------------------------------
// 7. TestDeviceCodeHandler_UnknownClient_ReturnsErrorJSON
//    The error response for an unknown client must be valid JSON with an
//    "error" field per RFC 6749 §5.2.
// ---------------------------------------------------------------------------

func TestDeviceCodeHandler_UnknownClient_ReturnsErrorJSON(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act
	resp := requestDeviceCode(t, srv.URL, "nonexistent-device-client-json", "any-secret", deviceScope)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — must not be 200.
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("status = 200, want non-200; body = %s", body)
	}

	// Assert — Content-Type must be application/json.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want it to contain \"application/json\"", ct)
	}

	// Assert — body has a non-empty "error" field.
	var errResp tokenErrorResponse
	if jsonErr := json.Unmarshal(body, &errResp); jsonErr != nil {
		t.Fatalf("response body is not valid JSON: %v — body: %s", jsonErr, body)
	}
	if errResp.Error == "" {
		t.Errorf("error field is empty; body = %s", body)
	}
}

// ---------------------------------------------------------------------------
// 8. TestDeviceCodeHandler_WrongSecret_ReturnsError
//    A request with an incorrect client_secret must be rejected.
//    RFC 6749 §3.2.1 requires client authentication at the token endpoint;
//    the device authorization endpoint applies the same rule.
// ---------------------------------------------------------------------------

func TestDeviceCodeHandler_WrongSecret_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act — correct client_id, wrong secret.
	resp := requestDeviceCode(t, srv.URL, deviceClientID, "wrong-device-secret", deviceScope)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — must not be 200.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("POST /oauth2/device/code with wrong secret: status = 200, want non-200")
	}
}

// ---------------------------------------------------------------------------
// 9. TestDeviceCodeHandler_TwoRequests_ProduceDistinctCodes
//    Each call to POST /oauth2/device/code must generate a fresh, unique
//    device_code and user_code. Repeated codes would allow replay attacks.
// ---------------------------------------------------------------------------

func TestDeviceCodeHandler_TwoRequests_ProduceDistinctCodes(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act — issue two sequential device code requests.
	resp1 := requestDeviceCode(t, srv.URL, deviceClientID, deviceClientSecret, deviceScope)
	defer resp1.Body.Close()
	body1, err := io.ReadAll(resp1.Body)
	if err != nil {
		t.Fatalf("io.ReadAll (req 1): %v", err)
	}

	resp2 := requestDeviceCode(t, srv.URL, deviceClientID, deviceClientSecret, deviceScope)
	defer resp2.Body.Close()
	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("io.ReadAll (req 2): %v", err)
	}

	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("request 1: status = %d, want 200; body = %s", resp1.StatusCode, body1)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("request 2: status = %d, want 200; body = %s", resp2.StatusCode, body2)
	}

	var dcr1, dcr2 deviceCodeResponse
	if err := json.Unmarshal(body1, &dcr1); err != nil {
		t.Fatalf("json.Unmarshal (req 1): %v", err)
	}
	if err := json.Unmarshal(body2, &dcr2); err != nil {
		t.Fatalf("json.Unmarshal (req 2): %v", err)
	}

	// Assert — device_codes must be distinct.
	if dcr1.DeviceCode == dcr2.DeviceCode {
		t.Errorf("device_code is identical across two requests (%q), want unique values", dcr1.DeviceCode)
	}

	// Assert — user_codes must be distinct.
	if dcr1.UserCode == dcr2.UserCode {
		t.Errorf("user_code is identical across two requests (%q), want unique values", dcr1.UserCode)
	}
}
