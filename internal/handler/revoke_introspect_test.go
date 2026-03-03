// Package handler_test contains integration tests for the OAuth2 token
// revocation endpoint (POST /oauth2/revoke, RFC 7009) and the token
// introspection endpoint (POST /oauth2/introspect, RFC 7662).
//
// These tests are written in the TDD Red Phase: the handlers under test
// (handler.NewRevokeHandler and handler.NewIntrospectHandler) do not yet
// exist, so the package will not compile until the implementations are
// provided.
//
// Implementation checklist (all items must be done before tests pass):
//
//  1. Create internal/handler/revoke.go with:
//     func NewRevokeHandler(provider fosite.OAuth2Provider) http.HandlerFunc
//
//  2. Create internal/handler/introspect.go with:
//     func NewIntrospectHandler(provider fosite.OAuth2Provider) http.HandlerFunc
//
//  3. Register the routes in internal/testhelper/server.go buildRouter():
//     r.Post("/oauth2/revoke",     handler.NewRevokeHandler(oauth2Provider))
//     r.Post("/oauth2/introspect", handler.NewIntrospectHandler(oauth2Provider))
//
//  4. Add the two fosite factories to newFositeProvider() in
//     internal/testhelper/server.go and cmd/server/main.go compose.Compose:
//     compose.OAuth2TokenRevocationFactory
//     compose.OAuth2TokenIntrospectionFactory
//
// Test coverage:
//   - POST /oauth2/revoke with a valid access_token → 200 OK (RFC 7009 §2.2)
//   - POST /oauth2/revoke with an unknown/invalid token → 200 OK (RFC 7009 §2.2)
//   - POST /oauth2/revoke without client credentials → non-200 error
//   - POST /oauth2/revoke with wrong client secret → non-200 error
//   - POST /oauth2/introspect with a valid active access_token → active:true
//   - POST /oauth2/introspect with a revoked token → active:false
//   - POST /oauth2/introspect without client credentials → non-200 error
//   - POST /oauth2/introspect with an unknown token → active:false
//   - POST /oauth2/introspect response contains required RFC 7662 fields
package handler_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Shared helpers for revocation and introspection tests
// ---------------------------------------------------------------------------

// introspectResponse represents the JSON body returned by POST /oauth2/introspect.
// RFC 7662 §2.2 defines the response fields.
type introspectResponse struct {
	Active    bool   `json:"active"`
	Sub       string `json:"sub"`
	ClientID  string `json:"client_id"`
	Scope     string `json:"scope"`
	TokenType string `json:"token_type"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
}

// revokeToken calls POST /oauth2/revoke with the given token and
// authenticates via HTTP Basic Auth using the standard test-client credentials.
// It returns the raw *http.Response. The caller is responsible for closing
// resp.Body.
func revokeToken(t *testing.T, srvURL string, token string, clientID string, clientSecret string) *http.Response {
	t.Helper()

	form := url.Values{
		"token": {token},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srvURL+"/oauth2/revoke",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("revokeToken: http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("revokeToken: POST /oauth2/revoke: %v", err)
	}
	return resp
}

// introspectToken calls POST /oauth2/introspect with the given token and
// authenticates via HTTP Basic Auth. It returns the parsed introspectResponse
// and the raw HTTP status code. On non-200 responses the parsed body is nil.
func introspectToken(t *testing.T, srvURL string, token string, clientID string, clientSecret string) (*introspectResponse, int) {
	t.Helper()

	form := url.Values{
		"token": {token},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srvURL+"/oauth2/introspect",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("introspectToken: http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("introspectToken: POST /oauth2/introspect: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("introspectToken: io.ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}

	var ir introspectResponse
	if err := json.Unmarshal(body, &ir); err != nil {
		t.Fatalf("introspectToken: json.Unmarshal: %v — body: %s", err, body)
	}
	return &ir, resp.StatusCode
}

// obtainAccessToken is a convenience wrapper that runs the full
// login → authorize → token-exchange flow and returns a valid access_token.
func obtainAccessToken(t *testing.T, srvURL string, nonce string) string {
	t.Helper()
	code := loginAndGetCode(t, srvURL, nonce)
	tokens, status := exchangeCodeForTokens(t, srvURL, code)
	if status != http.StatusOK {
		t.Fatalf("obtainAccessToken: token exchange status = %d, want 200", status)
	}
	if tokens.AccessToken == "" {
		t.Fatal("obtainAccessToken: access_token is empty")
	}
	return tokens.AccessToken
}

// ---------------------------------------------------------------------------
// POST /oauth2/revoke — RFC 7009
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 1. TestRevokeHandler_ValidToken_Returns200
//    Happy path: POST /oauth2/revoke with a valid (active) access_token must
//    return HTTP 200 OK. RFC 7009 §2.2 mandates a 200 response regardless of
//    whether the token was found, provided client authentication succeeds.
// ---------------------------------------------------------------------------

func TestRevokeHandler_ValidToken_Returns200(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessToken(t, srv.URL, "revoke-nonce-1")

	// Act
	resp := revokeToken(t, srv.URL, accessToken, validClientID, "test-client-secret")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — RFC 7009 §2.2: successful revocation MUST return 200.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST /oauth2/revoke with valid token: status = %d, want 200", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// 2. TestRevokeHandler_InvalidToken_Returns200
//    RFC 7009 §2.2: if the token presented is expired, already revoked, or
//    was never issued, the authorization server MUST respond with HTTP 200.
//    Clients must not be able to infer whether a token was valid.
// ---------------------------------------------------------------------------

func TestRevokeHandler_InvalidToken_Returns200(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act — present a token that was never issued by this server.
	resp := revokeToken(t, srv.URL, "totally-unknown-token-that-was-never-issued", validClientID, "test-client-secret")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — RFC 7009 §2.2: 200 even for unknown/invalid tokens.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("POST /oauth2/revoke with invalid token: status = %d, want 200", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// 3. TestRevokeHandler_NoClientAuth_ReturnsError
//    RFC 7009 §2.1: the revocation endpoint requires client authentication for
//    confidential clients. A request without credentials must be rejected.
// ---------------------------------------------------------------------------

func TestRevokeHandler_NoClientAuth_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessToken(t, srv.URL, "revoke-nonce-3")

	// Act — send revoke request with no client credentials (empty clientID).
	resp := revokeToken(t, srv.URL, accessToken, "", "")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — unauthenticated request must not return 200.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("POST /oauth2/revoke without client credentials: status = 200, want non-200")
	}
}

// ---------------------------------------------------------------------------
// 4. TestRevokeHandler_WrongClientSecret_ReturnsError
//    Client authentication with an incorrect secret must be rejected.
//    fosite returns HTTP 401 (invalid_client) when Basic Auth fails.
// ---------------------------------------------------------------------------

func TestRevokeHandler_WrongClientSecret_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessToken(t, srv.URL, "revoke-nonce-4")

	// Act — correct client_id but wrong secret.
	resp := revokeToken(t, srv.URL, accessToken, validClientID, "wrong-secret")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — must not return 200.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("POST /oauth2/revoke with wrong client secret: status = 200, want non-200")
	}
}

// ---------------------------------------------------------------------------
// 5. TestRevokeHandler_MissingToken_ReturnsError
//    A revocation request that omits the required "token" parameter is
//    malformed. fosite returns an unsupported_token_type or invalid_request
//    error for missing token parameter.
// ---------------------------------------------------------------------------

func TestRevokeHandler_MissingToken_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Build a request without the "token" form field.
	form := url.Values{}
	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/revoke",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(validClientID, "test-client-secret")

	// Act
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/revoke (no token): %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — missing token parameter should not yield 200.
	// RFC 7009 §2.1: "token" is REQUIRED.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("POST /oauth2/revoke without token param: status = 200, want non-200")
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/introspect — RFC 7662
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 6. TestIntrospectHandler_ValidToken_ReturnsActive
//    Happy path: POST /oauth2/introspect with a currently active access_token
//    must return HTTP 200 with {"active": true}.
//    RFC 7662 §2.2: active=true means the token is valid and not expired.
// ---------------------------------------------------------------------------

func TestIntrospectHandler_ValidToken_ReturnsActive(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessToken(t, srv.URL, "introspect-nonce-6")

	// Act
	ir, status := introspectToken(t, srv.URL, accessToken, validClientID, "test-client-secret")

	// Assert — HTTP 200 OK.
	if status != http.StatusOK {
		t.Fatalf("POST /oauth2/introspect status = %d, want 200", status)
	}

	// Assert — active must be true for a valid, non-expired token.
	if !ir.Active {
		t.Error("introspect response: active = false, want true for a valid access_token")
	}
}

// ---------------------------------------------------------------------------
// 7. TestIntrospectHandler_ValidToken_ContainsRequiredFields
//    RFC 7662 §2.2: when active=true the response SHOULD contain sub,
//    scope, client_id, token_type, and exp. These fields enable the
//    resource server to make authorization decisions without re-validating
//    the JWT signature.
// ---------------------------------------------------------------------------

func TestIntrospectHandler_ValidToken_ContainsRequiredFields(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessToken(t, srv.URL, "introspect-nonce-7")

	// Act
	ir, status := introspectToken(t, srv.URL, accessToken, validClientID, "test-client-secret")

	if status != http.StatusOK {
		t.Fatalf("POST /oauth2/introspect status = %d, want 200", status)
	}

	if !ir.Active {
		t.Fatal("introspect response: active = false; cannot verify other fields on inactive token")
	}

	// Assert — sub (Subject) must identify the authenticated user.
	if ir.Sub == "" {
		t.Error("introspect response: missing \"sub\" field, want a non-empty subject")
	}
	// The test owner is "admin@test.local" (from testhelper/config.go).
	if ir.Sub != "admin@test.local" {
		t.Errorf("introspect response: sub = %q, want \"admin@test.local\"", ir.Sub)
	}

	// Assert — scope must be present and non-empty.
	if ir.Scope == "" {
		t.Error("introspect response: missing \"scope\" field, want a non-empty scope string")
	}

	// Assert — token_type must be "Bearer" (RFC 6749 §7.1).
	if !strings.EqualFold(ir.TokenType, "bearer") {
		t.Errorf("introspect response: token_type = %q, want \"Bearer\"", ir.TokenType)
	}

	// Assert — exp must be a positive unix timestamp.
	if ir.Exp <= 0 {
		t.Errorf("introspect response: exp = %d, want a positive unix timestamp", ir.Exp)
	}
}

// ---------------------------------------------------------------------------
// 8. TestIntrospectHandler_RevokedToken_ReturnsInactive
//    A token that has been explicitly revoked via POST /oauth2/revoke must
//    appear as inactive (active:false) when subsequently introspected.
//    This is the key integration test that verifies revocation and introspection
//    work together correctly.
//
//    Completion criteria from the requirements:
//    "폐기된 토큰 introspect → active: false"
// ---------------------------------------------------------------------------

func TestIntrospectHandler_RevokedToken_ReturnsInactive(t *testing.T) {
	// Arrange — obtain a valid access_token.
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessToken(t, srv.URL, "introspect-nonce-8")

	// Revoke the token (must return 200 per RFC 7009 §2.2).
	revokeResp := revokeToken(t, srv.URL, accessToken, validClientID, "test-client-secret")
	defer revokeResp.Body.Close()
	_, _ = io.Copy(io.Discard, revokeResp.Body)

	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth2/revoke: status = %d, want 200 (prerequisite for this test)", revokeResp.StatusCode)
	}

	// Act — introspect the now-revoked token.
	ir, status := introspectToken(t, srv.URL, accessToken, validClientID, "test-client-secret")

	// Assert — HTTP 200 OK (introspection always returns 200).
	if status != http.StatusOK {
		t.Fatalf("POST /oauth2/introspect after revocation: status = %d, want 200", status)
	}

	// Assert — active must be false after revocation.
	if ir.Active {
		t.Error("introspect response after revocation: active = true, want false")
	}
}

// ---------------------------------------------------------------------------
// 9. TestIntrospectHandler_UnknownToken_ReturnsInactive
//    RFC 7662 §2.2: if the token is not recognised (never issued or already
//    expired from storage), the server MUST return {"active": false} with
//    HTTP 200. This prevents information leakage about token validity.
// ---------------------------------------------------------------------------

func TestIntrospectHandler_UnknownToken_ReturnsInactive(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act — introspect a fabricated token that was never issued.
	ir, status := introspectToken(t, srv.URL, "totally-unknown-access-token-never-issued", validClientID, "test-client-secret")

	// Assert — HTTP 200 OK.
	if status != http.StatusOK {
		t.Fatalf("POST /oauth2/introspect with unknown token: status = %d, want 200", status)
	}

	// Assert — active must be false for a never-issued token.
	if ir.Active {
		t.Error("introspect response for unknown token: active = true, want false")
	}
}

// ---------------------------------------------------------------------------
// 10. TestIntrospectHandler_NoClientAuth_ReturnsError
//     RFC 7662 §2.1: the introspection endpoint requires client authentication.
//     A request without credentials must be rejected with a non-200 status.
// ---------------------------------------------------------------------------

func TestIntrospectHandler_NoClientAuth_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessToken(t, srv.URL, "introspect-nonce-10")

	// Act — no client credentials (empty clientID).
	_, status := introspectToken(t, srv.URL, accessToken, "", "")

	// Assert — unauthenticated request must not return 200.
	if status == http.StatusOK {
		t.Errorf("POST /oauth2/introspect without client credentials: status = 200, want non-200")
	}
}

// ---------------------------------------------------------------------------
// 11. TestIntrospectHandler_WrongClientSecret_ReturnsError
//     Introspection with an incorrect client_secret must be rejected.
//     RFC 7662 §2.1 requires the protected endpoint to authenticate the caller.
// ---------------------------------------------------------------------------

func TestIntrospectHandler_WrongClientSecret_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessToken(t, srv.URL, "introspect-nonce-11")

	// Act — correct client_id but wrong secret.
	_, status := introspectToken(t, srv.URL, accessToken, validClientID, "wrong-secret")

	// Assert — must not return 200.
	if status == http.StatusOK {
		t.Errorf("POST /oauth2/introspect with wrong client secret: status = 200, want non-200")
	}
}

// ---------------------------------------------------------------------------
// 12. TestIntrospectHandler_ValidToken_ReturnsJSON
//     The Content-Type of a successful introspection response must be
//     "application/json" and the body must be valid JSON per RFC 7662 §2.2.
// ---------------------------------------------------------------------------

func TestIntrospectHandler_ValidToken_ReturnsJSON(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessToken(t, srv.URL, "introspect-nonce-12")

	form := url.Values{
		"token": {accessToken},
	}
	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/introspect",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(validClientID, "test-client-secret")

	// Act
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/introspect: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — HTTP 200 OK.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth2/introspect status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	// Assert — Content-Type must be application/json.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want it to contain \"application/json\"", ct)
	}

	// Assert — body is valid JSON with an "active" field.
	var raw map[string]interface{}
	if jsonErr := json.Unmarshal(body, &raw); jsonErr != nil {
		t.Fatalf("response body is not valid JSON: %v — body: %s", jsonErr, body)
	}
	if _, hasActive := raw["active"]; !hasActive {
		t.Errorf("introspect response JSON missing \"active\" field; body = %s", body)
	}
}

// ---------------------------------------------------------------------------
// 13. TestRevokeHandler_ThenIntrospect_FlowIntegration
//     End-to-end integration test that exercises the full revoke → introspect
//     flow to confirm the acceptance criteria:
//       1. POST /oauth2/revoke (token) → 200 OK
//       2. POST /oauth2/introspect (revoked token) → active: false
//
//     This test differs from TestIntrospectHandler_RevokedToken_ReturnsInactive
//     by explicitly asserting both the revocation response code and the
//     subsequent introspection result in a single documented test.
// ---------------------------------------------------------------------------

func TestRevokeHandler_ThenIntrospect_FlowIntegration(t *testing.T) {
	// Arrange — obtain a valid access_token via the full authorization flow.
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessToken(t, srv.URL, "revoke-introspect-flow-13")

	// Step 1: verify the token is currently active.
	irBefore, statusBefore := introspectToken(t, srv.URL, accessToken, validClientID, "test-client-secret")
	if statusBefore != http.StatusOK {
		t.Fatalf("pre-revocation introspect: status = %d, want 200", statusBefore)
	}
	if !irBefore.Active {
		t.Fatal("pre-revocation introspect: active = false; token must be active before revocation")
	}

	// Step 2: revoke the token — RFC 7009 §2.2 requires 200 OK.
	revokeResp := revokeToken(t, srv.URL, accessToken, validClientID, "test-client-secret")
	defer revokeResp.Body.Close()
	_, _ = io.Copy(io.Discard, revokeResp.Body)

	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth2/revoke: status = %d, want 200", revokeResp.StatusCode)
	}

	// Step 3: introspect the revoked token — must now be inactive.
	irAfter, statusAfter := introspectToken(t, srv.URL, accessToken, validClientID, "test-client-secret")
	if statusAfter != http.StatusOK {
		t.Fatalf("post-revocation introspect: status = %d, want 200", statusAfter)
	}
	if irAfter.Active {
		t.Error("post-revocation introspect: active = true, want false after revocation")
	}
}
