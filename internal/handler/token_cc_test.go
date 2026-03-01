// Package handler_test — Client Credentials grant integration tests (DLD-672).
//
// These tests are written in the TDD Red Phase. They exercise the
// POST /oauth2/token endpoint with grant_type=client_credentials and will
// fail until the following changes are made:
//
//  1. compose.OAuth2ClientCredentialsGrantFactory is added to the factory list
//     in internal/testhelper/server.go newFositeProvider() and
//     cmd/server/main.go.
//
//  2. A "cc-client" with grant_types=["client_credentials"] and
//     scopes=["read","write"] is seeded by seedTestClient() in
//     internal/testhelper/server.go.
//
// Test coverage:
//   - Happy path: client_credentials → access_token issued, no refresh_token
//   - Issued access_token is a JWT (RS256, three dot-separated segments)
//   - JWT access_token contains required claims: iss, sub, aud, scope, exp, jti
//   - Granted scope appears in both the token response and the access_token JWT
//   - Wrong client_secret → error response (non-200)
//   - Client not allowed to use client_credentials grant → error response
//   - Error response body is valid RFC 6749 §5.2 JSON with "error" field
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
// Client Credentials test constants
// ---------------------------------------------------------------------------

// ccClientID is the OAuth2 client ID used for all client_credentials tests.
// This client must be seeded by testhelper.NewTestServer with:
//   - grant_types: ["client_credentials"]
//   - scopes:      ["read", "write"]
//   - secret:      "cc-secret" (bcrypt-hashed)
const ccClientID = "cc-client"

// ccClientSecret is the plain-text secret for ccClientID.
const ccClientSecret = "cc-secret"

// ccScope is the scope string requested in client_credentials token requests.
const ccScope = "read write"

// ---------------------------------------------------------------------------
// requestClientCredentialsToken is a shared helper that posts a
// grant_type=client_credentials token request and returns the raw *http.Response.
//
// The caller is responsible for closing resp.Body.
// ---------------------------------------------------------------------------
func requestClientCredentialsToken(
	t *testing.T,
	srvURL string,
	clientID string,
	clientSecret string,
	scope string,
) *http.Response {
	t.Helper()

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {scope},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srvURL+"/oauth2/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("requestClientCredentialsToken: http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// RFC 6749 §2.3.1: client_secret_basic authentication via HTTP Basic Auth.
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("requestClientCredentialsToken: POST /oauth2/token: %v", err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// 1. TestTokenHandler_ClientCredentials_ReturnsAccessToken
//    Happy path: valid cc-client + correct secret → 200 with access_token.
//    RFC 6749 §4.4.3 mandates an access_token in the response.
//    Client Credentials MUST NOT return a refresh_token (RFC 6749 §4.4.3).
// ---------------------------------------------------------------------------

func TestTokenHandler_ClientCredentials_ReturnsAccessToken(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act
	resp := requestClientCredentialsToken(t, srv.URL, ccClientID, ccClientSecret, ccScope)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — HTTP 200 OK.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth2/token (client_credentials) status = %d, want 200; body = %s",
			resp.StatusCode, body)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatalf("json.Unmarshal tokenResponse: %v — body: %s", err, body)
	}

	// Assert — access_token is present and non-empty.
	if tr.AccessToken == "" {
		t.Error("access_token is empty, want a non-empty token string")
	}

	// Assert — token_type is "bearer" (case-insensitive, RFC 6749 §7.1).
	if !strings.EqualFold(tr.TokenType, "bearer") {
		t.Errorf("token_type = %q, want \"bearer\"", tr.TokenType)
	}

	// Assert — expires_in is a positive number.
	if tr.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want a positive value", tr.ExpiresIn)
	}

	// Assert — Client Credentials grant MUST NOT issue a refresh_token.
	// RFC 6749 §4.4.3: "A refresh token SHOULD NOT be included."
	if tr.RefreshToken != "" {
		t.Errorf("refresh_token = %q, want absent (client_credentials must not issue refresh tokens)", tr.RefreshToken)
	}

	// Assert — id_token must not be present (no end-user is involved).
	if tr.IDToken != "" {
		t.Errorf("id_token = %q, want absent (client_credentials is not an OpenID Connect flow)", tr.IDToken)
	}
}

// ---------------------------------------------------------------------------
// 2. TestTokenHandler_ClientCredentials_AccessToken_IsJWT
//    The access_token issued for client_credentials must be a compact JWS
//    (RS256 JWT) — three dot-separated base64url segments.
// ---------------------------------------------------------------------------

func TestTokenHandler_ClientCredentials_AccessToken_IsJWT(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act
	resp := requestClientCredentialsToken(t, srv.URL, ccClientID, ccClientSecret, ccScope)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth2/token status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatalf("json.Unmarshal tokenResponse: %v", err)
	}

	// Assert — access_token must be a compact JWS (three segments).
	if !isJWT(tr.AccessToken) {
		t.Errorf("access_token = %q, want a JWT (three dot-separated segments)", tr.AccessToken)
	}
}

// ---------------------------------------------------------------------------
// 3. TestTokenHandler_ClientCredentials_AccessToken_ContainsRequiredClaims
//    The JWT access_token payload must contain: iss, sub, aud, scope, exp, jti.
//    (RFC 9068 §2 — JWT Profile for OAuth 2.0 Access Tokens)
//
//    For client_credentials, "sub" is the client_id (no end-user principal).
// ---------------------------------------------------------------------------

func TestTokenHandler_ClientCredentials_AccessToken_ContainsRequiredClaims(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act
	resp := requestClientCredentialsToken(t, srv.URL, ccClientID, ccClientSecret, ccScope)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth2/token status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatalf("json.Unmarshal tokenResponse: %v", err)
	}

	if !isJWT(tr.AccessToken) {
		t.Fatalf("access_token is not a JWT: %q", tr.AccessToken)
	}

	claims := decodeJWTClaims(t, tr.AccessToken)

	// Assert — iss (Issuer) must be the configured issuer.
	iss, ok := claims["iss"].(string)
	if !ok || iss == "" {
		t.Error("access_token missing \"iss\" claim or it is not a string")
	}
	if iss != "https://auth.test.local" {
		t.Errorf("access_token claim iss = %q, want \"https://auth.test.local\"", iss)
	}

	// Assert — sub (Subject) must be present.
	// For client_credentials, fosite typically sets sub to the client_id.
	if _, hasSub := claims["sub"]; !hasSub {
		t.Error("access_token missing \"sub\" claim")
	}

	// Assert — aud (Audience) must be present.
	if _, hasAud := claims["aud"]; !hasAud {
		t.Error("access_token missing \"aud\" claim")
	}

	// Assert — scope must be present.
	if _, hasScope := claims["scope"]; !hasScope {
		t.Error("access_token missing \"scope\" claim")
	}

	// Assert — exp (Expiration) must be a positive unix timestamp.
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Error("access_token missing \"exp\" claim or it is not a number")
	} else if exp <= 0 {
		t.Errorf("access_token claim exp = %v, want a positive unix timestamp", exp)
	}

	// Assert — jti (JWT ID) must be a non-empty string (RFC 7519 §4.1.7).
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		t.Error("access_token missing \"jti\" claim or it is not a non-empty string")
	}
}

// ---------------------------------------------------------------------------
// 4. TestTokenHandler_ClientCredentials_ScopeReflectedInResponse
//    The "scope" field in the token response must reflect the scopes that were
//    granted. Both the top-level "scope" field and the JWT claim are checked.
// ---------------------------------------------------------------------------

func TestTokenHandler_ClientCredentials_ScopeReflectedInResponse(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act
	resp := requestClientCredentialsToken(t, srv.URL, ccClientID, ccClientSecret, ccScope)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth2/token status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatalf("json.Unmarshal tokenResponse: %v", err)
	}

	// Assert — top-level "scope" field must contain both requested scopes.
	for _, wantScope := range []string{"read", "write"} {
		if !strings.Contains(tr.Scope, wantScope) {
			t.Errorf("token response scope = %q, want it to contain %q", tr.Scope, wantScope)
		}
	}

	// Assert — the JWT access_token "scope" claim must also reflect the granted scopes.
	if isJWT(tr.AccessToken) {
		claims := decodeJWTClaims(t, tr.AccessToken)
		scopeVal, hasScopeClaim := claims["scope"]
		if !hasScopeClaim {
			t.Error("access_token JWT missing \"scope\" claim")
		} else {
			scopeStr, _ := scopeVal.(string)
			for _, wantScope := range []string{"read", "write"} {
				if !strings.Contains(scopeStr, wantScope) {
					t.Errorf("access_token JWT scope claim = %q, want it to contain %q", scopeStr, wantScope)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 5. TestTokenHandler_ClientCredentials_WrongSecret_ReturnsError
//    Supplying an incorrect client_secret must be rejected with a non-200
//    error response. RFC 6749 §3.2.1 and RFC 6749 §5.2 require this.
//    fosite returns HTTP 401 with error=invalid_client for Basic Auth failures.
// ---------------------------------------------------------------------------

func TestTokenHandler_ClientCredentials_WrongSecret_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act — correct client_id, but intentionally wrong secret.
	resp := requestClientCredentialsToken(t, srv.URL, ccClientID, "wrong-secret", ccScope)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — must not be 200.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("POST /oauth2/token with wrong client_secret: status = 200, want non-200")
	}
}

// ---------------------------------------------------------------------------
// 6. TestTokenHandler_ClientCredentials_WrongSecret_ReturnsErrorJSON
//    The error response body for an invalid_client failure must be valid JSON
//    conforming to RFC 6749 §5.2 with a non-empty "error" field.
// ---------------------------------------------------------------------------

func TestTokenHandler_ClientCredentials_WrongSecret_ReturnsErrorJSON(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act
	resp := requestClientCredentialsToken(t, srv.URL, ccClientID, "wrong-secret-json-test", ccScope)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — must not be 200.
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("status = 200, want non-200 for wrong secret; body = %s", body)
	}

	// Assert — Content-Type must be application/json.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want it to contain \"application/json\"", ct)
	}

	// Assert — body is valid RFC 6749 §5.2 JSON with "error" field.
	var errResp tokenErrorResponse
	if jsonErr := json.Unmarshal(body, &errResp); jsonErr != nil {
		t.Fatalf("response body is not valid JSON: %v — body: %s", jsonErr, body)
	}
	if errResp.Error == "" {
		t.Errorf("error response has empty \"error\" field; body = %s", body)
	}
}

// ---------------------------------------------------------------------------
// 7. TestTokenHandler_ClientCredentials_UnauthorizedClient_ReturnsError
//    A client that has NOT been granted the "client_credentials" grant type
//    must be rejected. The existing "test-client" only allows
//    "authorization_code" and "refresh_token", so it must not be allowed to
//    use the client_credentials flow.
//
//    RFC 6749 §5.2 requires error=unauthorized_client with HTTP 400.
// ---------------------------------------------------------------------------

func TestTokenHandler_ClientCredentials_UnauthorizedClient_ReturnsError(t *testing.T) {
	// Arrange
	// Use the standard test-client which only has authorization_code + refresh_token.
	// "test-client-secret" is the plain-text secret seeded in testhelper.
	srv, _ := testhelper.NewTestServer(t)

	// Act — test-client does not have client_credentials in its grant_types.
	resp := requestClientCredentialsToken(t, srv.URL, validClientID, "test-client-secret", "openid")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — must not be 200 (unauthorized_client → HTTP 400).
	if resp.StatusCode == http.StatusOK {
		t.Errorf("POST /oauth2/token with unauthorized client: status = 200, want non-200 (unauthorized_client)")
	}
}

// ---------------------------------------------------------------------------
// 8. TestTokenHandler_ClientCredentials_UnauthorizedClient_ReturnsErrorJSON
//    The error response for an unauthorized_client attempt must be well-formed
//    RFC 6749 §5.2 JSON with a non-empty "error" field.
// ---------------------------------------------------------------------------

func TestTokenHandler_ClientCredentials_UnauthorizedClient_ReturnsErrorJSON(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act
	resp := requestClientCredentialsToken(t, srv.URL, validClientID, "test-client-secret", "openid")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — must not be 200.
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("status = 200, want non-200 for unauthorized_client; body = %s", body)
	}

	// Assert — Content-Type must be application/json.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want it to contain \"application/json\"", ct)
	}

	// Assert — body must be valid JSON with a non-empty "error" field.
	var errResp tokenErrorResponse
	if jsonErr := json.Unmarshal(body, &errResp); jsonErr != nil {
		t.Fatalf("response body is not valid JSON: %v — body: %s", jsonErr, body)
	}
	if errResp.Error == "" {
		t.Errorf("error response has empty \"error\" field; body = %s", body)
	}
}
