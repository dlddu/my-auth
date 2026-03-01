// Package handler_test contains integration tests for the OAuth2 token
// endpoint (POST /oauth2/token).
//
// These tests are written in the TDD Red Phase: the handler under test
// (handler.NewTokenHandler) does not yet exist, so the package will not
// compile until the implementation is provided.
//
// Implementation checklist (both files must be updated before tests pass):
//
//  1. Create internal/handler/token.go with:
//     func NewTokenHandler(provider fosite.OAuth2Provider) http.HandlerFunc
//
//  2. Register the route in internal/testhelper/server.go buildRouter():
//     r.Post("/oauth2/token", handler.NewTokenHandler(oauth2Provider))
//
//  3. (Optional) Register the route in cmd/server/main.go as well.
//
//  4. Switch CoreStrategy in newFositeProvider() from NewOAuth2HMACStrategy
//     to a JWT-based strategy so that access_token is a signed RS256 JWT.
//     For tests to pass without that change, the isJWT() assertions
//     (TestTokenHandler_AccessToken_IsJWT and related claims tests) will
//     fail until the JWT strategy is wired in.
//
// Test coverage:
//   - Happy path: login → authorize → token exchange → access_token + id_token + refresh_token
//   - JWT access_token contains required claims: iss, sub, aud, scope, exp, jti
//   - id_token signature verifiable with JWKS and contains: sub, aud, iss, nonce, at_hash
//   - refresh_token is opaque (not a JWT)
//   - Invalid authorization code → error response
//   - Unknown/malformed code → error response
//   - Code reuse (replay) → error response
//   - Missing code parameter → error response
//   - Wrong client secret → error response
//   - Granted scope reflected in token response and access_token claims
package handler_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Shared token test helpers
// ---------------------------------------------------------------------------

// tokenResponse represents the JSON body returned by POST /oauth2/token.
// All fields are kept as strings or raw JSON so that tests can validate their
// presence and format without importing fosite internals.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// tokenErrorResponse represents the RFC 6749 §5.2 error body returned by
// POST /oauth2/token on failure.
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// loginAndGetCode performs the complete login → consent → code flow and
// returns the authorization code received at the redirect_uri callback.
//
// It uses the standard test credentials and the valid OAuth2 parameters
// defined in authorize_test.go (validClientID, validRedirectURI, etc.).
func loginAndGetCode(t *testing.T, srvURL string, nonce string) string {
	t.Helper()

	// Step 1: log in with the test owner credentials so the session cookie
	// is stored in the client's CookieJar.
	client := loginAndGetClient(t, srvURL)

	// Step 2: GET /oauth2/auth to load the consent page.
	// fosite validates client_id and redirect_uri before rendering the page.
	authParams := url.Values{
		"response_type": {"code"},
		"client_id":     {validClientID},
		"redirect_uri":  {validRedirectURI},
		"scope":         {validScope},
		"state":         {validState},
		"nonce":         {nonce},
	}
	getResp, err := client.Get(srvURL + "/oauth2/auth?" + authParams.Encode())
	if err != nil {
		t.Fatalf("loginAndGetCode: GET /oauth2/auth: %v", err)
	}
	_, _ = io.Copy(io.Discard, getResp.Body)
	getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("loginAndGetCode: GET /oauth2/auth status = %d, want 200", getResp.StatusCode)
	}

	// Step 3: POST /oauth2/auth with action=approve.
	// Use a client that stops at the first redirect so we can extract the
	// code from the Location header before the browser would follow it.
	noRedirectClient := &http.Client{
		Jar: client.Jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	formData := url.Values{
		"action":        {"approve"},
		"response_type": {"code"},
		"client_id":     {validClientID},
		"redirect_uri":  {validRedirectURI},
		"scope":         {validScope},
		"state":         {validState},
		"nonce":         {nonce},
	}

	postReq, err := http.NewRequest(
		http.MethodPost,
		srvURL+"/oauth2/auth?"+authParams.Encode(),
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("loginAndGetCode: http.NewRequest POST /oauth2/auth: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	postResp, err := noRedirectClient.Do(postReq)
	if err != nil {
		t.Fatalf("loginAndGetCode: POST /oauth2/auth: %v", err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusFound && postResp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(postResp.Body)
		t.Fatalf("loginAndGetCode: POST /oauth2/auth status = %d, want 302 or 303; body = %q",
			postResp.StatusCode, string(body))
	}

	location := postResp.Header.Get("Location")
	locationURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("loginAndGetCode: url.Parse(Location=%q): %v", location, err)
	}

	code := locationURL.Query().Get("code")
	if code == "" {
		t.Fatalf("loginAndGetCode: no code in Location header: %q", location)
	}

	return code
}

// exchangeCodeForTokens calls POST /oauth2/token with grant_type=authorization_code
// and returns the parsed response body and the raw HTTP status code.
//
// The client_secret is sent via HTTP Basic Auth as required by RFC 6749 §2.3.1.
func exchangeCodeForTokens(t *testing.T, srvURL string, code string) (*tokenResponse, int) {
	t.Helper()

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {validRedirectURI},
		"client_id":    {validClientID},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srvURL+"/oauth2/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("exchangeCodeForTokens: http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// fosite expects client credentials via HTTP Basic Auth when the client
	// was registered with a secret.
	req.SetBasicAuth(validClientID, "test-client-secret")

	// Use a plain http.Client without a CookieJar: token endpoint requests
	// are machine-to-machine and must not carry browser session cookies.
	plainClient := &http.Client{}
	resp, err := plainClient.Do(req)
	if err != nil {
		t.Fatalf("exchangeCodeForTokens: POST /oauth2/token: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("exchangeCodeForTokens: io.ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatalf("exchangeCodeForTokens: json.Unmarshal: %v — body: %s", err, body)
	}

	return &tr, resp.StatusCode
}

// decodeJWTClaims splits a compact JWS token and base64url-decodes the
// payload (middle) segment. It returns the claims as a raw JSON map.
// It does NOT verify the signature — signature verification is done by a
// separate test using the JWKS endpoint.
func decodeJWTClaims(t *testing.T, token string) map[string]interface{} {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("decodeJWTClaims: expected 3 dot-separated segments, got %d; token = %q", len(parts), token)
	}

	// Base64url decode without padding (RFC 7515 §2).
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decodeJWTClaims: base64url decode payload: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decodeJWTClaims: json.Unmarshal claims: %v — payload: %s", err, payload)
	}

	return claims
}

// fetchJWKS retrieves the JSON Web Key Set from the server's /jwks endpoint
// and returns the parsed key objects.
func fetchJWKS(t *testing.T, srvURL string) []map[string]interface{} {
	t.Helper()

	resp, err := http.Get(srvURL + "/jwks")
	if err != nil {
		t.Fatalf("fetchJWKS: GET /jwks: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fetchJWKS: GET /jwks status = %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("fetchJWKS: io.ReadAll: %v", err)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("fetchJWKS: json.Unmarshal: %v — body: %s", err, body)
	}

	return jwks.Keys
}

// isJWT returns true when s has the three-segment dot-separated structure of
// a compact JWS / JWT (RFC 7515 §3.1). It does not validate the content.
func isJWT(s string) bool {
	return len(strings.Split(s, ".")) == 3
}

// ---------------------------------------------------------------------------
// 1. TestTokenHandler_AuthorizationCode_ReturnsTokens
//    Happy path: full login → authorize → token exchange succeeds and the
//    response contains access_token, id_token, and refresh_token.
// ---------------------------------------------------------------------------

func TestTokenHandler_AuthorizationCode_ReturnsTokens(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	code := loginAndGetCode(t, srv.URL, "test-nonce-1")

	// Act
	tokens, status := exchangeCodeForTokens(t, srv.URL, code)

	// Assert — HTTP 200 OK
	if status != http.StatusOK {
		t.Fatalf("POST /oauth2/token status = %d, want 200", status)
	}

	// Assert — access_token is present and non-empty.
	if tokens.AccessToken == "" {
		t.Error("access_token is empty, want a non-empty token")
	}

	// Assert — id_token is present and non-empty.
	if tokens.IDToken == "" {
		t.Error("id_token is empty, want a non-empty token")
	}

	// Assert — refresh_token is present and non-empty.
	if tokens.RefreshToken == "" {
		t.Error("refresh_token is empty, want a non-empty token")
	}

	// Assert — token_type is "bearer" (case-insensitive per RFC 6749 §5.1).
	if !strings.EqualFold(tokens.TokenType, "bearer") {
		t.Errorf("token_type = %q, want \"bearer\"", tokens.TokenType)
	}

	// Assert — expires_in is a positive number.
	if tokens.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want a positive value", tokens.ExpiresIn)
	}
}

// ---------------------------------------------------------------------------
// 2. TestTokenHandler_AccessToken_IsJWT
//    The access_token must be a JWT (three dot-separated base64url segments).
//    This requirement comes from the E2E acceptance criteria: clients must be
//    able to decode and introspect the access token locally (RS256 JWT).
// ---------------------------------------------------------------------------

func TestTokenHandler_AccessToken_IsJWT(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	code := loginAndGetCode(t, srv.URL, "test-nonce-2")

	// Act
	tokens, status := exchangeCodeForTokens(t, srv.URL, code)

	// Assert — request succeeded.
	if status != http.StatusOK {
		t.Fatalf("POST /oauth2/token status = %d, want 200", status)
	}

	// Assert — access_token is a compact JWS (JWT).
	if !isJWT(tokens.AccessToken) {
		t.Errorf("access_token = %q, want a JWT (three dot-separated segments)", tokens.AccessToken)
	}
}

// ---------------------------------------------------------------------------
// 3. TestTokenHandler_AccessToken_ContainsRequiredClaims
//    JWT access_token payload must include: iss, sub, aud, scope, exp, jti.
//    (RFC 9068 §2 — JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens)
// ---------------------------------------------------------------------------

func TestTokenHandler_AccessToken_ContainsRequiredClaims(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	code := loginAndGetCode(t, srv.URL, "test-nonce-3")

	// Act
	tokens, status := exchangeCodeForTokens(t, srv.URL, code)

	if status != http.StatusOK {
		t.Fatalf("POST /oauth2/token status = %d, want 200", status)
	}

	if !isJWT(tokens.AccessToken) {
		t.Fatalf("access_token is not a JWT: %q", tokens.AccessToken)
	}

	// Decode without signature verification (separate test handles that).
	claims := decodeJWTClaims(t, tokens.AccessToken)

	// Assert — iss (Issuer) must be the configured issuer.
	iss, ok := claims["iss"].(string)
	if !ok || iss == "" {
		t.Error("access_token missing \"iss\" claim or it is not a string")
	}
	// The test issuer is "https://auth.test.local" (from testhelper/config.go).
	if iss != "https://auth.test.local" {
		t.Errorf("access_token claim iss = %q, want %q", iss, "https://auth.test.local")
	}

	// Assert — sub (Subject) must be the authenticated user's username.
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		t.Error("access_token missing \"sub\" claim or it is not a string")
	}
	// The test owner is "admin@test.local" (from testhelper/config.go).
	if sub != "admin@test.local" {
		t.Errorf("access_token claim sub = %q, want %q", sub, "admin@test.local")
	}

	// Assert — aud (Audience) must be present; fosite may encode it as a
	// string or string slice, so we check for either.
	if _, hasAud := claims["aud"]; !hasAud {
		t.Error("access_token missing \"aud\" claim")
	}

	// Assert — scope must be present.
	if _, hasScope := claims["scope"]; !hasScope {
		t.Error("access_token missing \"scope\" claim")
	}

	// Assert — exp (Expiration) must be a positive number.
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
// 4. TestTokenHandler_IDToken_IsJWT
//    id_token must be a compact JWS with three dot-separated segments.
// ---------------------------------------------------------------------------

func TestTokenHandler_IDToken_IsJWT(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	code := loginAndGetCode(t, srv.URL, "test-nonce-4")

	// Act
	tokens, status := exchangeCodeForTokens(t, srv.URL, code)

	if status != http.StatusOK {
		t.Fatalf("POST /oauth2/token status = %d, want 200", status)
	}

	// Assert — id_token is a compact JWS.
	if !isJWT(tokens.IDToken) {
		t.Errorf("id_token = %q, want a JWT (three dot-separated segments)", tokens.IDToken)
	}
}

// ---------------------------------------------------------------------------
// 5. TestTokenHandler_IDToken_ContainsRequiredClaims
//    id_token payload must include: sub, aud, iss, nonce, at_hash.
//    (OIDC Core 1.0 §2, §3.1.3.6)
// ---------------------------------------------------------------------------

func TestTokenHandler_IDToken_ContainsRequiredClaims(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	const nonce = "test-nonce-5-unique"
	code := loginAndGetCode(t, srv.URL, nonce)

	// Act
	tokens, status := exchangeCodeForTokens(t, srv.URL, code)

	if status != http.StatusOK {
		t.Fatalf("POST /oauth2/token status = %d, want 200", status)
	}

	if !isJWT(tokens.IDToken) {
		t.Fatalf("id_token is not a JWT: %q", tokens.IDToken)
	}

	claims := decodeJWTClaims(t, tokens.IDToken)

	// Assert — iss (Issuer) matches the server's configured issuer.
	iss, ok := claims["iss"].(string)
	if !ok || iss == "" {
		t.Error("id_token missing \"iss\" claim or it is not a string")
	}
	if iss != "https://auth.test.local" {
		t.Errorf("id_token claim iss = %q, want %q", iss, "https://auth.test.local")
	}

	// Assert — sub (Subject) identifies the authenticated end-user.
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		t.Error("id_token missing \"sub\" claim or it is not a string")
	}
	if sub != "admin@test.local" {
		t.Errorf("id_token claim sub = %q, want %q", sub, "admin@test.local")
	}

	// Assert — aud (Audience) contains the client_id.
	if _, hasAud := claims["aud"]; !hasAud {
		t.Error("id_token missing \"aud\" claim")
	}

	// Assert — nonce echoes the value sent in the authorization request.
	// OIDC Core §3.1.3.7.5 requires the nonce to be reproduced in the ID token.
	idNonce, ok := claims["nonce"].(string)
	if !ok || idNonce == "" {
		t.Error("id_token missing \"nonce\" claim or it is not a string")
	}
	if idNonce != nonce {
		t.Errorf("id_token claim nonce = %q, want %q", idNonce, nonce)
	}

	// Assert — at_hash (access token hash) must be present when an access
	// token is issued alongside the ID token (OIDC Core §3.3.2.11).
	atHash, ok := claims["at_hash"].(string)
	if !ok || atHash == "" {
		t.Error("id_token missing \"at_hash\" claim or it is not a string")
	}
}

// ---------------------------------------------------------------------------
// 6. TestTokenHandler_IDToken_SignatureVerifiableWithJWKS
//    The id_token header's "alg" must be RS256 and the key set returned by
//    /jwks must contain at least one RSA public key. This test verifies that
//    the signature could be validated by a relying party (it does not import
//    a full JWT verification library to keep the test dependency-free, but
//    checks all structural prerequisites for external verification).
// ---------------------------------------------------------------------------

func TestTokenHandler_IDToken_SignatureVerifiableWithJWKS(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	code := loginAndGetCode(t, srv.URL, "test-nonce-6")

	// Act
	tokens, status := exchangeCodeForTokens(t, srv.URL, code)

	if status != http.StatusOK {
		t.Fatalf("POST /oauth2/token status = %d, want 200", status)
	}

	if !isJWT(tokens.IDToken) {
		t.Fatalf("id_token is not a JWT: %q", tokens.IDToken)
	}

	// Decode the JOSE header (first segment).
	parts := strings.Split(tokens.IDToken, ".")
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("id_token header base64url decode: %v", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("id_token header json.Unmarshal: %v", err)
	}

	// Assert — id_token must be signed with RS256 (OIDC Core §3.1.3.7).
	alg, _ := header["alg"].(string)
	if alg != "RS256" {
		t.Errorf("id_token header alg = %q, want \"RS256\"", alg)
	}

	// Assert — "kid" header references a key in the JWKS so relying parties
	// can locate the correct verification key.
	kid, _ := header["kid"].(string)
	if kid == "" {
		t.Error("id_token header missing \"kid\" (key ID), want a non-empty string")
	}

	// Fetch /jwks and confirm at least one RSA key is present.
	keys := fetchJWKS(t, srv.URL)

	rsaKeyFound := false
	kidMatchFound := false
	for _, k := range keys {
		kty, _ := k["kty"].(string)
		if kty == "RSA" {
			rsaKeyFound = true
		}
		if jwkKID, _ := k["kid"].(string); jwkKID == kid {
			kidMatchFound = true
		}
	}

	if !rsaKeyFound {
		t.Error("JWKS endpoint returned no RSA key; id_token signature cannot be verified by relying parties")
	}

	// kid match is a best-effort assertion: some implementations omit kid in
	// the JWKS when there is only one key. Only fail if kid is set but absent.
	if kid != "" && !kidMatchFound {
		t.Errorf("id_token header kid = %q but no matching kid found in JWKS", kid)
	}
}

// ---------------------------------------------------------------------------
// 7. TestTokenHandler_RefreshToken_IsOpaque
//    The refresh_token must NOT be a JWT. fosite issues opaque (HMAC) refresh
//    tokens by design. Clients must treat the refresh_token as an opaque
//    string per RFC 6749 §1.5.
// ---------------------------------------------------------------------------

func TestTokenHandler_RefreshToken_IsOpaque(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	code := loginAndGetCode(t, srv.URL, "test-nonce-7")

	// Act
	tokens, status := exchangeCodeForTokens(t, srv.URL, code)

	if status != http.StatusOK {
		t.Fatalf("POST /oauth2/token status = %d, want 200", status)
	}

	if tokens.RefreshToken == "" {
		t.Fatal("refresh_token is empty, want an opaque token string")
	}

	// Assert — refresh_token must NOT have three dot-separated segments that
	// decode as valid base64url JSON (i.e. it must not be a JWT).
	if isJWT(tokens.RefreshToken) {
		t.Errorf("refresh_token = %q looks like a JWT; want an opaque token", tokens.RefreshToken)
	}
}

// ---------------------------------------------------------------------------
// 8. TestTokenHandler_InvalidCode_ReturnsError
//    Supplying a code that was never issued by the authorization endpoint must
//    result in an error response (non-200) with an RFC 6749 §5.2 error body.
// ---------------------------------------------------------------------------

func TestTokenHandler_InvalidCode_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act — attempt token exchange with a fabricated, never-issued code.
	_, status := exchangeCodeForTokens(t, srv.URL, "totally-invalid-code-that-was-never-issued")

	// Assert — the server must not return 200.
	if status == http.StatusOK {
		t.Errorf("POST /oauth2/token with invalid code: status = 200, want a non-200 error response")
	}
}

// ---------------------------------------------------------------------------
// 9. TestTokenHandler_InvalidCode_ReturnsErrorJSON
//    The error response body must be valid JSON with an "error" field
//    per RFC 6749 §5.2.
// ---------------------------------------------------------------------------

func TestTokenHandler_InvalidCode_ReturnsErrorJSON(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"invalid-code-for-json-test"},
		"redirect_uri": {validRedirectURI},
		"client_id":    {validClientID},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(validClientID, "test-client-secret")

	// Act
	plainClient := &http.Client{}
	resp, err := plainClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/token: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — response must not be 200.
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("status = 200, want non-200 for invalid code; body = %q", body)
	}

	// Assert — Content-Type is application/json.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want it to contain \"application/json\"", ct)
	}

	// Assert — body is valid JSON with an "error" field.
	var errResp tokenErrorResponse
	if jsonErr := json.Unmarshal(body, &errResp); jsonErr != nil {
		t.Fatalf("response body is not valid JSON: %v — body: %s", jsonErr, body)
	}

	if errResp.Error == "" {
		t.Errorf("error response body has empty \"error\" field; body = %s", body)
	}
}

// ---------------------------------------------------------------------------
// 10. TestTokenHandler_CodeReuse_ReturnsError
//     After a code is exchanged successfully once, a second attempt with the
//     same code must fail. RFC 6749 §4.1.2 requires that each code is
//     single-use; fosite marks codes as invalidated after first use.
// ---------------------------------------------------------------------------

func TestTokenHandler_CodeReuse_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	code := loginAndGetCode(t, srv.URL, "test-nonce-10")

	// Act — first exchange (must succeed).
	_, firstStatus := exchangeCodeForTokens(t, srv.URL, code)
	if firstStatus != http.StatusOK {
		t.Fatalf("first token exchange: status = %d, want 200", firstStatus)
	}

	// Act — second exchange with the same code (must fail).
	_, secondStatus := exchangeCodeForTokens(t, srv.URL, code)

	// Assert — second attempt must not succeed.
	if secondStatus == http.StatusOK {
		t.Errorf("second token exchange with reused code: status = 200, want non-200 (code replay must be rejected)")
	}
}

// ---------------------------------------------------------------------------
// 11. TestTokenHandler_MissingCode_ReturnsError
//     A POST /oauth2/token request without any code parameter is malformed
//     and must be rejected with a non-200 response.
// ---------------------------------------------------------------------------

func TestTokenHandler_MissingCode_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"redirect_uri": {validRedirectURI},
		"client_id":    {validClientID},
		// "code" deliberately omitted.
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(validClientID, "test-client-secret")

	// Act
	plainClient := &http.Client{}
	resp, err := plainClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/token (no code): %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — must not be 200.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("POST /oauth2/token without code: status = 200, want non-200")
	}
}

// ---------------------------------------------------------------------------
// 12. TestTokenHandler_WrongClientSecret_ReturnsError
//     If the client authenticates with an incorrect secret, fosite must
//     reject the request with a non-200 response. This ensures that token
//     endpoint authentication is enforced (RFC 6749 §3.2.1).
// ---------------------------------------------------------------------------

func TestTokenHandler_WrongClientSecret_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	code := loginAndGetCode(t, srv.URL, "test-nonce-12")

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {validRedirectURI},
		"client_id":    {validClientID},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Intentionally wrong secret.
	req.SetBasicAuth(validClientID, "wrong-secret")

	// Act
	plainClient := &http.Client{}
	resp, err := plainClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/token (wrong secret): %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — must not be 200.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("POST /oauth2/token with wrong client secret: status = 200, want non-200")
	}
}

// ---------------------------------------------------------------------------
// 13. TestTokenHandler_AccessToken_ScopeMatchesGranted
//     The "scope" in the token response (and access_token claim) must reflect
//     the scopes that were actually granted during the authorization step.
// ---------------------------------------------------------------------------

func TestTokenHandler_AccessToken_ScopeMatchesGranted(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	code := loginAndGetCode(t, srv.URL, "test-nonce-13")

	// Act
	tokens, status := exchangeCodeForTokens(t, srv.URL, code)

	if status != http.StatusOK {
		t.Fatalf("POST /oauth2/token status = %d, want 200", status)
	}

	// The authorization was approved with validScope = "openid profile email".
	// The token response "scope" field should reflect the granted scopes.
	if tokens.Scope == "" {
		t.Error("token response missing \"scope\" field, want a non-empty string")
	}

	// Each originally requested scope must appear in the granted scope list.
	for _, wantScope := range []string{"openid", "profile", "email"} {
		if !strings.Contains(tokens.Scope, wantScope) {
			t.Errorf("token response scope = %q, want it to contain %q", tokens.Scope, wantScope)
		}
	}

	// Also verify the scope inside the JWT access_token (if it is a JWT).
	if isJWT(tokens.AccessToken) {
		claims := decodeJWTClaims(t, tokens.AccessToken)
		scopeVal := claims["scope"]
		if scopeVal == nil {
			t.Error("access_token JWT missing \"scope\" claim")
		}
	}
}
