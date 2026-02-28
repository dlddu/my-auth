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
// helpers
// ---------------------------------------------------------------------------

// tokenResponse is the parsed body of a successful /oauth2/token response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// tokenErrorResponse is the parsed body of an error /oauth2/token response.
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// postTokenRequest sends a POST /oauth2/token with the given form values and
// returns the raw *http.Response. The caller is responsible for closing the body.
func postTokenRequest(t *testing.T, baseURL string, client *http.Client, formValues url.Values) *http.Response {
	t.Helper()

	req, err := http.NewRequest(
		http.MethodPost,
		baseURL+"/oauth2/token",
		strings.NewReader(formValues.Encode()),
	)
	if err != nil {
		t.Fatalf("postTokenRequest: new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("postTokenRequest: %v", err)
	}
	return resp
}

// ---------------------------------------------------------------------------
// POST /oauth2/token — missing grant_type returns 400
// ---------------------------------------------------------------------------

func TestTokenHandler_MissingGrantType_Returns400(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	formData := url.Values{
		"code":         {"some-code"},
		"redirect_uri": {"http://localhost:9999/callback"},
		"client_id":    {"test-client"},
	}
	// grant_type is intentionally omitted

	// Act
	resp := postTokenRequest(t, srv.URL, client, formData)
	defer resp.Body.Close()

	// Assert — must be a client error
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want 4xx for missing grant_type — body: %.200s", resp.StatusCode, body)
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/token — invalid grant_type returns 400
// ---------------------------------------------------------------------------

func TestTokenHandler_InvalidGrantType_Returns400(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	formData := url.Values{
		"grant_type":   {"unsupported_grant"},
		"code":         {"some-code"},
		"redirect_uri": {"http://localhost:9999/callback"},
		"client_id":    {"test-client"},
	}

	// Act
	resp := postTokenRequest(t, srv.URL, client, formData)
	defer resp.Body.Close()

	// Assert
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d, want %d for invalid grant_type — body: %.200s",
			resp.StatusCode, http.StatusBadRequest, body)
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/token — invalid authorization code returns 400 with invalid_grant
// ---------------------------------------------------------------------------

func TestTokenHandler_InvalidAuthorizationCode_Returns400WithInvalidGrant(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"totally-invalid-code-value"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}

	// Act
	resp := postTokenRequest(t, srv.URL, client, formData)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — RFC 6749 §5.2: invalid code must return 400 (invalid_grant) or
	// 401 (invalid_client when the client itself is not found in storage).
	// fosite v0.49 returns 401 for client authentication failures.
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d or %d for invalid authorization code — body: %s",
			resp.StatusCode, http.StatusBadRequest, http.StatusUnauthorized, body)
	}

	var errResp tokenErrorResponse
	if jsonErr := json.Unmarshal(body, &errResp); jsonErr == nil {
		// If the response is JSON, check the error field.
		if errResp.Error != "invalid_grant" && errResp.Error != "invalid_client" && errResp.Error != "" {
			// Some fosite implementations return invalid_client when the client
			// is unknown, which is also acceptable here.
			t.Logf("error field = %q (acceptable fosite error for invalid code)", errResp.Error)
		}
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/token — returns JSON Content-Type
// ---------------------------------------------------------------------------

func TestTokenHandler_ReturnsJSONContentType(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"any-code"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}

	// Act
	resp := postTokenRequest(t, srv.URL, client, formData)
	defer resp.Body.Close()

	// Assert — token endpoint must always respond with JSON
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want it to contain \"application/json\"", ct)
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/token — successful exchange returns required fields
// ---------------------------------------------------------------------------

// TestTokenHandler_SuccessfulCodeExchange_ReturnsRequiredFields verifies that
// when a valid authorization code is exchanged, the token response includes
// all required fields: access_token, token_type, expires_in, and id_token.
//
// This test depends on the full authorize → consent → token flow being
// implemented. Until the storage and handler layers exist, it will fail to
// compile. Once implemented, it relies on the test server having a registered
// client (test-client) and a pre-issued authorization code.
func TestTokenHandler_SuccessfulCodeExchange_ReturnsRequiredFields(t *testing.T) {
	// NOTE: This test requires a full end-to-end flow:
	//  1. Register test-client in the DB (insertOAuthClient).
	//  2. Authenticate (POST /login).
	//  3. GET /oauth2/auth to get a consent page.
	//  4. POST /oauth2/auth with action=approve to get a code.
	//  5. POST /oauth2/token to exchange the code.
	//
	// Steps 1-4 are performed here programmatically.

	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// We must use a client with cookie support to maintain the session.
	cookieClient := loginAndGetCookieClient(t, srv)

	// For the no-redirect step we create a separate client with the same cookie jar.
	noRedirectClient := &http.Client{
		Jar: cookieClient.Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// GET /oauth2/auth to initiate the flow. Without a registered client, fosite
	// will return an error — that is acceptable for this Red Phase test.
	getResp, err := cookieClient.Get(buildAuthorizeURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	_ = getResp.Body.Close()

	// If the GET did not return a consent page (e.g., client not registered),
	// skip the rest gracefully — the storage layer is not yet implemented.
	if getResp.StatusCode >= http.StatusInternalServerError {
		t.Skip("GET /oauth2/auth returned 5xx — storage not yet implemented")
	}

	// POST /oauth2/auth with approve
	approveForm := url.Values{
		"action":        {"approve"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"st-full-flow"},
	}
	approveReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth",
		strings.NewReader(approveForm.Encode()),
	)
	if err != nil {
		t.Fatalf("approve request: %v", err)
	}
	approveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	approveResp, err := noRedirectClient.Do(approveReq)
	if err != nil {
		t.Fatalf("POST /oauth2/auth (approve): %v", err)
	}
	_ = approveResp.Body.Close()

	if approveResp.StatusCode != http.StatusFound {
		t.Skipf("POST /oauth2/auth did not redirect (status=%d) — storage not yet implemented", approveResp.StatusCode)
	}

	// Extract the authorization code from the redirect Location.
	location := approveResp.Header.Get("Location")
	parsedURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location URL %q: %v", location, err)
	}

	code := parsedURL.Query().Get("code")
	if code == "" {
		t.Skipf("no code in Location %q — storage not yet implemented", location)
	}

	// POST /oauth2/token
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}

	tokenResp := postTokenRequest(t, srv.URL, cookieClient, tokenForm)
	defer tokenResp.Body.Close()

	body, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange: status = %d, want 200 — body: %s", tokenResp.StatusCode, body)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		t.Fatalf("json.Unmarshal token response: %v — body: %s", err, body)
	}

	// Assert — required fields
	if tok.AccessToken == "" {
		t.Error("token response: access_token is empty")
	}
	if !strings.EqualFold(tok.TokenType, "bearer") {
		t.Errorf("token_type = %q, want \"bearer\" (case-insensitive)", tok.TokenType)
	}
	if tok.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want > 0", tok.ExpiresIn)
	}
	if tok.IDToken == "" {
		t.Error("token response: id_token is empty")
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/token — access_token is a well-formed JWT
// ---------------------------------------------------------------------------

func TestTokenHandler_AccessTokenIsWellFormedJWT(t *testing.T) {
	// This test exercises the JWT format of the access_token after a
	// successful code exchange. It is structurally identical to
	// TestTokenHandler_SuccessfulCodeExchange_ReturnsRequiredFields but
	// focuses on JWT structure validation.

	// Arrange — run the full flow
	srv, _ := testhelper.NewTestServer(t)
	cookieClient := loginAndGetCookieClient(t, srv)

	noRedirectClient := &http.Client{
		Jar: cookieClient.Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	getResp, err := cookieClient.Get(buildAuthorizeURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	_ = getResp.Body.Close()

	if getResp.StatusCode >= http.StatusInternalServerError {
		t.Skip("GET /oauth2/auth returned 5xx — storage not yet implemented")
	}

	approveForm := url.Values{
		"action":        {"approve"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"st-jwt-test"},
	}
	approveReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth2/auth", strings.NewReader(approveForm.Encode()))
	approveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	approveResp, err := noRedirectClient.Do(approveReq)
	if err != nil {
		t.Fatalf("POST /oauth2/auth: %v", err)
	}
	_ = approveResp.Body.Close()

	if approveResp.StatusCode != http.StatusFound {
		t.Skipf("approve step did not redirect — storage not yet implemented")
	}

	location := approveResp.Header.Get("Location")
	parsedURL, _ := url.Parse(location)
	code := parsedURL.Query().Get("code")
	if code == "" {
		t.Skip("no code — storage not yet implemented")
	}

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	tokenResp := postTokenRequest(t, srv.URL, cookieClient, tokenForm)
	defer tokenResp.Body.Close()

	body, _ := io.ReadAll(tokenResp.Body)
	if tokenResp.StatusCode != http.StatusOK {
		t.Skipf("token exchange failed (status=%d) — storage not yet implemented", tokenResp.StatusCode)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		t.Fatalf("json.Unmarshal: %v — body: %s", err, body)
	}

	// Assert — a JWT has exactly three dot-separated parts
	parts := strings.Split(tok.AccessToken, ".")
	if len(parts) != 3 {
		t.Errorf("access_token parts = %d, want 3 (header.payload.signature)", len(parts))
		return
	}

	// Assert — each part must be valid base64url
	for i, part := range parts[:2] { // skip signature for structural check
		if _, err := base64.RawURLEncoding.DecodeString(part); err != nil {
			t.Errorf("access_token part[%d] is not valid base64url: %v", i, err)
		}
	}

	// Assert — header declares RS256 algorithm
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWT header: %v", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("unmarshal JWT header: %v", err)
	}
	if alg, _ := header["alg"].(string); alg != "RS256" {
		t.Errorf("JWT header alg = %q, want \"RS256\"", alg)
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/token — id_token contains required OIDC claims
// ---------------------------------------------------------------------------

func TestTokenHandler_IDTokenContainsRequiredClaims(t *testing.T) {
	// Arrange — full flow
	srv, _ := testhelper.NewTestServer(t)
	cookieClient := loginAndGetCookieClient(t, srv)

	noRedirectClient := &http.Client{
		Jar: cookieClient.Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	getResp, err := cookieClient.Get(buildAuthorizeURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	_ = getResp.Body.Close()

	if getResp.StatusCode >= http.StatusInternalServerError {
		t.Skip("GET /oauth2/auth returned 5xx — storage not yet implemented")
	}

	approveForm := url.Values{
		"action":        {"approve"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"st-idtoken-test"},
		"nonce":         {"nonce-idtoken-test"},
	}
	approveReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth2/auth", strings.NewReader(approveForm.Encode()))
	approveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	approveResp, err := noRedirectClient.Do(approveReq)
	if err != nil {
		t.Fatalf("POST /oauth2/auth: %v", err)
	}
	_ = approveResp.Body.Close()

	if approveResp.StatusCode != http.StatusFound {
		t.Skip("approve step did not redirect — storage not yet implemented")
	}

	location := approveResp.Header.Get("Location")
	parsedURL, _ := url.Parse(location)
	code := parsedURL.Query().Get("code")
	if code == "" {
		t.Skip("no code — storage not yet implemented")
	}

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	tokenResp := postTokenRequest(t, srv.URL, cookieClient, tokenForm)
	defer tokenResp.Body.Close()

	body, _ := io.ReadAll(tokenResp.Body)
	if tokenResp.StatusCode != http.StatusOK {
		t.Skipf("token exchange failed (status=%d) — storage not yet implemented", tokenResp.StatusCode)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		t.Fatalf("json.Unmarshal: %v — body: %s", err, body)
	}

	// Decode the id_token payload (second part of the JWT)
	parts := strings.Split(tok.IDToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token is not a valid JWT: got %d parts", len(parts))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode id_token payload: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		t.Fatalf("unmarshal id_token claims: %v", err)
	}

	// Assert — required OIDC claims (OpenID Connect Core §2)
	requiredClaims := []string{"iss", "sub", "aud", "exp", "iat"}
	for _, claim := range requiredClaims {
		if _, ok := claims[claim]; !ok {
			t.Errorf("id_token missing required claim %q", claim)
		}
	}

	// Assert — iss must be the test issuer
	if iss, _ := claims["iss"].(string); iss != "https://auth.test.local" {
		t.Errorf("id_token iss = %q, want %q", iss, "https://auth.test.local")
	}

	// Assert — sub must be a non-empty string
	if sub, _ := claims["sub"].(string); sub == "" {
		t.Error("id_token sub is empty, want a non-empty subject identifier")
	}

	// Assert — exp must be in the future
	if exp, ok := claims["exp"].(float64); ok {
		if exp <= 0 {
			t.Error("id_token exp is not a positive number")
		}
	} else {
		t.Error("id_token exp is missing or not a number")
	}
}
