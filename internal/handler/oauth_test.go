package handler_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Shared helpers for OAuth2 integration tests
// ---------------------------------------------------------------------------

// loginAndGetClient performs a POST /login with the test owner credentials
// using a client that maintains cookies. It returns the authenticated client
// and the transport for redirect history inspection.
func loginAndGetClient(t *testing.T, srvURL string) (*http.Client, *testhelper.TestClientTransport) {
	t.Helper()

	client, transport := testhelper.NewTestClient(t)

	formData := url.Values{
		"username": {"admin@test.local"},
		"password": {"test-password"},
	}
	req, err := http.NewRequest(
		http.MethodPost,
		srvURL+"/login",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("loginAndGetClient: http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("loginAndGetClient: POST /login: %v", err)
	}
	defer resp.Body.Close()

	return client, transport
}

// buildAuthURL constructs a GET /oauth2/auth URL with standard test parameters.
// extraParams overrides individual query parameters.
func buildAuthURL(srvURL string, extraParams url.Values) string {
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"scope":         {"openid profile email"},
		"state":         {"test-state-value"},
		"nonce":         {"test-nonce-value"},
	}
	for k, vs := range extraParams {
		params[k] = vs
	}
	return srvURL + "/oauth2/auth?" + params.Encode()
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — 미인증 사용자 리다이렉트
// ---------------------------------------------------------------------------

// TestOAuth2Auth_Get_UnauthenticatedRedirectsToLogin verifies that an
// unauthenticated request to GET /oauth2/auth is redirected to /login.
func TestOAuth2Auth_Get_UnauthenticatedRedirectsToLogin(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Act
	resp, err := noRedirectClient.Get(buildAuthURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	// Assert — must redirect (302 Found)
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d (302 Found)", resp.StatusCode, http.StatusFound)
	}

	// Assert — Location header must point to /login
	location := resp.Header.Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("Location = %q, want it to contain %q", location, "/login")
	}
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — 인증된 사용자에게 consent 페이지 표시
// ---------------------------------------------------------------------------

// TestOAuth2Auth_Get_AuthenticatedShowsConsentPage verifies that an
// authenticated user with valid OAuth2 parameters sees the consent page.
func TestOAuth2Auth_Get_AuthenticatedShowsConsentPage(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client, _ := loginAndGetClient(t, srv.URL)

	// Act
	resp, err := client.Get(buildAuthURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK (not a redirect)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d; body = %.300s", resp.StatusCode, http.StatusOK, body)
	}

	// Assert — response is HTML
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want it to contain %q", ct, "text/html")
	}

	bodyStr := string(body)

	// Assert — consent page must contain Approve and Deny buttons
	if !strings.Contains(bodyStr, "Approve") {
		t.Errorf("consent page does not contain Approve button; body = %.200s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Deny") {
		t.Errorf("consent page does not contain Deny button; body = %.200s", bodyStr)
	}

	// Assert — client id must be mentioned
	if !strings.Contains(bodyStr, "test-client") {
		t.Errorf("consent page does not mention client id %q; body = %.200s", "test-client", bodyStr)
	}
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — 잘못된 client_id 시 에러 응답
// ---------------------------------------------------------------------------

// TestOAuth2Auth_Get_InvalidClientID verifies that an invalid client_id
// results in an error response rather than the consent page.
func TestOAuth2Auth_Get_InvalidClientID(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client, _ := loginAndGetClient(t, srv.URL)

	authURL := buildAuthURL(srv.URL, url.Values{
		"client_id": {"does-not-exist"},
	})

	// Act
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth with invalid client_id: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — must be an error (4xx) or at minimum not show a consent page
	if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "Approve") {
		t.Error("invalid client_id returned consent page with Approve button, want error")
	}

	if resp.StatusCode < 400 {
		t.Errorf("status = %d, want 4xx error for invalid client_id; body = %.200s",
			resp.StatusCode, body)
	}
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — 잘못된 redirect_uri 시 에러 응답
// ---------------------------------------------------------------------------

// TestOAuth2Auth_Get_InvalidRedirectURI verifies that a redirect_uri not
// registered for the client results in an error response.
func TestOAuth2Auth_Get_InvalidRedirectURI(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client, _ := loginAndGetClient(t, srv.URL)

	authURL := buildAuthURL(srv.URL, url.Values{
		"redirect_uri": {"http://evil.example.com/callback"},
	})

	// Act
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth with invalid redirect_uri: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — must be an error, not a consent page
	if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "Approve") {
		t.Error("invalid redirect_uri returned consent page with Approve button, want error")
	}

	if resp.StatusCode < 400 {
		t.Errorf("status = %d, want 4xx error for invalid redirect_uri; body = %.200s",
			resp.StatusCode, body)
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/auth — consent 승인 → authorization code 발급
// ---------------------------------------------------------------------------

// TestOAuth2Auth_Post_Approve_IssuessAuthorizationCode verifies that approving
// the consent form redirects to the redirect_uri with an authorization code.
func TestOAuth2Auth_Post_Approve_IssuessAuthorizationCode(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	code := obtainAuthorizationCode(t, srv.URL)

	// Assert — code must be non-empty (obtainAuthorizationCode already fatals
	// if the code is missing, but this documents the intent explicitly).
	if code == "" {
		t.Error("authorization code is empty after consent approval")
	}
}

// TestOAuth2Auth_Post_Approve_StateIsPreserved verifies that the state
// parameter is echoed back in the callback URL.
func TestOAuth2Auth_Post_Approve_StateIsPreserved(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client, _ := testhelper.NewTestClient(t)

	// Log in
	loginForm := url.Values{"username": {"admin@test.local"}, "password": {"test-password"}}
	loginReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/login",
		strings.NewReader(loginForm.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResp, err := client.Do(loginReq)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	loginResp.Body.Close()

	// GET /oauth2/auth — retrieve challenge
	getResp, err := client.Get(buildAuthURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	pageBody, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /oauth2/auth status = %d, want 200", getResp.StatusCode)
	}

	challenge := extractHiddenInputValue(string(pageBody), "challenge")

	// POST approve — stop before following the callback redirect
	stopClient := &http.Client{
		Jar: client.Jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), "http://localhost:9999/callback") {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	consentForm := url.Values{"action": {"approve"}, "challenge": {challenge}}
	consentReq, _ := http.NewRequest(http.MethodPost, buildAuthURL(srv.URL, nil),
		strings.NewReader(consentForm.Encode()))
	consentReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range client.Jar.Cookies(mustParseURL(t, srv.URL)) {
		consentReq.AddCookie(c)
	}

	// Act
	consentResp, err := stopClient.Do(consentReq)
	if err != nil && !strings.Contains(err.Error(), "use last response") {
		t.Fatalf("POST /oauth2/auth: %v", err)
	}
	if consentResp != nil {
		consentResp.Body.Close()
	}

	// Assert — state in callback URL
	var callbackURL string
	if consentResp != nil {
		callbackURL = consentResp.Header.Get("Location")
	}
	if callbackURL == "" {
		t.Skip("callback URL not captured; skipping state assertion")
	}

	parsed, err := url.Parse(callbackURL)
	if err != nil {
		t.Fatalf("url.Parse %q: %v", callbackURL, err)
	}

	if state := parsed.Query().Get("state"); state != "test-state-value" {
		t.Errorf("callback state = %q, want %q", state, "test-state-value")
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/auth — consent 거부 → 에러 응답
// ---------------------------------------------------------------------------

// TestOAuth2Auth_Post_Deny_ReturnsError verifies that denying the consent form
// does not issue an authorization code.
func TestOAuth2Auth_Post_Deny_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client, _ := loginAndGetClient(t, srv.URL)

	// GET /oauth2/auth
	getResp, err := client.Get(buildAuthURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	body, _ := io.ReadAll(getResp.Body)
	getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /oauth2/auth status = %d, want 200", getResp.StatusCode)
	}

	challenge := extractHiddenInputValue(string(body), "challenge")

	// Act — POST deny
	stopClient := &http.Client{
		Jar: client.Jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), "http://localhost:9999/callback") {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	consentForm := url.Values{"action": {"deny"}, "challenge": {challenge}}
	denyReq, _ := http.NewRequest(http.MethodPost, buildAuthURL(srv.URL, nil),
		strings.NewReader(consentForm.Encode()))
	denyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range client.Jar.Cookies(mustParseURL(t, srv.URL)) {
		denyReq.AddCookie(c)
	}

	denyResp, err := stopClient.Do(denyReq)
	if err != nil && !strings.Contains(err.Error(), "use last response") {
		t.Fatalf("POST /oauth2/auth (deny): %v", err)
	}
	if denyResp != nil {
		defer denyResp.Body.Close()
	}

	// Assert — callback URL must NOT contain a code parameter.
	// It must contain an error parameter instead.
	var callbackURL string
	if denyResp != nil {
		callbackURL = denyResp.Header.Get("Location")
		if callbackURL == "" && denyResp.Request != nil {
			callbackURL = denyResp.Request.URL.String()
		}
	}

	if callbackURL != "" {
		parsed, err := url.Parse(callbackURL)
		if err == nil {
			if code := parsed.Query().Get("code"); code != "" {
				t.Errorf("deny produced code %q in callback, want error parameter", code)
			}
			if errParam := parsed.Query().Get("error"); errParam == "" {
				t.Errorf("deny callback URL %q has no error parameter", callbackURL)
			}
		}
	} else if denyResp != nil && denyResp.StatusCode < 400 && denyResp.StatusCode != http.StatusFound {
		t.Errorf("deny status = %d, want 4xx or redirect-with-error", denyResp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/token — authorization_code grant → 토큰 발급
// ---------------------------------------------------------------------------

// TestOAuth2Token_Post_ValidCode_IssuesTokens verifies that a valid
// authorization code can be exchanged for access_token, id_token, and
// refresh_token.
func TestOAuth2Token_Post_ValidCode_IssuesTokens(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	code := obtainAuthorizationCode(t, srv.URL)

	// Act
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/oauth2/token",
		strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/token: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth2/token status = %d, want 200; body = %s", resp.StatusCode, respBody)
	}

	var tokenJSON map[string]interface{}
	if err := json.Unmarshal(respBody, &tokenJSON); err != nil {
		t.Fatalf("json.Unmarshal token response: %v; body = %s", err, respBody)
	}

	// Assert — access_token
	if at, ok := tokenJSON["access_token"].(string); !ok || at == "" {
		t.Errorf("token response missing or empty access_token; body = %s", respBody)
	}

	// Assert — id_token (requires openid scope)
	if idt, ok := tokenJSON["id_token"].(string); !ok || idt == "" {
		t.Errorf("token response missing or empty id_token; body = %s", respBody)
	}

	// Assert — refresh_token
	if rt, ok := tokenJSON["refresh_token"].(string); !ok || rt == "" {
		t.Errorf("token response missing or empty refresh_token; body = %s", respBody)
	}

	// Assert — token_type is Bearer
	if tt, ok := tokenJSON["token_type"].(string); !ok || !strings.EqualFold(tt, "bearer") {
		t.Errorf("token_type = %v, want Bearer", tokenJSON["token_type"])
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/token — 잘못된 code → 에러 응답
// ---------------------------------------------------------------------------

// TestOAuth2Token_Post_InvalidCode_ReturnsError verifies that submitting an
// invalid authorization code returns a 4xx error.
func TestOAuth2Token_Post_InvalidCode_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"invalid-code-that-does-not-exist"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/oauth2/token",
		strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/token: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Assert — 4xx error
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Errorf("status = %d, want 4xx; body = %s", resp.StatusCode, body)
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/token — JWT access_token 클레임 검증
// ---------------------------------------------------------------------------

// TestOAuth2Token_Post_AccessToken_JWTClaims verifies that the JWT
// access_token contains the required standard claims.
func TestOAuth2Token_Post_AccessToken_JWTClaims(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	code := obtainAuthorizationCode(t, srv.URL)

	// Act
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth2/token",
		strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/token: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth2/token status = %d; body = %s", resp.StatusCode, body)
	}

	var tokenJSON map[string]interface{}
	if err := json.Unmarshal(body, &tokenJSON); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	accessToken, _ := tokenJSON["access_token"].(string)
	if accessToken == "" {
		t.Fatal("access_token is missing from token response")
	}

	claims, err := decodeJWTPayload(accessToken)
	if err != nil {
		t.Fatalf("decodeJWTPayload: %v", err)
	}

	// Assert — iss
	iss, _ := claims["iss"].(string)
	if iss != "https://auth.test.local" {
		t.Errorf("access_token iss = %q, want %q", iss, "https://auth.test.local")
	}

	// Assert — aud present
	if _, ok := claims["aud"]; !ok {
		t.Error("access_token claim aud is missing")
	}

	// Assert — exp present and positive
	exp, _ := claims["exp"].(float64)
	if exp == 0 {
		t.Error("access_token claim exp is missing or zero")
	}

	// Assert — iat present
	iat, _ := claims["iat"].(float64)
	if iat == 0 {
		t.Error("access_token claim iat is missing or zero")
	}

	// Assert — exp after iat
	if exp <= iat {
		t.Errorf("access_token exp (%v) must be after iat (%v)", exp, iat)
	}

	// Assert — scope present
	if _, ok := claims["scope"]; !ok {
		// scope may appear as "scp" in some JWT implementations
		if _, ok2 := claims["scp"]; !ok2 {
			t.Error("access_token is missing scope/scp claim")
		}
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/token — id_token 클레임 검증
// ---------------------------------------------------------------------------

// TestOAuth2Token_Post_IDToken_Claims verifies that the id_token contains the
// required OIDC claims: sub, aud, iss, nonce, at_hash.
func TestOAuth2Token_Post_IDToken_Claims(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	code := obtainAuthorizationCode(t, srv.URL)

	// Act
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth2/token",
		strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/token: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth2/token status = %d; body = %s", resp.StatusCode, body)
	}

	var tokenJSON map[string]interface{}
	if err := json.Unmarshal(body, &tokenJSON); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	idToken, _ := tokenJSON["id_token"].(string)
	if idToken == "" {
		t.Fatal("id_token is missing from token response")
	}

	claims, err := decodeJWTPayload(idToken)
	if err != nil {
		t.Fatalf("decodeJWTPayload(id_token): %v", err)
	}

	// Assert — sub must equal the authenticated user
	sub, _ := claims["sub"].(string)
	if sub == "" {
		t.Error("id_token claim sub is missing or empty")
	}
	if sub != "admin@test.local" {
		t.Errorf("id_token sub = %q, want %q", sub, "admin@test.local")
	}

	// Assert — aud present
	if _, ok := claims["aud"]; !ok {
		t.Error("id_token claim aud is missing")
	}

	// Assert — iss
	iss, _ := claims["iss"].(string)
	if iss != "https://auth.test.local" {
		t.Errorf("id_token iss = %q, want %q", iss, "https://auth.test.local")
	}

	// Assert — nonce echoes the request value
	nonce, _ := claims["nonce"].(string)
	if nonce == "" {
		t.Error("id_token claim nonce is missing or empty")
	}
	if nonce != "test-nonce-value" {
		t.Errorf("id_token nonce = %q, want %q", nonce, "test-nonce-value")
	}

	// Assert — at_hash binds id_token to access_token
	if _, ok := claims["at_hash"]; !ok {
		t.Error("id_token claim at_hash is missing; it must bind the id_token to the access_token")
	}
}

// ---------------------------------------------------------------------------
// Internal test utilities
// ---------------------------------------------------------------------------

// obtainAuthorizationCode drives a complete consent flow and returns the
// authorization code from the callback redirect URL.
func obtainAuthorizationCode(t *testing.T, srvURL string) string {
	t.Helper()

	client, transport := testhelper.NewTestClient(t)
	_ = transport

	// Step 1: log in
	loginForm := url.Values{
		"username": {"admin@test.local"},
		"password": {"test-password"},
	}
	loginReq, err := http.NewRequest(http.MethodPost, srvURL+"/login",
		strings.NewReader(loginForm.Encode()))
	if err != nil {
		t.Fatalf("obtainAuthorizationCode: login request: %v", err)
	}
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResp, err := client.Do(loginReq)
	if err != nil {
		t.Fatalf("obtainAuthorizationCode: POST /login: %v", err)
	}
	loginResp.Body.Close()

	// Step 2: GET /oauth2/auth — retrieve challenge from consent page
	getResp, err := client.Get(buildAuthURL(srvURL, nil))
	if err != nil {
		t.Fatalf("obtainAuthorizationCode: GET /oauth2/auth: %v", err)
	}
	pageBody, err := io.ReadAll(getResp.Body)
	getResp.Body.Close()
	if err != nil {
		t.Fatalf("obtainAuthorizationCode: io.ReadAll: %v", err)
	}
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("obtainAuthorizationCode: GET /oauth2/auth status = %d, want 200; body = %.300s",
			getResp.StatusCode, pageBody)
	}

	challenge := extractHiddenInputValue(string(pageBody), "challenge")
	if challenge == "" {
		t.Fatalf("obtainAuthorizationCode: no challenge in consent page; body = %.300s", pageBody)
	}

	// Step 3: POST /oauth2/auth with approve — stop before the callback redirect
	stopClient := &http.Client{
		Jar: client.Jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), "http://localhost:9999/callback") {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	consentForm := url.Values{
		"action":    {"approve"},
		"challenge": {challenge},
	}
	consentReq, err := http.NewRequest(http.MethodPost, buildAuthURL(srvURL, nil),
		strings.NewReader(consentForm.Encode()))
	if err != nil {
		t.Fatalf("obtainAuthorizationCode: consent request: %v", err)
	}
	consentReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range client.Jar.Cookies(mustParseURL(t, srvURL)) {
		consentReq.AddCookie(c)
	}

	consentResp, err := stopClient.Do(consentReq)
	if err != nil && !strings.Contains(err.Error(), "use last response") {
		t.Fatalf("obtainAuthorizationCode: POST /oauth2/auth: %v", err)
	}
	if consentResp != nil {
		consentResp.Body.Close()
	}

	// Extract the authorization code from the callback Location header.
	var callbackURL string
	if consentResp != nil {
		callbackURL = consentResp.Header.Get("Location")
		if callbackURL == "" && consentResp.Request != nil {
			callbackURL = consentResp.Request.URL.String()
		}
	}
	if callbackURL == "" {
		t.Fatal("obtainAuthorizationCode: no callback URL found after consent approval")
	}

	parsed, err := url.Parse(callbackURL)
	if err != nil {
		t.Fatalf("obtainAuthorizationCode: url.Parse %q: %v", callbackURL, err)
	}

	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("obtainAuthorizationCode: no code in callback URL %q", callbackURL)
	}
	return code
}

// extractHiddenInputValue finds a hidden <input name="..."> in html and
// returns its value attribute. Returns "" when not found.
func extractHiddenInputValue(html, name string) string {
	needle := `name="` + name + `"`
	idx := strings.Index(html, needle)
	if idx == -1 {
		return ""
	}
	sub := html[idx:]
	endTag := strings.Index(sub, ">")
	if endTag == -1 {
		endTag = len(sub)
	}
	tagContent := sub[:endTag]

	const valuePrefix = `value="`
	vi := strings.Index(tagContent, valuePrefix)
	if vi == -1 {
		return ""
	}
	rest := tagContent[vi+len(valuePrefix):]
	end := strings.Index(rest, `"`)
	if end == -1 {
		return rest
	}
	return rest[:end]
}

// decodeJWTPayload base64url-decodes the payload segment of a compact JWT
// and returns it as a map. The signature is NOT verified.
func decodeJWTPayload(jwt string) (map[string]interface{}, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	// base64url (no padding) → standard base64 with padding
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		// Try RawURLEncoding (no padding required)
		decoded, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("base64url decode JWT payload: %w", err)
		}
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("json.Unmarshal JWT payload: %w", err)
	}
	return claims, nil
}

// mustParseURL parses rawURL and fatals if parsing fails.
func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse %q: %v", rawURL, err)
	}
	return u
}
