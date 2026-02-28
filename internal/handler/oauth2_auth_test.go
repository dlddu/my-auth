// Package handler_test contains integration tests for the OAuth2/OIDC handler
// layer.  This file covers the /oauth2/auth (GET and POST) and /oauth2/token
// (POST) endpoints.
//
// TDD Red Phase: tests are written before the implementation exists.
// They will fail until the corresponding handlers are implemented.
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

// loginAndGetSession performs a POST /login with the canonical test credentials
// and returns an *http.Client whose cookie jar contains the session cookie.
// The server URL is also returned for convenience.
func loginAndGetSession(t *testing.T, srvURL string) *http.Client {
	t.Helper()

	client, _ := testhelper.NewTestClient(t)

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
		t.Fatalf("loginAndGetSession: http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("loginAndGetSession: POST /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("loginAndGetSession: POST /login status = %d, want 200 or 303", resp.StatusCode)
	}

	return client
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — 미인증 시 /login 리다이렉트
// ---------------------------------------------------------------------------

// TestGetOAuth2Auth_UnauthenticatedRedirectsToLogin verifies that an
// unauthenticated GET /oauth2/auth request is redirected (302) to /login with
// the return_to parameter set to /oauth2/auth (or the full query string).
func TestGetOAuth2Auth_UnauthenticatedRedirectsToLogin(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	authURL := srv.URL + "/oauth2/auth?client_id=test-client&response_type=code" +
		"&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&scope=openid+profile+email&state=test-state"

	// Act
	resp, err := noRedirectClient.Get(authURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	// Assert — must be 302 Found
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d (302 Found)", resp.StatusCode, http.StatusFound)
	}

	// Assert — Location header must point to /login
	location := resp.Header.Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("Location = %q, want it to contain %q", location, "/login")
	}
}

// TestGetOAuth2Auth_UnauthenticatedRedirect_HasReturnToParam verifies that the
// redirect to /login includes a return_to parameter that encodes the original
// /oauth2/auth URL so the user is returned there after login.
func TestGetOAuth2Auth_UnauthenticatedRedirect_HasReturnToParam(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Act
	resp, err := noRedirectClient.Get(srv.URL + "/oauth2/auth?client_id=test-client&response_type=code")
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	// Assert — Location must contain return_to
	location := resp.Header.Get("Location")
	if !strings.Contains(location, "return_to") {
		t.Errorf("Location = %q, want it to contain %q", location, "return_to")
	}
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — 인증된 사용자에게 Consent 페이지 렌더링
// ---------------------------------------------------------------------------

// TestGetOAuth2Auth_AuthenticatedRendersConsentPage verifies that an
// authenticated GET /oauth2/auth request returns 200 with an HTML consent page
// that contains the client name (or ID) and the requested scope.
func TestGetOAuth2Auth_AuthenticatedRendersConsentPage(t *testing.T) {
	// Arrange — create a test server and seed the OAuth client
	srv, _ := testhelper.NewTestServer(t)

	// Seed the OAuth client into the test DB.
	// We need a raw DB handle for seeding; obtain one from the test helper DSN.
	// The testhelper.NewTestServer already opens the DB internally; we open a
	// second read/write handle to the same file.  In practice the integration
	// test server must expose or seed clients before the OAuth flow begins.
	//
	// NOTE: This seed step will need the actual server to wire the storage
	// layer.  Until storage is implemented, this test will fail at the
	// rendering step (not the seed step) because the handler does not exist yet.
	authenticatedClient := loginAndGetSession(t, srv.URL)

	authURL := srv.URL + "/oauth2/auth?client_id=test-client&response_type=code" +
		"&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&scope=openid+profile+email&state=test-state&nonce=test-nonce"

	// Act
	resp, err := authenticatedClient.Get(authURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth (authenticated): %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	bodyStr := string(body)

	// Assert — 200 OK (not a redirect)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d (200 OK); body = %q", resp.StatusCode, http.StatusOK, bodyStr)
	}

	// Assert — HTML response
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want it to contain text/html", ct)
	}

	// Assert — page contains scope information
	hasScopeInfo := strings.Contains(bodyStr, "openid") ||
		strings.Contains(bodyStr, "profile") ||
		strings.Contains(bodyStr, "email") ||
		strings.Contains(bodyStr, "scope")
	if !hasScopeInfo {
		t.Errorf("consent page body does not mention scope; body = %q", bodyStr)
	}
}

// TestGetOAuth2Auth_AuthenticatedRendersConsentPage_ContainsApproveForm verifies
// that the consent page contains a form with an approve action.
func TestGetOAuth2Auth_AuthenticatedRendersConsentPage_ContainsApproveForm(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	authURL := srv.URL + "/oauth2/auth?client_id=test-client&response_type=code" +
		"&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&scope=openid+profile+email&state=test-state"

	// Act
	resp, err := authenticatedClient.Get(authURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth (authenticated): %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	bodyStr := string(body)

	// Assert — form must exist
	if !strings.Contains(bodyStr, "<form") {
		t.Errorf("consent page body does not contain a <form element; body = %q", bodyStr)
	}

	// Assert — an approve/allow button or action must be present
	hasApprove := strings.Contains(bodyStr, "approve") ||
		strings.Contains(bodyStr, "Approve") ||
		strings.Contains(bodyStr, "allow") ||
		strings.Contains(bodyStr, "Allow") ||
		strings.Contains(bodyStr, "authorize") ||
		strings.Contains(bodyStr, "Authorize")
	if !hasApprove {
		t.Errorf("consent page body does not contain an approve/allow action; body = %q", bodyStr)
	}
}

// TestGetOAuth2Auth_AuthenticatedRendersConsentPage_ContainsDenyOption verifies
// that the consent page contains a deny/reject option.
func TestGetOAuth2Auth_AuthenticatedRendersConsentPage_ContainsDenyOption(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	authURL := srv.URL + "/oauth2/auth?client_id=test-client&response_type=code" +
		"&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&scope=openid+profile+email&state=test-state"

	// Act
	resp, err := authenticatedClient.Get(authURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth (authenticated): %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	bodyStr := string(body)

	// Assert — a deny/reject option must be present
	hasDeny := strings.Contains(bodyStr, "deny") ||
		strings.Contains(bodyStr, "Deny") ||
		strings.Contains(bodyStr, "reject") ||
		strings.Contains(bodyStr, "Reject") ||
		strings.Contains(bodyStr, "cancel") ||
		strings.Contains(bodyStr, "Cancel")
	if !hasDeny {
		t.Errorf("consent page body does not contain a deny/reject option; body = %q", bodyStr)
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/auth — approve: authorization code 발급
// ---------------------------------------------------------------------------

// TestPostOAuth2Auth_ApproveIssuesAuthorizationCode verifies that when an
// authenticated user POSTs /oauth2/auth with action=approve, the server
// redirects to the redirect_uri with a "code" query parameter.
func TestPostOAuth2Auth_ApproveIssuesAuthorizationCode(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	// Do not follow the final redirect so we can inspect the Location header.
	authenticatedClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Follow redirects within the auth server (e.g. login → auth) but stop
		// at the redirect to the callback URI.
		for _, v := range via {
			if strings.Contains(v.URL.String(), "localhost:9999") {
				return http.ErrUseLastResponse
			}
		}
		if strings.Contains(req.URL.String(), "localhost:9999") {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	formData := url.Values{
		"action":       {"approve"},
		"client_id":    {"test-client"},
		"redirect_uri": {"http://localhost:9999/callback"},
		"scope":        {"openid profile email"},
		"state":        {"test-state"},
		"nonce":        {"test-nonce"},
		"response_type": {"code"},
	}
	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Act
	resp, err := authenticatedClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	// Assert — 302 redirect to the callback URI
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d (302 Found); body = %q", resp.StatusCode, http.StatusFound, body)
	}

	location := resp.Header.Get("Location")

	// Assert — Location must point to the registered redirect_uri
	if !strings.Contains(location, "localhost:9999/callback") {
		t.Errorf("Location = %q, want it to contain callback URI", location)
	}

	// Assert — Location must contain a "code" parameter
	parsedLoc, err := url.Parse(location)
	if err != nil {
		t.Fatalf("url.Parse(Location %q): %v", location, err)
	}
	code := parsedLoc.Query().Get("code")
	if code == "" {
		t.Errorf("Location %q does not contain a 'code' query parameter", location)
	}
}

// TestPostOAuth2Auth_ApprovePreservesState verifies that the state parameter
// is echoed back in the redirect to the callback URI.
func TestPostOAuth2Auth_ApprovePreservesState(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	// Stop redirects at the callback URI.
	authenticatedClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.Contains(req.URL.String(), "localhost:9999") {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	wantState := "unique-state-xyz"
	formData := url.Values{
		"action":        {"approve"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"scope":         {"openid profile email"},
		"state":         {wantState},
		"nonce":         {"test-nonce"},
		"response_type": {"code"},
	}
	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Act
	resp, err := authenticatedClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}

	location := resp.Header.Get("Location")
	parsedLoc, err := url.Parse(location)
	if err != nil {
		t.Fatalf("url.Parse(Location %q): %v", location, err)
	}

	// Assert — state must be echoed back
	gotState := parsedLoc.Query().Get("state")
	if gotState != wantState {
		t.Errorf("state = %q, want %q", gotState, wantState)
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/auth — deny: 에러 응답
// ---------------------------------------------------------------------------

// TestPostOAuth2Auth_DenyReturnsErrorRedirect verifies that when an
// authenticated user POSTs /oauth2/auth with action=deny, the server redirects
// to the redirect_uri with an "error" query parameter (access_denied).
func TestPostOAuth2Auth_DenyReturnsErrorRedirect(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	// Stop redirects at the callback URI.
	authenticatedClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.Contains(req.URL.String(), "localhost:9999") {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	formData := url.Values{
		"action":        {"deny"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"scope":         {"openid profile email"},
		"state":         {"test-state"},
		"response_type": {"code"},
	}
	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Act
	resp, err := authenticatedClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/auth (deny): %v", err)
	}
	defer resp.Body.Close()

	// Assert — must be a redirect (302)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d (302 Found)", resp.StatusCode, http.StatusFound)
	}

	location := resp.Header.Get("Location")
	parsedLoc, err := url.Parse(location)
	if err != nil {
		t.Fatalf("url.Parse(Location %q): %v", location, err)
	}

	// Assert — error parameter must be "access_denied"
	errParam := parsedLoc.Query().Get("error")
	if errParam != "access_denied" {
		t.Errorf("error = %q, want %q", errParam, "access_denied")
	}
}

// TestPostOAuth2Auth_UnauthenticatedReturns302ToLogin verifies that an
// unauthenticated POST /oauth2/auth is redirected to /login.
func TestPostOAuth2Auth_UnauthenticatedReturns302ToLogin(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	formData := url.Values{
		"action":        {"approve"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"scope":         {"openid profile email"},
		"state":         {"test-state"},
		"response_type": {"code"},
	}
	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Act
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/auth (unauthenticated): %v", err)
	}
	defer resp.Body.Close()

	// Assert — must redirect (302) to /login
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d (302 Found)", resp.StatusCode, http.StatusFound)
	}
	location := resp.Header.Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("Location = %q, want it to contain %q", location, "/login")
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/token — authorization_code grant
// ---------------------------------------------------------------------------

// TestPostOAuth2Token_AuthorizationCodeGrant_ReturnsAccessToken verifies the
// full authorization_code flow: GET /oauth2/auth (approve) → exchange code for
// token → response contains access_token.
func TestPostOAuth2Token_AuthorizationCodeGrant_ReturnsAccessToken(t *testing.T) {
	// Arrange — login and capture the authorization code from the redirect.
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	// Stop redirect at callback to capture the code.
	var capturedCode, capturedState string
	authenticatedClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.Contains(req.URL.String(), "localhost:9999") {
			capturedCode = req.URL.Query().Get("code")
			capturedState = req.URL.Query().Get("state")
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	// Step 1: GET /oauth2/auth to land on consent page — then POST approve.
	formData := url.Values{
		"action":        {"approve"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"scope":         {"openid profile email"},
		"state":         {"state-token-test"},
		"nonce":         {"nonce-token-test"},
		"response_type": {"code"},
	}
	approveReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest (approve): %v", err)
	}
	approveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	approveResp, err := authenticatedClient.Do(approveReq)
	if err != nil {
		t.Fatalf("POST /oauth2/auth (approve): %v", err)
	}
	approveResp.Body.Close()

	if capturedCode == "" {
		t.Fatal("no authorization code captured from redirect; check POST /oauth2/auth implementation")
	}
	_ = capturedState // silence unused variable warning

	// Step 2: POST /oauth2/token — exchange code for token.
	tokenFormData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {capturedCode},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	tokenReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/token",
		strings.NewReader(tokenFormData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest (token): %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Use a plain client (no redirect following) for the token endpoint.
	plainClient := srv.Client()

	tokenResp, err := plainClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /oauth2/token: %v", err)
	}
	defer tokenResp.Body.Close()

	// Assert — 200 OK
	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("POST /oauth2/token status = %d, want 200; body = %q", tokenResp.StatusCode, body)
	}

	// Assert — JSON response
	ct := tokenResp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var tokenBody map[string]interface{}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("json.Decode token response: %v", err)
	}

	// Assert — access_token must be present and non-empty
	accessToken, _ := tokenBody["access_token"].(string)
	if accessToken == "" {
		t.Errorf("token response missing 'access_token': %v", tokenBody)
	}

	// Assert — token_type must be "bearer"
	tokenType, _ := tokenBody["token_type"].(string)
	if !strings.EqualFold(tokenType, "bearer") {
		t.Errorf("token_type = %q, want 'bearer'", tokenType)
	}
}

// TestPostOAuth2Token_ReturnsIDToken verifies that the token response includes
// an id_token when the openid scope is requested.
func TestPostOAuth2Token_ReturnsIDToken(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	var capturedCode string
	authenticatedClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.Contains(req.URL.String(), "localhost:9999") {
			capturedCode = req.URL.Query().Get("code")
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	formData := url.Values{
		"action":        {"approve"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"scope":         {"openid profile email"},
		"state":         {"state-idtoken"},
		"nonce":         {"nonce-idtoken"},
		"response_type": {"code"},
	}
	approveReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest (approve): %v", err)
	}
	approveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	approveResp, err := authenticatedClient.Do(approveReq)
	if err != nil {
		t.Fatalf("POST /oauth2/auth: %v", err)
	}
	approveResp.Body.Close()

	if capturedCode == "" {
		t.Fatal("no authorization code captured")
	}

	// Exchange code for token
	tokenFormData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {capturedCode},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	tokenReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/token",
		strings.NewReader(tokenFormData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest (token): %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	plainClient := srv.Client()
	tokenResp, err := plainClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /oauth2/token: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("POST /oauth2/token status = %d; body = %q", tokenResp.StatusCode, body)
	}

	var tokenBody map[string]interface{}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("json.Decode: %v", err)
	}

	// Assert — id_token must be present
	idToken, _ := tokenBody["id_token"].(string)
	if idToken == "" {
		t.Errorf("token response missing 'id_token' for openid scope: %v", tokenBody)
	}
}

// TestPostOAuth2Token_ReturnsRefreshToken verifies that the token response
// includes a refresh_token.
func TestPostOAuth2Token_ReturnsRefreshToken(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	var capturedCode string
	authenticatedClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.Contains(req.URL.String(), "localhost:9999") {
			capturedCode = req.URL.Query().Get("code")
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	formData := url.Values{
		"action":        {"approve"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"scope":         {"openid profile email"},
		"state":         {"state-refresh"},
		"nonce":         {"nonce-refresh"},
		"response_type": {"code"},
	}
	approveReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest (approve): %v", err)
	}
	approveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	approveResp, err := authenticatedClient.Do(approveReq)
	if err != nil {
		t.Fatalf("POST /oauth2/auth: %v", err)
	}
	approveResp.Body.Close()

	if capturedCode == "" {
		t.Fatal("no authorization code captured")
	}

	tokenFormData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {capturedCode},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	tokenReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/token",
		strings.NewReader(tokenFormData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest (token): %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	plainClient := srv.Client()
	tokenResp, err := plainClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /oauth2/token: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("POST /oauth2/token status = %d; body = %q", tokenResp.StatusCode, body)
	}

	var tokenBody map[string]interface{}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("json.Decode: %v", err)
	}

	// Assert — refresh_token must be present
	refreshToken, _ := tokenBody["refresh_token"].(string)
	if refreshToken == "" {
		t.Errorf("token response missing 'refresh_token': %v", tokenBody)
	}
}

// TestPostOAuth2Token_InvalidClient_Returns401 verifies that providing a wrong
// client_secret results in a 401 Unauthorized response.
func TestPostOAuth2Token_InvalidClient_Returns401(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	tokenFormData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"some-code"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"wrong-secret"},
	}
	tokenReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/token",
		strings.NewReader(tokenFormData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	plainClient := srv.Client()

	// Act
	tokenResp, err := plainClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /oauth2/token: %v", err)
	}
	defer tokenResp.Body.Close()

	// Assert — 401 Unauthorized (or 400 for invalid_client)
	if tokenResp.StatusCode != http.StatusUnauthorized && tokenResp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d or %d", tokenResp.StatusCode, http.StatusUnauthorized, http.StatusBadRequest)
	}
}

// TestPostOAuth2Token_InvalidCode_Returns400 verifies that using an invalid or
// expired authorization code results in a 400 Bad Request.
func TestPostOAuth2Token_InvalidCode_Returns400(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	tokenFormData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"invalid-code-that-does-not-exist"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	tokenReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/token",
		strings.NewReader(tokenFormData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	plainClient := srv.Client()

	// Act
	tokenResp, err := plainClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /oauth2/token: %v", err)
	}
	defer tokenResp.Body.Close()

	// Assert — non-2xx response
	if tokenResp.StatusCode >= 200 && tokenResp.StatusCode < 300 {
		t.Errorf("status = %d, want a non-2xx error for invalid code", tokenResp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/token — id_token クレーム検証
// ---------------------------------------------------------------------------

// jwtPayload is a helper that base64url-decodes the payload part of a JWT
// string and returns it as a map.  It does NOT verify the signature.
func jwtPayload(t *testing.T, jwtStr string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		t.Fatalf("jwtPayload: expected 3 parts, got %d; jwt = %q", len(parts), jwtStr)
	}
	// RFC 4648 §5 base64url (no padding)
	padded := parts[1]
	switch len(padded) % 4 {
	case 2:
		padded += "=="
	case 3:
		padded += "="
	}
	padded = strings.ReplaceAll(padded, "-", "+")
	padded = strings.ReplaceAll(padded, "_", "/")

	raw, err := base64.StdEncoding.DecodeString(padded)
	if err != nil {
		t.Fatalf("jwtPayload: base64 decode: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("jwtPayload: json.Unmarshal: %v", err)
	}
	return payload
}

// TestPostOAuth2Token_IDTokenContainsRequiredClaims verifies that the id_token
// JWT contains the mandatory OIDC claims: iss, sub, aud, exp, iat, and nonce.
func TestPostOAuth2Token_IDTokenContainsRequiredClaims(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	var capturedCode string
	authenticatedClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.Contains(req.URL.String(), "localhost:9999") {
			capturedCode = req.URL.Query().Get("code")
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	wantNonce := "nonce-claims-test"
	formData := url.Values{
		"action":        {"approve"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"scope":         {"openid profile email"},
		"state":         {"state-claims"},
		"nonce":         {wantNonce},
		"response_type": {"code"},
	}
	approveReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest (approve): %v", err)
	}
	approveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approveResp, err := authenticatedClient.Do(approveReq)
	if err != nil {
		t.Fatalf("POST /oauth2/auth: %v", err)
	}
	approveResp.Body.Close()

	if capturedCode == "" {
		t.Fatal("no authorization code captured")
	}

	tokenFormData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {capturedCode},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	tokenReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/token",
		strings.NewReader(tokenFormData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest (token): %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	plainClient := srv.Client()
	tokenResp, err := plainClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /oauth2/token: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("POST /oauth2/token status = %d; body = %q", tokenResp.StatusCode, body)
	}

	var tokenBody map[string]interface{}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("json.Decode: %v", err)
	}

	idTokenStr, _ := tokenBody["id_token"].(string)
	if idTokenStr == "" {
		t.Fatal("id_token missing from token response")
	}

	// Decode the payload (no signature verification — that is the job of the
	// JWKS handler test).
	payload := jwtPayload(t, idTokenStr)

	// Assert — iss (issuer)
	iss, _ := payload["iss"].(string)
	if iss == "" {
		t.Errorf("id_token missing 'iss' claim; payload = %v", payload)
	}
	if !strings.HasPrefix(iss, "https://") {
		t.Errorf("id_token 'iss' = %q, want HTTPS issuer", iss)
	}

	// Assert — sub (subject)
	sub, _ := payload["sub"].(string)
	if sub == "" {
		t.Errorf("id_token missing 'sub' claim; payload = %v", payload)
	}

	// Assert — aud (audience) — must include client_id
	switch aud := payload["aud"].(type) {
	case string:
		if aud != "test-client" {
			t.Errorf("id_token 'aud' = %q, want %q", aud, "test-client")
		}
	case []interface{}:
		found := false
		for _, a := range aud {
			if a, ok := a.(string); ok && a == "test-client" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("id_token 'aud' = %v, want to contain %q", aud, "test-client")
		}
	default:
		t.Errorf("id_token 'aud' has unexpected type %T: %v", payload["aud"], payload["aud"])
	}

	// Assert — exp (expiration)
	if _, ok := payload["exp"]; !ok {
		t.Errorf("id_token missing 'exp' claim; payload = %v", payload)
	}

	// Assert — iat (issued at)
	if _, ok := payload["iat"]; !ok {
		t.Errorf("id_token missing 'iat' claim; payload = %v", payload)
	}

	// Assert — nonce must match what was sent
	nonce, _ := payload["nonce"].(string)
	if nonce != wantNonce {
		t.Errorf("id_token 'nonce' = %q, want %q", nonce, wantNonce)
	}
}

// TestPostOAuth2Token_IDTokenContainsAtHash verifies that the id_token includes
// the at_hash claim (access token hash) as required by OIDC Core §3.3.2.11.
func TestPostOAuth2Token_IDTokenContainsAtHash(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	var capturedCode string
	authenticatedClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.Contains(req.URL.String(), "localhost:9999") {
			capturedCode = req.URL.Query().Get("code")
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	formData := url.Values{
		"action":        {"approve"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"scope":         {"openid profile email"},
		"state":         {"state-athash"},
		"nonce":         {"nonce-athash"},
		"response_type": {"code"},
	}
	approveReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest (approve): %v", err)
	}
	approveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approveResp, err := authenticatedClient.Do(approveReq)
	if err != nil {
		t.Fatalf("POST /oauth2/auth: %v", err)
	}
	approveResp.Body.Close()

	if capturedCode == "" {
		t.Fatal("no authorization code captured")
	}

	tokenFormData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {capturedCode},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	tokenReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/token",
		strings.NewReader(tokenFormData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest (token): %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	plainClient := srv.Client()
	tokenResp, err := plainClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /oauth2/token: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("POST /oauth2/token status = %d; body = %q", tokenResp.StatusCode, body)
	}

	var tokenBody map[string]interface{}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("json.Decode: %v", err)
	}

	idTokenStr, _ := tokenBody["id_token"].(string)
	if idTokenStr == "" {
		t.Fatal("id_token missing from token response")
	}

	payload := jwtPayload(t, idTokenStr)

	// Assert — at_hash must be present and non-empty
	atHash, _ := payload["at_hash"].(string)
	if atHash == "" {
		t.Errorf("id_token missing 'at_hash' claim; payload = %v", payload)
	}
}
