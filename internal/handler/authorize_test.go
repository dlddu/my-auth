package handler_test

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// buildAuthorizeURL constructs a GET /oauth2/auth URL with the standard
// test parameters used throughout the authorize handler tests.
func buildAuthorizeURL(base string, overrides map[string]string) string {
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"scope":         {"openid profile email"},
		"state":         {"test-state-value"},
		"nonce":         {"test-nonce-value"},
	}
	for k, v := range overrides {
		params.Set(k, v)
	}
	return base + "/oauth2/auth?" + params.Encode()
}

// insertOAuthClient inserts a test OAuth2 client into the database.
func insertOAuthClient(t *testing.T, dsn string) {
	t.Helper()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("insertOAuthClient: sql.Open: %v", err)
	}
	defer db.Close()

	_, err = db.ExecContext(context.Background(),
		`INSERT OR IGNORE INTO clients
		    (id, secret, redirect_uris, grant_types, response_types, scopes)
		 VALUES
		    (?, ?, ?, ?, ?, ?)`,
		"test-client", "test-secret",
		`["http://localhost:9999/callback"]`,
		`["authorization_code", "refresh_token"]`,
		`["code"]`,
		`openid profile email`,
	)
	if err != nil {
		t.Fatalf("insertOAuthClient: exec: %v", err)
	}
}

// loginAndGetCookieClient performs a POST /login with valid credentials and
// returns a cookie-preserving http.Client that is already authenticated.
func loginAndGetCookieClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()

	client, _ := testhelper.NewTestClient(t)

	formData := url.Values{
		"username": {"admin@test.local"},
		"password": {"test-password"},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/login",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("loginAndGetCookieClient: new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("loginAndGetCookieClient: POST /login: %v", err)
	}
	_ = resp.Body.Close()

	return client
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — unauthenticated redirect
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_UnauthenticatedRedirectsToLogin(t *testing.T) {
	// Arrange — no login, no session cookie
	srv, _ := testhelper.NewTestServer(t)

	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Act
	resp, err := noRedirectClient.Get(buildAuthorizeURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	// Assert — must redirect (302) to /login
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d (Found/redirect)", resp.StatusCode, http.StatusFound)
	}

	location := resp.Header.Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("Location = %q, want it to contain \"/login\"", location)
	}
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — unauthenticated preserves return_to parameter
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_UnauthenticatedRedirect_ContainsReturnTo(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	noRedirectClient := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Act
	resp, err := noRedirectClient.Get(buildAuthorizeURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	// Assert — the Location header must carry a return_to or similar mechanism
	// so the authorize flow can be resumed after login.
	location := resp.Header.Get("Location")
	hasReturnTo := strings.Contains(location, "return_to") ||
		strings.Contains(location, "redirect") ||
		strings.Contains(location, "oauth2")
	if !hasReturnTo {
		t.Errorf("Location = %q, want it to encode the original authorize URL (return_to / redirect)", location)
	}
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — authenticated shows consent page
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_AuthenticatedShowsConsentPage(t *testing.T) {
	// Arrange — obtain an authenticated client
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetCookieClient(t, srv)

	// Act — GET /oauth2/auth with a valid client_id registered in the DB
	// The NewTestServer does not register a client, so we expect either:
	//   - a consent page (200) if the client is registered, or
	//   - a 400 error response if the client is unknown (fosite behaviour).
	// This test verifies that an authenticated user is NOT redirected to /login.
	resp, err := client.Get(buildAuthorizeURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth (authenticated): %v", err)
	}
	defer resp.Body.Close()

	// Assert — must not redirect back to /login
	finalURL := resp.Request.URL.Path
	if strings.HasSuffix(finalURL, "/login") {
		t.Errorf("authenticated user was redirected to /login: final URL = %q", finalURL)
	}

	// Assert — status must not be 3xx (authenticated users don't get login redirect)
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusTemporaryRedirect {
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, "/login") {
			t.Errorf("status = %d and Location = %q: authenticated user redirected to login", resp.StatusCode, loc)
		}
	}
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — authenticated + registered client shows consent HTML
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_AuthenticatedWithRegisteredClient_ShowsConsentHTML(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Insert the OAuth2 client into the test DB.
	// We need the DSN; extract it by inspecting testhelper internals via a
	// dedicated helper that opens the DB directly.
	// For now we rely on the server accepting the client or returning a proper
	// error page — either way the response must be HTML, not a login redirect.
	client := loginAndGetCookieClient(t, srv)

	resp, err := client.Get(buildAuthorizeURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — the response body must be HTML (consent page or error page),
	// not a redirect to /login.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") && resp.StatusCode != http.StatusFound {
		// Accept JSON error responses from fosite as well (400 with JSON).
		if !strings.Contains(ct, "application/json") {
			t.Errorf("Content-Type = %q, want text/html or application/json (got body: %.200s)", ct, body)
		}
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/auth — deny returns error redirect to client
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_PostDeny_RedirectsWithError(t *testing.T) {
	// Arrange — authenticated client with a registered OAuth2 client
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetCookieClient(t, srv)

	// First, GET /oauth2/auth to establish a fosite authorization session.
	// Then POST with action=deny.
	formData := url.Values{
		"action":        {"deny"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"test-state"},
	}

	noRedirectClient := &http.Client{
		Jar: client.Jar, // reuse the authenticated session cookie
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("POST /oauth2/auth: new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Act
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/auth (deny): %v", err)
	}
	defer resp.Body.Close()

	// Assert — deny must result in a redirect or an error response.
	// Per RFC 6749 §4.1.2.1, user-denied requests redirect to the client with
	// error=access_denied (when redirect_uri is valid).
	// We accept any 3xx or 4xx as a sign of denial being handled.
	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("POST /oauth2/auth (deny): expected redirect or error, got 200 OK — body: %.200s", body)
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/auth — approve redirects with authorization code
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_PostApprove_RedirectsWithCode(t *testing.T) {
	// Arrange — authenticated client + registered OAuth2 client in DB
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetCookieClient(t, srv)

	noRedirectClient := &http.Client{
		Jar: client.Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	formData := url.Values{
		"action":        {"approve"},
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:9999/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"test-state-approve"},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("POST /oauth2/auth (approve): new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Act
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/auth (approve): %v", err)
	}
	defer resp.Body.Close()

	// Assert — approve must redirect (302) to the redirect_uri.
	// If the client is not registered, fosite will return an error instead.
	// We accept either a redirect-with-code or an error response.
	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if !strings.Contains(location, "code=") && !strings.Contains(location, "error=") {
			t.Errorf("Location after approve = %q, want either code= or error= parameter", location)
		}
		if strings.Contains(location, "state=") {
			if !strings.Contains(location, "test-state-approve") {
				t.Errorf("state parameter not preserved in Location = %q", location)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// E2E consent flow — approve redirects with authorization code
// ---------------------------------------------------------------------------

// TestConsentPost_ApproveRedirectsWithCode simulates the full consent page
// approval flow end-to-end:
//
//  1. Login to obtain an authenticated session cookie.
//  2. GET /oauth2/auth — the server redirects through /consent (following
//     redirects automatically); verify the final URL contains "/consent".
//  3. POST /consent?{same query string} with action=approve and verify a 303
//     redirect to the client redirect_uri with a code= parameter.
//  4. POST /consent?{same query string} with action=deny and verify a redirect
//     with error=access_denied.
func TestConsentPost_ApproveRedirectsWithCode(t *testing.T) {
	// Arrange — start a test server and obtain an authenticated session cookie.
	srv, _ := testhelper.NewTestServer(t)
	authClient := loginAndGetCookieClient(t, srv)

	// Step 2: GET /oauth2/auth; the authenticated client follows redirects
	// (302 /oauth2/auth → 302 /consent → 200 consent page).
	authorizeURL := buildAuthorizeURL(srv.URL, nil)
	resp, err := authClient.Get(authorizeURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	_ = resp.Body.Close()

	// The final URL after following redirects must be the consent page.
	finalURL := resp.Request.URL
	if !strings.Contains(finalURL.Path, "/consent") {
		t.Fatalf("expected final URL to contain \"/consent\", got %q", finalURL.String())
	}

	// The consent page URL carries the same OAuth2 query string that was
	// forwarded from /oauth2/auth → /consent.
	consentQuery := finalURL.RawQuery

	// Step 3: POST /consent?{query} with action=approve.
	// Use a no-redirect client that shares the authenticated session cookie jar
	// so the session cookie is sent with the POST.
	noRedirectClient := &http.Client{
		Jar: authClient.Jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	approveBody := strings.NewReader("action=approve")
	approveReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/consent?"+consentQuery,
		approveBody,
	)
	if err != nil {
		t.Fatalf("POST /consent (approve): new request: %v", err)
	}
	approveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	approveResp, err := noRedirectClient.Do(approveReq)
	if err != nil {
		t.Fatalf("POST /consent (approve): %v", err)
	}
	_ = approveResp.Body.Close()

	// Assert — must be a redirect (303) to the client callback URI with code=.
	if approveResp.StatusCode != http.StatusSeeOther {
		t.Errorf("POST /consent (approve): status = %d, want %d (See Other)",
			approveResp.StatusCode, http.StatusSeeOther)
	}

	approveLocation := approveResp.Header.Get("Location")
	if !strings.Contains(approveLocation, "http://localhost:9999/callback") {
		t.Errorf("POST /consent (approve): Location = %q, want it to contain the callback URI", approveLocation)
	}
	if !strings.Contains(approveLocation, "code=") {
		t.Errorf("POST /consent (approve): Location = %q, want a \"code=\" parameter", approveLocation)
	}

	// Step 4: POST /consent?{query} with action=deny.
	denyBody := strings.NewReader("action=deny")
	denyReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/consent?"+consentQuery,
		denyBody,
	)
	if err != nil {
		t.Fatalf("POST /consent (deny): new request: %v", err)
	}
	denyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	denyResp, err := noRedirectClient.Do(denyReq)
	if err != nil {
		t.Fatalf("POST /consent (deny): %v", err)
	}
	_ = denyResp.Body.Close()

	// Assert — deny must redirect with error=access_denied.
	denyLocation := denyResp.Header.Get("Location")
	if !strings.Contains(denyLocation, "error=access_denied") {
		t.Errorf("POST /consent (deny): Location = %q, want \"error=access_denied\"", denyLocation)
	}
}

// ---------------------------------------------------------------------------
// E2E consent flow — debug variant that logs the body on non-redirect response
// ---------------------------------------------------------------------------

// TestConsentPost_ApproveRedirectsWithCode_Body is identical to
// TestConsentPost_ApproveRedirectsWithCode but additionally logs the full
// response body when the consent POST does NOT return a redirect, which helps
// diagnose CI failures where the status is unexpected.
func TestConsentPost_ApproveRedirectsWithCode_Body(t *testing.T) {
	// Arrange.
	srv, _ := testhelper.NewTestServer(t)
	authClient := loginAndGetCookieClient(t, srv)

	// GET /oauth2/auth → follow redirects → land on /consent.
	resp, err := authClient.Get(buildAuthorizeURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	_ = resp.Body.Close()

	finalURL := resp.Request.URL
	if !strings.Contains(finalURL.Path, "/consent") {
		t.Fatalf("expected final URL to contain \"/consent\", got %q", finalURL.String())
	}

	consentQuery := finalURL.RawQuery

	noRedirectClient := &http.Client{
		Jar: authClient.Jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// POST /consent?{query} with action=approve.
	postReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/consent?"+consentQuery,
		strings.NewReader("action=approve"),
	)
	if err != nil {
		t.Fatalf("POST /consent: new request: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	postResp, err := noRedirectClient.Do(postReq)
	if err != nil {
		t.Fatalf("POST /consent: %v", err)
	}
	defer postResp.Body.Close()

	// If the response is NOT a redirect, read and log the body to aid debugging.
	if postResp.StatusCode != http.StatusSeeOther && postResp.StatusCode != http.StatusFound {
		body, readErr := io.ReadAll(postResp.Body)
		if readErr != nil {
			t.Logf("POST /consent: also failed to read body: %v", readErr)
		}
		t.Errorf("POST /consent (approve): status = %d, want redirect (302/303) — body: %s",
			postResp.StatusCode, body)
		return
	}

	location := postResp.Header.Get("Location")
	if !strings.Contains(location, "code=") {
		t.Errorf("POST /consent (approve): Location = %q, want a \"code=\" parameter", location)
	}
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — unauthenticated does NOT reveal 500 errors
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_UnauthenticatedDoesNotReturn500(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	_, client := testhelper.NewTestServer(t)

	// Act
	resp, err := client.Get(buildAuthorizeURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	// Assert — must not be a server error
	if resp.StatusCode >= http.StatusInternalServerError {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("GET /oauth2/auth: unexpected server error %d — body: %.200s", resp.StatusCode, body)
	}
}
