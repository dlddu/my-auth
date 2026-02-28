// Package handler_test contains integration tests for the OAuth2 / OIDC
// authorisation and token endpoints.
//
// TDD Red Phase: all tests in this file are expected to FAIL until the
// OAuth2 handler implementation (handler/oauth2.go) is complete.
//
// Test conventions follow the existing handler test style:
//   - package handler_test (external test package)
//   - Arrange / Act / Assert with plain if / t.Errorf (no testify)
//   - testhelper.NewTestServer / NewTestClient for isolated servers
//   - Direct SQL insertion to seed the database with an OAuth2 client
package handler_test

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/database"
	"github.com/dlddu/my-auth/internal/testhelper"
	"golang.org/x/crypto/bcrypt"
)

// ---------------------------------------------------------------------------
// Test setup helpers
// ---------------------------------------------------------------------------

// openTestDB opens the SQLite database at dsn without re-running migrations.
// It registers t.Cleanup to close the connection when the test ends.
func openTestDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("openTestDB: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Logf("openTestDB cleanup: %v", err)
		}
	})
	return db
}

// newMigratedDB creates a fresh SQLite database in a temp directory, runs all
// migrations, and returns both the *sql.DB and the DSN.
func newMigratedDB(t *testing.T) (*sql.DB, string) {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=ON", dbPath)

	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("newMigratedDB: open: %v", err)
	}

	migrationsDir, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		db.Close()
		t.Fatalf("newMigratedDB: resolve migrations path: %v", err)
	}

	if err := database.Migrate(db, migrationsDir); err != nil {
		db.Close()
		t.Fatalf("newMigratedDB: migrate: %v", err)
	}

	t.Cleanup(func() { db.Close() })
	return db, dsn
}

// testClientID / testClientSecret / testRedirectURI are the fixed OAuth2
// client credentials used in every test within this file.
const (
	testClientID     = "test-client"
	testClientSecret = "test-secret"
	testRedirectURI  = "http://localhost:9999/callback"
)

// seedOAuthClient inserts a test OAuth2 client into the clients table.
// The secret is stored as a bcrypt hash so fosite can verify it.
func seedOAuthClient(t *testing.T, db *sql.DB) {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte(testClientSecret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("seedOAuthClient: bcrypt: %v", err)
	}

	_, err = db.Exec(
		`INSERT OR IGNORE INTO clients
		   (id, secret, redirect_uris, grant_types, response_types, scopes)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		testClientID,
		string(hash),
		fmt.Sprintf(`[%q]`, testRedirectURI),
		`["authorization_code","refresh_token"]`,
		`["code"]`,
		"openid profile email",
	)
	if err != nil {
		t.Fatalf("seedOAuthClient: INSERT: %v", err)
	}
}

// loginAndGetCookies performs POST /login with the test owner credentials and
// returns the session cookies set by the server.
func loginAndGetCookies(t *testing.T, srvURL string) []*http.Cookie {
	t.Helper()

	formData := url.Values{
		"username": {"admin@test.local"},
		"password": {"test-password"},
	}

	noRedirect := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srvURL+"/login",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("loginAndGetCookies: NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatalf("loginAndGetCookies: POST /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("loginAndGetCookies: status = %d, want 303 See Other", resp.StatusCode)
	}
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("loginAndGetCookies: no cookies in response")
	}
	return cookies
}

// buildAuthorizeURL constructs a GET /oauth2/auth URL with standard
// authorization-code flow query parameters.
func buildAuthorizeURL(srvURL, state, nonce string) string {
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid profile email"},
		"state":         {state},
		"nonce":         {nonce},
	}
	return srvURL + "/oauth2/auth?" + params.Encode()
}

// tokenResponse is a minimal struct for deserialising the token endpoint JSON.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
}

// obtainAuthorizationCode drives the consent-approve flow and returns the
// authorization code extracted from the callback Location header.
func obtainAuthorizationCode(t *testing.T, srvURL string, cookies []*http.Cookie, state, nonce string) string {
	t.Helper()

	noRedirect := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	form := url.Values{
		"response_type": {"code"},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid profile email"},
		"state":         {state},
		"nonce":         {nonce},
		"action":        {"approve"},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srvURL+"/oauth2/auth",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("obtainAuthorizationCode: NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}

	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatalf("obtainAuthorizationCode: POST /oauth2/auth: %v", err)
	}
	resp.Body.Close()

	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("obtainAuthorizationCode: url.Parse(%q): %v", loc, err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("obtainAuthorizationCode: no 'code' in Location: %s", loc)
	}
	return code
}

// exchangeCodeForTokens sends POST /oauth2/token with Basic Auth and returns
// the parsed token response.
func exchangeCodeForTokens(t *testing.T, srvURL, code string) tokenResponse {
	t.Helper()

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {testRedirectURI},
		"client_id":    {testClientID},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srvURL+"/oauth2/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("exchangeCodeForTokens: NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testClientSecret)

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("exchangeCodeForTokens: POST /oauth2/token: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("exchangeCodeForTokens: io.ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchangeCodeForTokens: status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatalf("exchangeCodeForTokens: json.Unmarshal: %v; body = %s", err, body)
	}
	return tr
}

// parseJWTClaims extracts the payload claims from a JWT string without
// verifying the signature. Sufficient for integration-level claim checks.
func parseJWTClaims(t *testing.T, token string) map[string]interface{} {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("parseJWTClaims: expected 3 JWT parts, got %d in %q", len(parts), token)
	}

	// Convert base64url (no padding) → standard base64 with padding
	payload := parts[1]
	payload = strings.NewReplacer("-", "+", "_", "/").Replace(payload)
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("parseJWTClaims: base64 decode: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		t.Fatalf("parseJWTClaims: json.Unmarshal: %v", err)
	}
	return claims
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — unauthenticated → redirect to /login
// ---------------------------------------------------------------------------

// TestOAuth2Auth_UnauthenticatedRedirectsToLogin verifies that hitting
// GET /oauth2/auth without a valid session cookie redirects to /login.
func TestOAuth2Auth_UnauthenticatedRedirectsToLogin(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	noRedirect := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	targetURL := buildAuthorizeURL(srv.URL, "state-unauth", "nonce-unauth")

	// Act
	resp, err := noRedirect.Get(targetURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	// Assert — must be a 3xx redirect
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		t.Errorf("status = %d, want a 3xx redirect", resp.StatusCode)
	}

	// Assert — Location must point to /login
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/login") {
		t.Errorf("Location = %q, want it to contain %q", loc, "/login")
	}
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — authenticated, valid client → consent page
// ---------------------------------------------------------------------------

// TestOAuth2Auth_AuthenticatedValidClient_ReturnsConsentPage verifies that an
// authenticated request with a valid client_id renders the consent HTML page.
func TestOAuth2Auth_AuthenticatedValidClient_ReturnsConsentPage(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	db, _ := newMigratedDB(t)
	seedOAuthClient(t, db)

	cookies := loginAndGetCookies(t, srv.URL)

	// Build a client with a cookie jar and pre-load the session cookies.
	client, _ := testhelper.NewTestClient(t)
	u, _ := url.Parse(srv.URL)
	client.Jar.SetCookies(u, cookies)

	targetURL := buildAuthorizeURL(srv.URL, "state-consent", "nonce-consent")

	// Act
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK with HTML
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want it to contain text/html", ct)
	}

	// Assert — page must contain approve and deny affordances
	bodyStr := string(body)
	hasApprove := strings.Contains(bodyStr, "approve") || strings.Contains(bodyStr, "Approve") ||
		strings.Contains(bodyStr, "allow") || strings.Contains(bodyStr, "Allow")
	hasDeny := strings.Contains(bodyStr, "deny") || strings.Contains(bodyStr, "Deny") ||
		strings.Contains(bodyStr, "decline") || strings.Contains(bodyStr, "Decline")

	if !hasApprove {
		t.Error("consent page does not contain an approve/allow element")
	}
	if !hasDeny {
		t.Error("consent page does not contain a deny/decline element")
	}
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — unknown client_id → 4xx error (no redirect)
// ---------------------------------------------------------------------------

// TestOAuth2Auth_UnknownClientID_ReturnsError verifies that an unknown
// client_id causes a server-side error response, not a redirect to the
// (potentially untrusted) redirect_uri.
func TestOAuth2Auth_UnknownClientID_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	cookies := loginAndGetCookies(t, srv.URL)

	client, _ := testhelper.NewTestClient(t)
	u, _ := url.Parse(srv.URL)
	client.Jar.SetCookies(u, cookies)

	params := url.Values{
		"response_type": {"code"},
		"client_id":     {"unknown-client-xyz"},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid"},
		"state":         {"state-unknown"},
	}
	targetURL := srv.URL + "/oauth2/auth?" + params.Encode()

	// Act
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	// Assert — must be 4xx, NOT a redirect to redirect_uri
	if resp.StatusCode < 400 {
		t.Errorf("status = %d, want a 4xx error for unknown client_id", resp.StatusCode)
	}
	if strings.Contains(resp.Request.URL.String(), "localhost:9999") {
		t.Errorf("server redirected to callback URI for unknown client; final URL = %s", resp.Request.URL)
	}
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — mismatched redirect_uri → 4xx error (no redirect)
// ---------------------------------------------------------------------------

// TestOAuth2Auth_MismatchedRedirectURI_ReturnsError verifies that a known
// client with a mismatched redirect_uri results in a server-side error rather
// than a redirect to the attacker-supplied URI.
func TestOAuth2Auth_MismatchedRedirectURI_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	db, _ := newMigratedDB(t)
	seedOAuthClient(t, db)

	cookies := loginAndGetCookies(t, srv.URL)
	client, _ := testhelper.NewTestClient(t)
	u, _ := url.Parse(srv.URL)
	client.Jar.SetCookies(u, cookies)

	params := url.Values{
		"response_type": {"code"},
		"client_id":     {testClientID},
		"redirect_uri":  {"http://evil.example.com/callback"},
		"scope":         {"openid"},
		"state":         {"state-mismatch"},
	}
	targetURL := srv.URL + "/oauth2/auth?" + params.Encode()

	// Act
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	// Assert — server must not redirect to the evil URI
	if resp.StatusCode < 400 {
		t.Errorf("status = %d, want a 4xx error for mismatched redirect_uri", resp.StatusCode)
	}
	if strings.Contains(resp.Request.URL.String(), "evil.example.com") {
		t.Errorf("server redirected to mismatched redirect_uri: %s", resp.Request.URL)
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/auth — approve consent → authorization code issued
// ---------------------------------------------------------------------------

// TestOAuth2Auth_ApproveConsent_IssuesAuthorizationCode verifies that
// submitting the consent form with action=approve redirects to the callback
// URI with 'code' and 'state' query parameters.
func TestOAuth2Auth_ApproveConsent_IssuesAuthorizationCode(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	db, _ := newMigratedDB(t)
	seedOAuthClient(t, db)

	cookies := loginAndGetCookies(t, srv.URL)

	noRedirect := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	formData := url.Values{
		"response_type": {"code"},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid profile email"},
		"state":         {"state-approve"},
		"nonce":         {"nonce-approve"},
		"action":        {"approve"},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}

	// Act
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/auth: %v", err)
	}
	defer func() {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		_ = body
	}()

	// Assert — must redirect (3xx)
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want a 3xx redirect; body = %s", resp.StatusCode, body)
	}

	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, testRedirectURI) {
		t.Errorf("Location = %q, want it to start with %q", loc, testRedirectURI)
	}

	// Assert — callback URL must contain code and state
	callbackURL, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("url.Parse(Location=%q): %v", loc, err)
	}
	q := callbackURL.Query()

	if q.Get("code") == "" {
		t.Errorf("callback URL missing 'code' parameter; URL = %s", loc)
	}
	if q.Get("state") != "state-approve" {
		t.Errorf("state = %q, want %q", q.Get("state"), "state-approve")
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/auth — deny consent → access_denied redirect
// ---------------------------------------------------------------------------

// TestOAuth2Auth_DenyConsent_ReturnsAccessDenied verifies that submitting the
// consent form with action=deny redirects to the callback URI with
// error=access_denied.
func TestOAuth2Auth_DenyConsent_ReturnsAccessDenied(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	db, _ := newMigratedDB(t)
	seedOAuthClient(t, db)

	cookies := loginAndGetCookies(t, srv.URL)

	noRedirect := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	formData := url.Values{
		"response_type": {"code"},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirectURI},
		"scope":         {"openid profile email"},
		"state":         {"state-deny"},
		"nonce":         {"nonce-deny"},
		"action":        {"deny"},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}

	// Act
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	// Assert — must redirect
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want a 3xx redirect; body = %s", resp.StatusCode, body)
	}

	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, testRedirectURI) {
		t.Errorf("Location = %q, want it to start with %q", loc, testRedirectURI)
	}

	// Assert — callback must contain error=access_denied
	callbackURL, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("url.Parse(Location=%q): %v", loc, err)
	}
	if callbackURL.Query().Get("error") != "access_denied" {
		t.Errorf("error = %q, want %q", callbackURL.Query().Get("error"), "access_denied")
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/token — valid code → tokens issued
// ---------------------------------------------------------------------------

// TestOAuth2Token_ValidCode_IssuesTokens verifies the full authorization_code
// grant: approve consent to get a code, then exchange it for tokens.
func TestOAuth2Token_ValidCode_IssuesTokens(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	db, _ := newMigratedDB(t)
	seedOAuthClient(t, db)

	cookies := loginAndGetCookies(t, srv.URL)
	code := obtainAuthorizationCode(t, srv.URL, cookies, "state-tok", "nonce-tok")

	// Act
	tr := exchangeCodeForTokens(t, srv.URL, code)

	// Assert — all expected token fields must be present
	if tr.AccessToken == "" {
		t.Error("access_token is empty")
	}
	if tr.IDToken == "" {
		t.Error("id_token is empty")
	}
	if tr.RefreshToken == "" {
		t.Error("refresh_token is empty")
	}
	if !strings.EqualFold(tr.TokenType, "bearer") {
		t.Errorf("token_type = %q, want %q (case-insensitive)", tr.TokenType, "bearer")
	}
	if tr.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want > 0", tr.ExpiresIn)
	}
}

// ---------------------------------------------------------------------------
// POST /oauth2/token — invalid code → 400 error
// ---------------------------------------------------------------------------

// TestOAuth2Token_InvalidCode_ReturnsError verifies that an invalid or
// fabricated authorization code yields a 4xx JSON error response.
func TestOAuth2Token_InvalidCode_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	db, _ := newMigratedDB(t)
	seedOAuthClient(t, db)

	tokenForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"totally-invalid-code-xyz"},
		"redirect_uri": {testRedirectURI},
		"client_id":    {testClientID},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/token",
		strings.NewReader(tokenForm.Encode()),
	)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testClientSecret)

	// Act
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/token: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — must be 4xx
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Errorf("status = %d, want 4xx for invalid code; body = %s", resp.StatusCode, body)
	}

	// Assert — JSON error body with 'error' field
	var errResp map[string]interface{}
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("json.Unmarshal: %v — body: %s", err, body)
	}
	if _, ok := errResp["error"]; !ok {
		t.Errorf("error response missing 'error' field; body = %s", body)
	}
}

// ---------------------------------------------------------------------------
// JWT access_token claims validation
// ---------------------------------------------------------------------------

// TestOAuth2Token_AccessTokenClaims_ContainsRequiredFields verifies that the
// JWT access_token contains the required RFC 7519 claims after a successful
// authorization_code exchange.
func TestOAuth2Token_AccessTokenClaims_ContainsRequiredFields(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	db, _ := newMigratedDB(t)
	seedOAuthClient(t, db)

	cookies := loginAndGetCookies(t, srv.URL)
	code := obtainAuthorizationCode(t, srv.URL, cookies, "state-at", "nonce-at")
	tr := exchangeCodeForTokens(t, srv.URL, code)

	// Act — parse access_token claims (no signature verification needed here)
	claims := parseJWTClaims(t, tr.AccessToken)

	// Assert — required claims per RFC 7519 §4.1
	for _, claimName := range []string{"iss", "sub", "aud", "exp", "iat"} {
		if _, ok := claims[claimName]; !ok {
			t.Errorf("access_token missing required claim %q", claimName)
		}
	}

	// Assert — iss must match the test issuer
	if iss, _ := claims["iss"].(string); iss != "https://auth.test.local" {
		t.Errorf("access_token iss = %q, want %q", iss, "https://auth.test.local")
	}

	// Assert — sub must be non-empty
	if sub, _ := claims["sub"].(string); sub == "" {
		t.Error("access_token sub is empty")
	}

	// Assert — exp must be a positive number
	if exp, ok := claims["exp"].(float64); !ok || exp <= 0 {
		t.Errorf("access_token exp = %v, want a positive unix timestamp", claims["exp"])
	}
}

// ---------------------------------------------------------------------------
// JWT id_token claims validation
// ---------------------------------------------------------------------------

// TestOAuth2Token_IDTokenClaims_ContainsRequiredFields verifies that the
// id_token JWT contains OIDC Core 1.0 required claims including nonce and
// at_hash.
func TestOAuth2Token_IDTokenClaims_ContainsRequiredFields(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	db, _ := newMigratedDB(t)
	seedOAuthClient(t, db)

	cookies := loginAndGetCookies(t, srv.URL)
	code := obtainAuthorizationCode(t, srv.URL, cookies, "state-id", "nonce-id")
	tr := exchangeCodeForTokens(t, srv.URL, code)

	// Act — parse id_token claims
	claims := parseJWTClaims(t, tr.IDToken)

	// Assert — OIDC Core 1.0 §2 required claims
	for _, claimName := range []string{"iss", "sub", "aud", "exp", "iat"} {
		if _, ok := claims[claimName]; !ok {
			t.Errorf("id_token missing required claim %q", claimName)
		}
	}

	// Assert — nonce must match what was sent in the authorization request
	if nonce, _ := claims["nonce"].(string); nonce != "nonce-id" {
		t.Errorf("id_token nonce = %q, want %q", nonce, "nonce-id")
	}

	// Assert — at_hash must be present (code flow with id_token)
	if _, ok := claims["at_hash"]; !ok {
		t.Error("id_token missing at_hash claim")
	}

	// Assert — iss must match test issuer
	if iss, _ := claims["iss"].(string); iss != "https://auth.test.local" {
		t.Errorf("id_token iss = %q, want %q", iss, "https://auth.test.local")
	}

	// Assert — aud must include the client_id
	audContainsClient := false
	switch aud := claims["aud"].(type) {
	case string:
		audContainsClient = aud == testClientID
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == testClientID {
				audContainsClient = true
				break
			}
		}
	}
	if !audContainsClient {
		t.Errorf("id_token aud = %v, want it to contain %q", claims["aud"], testClientID)
	}
}
