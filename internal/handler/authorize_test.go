// Package handler_test contains integration tests for the OAuth2 authorize
// endpoint (/oauth2/auth).
//
// These tests are written in the TDD Red Phase: the handler under test
// (handler.NewAuthorizeHandler) does not yet exist, so the package will not
// compile until the implementation is provided.
//
// Test coverage:
//   - Unauthenticated GET → 302 redirect to /login with return_to
//   - return_to preserves the full original authorization URL (query params)
//   - Authenticated GET → 200 HTML consent page
//   - Consent page displays client ID text
//   - Consent page displays all requested scopes (openid, profile, email)
//   - Authenticated POST approve → 302 to redirect_uri with code + state
//   - Authenticated POST deny → 302 to redirect_uri with error=access_denied + state
//   - Invalid client_id → non-200 error response
//   - Invalid redirect_uri → non-200 error, no redirect to evil domain
package handler_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Shared test constants — must match e2e/authorize.spec.ts
// ---------------------------------------------------------------------------

const (
	validClientID    = "test-client"
	validRedirectURI = "http://localhost:9000/callback"
	validScope       = "openid profile email"
	validState       = "test-state-abc123"
)

// authQuery builds a /oauth2/auth URL with the standard valid parameters.
// Individual fields can be overridden via the overrides map.
func authQuery(srvURL string, overrides map[string]string) string {
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {validClientID},
		"redirect_uri":  {validRedirectURI},
		"scope":         {validScope},
		"state":         {validState},
	}
	for k, v := range overrides {
		params.Set(k, v)
	}
	return srvURL + "/oauth2/auth?" + params.Encode()
}

// loginAndGetClient performs a POST /login with the test owner credentials and
// returns an *http.Client whose CookieJar holds the resulting session cookie.
// The returned client follows redirects automatically.
func loginAndGetClient(t *testing.T, srvURL string) *http.Client {
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
		t.Fatalf("loginAndGetClient: http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("loginAndGetClient: POST /login: %v", err)
	}
	defer resp.Body.Close()

	// Drain the body so the connection is reusable.
	_, _ = io.Copy(io.Discard, resp.Body)

	return client
}

// ---------------------------------------------------------------------------
// 1. TestAuthorizeHandler_Get_Unauthenticated_RedirectToLogin
//    未인증 GET /oauth2/auth → 302 /login
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_Get_Unauthenticated_RedirectToLogin(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// A client that does not follow redirects so we can inspect the 302 itself.
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Act
	resp, err := noRedirectClient.Get(authQuery(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	// Assert — must be 302 Found.
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d (302 Found)", resp.StatusCode, http.StatusFound)
	}

	// Assert — Location header must point to /login.
	location := resp.Header.Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("Location = %q, want it to contain \"/login\"", location)
	}
}

// ---------------------------------------------------------------------------
// 2. TestAuthorizeHandler_Get_Unauthenticated_ReturnToPreservesURL
//    return_to 파라미터에 원래 URL의 response_type, client_id 등이 보존되는지 검증
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_Get_Unauthenticated_ReturnToPreservesURL(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	originalURL := authQuery(srv.URL, nil)

	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Act
	resp, err := noRedirectClient.Get(originalURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	// Assert — 302 redirect.
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d (302 Found)", resp.StatusCode, http.StatusFound)
	}

	location := resp.Header.Get("Location")

	// Parse the Location header to extract return_to.
	locationURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("url.Parse(Location=%q): %v", location, err)
	}

	returnTo := locationURL.Query().Get("return_to")
	if returnTo == "" {
		t.Fatal("Location header does not contain return_to parameter")
	}

	// Assert — return_to must contain the original path and key query params.
	if !strings.Contains(returnTo, "/oauth2/auth") {
		t.Errorf("return_to = %q, want it to contain \"/oauth2/auth\"", returnTo)
	}
	if !strings.Contains(returnTo, "response_type=code") {
		t.Errorf("return_to = %q, want it to contain \"response_type=code\"", returnTo)
	}
	if !strings.Contains(returnTo, "client_id="+validClientID) {
		t.Errorf("return_to = %q, want it to contain \"client_id=%s\"", returnTo, validClientID)
	}
}

// ---------------------------------------------------------------------------
// 3. TestAuthorizeHandler_Get_Authenticated_RendersConsentPage
//    인증 후 GET /oauth2/auth → 200 HTML consent 페이지
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_Get_Authenticated_RendersConsentPage(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetClient(t, srv.URL)

	// Act
	resp, err := client.Get(authQuery(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d (200 OK)", resp.StatusCode, http.StatusOK)
	}

	// Assert — Content-Type must be HTML.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want it to contain \"text/html\"", ct)
	}

	// Assert — body must contain a <form element (consent form).
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "<form") {
		t.Errorf("response body does not contain <form tag")
	}

	// Assert — body must contain an approve action (button or input).
	hasApprove := strings.Contains(bodyStr, "approve") ||
		strings.Contains(bodyStr, "Approve") ||
		strings.Contains(bodyStr, "승인")
	if !hasApprove {
		t.Errorf("response body does not contain an approve button/action, body = %q", bodyStr)
	}
}

// ---------------------------------------------------------------------------
// 4. TestAuthorizeHandler_Get_Authenticated_ConsentShowsClientInfo
//    consent 페이지에 클라이언트 ID 텍스트가 표시되는지 검증
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_Get_Authenticated_ConsentShowsClientInfo(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetClient(t, srv.URL)

	// Act
	resp, err := client.Get(authQuery(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	bodyStr := string(body)

	// Assert — 200 OK.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d (200 OK)", resp.StatusCode, http.StatusOK)
	}

	// Assert — the client ID must appear somewhere in the consent page body.
	if !strings.Contains(bodyStr, validClientID) {
		t.Errorf("consent page body does not contain client ID %q", validClientID)
	}
}

// ---------------------------------------------------------------------------
// 5. TestAuthorizeHandler_Get_Authenticated_ConsentShowsScopes
//    consent 페이지에 openid, profile, email scope가 표시되는지 검증
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_Get_Authenticated_ConsentShowsScopes(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetClient(t, srv.URL)

	// Act
	resp, err := client.Get(authQuery(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	bodyStr := string(body)

	// Assert — 200 OK.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d (200 OK)", resp.StatusCode, http.StatusOK)
	}

	// Assert — each requested scope must appear in the consent page body.
	for _, scope := range []string{"openid", "profile", "email"} {
		if !strings.Contains(bodyStr, scope) {
			t.Errorf("consent page body does not contain scope %q", scope)
		}
	}
}

// ---------------------------------------------------------------------------
// 6. TestAuthorizeHandler_Post_Approve_RedirectsWithCode
//    POST /oauth2/auth (approve) → 302 callback?code=...&state=...
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_Post_Approve_RedirectsWithCode(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetClient(t, srv.URL)

	// First perform a GET to obtain the consent page (fosite may set cookies or
	// hidden fields required by the POST).
	getResp, err := client.Get(authQuery(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	_, _ = io.Copy(io.Discard, getResp.Body)
	getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /oauth2/auth status = %d, want 200 (prerequisite for POST)", getResp.StatusCode)
	}

	// Build the approve POST request, mirroring the original authorize query
	// params so the handler can reconstruct the fosite request.
	formData := url.Values{
		"action":        {"approve"},
		"response_type": {"code"},
		"client_id":     {validClientID},
		"redirect_uri":  {validRedirectURI},
		"scope":         {validScope},
		"state":         {validState},
	}

	// Use a client that stops at the first redirect so we can inspect the 302.
	noRedirectClient := &http.Client{
		Jar: client.Jar, // share the same cookie jar (authenticated session)
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth?"+url.Values{
			"response_type": {"code"},
			"client_id":     {validClientID},
			"redirect_uri":  {validRedirectURI},
			"scope":         {validScope},
			"state":         {validState},
		}.Encode(),
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest POST /oauth2/auth: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Act
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	// Assert — must redirect (302 or 303).
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /oauth2/auth approve: status = %d, want 302 or 303; body = %q",
			resp.StatusCode, string(body))
	}

	location := resp.Header.Get("Location")

	// Assert — Location must start with the registered redirect_uri.
	if !strings.HasPrefix(location, validRedirectURI) {
		t.Errorf("Location = %q, want it to start with %q", location, validRedirectURI)
	}

	// Assert — Location must contain a non-empty code parameter.
	locationURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("url.Parse(Location=%q): %v", location, err)
	}

	code := locationURL.Query().Get("code")
	if code == "" {
		t.Errorf("Location = %q, want a non-empty \"code\" query parameter", location)
	}

	// Assert — Location must carry the original state value.
	state := locationURL.Query().Get("state")
	if state != validState {
		t.Errorf("state = %q, want %q", state, validState)
	}
}

// ---------------------------------------------------------------------------
// 7. TestAuthorizeHandler_Post_Deny_RedirectsWithAccessDenied
//    POST /oauth2/auth (deny) → 302 callback?error=access_denied&state=...
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_Post_Deny_RedirectsWithAccessDenied(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetClient(t, srv.URL)

	// Perform a GET first to initialise the fosite session.
	getResp, err := client.Get(authQuery(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	_, _ = io.Copy(io.Discard, getResp.Body)
	getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /oauth2/auth status = %d, want 200 (prerequisite for POST)", getResp.StatusCode)
	}

	formData := url.Values{
		"action":        {"deny"},
		"response_type": {"code"},
		"client_id":     {validClientID},
		"redirect_uri":  {validRedirectURI},
		"scope":         {validScope},
		"state":         {validState},
	}

	noRedirectClient := &http.Client{
		Jar: client.Jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/oauth2/auth?"+url.Values{
			"response_type": {"code"},
			"client_id":     {validClientID},
			"redirect_uri":  {validRedirectURI},
			"scope":         {validScope},
			"state":         {validState},
		}.Encode(),
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest POST /oauth2/auth: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Act
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oauth2/auth deny: %v", err)
	}
	defer resp.Body.Close()

	// Assert — must redirect (302 or 303).
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /oauth2/auth deny: status = %d, want 302 or 303; body = %q",
			resp.StatusCode, string(body))
	}

	location := resp.Header.Get("Location")

	// Assert — Location must start with the registered redirect_uri.
	if !strings.HasPrefix(location, validRedirectURI) {
		t.Errorf("Location = %q, want it to start with %q", location, validRedirectURI)
	}

	locationURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("url.Parse(Location=%q): %v", location, err)
	}

	// Assert — error=access_denied per RFC 6749 §4.1.2.1.
	errParam := locationURL.Query().Get("error")
	if errParam != "access_denied" {
		t.Errorf("error = %q, want \"access_denied\"", errParam)
	}

	// Assert — original state is preserved.
	state := locationURL.Query().Get("state")
	if state != validState {
		t.Errorf("state = %q, want %q", state, validState)
	}
}

// ---------------------------------------------------------------------------
// 8. TestAuthorizeHandler_Get_InvalidClientID_ReturnsError
//    잘못된 client_id → non-200 에러 응답
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_Get_InvalidClientID_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetClient(t, srv.URL)

	// Use a client that stops at the first redirect so we see the raw response.
	noRedirectClient := &http.Client{
		Jar: client.Jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Act — request with a client_id that was never registered.
	resp, err := noRedirectClient.Get(authQuery(srv.URL, map[string]string{
		"client_id": "nonexistent-client-id",
	}))
	if err != nil {
		t.Fatalf("GET /oauth2/auth (invalid client_id): %v", err)
	}
	defer resp.Body.Close()

	// Assert — fosite must not return 200 for an unknown client.
	// RFC 6749 §4.1.2.1: if client_id is invalid the AS returns the error
	// directly (not via redirect) with a non-200 status.
	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = 200, want non-200 for unknown client_id; body = %q", string(body))
	}
}

// ---------------------------------------------------------------------------
// 9. TestAuthorizeHandler_Get_InvalidRedirectURI_ReturnsError
//    잘못된 redirect_uri → non-200 에러, evil.example.com 으로 리다이렉트 불가
// ---------------------------------------------------------------------------

func TestAuthorizeHandler_Get_InvalidRedirectURI_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetClient(t, srv.URL)

	noRedirectClient := &http.Client{
		Jar: client.Jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Act — request with a redirect_uri that is not registered for the client.
	resp, err := noRedirectClient.Get(authQuery(srv.URL, map[string]string{
		"redirect_uri": "http://evil.example.com/callback",
	}))
	if err != nil {
		t.Fatalf("GET /oauth2/auth (invalid redirect_uri): %v", err)
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")

	// Assert — the server must NEVER redirect to the attacker-controlled URI.
	// RFC 6749 §4.1.2.1 security note: redirect_uri mismatch must not result
	// in a redirect to the supplied URI.
	if strings.Contains(location, "evil.example.com") {
		t.Errorf("Location = %q, must not redirect to evil.example.com", location)
	}

	// Assert — response must not be 200 OK; an error page or 4xx is expected.
	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = 200, want non-200 for mismatched redirect_uri; body = %q", string(body))
	}
}
