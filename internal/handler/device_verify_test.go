// Package handler_test — Device Authorization Grant (RFC 8628) handler
// integration tests for the device verification endpoints:
//   - GET  /device/verify  — user_code entry form
//   - POST /device/verify  — code validation & approval
//
// These tests are written in the TDD Red Phase. They exercise the
// /device/verify endpoints and will fail until the following are implemented:
//
//  1. GET /device/verify handler (handler.NewDeviceVerifyHandler):
//     - Renders an HTML form for the user to enter their user_code.
//     - Unauthenticated users are redirected to /login.
//
//  2. POST /device/verify handler:
//     - Validates the submitted user_code against the device_codes table.
//     - On invalid code: re-renders the form with an error message.
//     - On valid code + authenticated user: updates device_codes.status → "approved"
//       and device_codes.subject → authenticated username.
//     - On valid code + unauthenticated user: redirects to /login.
//
//  3. Routes registered in testhelper/server.go buildRouter():
//     r.Get("/device/verify", handler.NewDeviceVerifyHandler(...))
//     r.Post("/device/verify", handler.NewDeviceVerifyHandler(...))
//
// Test coverage:
//   - GET /device/verify unauthenticated → 302 redirect to /login
//   - GET /device/verify authenticated → 200 HTML form with user_code input
//   - GET /device/verify authenticated → Content-Type text/html
//   - POST /device/verify unauthenticated → 302 redirect to /login
//   - POST /device/verify authenticated + valid user_code → 200 success page
//   - POST /device/verify authenticated + invalid user_code → 200 with error message
//   - POST /device/verify authenticated + invalid user_code → form is re-rendered
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
// Shared helpers for device verify tests
// ---------------------------------------------------------------------------

// getDeviceUserCode performs the full POST /oauth2/device/code flow and
// returns both the device_code and user_code strings.
// It uses the device-client credentials seeded by testhelper.NewTestServer.
func getDeviceUserCode(t *testing.T, srvURL string) (deviceCode, userCode string) {
	t.Helper()

	resp := requestDeviceCode(t, srvURL, deviceClientID, deviceClientSecret, deviceScope)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("getDeviceUserCode: io.ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("getDeviceUserCode: POST /oauth2/device/code status = %d, want 200; body = %s",
			resp.StatusCode, body)
	}

	var dcr deviceCodeResponse
	if parseErr := json.Unmarshal(body, &dcr); parseErr != nil {
		t.Fatalf("getDeviceUserCode: json.Unmarshal: %v — body: %s", parseErr, body)
	}

	if dcr.UserCode == "" {
		t.Fatal("getDeviceUserCode: user_code is empty")
	}
	if dcr.DeviceCode == "" {
		t.Fatal("getDeviceUserCode: device_code is empty")
	}

	return dcr.DeviceCode, dcr.UserCode
}

// ---------------------------------------------------------------------------
// 1. TestDeviceVerifyHandler_Get_Unauthenticated_RedirectToLogin
//    An unauthenticated GET /device/verify must result in a 302 redirect to
//    /login, consistent with the authorize endpoint behaviour.
// ---------------------------------------------------------------------------

func TestDeviceVerifyHandler_Get_Unauthenticated_RedirectToLogin(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Act
	resp, err := noRedirectClient.Get(srv.URL + "/device/verify")
	if err != nil {
		t.Fatalf("GET /device/verify: %v", err)
	}
	defer resp.Body.Close()

	// Assert — must be 302 Found.
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d (302 Found)", resp.StatusCode, http.StatusFound)
	}

	// Assert — Location must point to /login.
	location := resp.Header.Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("Location = %q, want it to contain \"/login\"", location)
	}
}

// ---------------------------------------------------------------------------
// 2. TestDeviceVerifyHandler_Get_Authenticated_RendersForm
//    An authenticated GET /device/verify must render an HTML form containing
//    an input for the user_code.
// ---------------------------------------------------------------------------

func TestDeviceVerifyHandler_Get_Authenticated_RendersForm(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetClient(t, srv.URL)

	// Act
	resp, err := client.Get(srv.URL + "/device/verify")
	if err != nil {
		t.Fatalf("GET /device/verify: %v", err)
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

	bodyStr := string(body)

	// Assert — Content-Type is HTML.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want it to contain \"text/html\"", ct)
	}

	// Assert — a <form element is present.
	if !strings.Contains(bodyStr, "<form") {
		t.Errorf("response body does not contain <form tag")
	}

	// Assert — there is an input for the user_code.
	// The field name may be "user_code" or "code" depending on implementation.
	hasUserCodeInput := strings.Contains(bodyStr, `name="user_code"`) ||
		strings.Contains(bodyStr, `name="code"`)
	if !hasUserCodeInput {
		t.Errorf("response body does not contain input for user_code (name=\"user_code\" or name=\"code\")")
	}
}

// ---------------------------------------------------------------------------
// 3. TestDeviceVerifyHandler_Get_Authenticated_ContentTypeIsHTML
//    Verify that Content-Type is text/html for authenticated GET requests
//    (separate assertion test for clarity).
// ---------------------------------------------------------------------------

func TestDeviceVerifyHandler_Get_Authenticated_ContentTypeIsHTML(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetClient(t, srv.URL)

	// Act
	resp, err := client.Get(srv.URL + "/device/verify")
	if err != nil {
		t.Fatalf("GET /device/verify: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — 200 OK.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d (200 OK)", resp.StatusCode, http.StatusOK)
	}

	// Assert — Content-Type includes text/html.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want it to contain \"text/html\"", ct)
	}
}

// ---------------------------------------------------------------------------
// 4. TestDeviceVerifyHandler_Post_Unauthenticated_RedirectToLogin
//    An unauthenticated POST /device/verify must redirect to /login.
//    The user_code validation must not proceed without an authenticated session.
// ---------------------------------------------------------------------------

func TestDeviceVerifyHandler_Post_Unauthenticated_RedirectToLogin(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	form := url.Values{
		"user_code": {"ABCD-EFGH"},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/device/verify",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Act
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatalf("POST /device/verify: %v", err)
	}
	defer resp.Body.Close()

	// Assert — must redirect to /login (302 or 303).
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want 302 or 303 redirect to /login", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("Location = %q, want it to contain \"/login\"", location)
	}
}

// ---------------------------------------------------------------------------
// 5. TestDeviceVerifyHandler_Post_Authenticated_ValidCode_ReturnsSuccess
//    POST /device/verify with a valid user_code from an authenticated user
//    must succeed (200 OK or redirect to a success page).
//
//    Full flow:
//    1. Issue device codes via POST /oauth2/device/code.
//    2. Log in as the test owner.
//    3. POST /device/verify with the obtained user_code.
//    4. Assert the response indicates success (no error content).
// ---------------------------------------------------------------------------

func TestDeviceVerifyHandler_Post_Authenticated_ValidCode_ReturnsSuccess(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Step 1: obtain a device user_code.
	_, userCode := getDeviceUserCode(t, srv.URL)

	// Step 2: log in so the session cookie is present.
	authClient := loginAndGetClient(t, srv.URL)

	// Step 3: POST /device/verify with the valid user_code.
	form := url.Values{
		"user_code": {userCode},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/device/verify",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Act
	resp, err := authClient.Do(req)
	if err != nil {
		t.Fatalf("POST /device/verify: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — the response must indicate success (not a 4xx/5xx error).
	// Acceptable outcomes: 200 OK with success page, or 302/303 redirect.
	isSuccess := resp.StatusCode == http.StatusOK ||
		resp.StatusCode == http.StatusFound ||
		resp.StatusCode == http.StatusSeeOther

	if !isSuccess {
		t.Errorf("POST /device/verify with valid code: status = %d, want 200 or redirect; body = %s",
			resp.StatusCode, body)
	}

	// Assert — if 200, the body must NOT contain an error message.
	if resp.StatusCode == http.StatusOK {
		bodyStr := string(body)
		hasErrorText := strings.Contains(bodyStr, "invalid code") ||
			strings.Contains(bodyStr, "Invalid code") ||
			strings.Contains(bodyStr, "code not found") ||
			strings.Contains(bodyStr, "Code not found") ||
			strings.Contains(bodyStr, "expired") ||
			strings.Contains(bodyStr, "Expired")
		if hasErrorText {
			t.Errorf("POST /device/verify with valid code returned 200 with error message; body = %s", body)
		}
	}
}

// ---------------------------------------------------------------------------
// 6. TestDeviceVerifyHandler_Post_Authenticated_InvalidCode_ReturnsError
//    POST /device/verify with a user_code that was never issued must result
//    in a response that communicates an error to the user (200 + error message
//    on the re-rendered form, or a 4xx response).
// ---------------------------------------------------------------------------

func TestDeviceVerifyHandler_Post_Authenticated_InvalidCode_ReturnsError(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetClient(t, srv.URL)

	form := url.Values{
		// Fabricate a code that was never issued.
		"user_code": {"FAKE-CODE"},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/device/verify",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Act
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /device/verify: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — must not be a successful 2xx with no error indication.
	// A 200 re-render with error text or a 4xx status are both acceptable.
	if resp.StatusCode == http.StatusOK {
		bodyStr := string(body)
		hasErrorText := strings.Contains(bodyStr, "invalid") ||
			strings.Contains(bodyStr, "Invalid") ||
			strings.Contains(bodyStr, "not found") ||
			strings.Contains(bodyStr, "error") ||
			strings.Contains(bodyStr, "Error") ||
			strings.Contains(bodyStr, "incorrect") ||
			strings.Contains(bodyStr, "Incorrect")
		if !hasErrorText {
			t.Errorf("POST /device/verify with invalid code returned 200 without error message; body = %s", body)
		}
	} else if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		// A redirect is not a valid response to an invalid user_code submission
		// (there is no success URI to redirect to).
		location := resp.Header.Get("Location")
		// Allow redirect to login or error pages, but not to an approval success page.
		if strings.Contains(location, "approved") || strings.Contains(location, "success") {
			t.Errorf("POST /device/verify with invalid code redirected to %q (looks like success), want error", location)
		}
	}
}

// ---------------------------------------------------------------------------
// 7. TestDeviceVerifyHandler_Post_Authenticated_InvalidCode_FormIsReRendered
//    After an invalid user_code submission the HTML form must still be present
//    so the user can enter a corrected code.
// ---------------------------------------------------------------------------

func TestDeviceVerifyHandler_Post_Authenticated_InvalidCode_FormIsReRendered(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetClient(t, srv.URL)

	form := url.Values{
		"user_code": {"ZZZZ-ZZZZ"},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/device/verify",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Act
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /device/verify: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Only assert form re-render for 200 responses.
	if resp.StatusCode != http.StatusOK {
		return
	}

	bodyStr := string(body)

	// Assert — a <form element must still be present (user can retry).
	if !strings.Contains(bodyStr, "<form") {
		t.Errorf("POST /device/verify with invalid code: response body does not contain <form tag; body = %s", body)
	}

	// Assert — user_code input must still be present.
	hasInput := strings.Contains(bodyStr, `name="user_code"`) ||
		strings.Contains(bodyStr, `name="code"`)
	if !hasInput {
		t.Errorf("POST /device/verify with invalid code: response body does not contain user_code input; body = %s", body)
	}
}
