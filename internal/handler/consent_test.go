// Package handler_test — Consent page rendering tests.
//
// These tests verify that the consent page template is rendered correctly with
// the expected client information and scope list.
//
// TDD Red Phase: tests will fail until the consent handler and template are
// implemented.
package handler_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Consent page — template rendering
// ---------------------------------------------------------------------------

// TestConsentPage_RendersClientID verifies that the consent page HTML includes
// the client_id (or client name derived from it) so the user knows which
// application is requesting access.
func TestConsentPage_RendersClientID(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	authURL := srv.URL + "/oauth2/auth?client_id=test-client&response_type=code" +
		"&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&scope=openid+profile+email&state=state-consent-client"

	// Act
	resp, err := authenticatedClient.Get(authURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 OK", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	bodyStr := string(body)

	// Assert — the client ID or a human-readable name derived from it must
	// appear in the rendered HTML.
	if !strings.Contains(bodyStr, "test-client") {
		t.Errorf("consent page does not render the client_id %q; body = %q", "test-client", bodyStr)
	}
}

// TestConsentPage_RendersRequestedScopes verifies that the consent page lists
// all requested OAuth2 scopes so the user can see what access is being granted.
func TestConsentPage_RendersRequestedScopes(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	authURL := srv.URL + "/oauth2/auth?client_id=test-client&response_type=code" +
		"&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&scope=openid+profile+email&state=state-scopes"

	// Act
	resp, err := authenticatedClient.Get(authURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 OK", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	bodyStr := string(body)

	// Assert — each requested scope must appear on the consent page.
	requiredScopes := []string{"openid", "profile", "email"}
	for _, scope := range requiredScopes {
		if !strings.Contains(bodyStr, scope) {
			t.Errorf("consent page does not render scope %q; body = %q", scope, bodyStr)
		}
	}
}

// TestConsentPage_RendersRedirectDomain verifies that the consent page shows
// the domain of the redirect_uri so the user knows where they will be sent.
func TestConsentPage_RendersRedirectDomain(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	authURL := srv.URL + "/oauth2/auth?client_id=test-client&response_type=code" +
		"&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&scope=openid+profile+email&state=state-domain"

	// Act
	resp, err := authenticatedClient.Get(authURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 OK", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	bodyStr := string(body)

	// Assert — the redirect domain (localhost:9999) must appear on the page.
	if !strings.Contains(bodyStr, "localhost") {
		t.Errorf("consent page does not render redirect domain %q; body = %q", "localhost", bodyStr)
	}
}

// TestConsentPage_UsesBaseTemplate verifies that the consent page is rendered
// using the shared base.html template (i.e. it is a complete HTML page).
func TestConsentPage_UsesBaseTemplate(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	authURL := srv.URL + "/oauth2/auth?client_id=test-client&response_type=code" +
		"&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&scope=openid+profile+email&state=state-basetemplate"

	// Act
	resp, err := authenticatedClient.Get(authURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 OK", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	bodyStr := string(body)

	// Assert — the response must be a complete HTML document (from base.html).
	if !strings.Contains(bodyStr, "<!DOCTYPE html>") && !strings.Contains(bodyStr, "<!doctype html>") {
		t.Errorf("consent page does not appear to use base.html (no DOCTYPE); body = %q", bodyStr)
	}

	if !strings.Contains(bodyStr, "</html>") {
		t.Errorf("consent page HTML is incomplete (no </html>); body = %q", bodyStr)
	}
}

// TestConsentPage_ContentType_IsHTML verifies that the consent page response
// has the correct Content-Type header.
func TestConsentPage_ContentType_IsHTML(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	authURL := srv.URL + "/oauth2/auth?client_id=test-client&response_type=code" +
		"&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&scope=openid+profile+email&state=state-ct"

	// Act
	resp, err := authenticatedClient.Get(authURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	// Assert
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want it to contain text/html", ct)
	}
}

// TestConsentPage_PostApproveForm_HasHiddenFields verifies that the consent
// form includes hidden fields necessary for the POST /oauth2/auth handler to
// reconstruct the original authorization request (client_id, redirect_uri,
// scope, state, nonce, response_type).
func TestConsentPage_PostApproveForm_HasHiddenFields(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	authURL := srv.URL + "/oauth2/auth?client_id=test-client&response_type=code" +
		"&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&scope=openid+profile+email" +
		"&state=state-hidden&nonce=nonce-hidden"

	// Act
	resp, err := authenticatedClient.Get(authURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 OK", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	bodyStr := string(body)

	// Assert — key request parameters must be present in the form (as hidden
	// input fields or embedded in the form action URL) so POST /oauth2/auth
	// can reconstruct the authorization request.
	requiredFields := []string{
		"client_id",
		"redirect_uri",
		"scope",
		"state",
		"response_type",
	}
	for _, field := range requiredFields {
		if !strings.Contains(bodyStr, field) {
			t.Errorf("consent page form does not contain field %q; body = %q", field, bodyStr)
		}
	}
}

// TestConsentPage_MissingClientID_ReturnsBadRequest verifies that the
// authorization endpoint returns a 400 Bad Request (or an error redirect) when
// the required client_id parameter is absent.
func TestConsentPage_MissingClientID_ReturnsBadRequest(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	// Stop redirects so we can inspect the response directly.
	authenticatedClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// auth URL is intentionally missing client_id
	authURL := srv.URL + "/oauth2/auth?response_type=code" +
		"&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&scope=openid"

	// Act
	resp, err := authenticatedClient.Get(authURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth (no client_id): %v", err)
	}
	defer resp.Body.Close()

	// Assert — the server must not return 200 OK for a malformed request.
	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = 200 OK for missing client_id, want a non-200 response; body = %q", body)
	}
}

// TestConsentPage_InvalidClientID_ReturnsBadRequest verifies that the
// authorization endpoint returns an appropriate error when the client_id does
// not correspond to any registered client.
func TestConsentPage_InvalidClientID_ReturnsBadRequest(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	authenticatedClient := loginAndGetSession(t, srv.URL)

	authenticatedClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	authURL := srv.URL + "/oauth2/auth?client_id=nonexistent-client&response_type=code" +
		"&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&scope=openid"

	// Act
	resp, err := authenticatedClient.Get(authURL)
	if err != nil {
		t.Fatalf("GET /oauth2/auth (invalid client): %v", err)
	}
	defer resp.Body.Close()

	// Assert — must be an error response (400 or similar) since the client is unknown.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d for unknown client_id, want a non-2xx error; body = %q", resp.StatusCode, body)
	}
}
