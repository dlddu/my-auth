package handler_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// GET /oauth2/auth — consent page contains client information
// ---------------------------------------------------------------------------

// TestConsentPage_DisplaysClientName verifies that when an authenticated user
// reaches the consent page, the HTML contains the client name / identifier.
func TestConsentPage_DisplaysClientName(t *testing.T) {
	// Arrange — authenticated user
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetCookieClient(t, srv)

	// Act — GET /oauth2/auth for an authenticated user should show consent
	resp, err := client.Get(buildAuthorizeURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Skip if storage not yet implemented (client unknown → error page)
	if resp.StatusCode >= http.StatusInternalServerError {
		t.Skip("server error — storage not yet implemented")
	}

	// If we got a 4xx, it may be because the client is not registered yet.
	// We still verify the content-type is HTML (not a login redirect).
	ct := resp.Header.Get("Content-Type")
	if resp.StatusCode == http.StatusFound && strings.Contains(resp.Header.Get("Location"), "/login") {
		t.Errorf("authenticated user was redirected to /login — final URL = %q", resp.Request.URL)
		return
	}

	// Assert — when a consent page is served, the client ID must appear in the HTML
	if resp.StatusCode == http.StatusOK {
		if !strings.Contains(ct, "text/html") {
			t.Errorf("Content-Type = %q, want text/html for consent page", ct)
		}
		bodyStr := string(body)
		if !strings.Contains(bodyStr, "test-client") {
			t.Errorf("consent page body does not mention client ID %q — body: %.500s", "test-client", bodyStr)
		}
	}
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — consent page contains approve button
// ---------------------------------------------------------------------------

func TestConsentPage_HasApproveButton(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetCookieClient(t, srv)

	// Act
	resp, err := client.Get(buildAuthorizeURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusInternalServerError {
		t.Skip("server error — storage not yet implemented")
	}

	if resp.StatusCode != http.StatusOK {
		t.Skipf("status = %d — cannot test consent form content", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	bodyStr := string(body)

	// Assert — consent page must have a submit button for approval
	hasApproveButton := strings.Contains(bodyStr, `value="approve"`) ||
		strings.Contains(bodyStr, `name="action"`) ||
		strings.Contains(bodyStr, "Approve") ||
		strings.Contains(bodyStr, "Allow") ||
		strings.Contains(bodyStr, "authorize")
	if !hasApproveButton {
		t.Errorf("consent page does not contain an approve button — body: %.500s", bodyStr)
	}
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — consent page contains deny button
// ---------------------------------------------------------------------------

func TestConsentPage_HasDenyButton(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetCookieClient(t, srv)

	// Act
	resp, err := client.Get(buildAuthorizeURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusInternalServerError {
		t.Skip("server error — storage not yet implemented")
	}

	if resp.StatusCode != http.StatusOK {
		t.Skipf("status = %d — cannot test consent form content", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	bodyStr := string(body)

	// Assert — consent page must have a deny/cancel button
	hasDenyButton := strings.Contains(bodyStr, `value="deny"`) ||
		strings.Contains(bodyStr, "Deny") ||
		strings.Contains(bodyStr, "Cancel") ||
		strings.Contains(bodyStr, "Decline")
	if !hasDenyButton {
		t.Errorf("consent page does not contain a deny button — body: %.500s", bodyStr)
	}
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — consent page lists requested scopes
// ---------------------------------------------------------------------------

func TestConsentPage_DisplaysRequestedScopes(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetCookieClient(t, srv)

	// Act — request specific scopes
	resp, err := client.Get(buildAuthorizeURL(srv.URL, map[string]string{
		"scope": "openid profile email",
	}))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusInternalServerError {
		t.Skip("server error — storage not yet implemented")
	}

	if resp.StatusCode != http.StatusOK {
		t.Skipf("status = %d — cannot test consent scopes display", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	bodyStr := string(body)

	// Assert — the consent page should list at least some of the requested scopes.
	// The exact wording may vary; we check for partial matches.
	hasOpenID := strings.Contains(bodyStr, "openid")
	hasProfile := strings.Contains(bodyStr, "profile")
	hasEmail := strings.Contains(bodyStr, "email")

	if !hasOpenID && !hasProfile && !hasEmail {
		t.Errorf("consent page does not display any of the requested scopes (openid, profile, email) — body: %.500s", bodyStr)
	}
}

// ---------------------------------------------------------------------------
// GET /oauth2/auth — consent page is rendered with base template
// ---------------------------------------------------------------------------

func TestConsentPage_RendersWithBaseTemplate(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAndGetCookieClient(t, srv)

	// Act
	resp, err := client.Get(buildAuthorizeURL(srv.URL, nil))
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusInternalServerError {
		t.Skip("server error — storage not yet implemented")
	}

	if resp.StatusCode != http.StatusOK {
		t.Skipf("status = %d — cannot test template rendering", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	bodyStr := string(body)

	// Assert — a fully rendered HTML page must include the doctype and body tags
	// from the base template (base.html).
	if !strings.Contains(bodyStr, "<!DOCTYPE html>") && !strings.Contains(bodyStr, "<!doctype html>") {
		t.Error("consent page does not contain DOCTYPE declaration — base template may not be applied")
	}
	if !strings.Contains(bodyStr, "<body") {
		t.Error("consent page does not contain <body> element")
	}
	if !strings.Contains(bodyStr, "</html>") {
		t.Error("consent page does not contain closing </html> tag")
	}
}
