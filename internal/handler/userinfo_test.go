// Package handler_test contains integration tests for the OIDC UserInfo
// endpoint (GET /oauth2/userinfo, OIDC Core 1.0 §5.3).
//
// These tests are written in the TDD Red Phase: the handler under test
// (handler.NewUserInfoHandler) does not yet exist, so the package will not
// compile until the implementation is provided.
//
// Implementation checklist (all items must be done before tests pass):
//
//  1. Create internal/handler/userinfo.go with:
//     func NewUserInfoHandler(provider fosite.OAuth2Provider, cfg *config.Config) http.HandlerFunc
//
//  2. Register the route in internal/testhelper/server.go buildRouter():
//     r.Get("/oauth2/userinfo", handler.NewUserInfoHandler(oauth2Provider, cfg))
//
//  3. The handler must:
//     a. Extract the Bearer token from the Authorization header (RFC 6750 §2.1).
//     b. Validate the token via fosite's NewIntrospectionRequest.
//     c. Return HTTP 401 with WWW-Authenticate: Bearer for invalid/absent tokens.
//     d. Inspect the granted scopes on the validated token and return only the
//        claims that correspond to those scopes:
//          - openid  → sub (always required)
//          - profile → name, given_name, family_name (populated from config.Owner)
//          - email   → email, email_verified (populated from config.Owner)
//     e. Respond with Content-Type: application/json.
//
//  4. Owner claims source: the server-side Config.Owner field holds the
//     single resource owner's username (used as sub and email) and a display
//     name can be derived from it. Tests assume username="admin@test.local".
//
// Test coverage:
//   - Valid Bearer token + openid scope only → 200, sub claim only
//   - Valid Bearer token + openid+profile → 200, sub + profile claims
//   - Valid Bearer token + openid+email → 200, sub + email claims
//   - Valid Bearer token + openid+profile+email → 200, all claims
//   - Invalid Bearer token → 401 Unauthorized
//   - No Authorization header → 401 Unauthorized
//   - Content-Type: application/json confirmed on all 200 responses
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
// Shared helpers for UserInfo tests
// ---------------------------------------------------------------------------

// userinfoResponse represents the JSON body returned by GET /oauth2/userinfo.
// All fields are pointers so that absent claims can be distinguished from
// zero-value strings (nil means the field was not present in the response).
type userinfoResponse struct {
	Sub           *string `json:"sub"`
	Name          *string `json:"name"`
	GivenName     *string `json:"given_name"`
	FamilyName    *string `json:"family_name"`
	Email         *string `json:"email"`
	EmailVerified *bool   `json:"email_verified"`
}

// callUserInfo sends GET /oauth2/userinfo with the given Bearer token.
// It returns the raw *http.Response; the caller is responsible for closing
// resp.Body.
func callUserInfo(t *testing.T, srvURL string, bearerToken string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, srvURL+"/oauth2/userinfo", nil)
	if err != nil {
		t.Fatalf("callUserInfo: http.NewRequest: %v", err)
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("callUserInfo: GET /oauth2/userinfo: %v", err)
	}
	return resp
}

// parseUserInfoResponse reads and JSON-decodes the body of a userinfo response.
// It returns the decoded struct and raw body bytes for diagnostic messages.
// The caller must have already verified that the status is 200.
func parseUserInfoResponse(t *testing.T, resp *http.Response) (*userinfoResponse, []byte) {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("parseUserInfoResponse: io.ReadAll: %v", err)
	}

	var ur userinfoResponse
	if err := json.Unmarshal(body, &ur); err != nil {
		t.Fatalf("parseUserInfoResponse: json.Unmarshal: %v — body: %s", err, body)
	}
	return &ur, body
}

// obtainAccessTokenWithScope runs the full login → authorize → token-exchange
// flow requesting the specified scope and returns a valid access_token.
//
// This helper is needed because the default obtainAccessToken (defined in
// revoke_introspect_test.go) always uses validScope="openid profile email".
// UserInfo scope tests require controlling which scopes are granted.
func obtainAccessTokenWithScope(t *testing.T, srvURL string, nonce string, scope string) string {
	t.Helper()

	// Step 1: log in.
	client := loginAndGetClient(t, srvURL)

	// Step 2: GET /oauth2/auth to load the consent page with the requested scope.
	authParams := url.Values{
		"response_type": {"code"},
		"client_id":     {validClientID},
		"redirect_uri":  {validRedirectURI},
		"scope":         {scope},
		"state":         {validState},
		"nonce":         {nonce},
	}
	getResp, err := client.Get(srvURL + "/oauth2/auth?" + authParams.Encode())
	if err != nil {
		t.Fatalf("obtainAccessTokenWithScope: GET /oauth2/auth: %v", err)
	}
	_, _ = io.Copy(io.Discard, getResp.Body)
	getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("obtainAccessTokenWithScope: GET /oauth2/auth status = %d, want 200", getResp.StatusCode)
	}

	// Step 3: POST /oauth2/auth with action=approve and the specific scope.
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
		"scope":         {scope},
		"state":         {validState},
		"nonce":         {nonce},
	}

	postReq, err := http.NewRequest(
		http.MethodPost,
		srvURL+"/oauth2/auth?"+authParams.Encode(),
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("obtainAccessTokenWithScope: http.NewRequest POST /oauth2/auth: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	postResp, err := noRedirectClient.Do(postReq)
	if err != nil {
		t.Fatalf("obtainAccessTokenWithScope: POST /oauth2/auth: %v", err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusFound && postResp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(postResp.Body)
		t.Fatalf("obtainAccessTokenWithScope: POST /oauth2/auth status = %d, want 302/303; body = %q",
			postResp.StatusCode, string(body))
	}

	location := postResp.Header.Get("Location")
	locationURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("obtainAccessTokenWithScope: url.Parse(Location=%q): %v", location, err)
	}

	code := locationURL.Query().Get("code")
	if code == "" {
		t.Fatalf("obtainAccessTokenWithScope: no code in Location header: %q", location)
	}

	// Step 4: exchange the code for tokens.
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {validRedirectURI},
		"client_id":    {validClientID},
	}

	tokenReq, err := http.NewRequest(
		http.MethodPost,
		srvURL+"/oauth2/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatalf("obtainAccessTokenWithScope: token http.NewRequest: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(validClientID, "test-client-secret")

	plainClient := &http.Client{}
	tokenResp, err := plainClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("obtainAccessTokenWithScope: POST /oauth2/token: %v", err)
	}
	defer tokenResp.Body.Close()

	tokenBody, err := io.ReadAll(tokenResp.Body)
	if err != nil {
		t.Fatalf("obtainAccessTokenWithScope: io.ReadAll token: %v", err)
	}

	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("obtainAccessTokenWithScope: POST /oauth2/token status = %d, want 200; body = %s",
			tokenResp.StatusCode, tokenBody)
	}

	var tr tokenResponse
	if err := json.Unmarshal(tokenBody, &tr); err != nil {
		t.Fatalf("obtainAccessTokenWithScope: json.Unmarshal token: %v — body: %s", err, tokenBody)
	}
	if tr.AccessToken == "" {
		t.Fatal("obtainAccessTokenWithScope: access_token is empty")
	}
	return tr.AccessToken
}

// ---------------------------------------------------------------------------
// GET /oauth2/userinfo — OIDC Core 1.0 §5.3
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 1. TestUserInfoHandler_OpenIDScopeOnly_ReturnsSub
//    OIDC Core §5.4: when only the "openid" scope is granted, the UserInfo
//    response MUST contain the "sub" claim and MUST NOT include profile or
//    email claims (name, given_name, family_name, email, email_verified).
// ---------------------------------------------------------------------------

func TestUserInfoHandler_OpenIDScopeOnly_ReturnsSub(t *testing.T) {
	// Arrange — obtain an access_token with only the "openid" scope.
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessTokenWithScope(t, srv.URL, "ui-nonce-1", "openid")

	// Act
	resp := callUserInfo(t, srv.URL, accessToken)
	defer resp.Body.Close()

	// Assert — HTTP 200 OK.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /oauth2/userinfo with openid scope: status = %d, want 200; body = %s",
			resp.StatusCode, body)
	}

	ur, body := parseUserInfoResponse(t, resp)

	// Assert — sub must be present and non-empty.
	if ur.Sub == nil || *ur.Sub == "" {
		t.Errorf("userinfo response missing \"sub\" claim; body = %s", body)
	}
	// The test owner username is "admin@test.local" (testhelper/config.go).
	if ur.Sub != nil && *ur.Sub != "admin@test.local" {
		t.Errorf("userinfo sub = %q, want \"admin@test.local\"", *ur.Sub)
	}

	// Assert — profile claims must NOT be present (scope was not granted).
	if ur.Name != nil {
		t.Errorf("userinfo response contains \"name\" = %q, but profile scope was not granted; body = %s",
			*ur.Name, body)
	}
	if ur.GivenName != nil {
		t.Errorf("userinfo response contains \"given_name\" = %q, but profile scope was not granted; body = %s",
			*ur.GivenName, body)
	}
	if ur.FamilyName != nil {
		t.Errorf("userinfo response contains \"family_name\" = %q, but profile scope was not granted; body = %s",
			*ur.FamilyName, body)
	}

	// Assert — email claims must NOT be present (scope was not granted).
	if ur.Email != nil {
		t.Errorf("userinfo response contains \"email\" = %q, but email scope was not granted; body = %s",
			*ur.Email, body)
	}
	if ur.EmailVerified != nil {
		t.Errorf("userinfo response contains \"email_verified\" but email scope was not granted; body = %s", body)
	}
}

// ---------------------------------------------------------------------------
// 2. TestUserInfoHandler_OpenIDAndProfileScope_ReturnsSubAndProfileClaims
//    When "openid" and "profile" scopes are granted, the UserInfo response
//    must include "sub" and at least one of the OIDC profile claims:
//    name, given_name, or family_name (OIDC Core §5.1).
// ---------------------------------------------------------------------------

func TestUserInfoHandler_OpenIDAndProfileScope_ReturnsSubAndProfileClaims(t *testing.T) {
	// Arrange — obtain an access_token with "openid profile" scope.
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessTokenWithScope(t, srv.URL, "ui-nonce-2", "openid profile")

	// Act
	resp := callUserInfo(t, srv.URL, accessToken)
	defer resp.Body.Close()

	// Assert — HTTP 200 OK.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /oauth2/userinfo with openid+profile scope: status = %d, want 200; body = %s",
			resp.StatusCode, body)
	}

	ur, body := parseUserInfoResponse(t, resp)

	// Assert — sub must be present.
	if ur.Sub == nil || *ur.Sub == "" {
		t.Errorf("userinfo response missing \"sub\" claim; body = %s", body)
	}

	// Assert — at least one profile claim must be present.
	// OIDC Core §5.1: the "profile" scope requests name, given_name, family_name,
	// middle_name, nickname, preferred_username, profile, picture, website,
	// gender, birthdate, zoneinfo, locale, and updated_at.
	hasProfileClaim := ur.Name != nil || ur.GivenName != nil || ur.FamilyName != nil
	if !hasProfileClaim {
		t.Errorf("userinfo response with profile scope is missing profile claims (name/given_name/family_name); body = %s", body)
	}

	// Assert — email claims must NOT be present (email scope was not granted).
	if ur.Email != nil {
		t.Errorf("userinfo response contains \"email\" = %q, but email scope was not granted; body = %s",
			*ur.Email, body)
	}
	if ur.EmailVerified != nil {
		t.Errorf("userinfo response contains \"email_verified\" but email scope was not granted; body = %s", body)
	}
}

// ---------------------------------------------------------------------------
// 3. TestUserInfoHandler_OpenIDAndEmailScope_ReturnsSubAndEmailClaims
//    When "openid" and "email" scopes are granted, the UserInfo response
//    must include "sub" and the email claims: email, email_verified
//    (OIDC Core §5.1).
// ---------------------------------------------------------------------------

func TestUserInfoHandler_OpenIDAndEmailScope_ReturnsSubAndEmailClaims(t *testing.T) {
	// Arrange — obtain an access_token with "openid email" scope.
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessTokenWithScope(t, srv.URL, "ui-nonce-3", "openid email")

	// Act
	resp := callUserInfo(t, srv.URL, accessToken)
	defer resp.Body.Close()

	// Assert — HTTP 200 OK.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /oauth2/userinfo with openid+email scope: status = %d, want 200; body = %s",
			resp.StatusCode, body)
	}

	ur, body := parseUserInfoResponse(t, resp)

	// Assert — sub must be present.
	if ur.Sub == nil || *ur.Sub == "" {
		t.Errorf("userinfo response missing \"sub\" claim; body = %s", body)
	}

	// Assert — email must be present and non-empty.
	if ur.Email == nil || *ur.Email == "" {
		t.Errorf("userinfo response with email scope missing \"email\" claim; body = %s", body)
	}

	// Assert — profile claims must NOT be present (profile scope was not granted).
	if ur.Name != nil {
		t.Errorf("userinfo response contains \"name\" = %q, but profile scope was not granted; body = %s",
			*ur.Name, body)
	}
	if ur.GivenName != nil {
		t.Errorf("userinfo response contains \"given_name\" = %q, but profile scope was not granted; body = %s",
			*ur.GivenName, body)
	}
	if ur.FamilyName != nil {
		t.Errorf("userinfo response contains \"family_name\" = %q, but profile scope was not granted; body = %s",
			*ur.FamilyName, body)
	}
}

// ---------------------------------------------------------------------------
// 4. TestUserInfoHandler_AllScopes_ReturnsAllClaims
//    When "openid", "profile", and "email" scopes are all granted, the
//    UserInfo response must include sub, at least one profile claim, and
//    the email claim (OIDC Core §5.3 "UserInfo Endpoint").
// ---------------------------------------------------------------------------

func TestUserInfoHandler_AllScopes_ReturnsAllClaims(t *testing.T) {
	// Arrange — obtain an access_token with all three OIDC scopes.
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessTokenWithScope(t, srv.URL, "ui-nonce-4", "openid profile email")

	// Act
	resp := callUserInfo(t, srv.URL, accessToken)
	defer resp.Body.Close()

	// Assert — HTTP 200 OK.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /oauth2/userinfo with openid+profile+email scope: status = %d, want 200; body = %s",
			resp.StatusCode, body)
	}

	ur, body := parseUserInfoResponse(t, resp)

	// Assert — sub must be present.
	if ur.Sub == nil || *ur.Sub == "" {
		t.Errorf("userinfo response missing \"sub\" claim; body = %s", body)
	}

	// Assert — at least one profile claim must be present.
	hasProfileClaim := ur.Name != nil || ur.GivenName != nil || ur.FamilyName != nil
	if !hasProfileClaim {
		t.Errorf("userinfo response with profile scope missing profile claims; body = %s", body)
	}

	// Assert — email claim must be present.
	if ur.Email == nil || *ur.Email == "" {
		t.Errorf("userinfo response with email scope missing \"email\" claim; body = %s", body)
	}
}

// ---------------------------------------------------------------------------
// 5. TestUserInfoHandler_InvalidToken_Returns401
//    RFC 6750 §3.1: the server must respond with HTTP 401 Unauthorized when
//    the Bearer token is invalid, expired, or was never issued.
//    The WWW-Authenticate response header must be present and indicate the
//    Bearer scheme (RFC 6750 §3 "The WWW-Authenticate Response Header Field").
// ---------------------------------------------------------------------------

func TestUserInfoHandler_InvalidToken_Returns401(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Use a completely fabricated token that was never issued by this server.
	forgedToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlIn0.invalidsignature"

	// Act
	resp := callUserInfo(t, srv.URL, forgedToken)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — RFC 6750 §3.1 requires HTTP 401.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /oauth2/userinfo with forged token: status = %d, want 401", resp.StatusCode)
	}

	// Assert — WWW-Authenticate header must be present and start with "Bearer".
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(strings.ToLower(wwwAuth), "bearer") {
		t.Errorf("WWW-Authenticate = %q, want it to start with \"Bearer\" (RFC 6750 §3)", wwwAuth)
	}
}

// ---------------------------------------------------------------------------
// 6. TestUserInfoHandler_NoBearerToken_Returns401
//    RFC 6750 §3.1: a request without an Authorization header must also be
//    rejected with HTTP 401. Omitting the token entirely is treated the same
//    as presenting an invalid token.
// ---------------------------------------------------------------------------

func TestUserInfoHandler_NoBearerToken_Returns401(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act — send GET /oauth2/userinfo with no Authorization header.
	resp := callUserInfo(t, srv.URL, "") // empty token → no header set
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — RFC 6750 §3.1: 401 for missing credentials.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /oauth2/userinfo with no token: status = %d, want 401", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// 7. TestUserInfoHandler_ValidToken_ReturnsJSON
//    The Content-Type of a successful UserInfo response must be
//    "application/json" and the body must be valid JSON per OIDC Core §5.3.
// ---------------------------------------------------------------------------

func TestUserInfoHandler_ValidToken_ReturnsJSON(t *testing.T) {
	// Arrange — obtain a valid access_token using the standard full scope.
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessToken(t, srv.URL, "ui-nonce-7")

	// Act
	resp := callUserInfo(t, srv.URL, accessToken)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — HTTP 200 OK.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /oauth2/userinfo status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	// Assert — Content-Type must contain "application/json".
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want it to contain \"application/json\"", ct)
	}

	// Assert — body is valid JSON with a "sub" field.
	var raw map[string]interface{}
	if jsonErr := json.Unmarshal(body, &raw); jsonErr != nil {
		t.Fatalf("response body is not valid JSON: %v — body: %s", jsonErr, body)
	}
	if _, hasSub := raw["sub"]; !hasSub {
		t.Errorf("userinfo response JSON missing \"sub\" field; body = %s", body)
	}
}

// ---------------------------------------------------------------------------
// 8. TestUserInfoHandler_Sub_MatchesTokenSubject
//    The "sub" claim in the UserInfo response must be identical to the "sub"
//    claim embedded in the access_token JWT (OIDC Core §5.3.2: "The sub
//    Claim in the UserInfo Response is REQUIRED ... and MUST be identical to
//    the sub Claim in the ID Token").
// ---------------------------------------------------------------------------

func TestUserInfoHandler_Sub_MatchesTokenSubject(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	accessToken := obtainAccessToken(t, srv.URL, "ui-nonce-8")

	// Extract the sub claim directly from the JWT access_token payload.
	// (No signature verification — this is covered by TestTokenHandler tests.)
	claims := decodeJWTClaims(t, accessToken)
	tokenSub, ok := claims["sub"].(string)
	if !ok || tokenSub == "" {
		t.Fatal("access_token JWT missing \"sub\" claim — prerequisite for this test")
	}

	// Act
	resp := callUserInfo(t, srv.URL, accessToken)
	defer resp.Body.Close()

	// Assert — HTTP 200 OK.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /oauth2/userinfo status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	ur, body := parseUserInfoResponse(t, resp)

	// Assert — UserInfo sub must match access_token sub (OIDC Core §5.3.2).
	if ur.Sub == nil {
		t.Fatalf("userinfo response missing \"sub\" claim; body = %s", body)
	}
	if *ur.Sub != tokenSub {
		t.Errorf("userinfo sub = %q, access_token sub = %q; they must be identical (OIDC Core §5.3.2)",
			*ur.Sub, tokenSub)
	}
}
