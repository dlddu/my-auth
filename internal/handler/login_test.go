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
// TestLoginHandler_GetReturnsLoginForm — GET /login → 200 OK + HTML 로그인 폼
// ---------------------------------------------------------------------------

func TestLoginHandler_GetReturnsLoginForm(t *testing.T) {
	// TODO: Activate when DLD-582 is implemented
	t.Skip("not implemented yet")

	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp, err := client.Get(srv.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Assert — Content-Type에 text/html 포함
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want it to contain %q", ct, "text/html")
	}

	// Assert — HTML 바디에 <form 태그 포함
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "<form") {
		t.Errorf("response body does not contain <form tag")
	}

	// Assert — username 또는 email 인풋 포함
	hasUsername := strings.Contains(bodyStr, `name="username"`)
	hasEmail := strings.Contains(bodyStr, `name="email"`)
	if !hasUsername && !hasEmail {
		t.Errorf("response body does not contain input with name=\"username\" or name=\"email\"")
	}

	// Assert — password 인풋 포함
	if !strings.Contains(bodyStr, `name="password"`) {
		t.Errorf("response body does not contain input with name=\"password\"")
	}
}

// ---------------------------------------------------------------------------
// TestLoginHandler_PostValidCredentials — POST /login (올바른 자격증명) → 303 + 세션 쿠키
// ---------------------------------------------------------------------------

func TestLoginHandler_PostValidCredentials(t *testing.T) {
	// TODO: Activate when DLD-582 is implemented
	t.Skip("not implemented yet")

	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// 리다이렉트를 따르지 않는 클라이언트: 303 응답 자체를 검증해야 한다
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

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
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Act
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	// Assert — 303 See Other
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want %d (303 See Other)", resp.StatusCode, http.StatusSeeOther)
	}

	// Assert — Set-Cookie 헤더에 세션 쿠키 존재
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("no Set-Cookie header in response, want at least one session cookie")
	}

	// 세션 쿠키가 비어있지 않은 값을 가져야 한다
	hasSessionCookie := false
	for _, c := range cookies {
		if c.Value != "" {
			hasSessionCookie = true
			break
		}
	}
	if !hasSessionCookie {
		t.Errorf("all Set-Cookie values are empty, want a non-empty session cookie value")
	}
}

// ---------------------------------------------------------------------------
// TestLoginHandler_PostValidCredentials_RedirectTracked — 리다이렉트 추적 확인
// ---------------------------------------------------------------------------

func TestLoginHandler_PostValidCredentials_RedirectTracked(t *testing.T) {
	// TODO: Activate when DLD-582 is implemented
	t.Skip("not implemented yet")

	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client, transport := testhelper.NewTestClient(t)

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
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Act
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	// Assert — 리다이렉트가 최소 1회 발생해야 한다
	history := transport.RedirectHistory()
	if len(history) == 0 {
		t.Errorf("redirect history is empty, want at least one redirect after login")
	}
}

// ---------------------------------------------------------------------------
// TestLoginHandler_PostInvalidCredentials — POST /login (잘못된 자격증명) → 200 + 에러 메시지
// ---------------------------------------------------------------------------

func TestLoginHandler_PostInvalidCredentials(t *testing.T) {
	// TODO: Activate when DLD-582 is implemented
	t.Skip("not implemented yet")

	// Arrange
	srv, client := testhelper.NewTestServer(t)

	formData := url.Values{
		"username": {"wrong@test.local"},
		"password": {"wrong-password"},
	}

	req, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/login",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Act
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 리다이렉트 없이 200 OK 반환
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d (should not redirect on invalid credentials)", resp.StatusCode, http.StatusOK)
	}

	bodyStr := string(body)

	// Assert — HTML 바디에 에러 메시지 포함
	// 구현에 따라 텍스트가 다를 수 있으나 일반적인 인증 실패 메시지를 확인한다
	hasErrorMessage := strings.Contains(bodyStr, "invalid") ||
		strings.Contains(bodyStr, "Invalid") ||
		strings.Contains(bodyStr, "incorrect") ||
		strings.Contains(bodyStr, "Incorrect") ||
		strings.Contains(bodyStr, "wrong") ||
		strings.Contains(bodyStr, "Wrong") ||
		strings.Contains(bodyStr, "error") ||
		strings.Contains(bodyStr, "Error") ||
		strings.Contains(bodyStr, "failed") ||
		strings.Contains(bodyStr, "Failed")
	if !hasErrorMessage {
		t.Errorf("response body does not contain an error message, body = %q", bodyStr)
	}

	// Assert — 로그인 폼이 여전히 존재해야 한다
	if !strings.Contains(bodyStr, "<form") {
		t.Errorf("response body does not contain <form tag after failed login")
	}

	hasUsername := strings.Contains(bodyStr, `name="username"`)
	hasEmail := strings.Contains(bodyStr, `name="email"`)
	if !hasUsername && !hasEmail {
		t.Errorf("response body does not contain input with name=\"username\" or name=\"email\" after failed login")
	}

	if !strings.Contains(bodyStr, `name="password"`) {
		t.Errorf("response body does not contain input with name=\"password\" after failed login")
	}
}

// ---------------------------------------------------------------------------
// TestLoginHandler_SessionCookieMaintainsAuthState — 세션 쿠키로 보호된 엔드포인트 접근
// ---------------------------------------------------------------------------

func TestLoginHandler_SessionCookieMaintainsAuthState(t *testing.T) {
	// TODO: Activate when DLD-582 is implemented
	t.Skip("not implemented yet")

	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// CookieJar가 포함된 클라이언트를 사용하여 세션 쿠키가 자동으로 유지되도록 한다
	client, _ := testhelper.NewTestClient(t)

	// Step 1: POST /login으로 로그인 (올바른 자격증명)
	formData := url.Values{
		"username": {"admin@test.local"},
		"password": {"test-password"},
	}

	loginReq, err := http.NewRequest(
		http.MethodPost,
		srv.URL+"/login",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("http.NewRequest (login): %v", err)
	}
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	loginResp, err := client.Do(loginReq)
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer loginResp.Body.Close()

	// 로그인이 리다이렉트(303) 또는 성공(200)으로 완료되어야 한다
	if loginResp.StatusCode != http.StatusOK && loginResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /login status = %d, want 200 or 303", loginResp.StatusCode)
	}

	// Step 2: 같은 클라이언트(쿠키 자동 유지)로 보호된 엔드포인트 접근
	// /oauth2/auth 엔드포인트는 인증이 필요한 OAuth2 인가 엔드포인트이다
	protectedResp, err := client.Get(srv.URL + "/oauth2/auth")
	if err != nil {
		t.Fatalf("GET /oauth2/auth: %v", err)
	}
	defer protectedResp.Body.Close()

	// Assert — 인증된 사용자는 401 Unauthorized를 받지 않아야 한다
	if protectedResp.StatusCode == http.StatusUnauthorized {
		t.Errorf("GET /oauth2/auth status = %d (Unauthorized) after login, want authenticated response", protectedResp.StatusCode)
	}

	// Assert — 인증된 사용자는 /login 페이지로 리다이렉트되지 않아야 한다
	// (최종 URL이 /login이면 인증이 유지되지 않은 것)
	finalURL := protectedResp.Request.URL.Path
	if strings.HasSuffix(finalURL, "/login") {
		t.Errorf("GET /oauth2/auth redirected to %q after login, session cookie is not maintained", finalURL)
	}
}
