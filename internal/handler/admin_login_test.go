// Package handler_test — Admin 로그인 엔드포인트 및 관련 기능 통합 테스트 (TDD Red Phase)
//
// 이 테스트들은 다음 기능이 구현되기 전에 작성되었으므로
// 현재 컴파일/실패 상태가 정상입니다.
//
// 구현이 필요한 항목:
//
//  1. Admin 로그인 핸들러 (internal/handler/admin_login.go):
//     func NewAdminLoginHandler(cfg *config.Config) http.HandlerFunc
//     - POST /api/admin/login
//     - 요청 body: { "id": "admin", "password": "..." }
//     - Config.Owner.Username 과 Config.Owner.PasswordHash (bcrypt) 로 인증
//     - 성공: admin_session 쿠키 발급 + 200 JSON { "ok": true }
//     - 실패: 401 JSON { "error": "invalid credentials" }
//
//  2. Admin 세션 미들웨어 (internal/handler/admin_session_middleware.go):
//     func NewAdminSessionMiddleware() func(http.Handler) http.Handler
//     - admin_session 쿠키 확인 → 유효하면 next 호출
//     - 쿠키 없거나 무효 → 401 JSON { "error": "unauthorized" }
//
//  3. 대시보드 통계 핸들러 (internal/handler/admin_stats.go):
//     func NewAdminStatsHandler(store AdminStatsStore) http.HandlerFunc
//     - GET /api/admin/stats
//     - AdminStatsStore 인터페이스: ListClients, ListSessions, ListTokens, CountAuth24h
//     - 응답: { "clients": N, "sessions": N, "tokens": N, "auth_24h": N }
//
//  4. 라우트 등록 (internal/testhelper/server.go buildRouter()):
//     r.Post("/api/admin/login", handler.NewAdminLoginHandler(cfg))
//     r.Route("/api/admin", func(r chi.Router) {
//         r.Use(handler.NewAdminSessionMiddleware())
//         r.Get("/stats", handler.NewAdminStatsHandler(store))
//         ... (기존 Bearer 인증 라우트는 유지)
//     })
//
// 테스트 커버리지:
//   - POST /api/admin/login: 정상 로그인 → 200 + admin_session 쿠키 발급
//   - POST /api/admin/login: 잘못된 비밀번호 → 401
//   - POST /api/admin/login: 잘못된 사용자 ID → 401
//   - POST /api/admin/login: 빈 body → 400
//   - POST /api/admin/login: 성공 응답이 { "ok": true } JSON
//   - POST /api/admin/login: 실패 응답이 { "error": "..." } JSON
//   - POST /api/admin/login: 쿠키 속성 (HttpOnly, SameSite=Strict)
//   - Admin 세션 미들웨어: 쿠키 없음 → 401
//   - Admin 세션 미들웨어: 유효한 쿠키 → 통과
//   - Admin 세션 미들웨어: 무효한 쿠키 값 → 401
//   - GET /api/admin/stats: 인증 없음 → 401
//   - GET /api/admin/stats: 유효한 세션으로 접근 → 200
//   - GET /api/admin/stats: 응답 구조 검증 (clients, sessions, tokens, auth_24h 필드)
package handler_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// URL 상수
// ---------------------------------------------------------------------------

const adminLoginURL = "/api/admin/login"
const adminStatsURL = "/api/admin/stats"

// ---------------------------------------------------------------------------
// 응답 구조체
// ---------------------------------------------------------------------------

// adminLoginSuccessResponse는 POST /api/admin/login 성공 시 응답 body입니다.
type adminLoginSuccessResponse struct {
	OK bool `json:"ok"`
}

// adminStatsResponse는 GET /api/admin/stats 응답 body입니다.
type adminStatsResponse struct {
	Clients  int `json:"clients"`
	Sessions int `json:"sessions"`
	Tokens   int `json:"tokens"`
	Auth24h  int `json:"auth_24h"`
}

// ---------------------------------------------------------------------------
// 테스트 헬퍼
// ---------------------------------------------------------------------------

// adminLoginPayload는 POST /api/admin/login 요청 body를 빌드합니다.
func adminLoginPayload(id, password string) map[string]string {
	return map[string]string{
		"id":       id,
		"password": password,
	}
}

// doAdminLogin은 /api/admin/login에 JSON body로 POST 요청을 보내고
// *http.Response를 반환합니다.
// 호출자는 resp.Body를 닫아야 합니다.
func doAdminLogin(t *testing.T, client *http.Client, baseURL, id, password string) *http.Response {
	t.Helper()

	payload := adminLoginPayload(id, password)
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("doAdminLogin: json.Marshal: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+adminLoginURL, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("doAdminLogin: http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("doAdminLogin: %v", err)
	}
	return resp
}

// newClientWithCookieJar는 쿠키를 자동으로 관리하는 *http.Client를 반환합니다.
// admin_session 쿠키를 발급 받은 후 이후 요청에서 자동으로 첨부하는 데 사용합니다.
func newClientWithCookieJar(t *testing.T) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("newClientWithCookieJar: cookiejar.New: %v", err)
	}
	return &http.Client{Jar: jar}
}

// loginAsAdmin은 테스트 서버에 Admin 자격증명으로 로그인하고
// admin_session 쿠키가 설정된 *http.Client를 반환합니다.
//
// testhelper.NewTestConfig의 testOwnerUsername = "admin@test.local"
// testOwnerPasswordHash = bcrypt("test-password", cost=12)
func loginAsAdmin(t *testing.T, baseURL string) *http.Client {
	t.Helper()

	client := newClientWithCookieJar(t)
	resp := doAdminLogin(t, client, baseURL, "admin@test.local", "test-password")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("loginAsAdmin: status = %d, want 200; body = %s", resp.StatusCode, body)
	}
	return client
}

// ---------------------------------------------------------------------------
// POST /api/admin/login — 정상 케이스 (happy path)
// ---------------------------------------------------------------------------

// TestAdminLogin_ValidCredentials_Returns200은 올바른 자격증명으로 로그인하면
// 200 OK가 반환되는지 검증합니다.
func TestAdminLogin_ValidCredentials_Returns200(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := newClientWithCookieJar(t)

	// Act
	resp := doAdminLogin(t, client, srv.URL, "admin@test.local", "test-password")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s status = %d, want 200; body = %s", adminLoginURL, resp.StatusCode, body)
	}
}

// TestAdminLogin_ValidCredentials_ResponseIsOkTrue는 로그인 성공 응답이
// { "ok": true } JSON인지 검증합니다.
func TestAdminLogin_ValidCredentials_ResponseIsOkTrue(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := newClientWithCookieJar(t)

	// Act
	resp := doAdminLogin(t, client, srv.URL, "admin@test.local", "test-password")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	// Assert — Content-Type: application/json
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want to contain \"application/json\"", ct)
	}

	// Assert — body: { "ok": true }
	var result adminLoginSuccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("json.Decode: %v", err)
	}
	if !result.OK {
		t.Errorf("response.ok = %v, want true", result.OK)
	}
}

// TestAdminLogin_ValidCredentials_SetsAdminSessionCookie는 로그인 성공 시
// admin_session 쿠키가 발급되는지 검증합니다.
func TestAdminLogin_ValidCredentials_SetsAdminSessionCookie(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// 리다이렉트를 따르지 않는 클라이언트로 Set-Cookie 헤더를 직접 확인합니다.
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Act
	resp := doAdminLogin(t, noRedirectClient, srv.URL, "admin@test.local", "test-password")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Assert — admin_session 쿠키가 존재해야 합니다.
	var adminSessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "admin_session" {
			adminSessionCookie = c
			break
		}
	}

	if adminSessionCookie == nil {
		t.Fatalf("no \"admin_session\" cookie in Set-Cookie header; got cookies: %v", resp.Cookies())
	}

	// Assert — 쿠키 값이 비어있지 않아야 합니다.
	if adminSessionCookie.Value == "" {
		t.Errorf("admin_session cookie value is empty, want a non-empty session token")
	}
}

// TestAdminLogin_ValidCredentials_CookieIsHttpOnly는 admin_session 쿠키가
// HttpOnly 속성을 가지는지 검증합니다 (XSS 방어).
func TestAdminLogin_ValidCredentials_CookieIsHttpOnly(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Act
	resp := doAdminLogin(t, noRedirectClient, srv.URL, "admin@test.local", "test-password")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Assert — admin_session 쿠키의 HttpOnly 속성 확인
	var adminSessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "admin_session" {
			adminSessionCookie = c
			break
		}
	}
	if adminSessionCookie == nil {
		t.Fatalf("admin_session cookie not found in response")
	}

	if !adminSessionCookie.HttpOnly {
		t.Errorf("admin_session cookie HttpOnly = false, want true")
	}
}

// TestAdminLogin_ValidCredentials_CookieIsSameSiteStrict는 admin_session 쿠키가
// SameSite=Strict 속성을 가지는지 검증합니다 (CSRF 방어).
func TestAdminLogin_ValidCredentials_CookieIsSameSiteStrict(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Act
	resp := doAdminLogin(t, noRedirectClient, srv.URL, "admin@test.local", "test-password")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Assert — admin_session 쿠키의 SameSite 속성 확인
	var adminSessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "admin_session" {
			adminSessionCookie = c
			break
		}
	}
	if adminSessionCookie == nil {
		t.Fatalf("admin_session cookie not found in response")
	}

	if adminSessionCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("admin_session cookie SameSite = %v, want SameSiteStrictMode",
			adminSessionCookie.SameSite)
	}
}

// ---------------------------------------------------------------------------
// POST /api/admin/login — 에러 케이스 (error cases)
// ---------------------------------------------------------------------------

// TestAdminLogin_WrongPassword_Returns401은 올바른 사용자 ID지만 잘못된
// 비밀번호로 로그인하면 401이 반환되는지 검증합니다.
func TestAdminLogin_WrongPassword_Returns401(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := newClientWithCookieJar(t)

	// Act
	resp := doAdminLogin(t, client, srv.URL, "admin@test.local", "wrong-password")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST %s with wrong password: status = %d, want 401; body = %s",
			adminLoginURL, resp.StatusCode, body)
	}
}

// TestAdminLogin_WrongUsername_Returns401은 잘못된 사용자 ID로 로그인하면
// 401이 반환되는지 검증합니다.
func TestAdminLogin_WrongUsername_Returns401(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := newClientWithCookieJar(t)

	// Act
	resp := doAdminLogin(t, client, srv.URL, "wrong-admin", "test-password")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST %s with wrong username: status = %d, want 401; body = %s",
			adminLoginURL, resp.StatusCode, body)
	}
}

// TestAdminLogin_WrongCredentials_ResponseHasErrorField는 인증 실패 응답이
// JSON { "error": "..." } 형태인지 검증합니다.
func TestAdminLogin_WrongCredentials_ResponseHasErrorField(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := newClientWithCookieJar(t)

	// Act
	resp := doAdminLogin(t, client, srv.URL, "admin@test.local", "wrong-password")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 401
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", resp.StatusCode, body)
	}

	// Assert — Content-Type: application/json
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want to contain \"application/json\"", ct)
	}

	// Assert — body에 "error" 필드가 존재해야 합니다.
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("response body is not valid JSON: %v — body: %s", err, body)
	}
	if errResp.Error == "" {
		t.Errorf("error field is empty; body = %s", body)
	}
}

// TestAdminLogin_WrongCredentials_DoesNotSetCookie는 인증 실패 시
// admin_session 쿠키가 발급되지 않는지 검증합니다.
func TestAdminLogin_WrongCredentials_DoesNotSetCookie(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := newClientWithCookieJar(t)

	// Act
	resp := doAdminLogin(t, client, srv.URL, "admin@test.local", "wrong-password")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	// Assert — admin_session 쿠키가 없어야 합니다.
	for _, c := range resp.Cookies() {
		if c.Name == "admin_session" {
			t.Errorf("admin_session cookie was set on failed login, want no cookie; value = %q",
				c.Value)
		}
	}
}

// TestAdminLogin_EmptyBody_Returns400은 빈 body로 요청하면 400이 반환되는지
// 검증합니다.
func TestAdminLogin_EmptyBody_Returns400(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	req, err := http.NewRequest(http.MethodPost, srv.URL+adminLoginURL, bytes.NewReader([]byte{}))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Act
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", adminLoginURL, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Assert — 400 Bad Request
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST %s with empty body: status = %d, want 400; body = %s",
			adminLoginURL, resp.StatusCode, body)
	}
}

// TestAdminLogin_MalformedJSON_Returns400은 유효하지 않은 JSON body로 요청하면
// 400이 반환되는지 검증합니다.
func TestAdminLogin_MalformedJSON_Returns400(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	req, err := http.NewRequest(http.MethodPost, srv.URL+adminLoginURL,
		bytes.NewReader([]byte(`{not valid json`)))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Act
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", adminLoginURL, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Assert — 400 Bad Request
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST %s with malformed JSON: status = %d, want 400; body = %s",
			adminLoginURL, resp.StatusCode, body)
	}
}

// ---------------------------------------------------------------------------
// Admin 세션 미들웨어 테스트
// ---------------------------------------------------------------------------

// TestAdminSessionMiddleware_NoCookie_Returns401은 admin_session 쿠키 없이
// 세션 미들웨어로 보호된 엔드포인트에 접근하면 401이 반환되는지 검증합니다.
//
// 세션 미들웨어는 /api/admin/stats와 같은 엔드포인트를 보호합니다.
func TestAdminSessionMiddleware_NoCookie_Returns401(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+adminStatsURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	// 쿠키를 첨부하지 않습니다.

	// Act
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", adminStatsURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s without cookie: status = %d, want 401", adminStatsURL, resp.StatusCode)
	}
}

// TestAdminSessionMiddleware_InvalidCookieValue_Returns401은 유효하지 않은
// admin_session 쿠키 값으로 접근하면 401이 반환되는지 검증합니다.
func TestAdminSessionMiddleware_InvalidCookieValue_Returns401(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+adminStatsURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.AddCookie(&http.Cookie{
		Name:  "admin_session",
		Value: "invalid-session-token-xyz",
	})

	// Act
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", adminStatsURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s with invalid cookie: status = %d, want 401", adminStatsURL, resp.StatusCode)
	}
}

// TestAdminSessionMiddleware_ValidSession_AllowsRequest는 로그인 후 발급된
// admin_session 쿠키로 세션 미들웨어를 통과하는지 검증합니다.
func TestAdminSessionMiddleware_ValidSession_AllowsRequest(t *testing.T) {
	// Arrange — 쿠키 jar가 있는 클라이언트로 로그인하여 admin_session 쿠키를 획득합니다.
	srv, _ := testhelper.NewTestServer(t)
	client := loginAsAdmin(t, srv.URL)

	// Act — 세션 미들웨어로 보호된 엔드포인트에 접근합니다.
	req, err := http.NewRequest(http.MethodGet, srv.URL+adminStatsURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", adminStatsURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — 401이 아니어야 합니다 (세션이 유효하므로 통과해야 함).
	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("GET %s with valid session cookie: status = 401, want non-401",
			adminStatsURL)
	}
}

// TestAdminSessionMiddleware_Returns401AsJSON은 세션 미들웨어의 401 응답이
// JSON { "error": "..." } 형태인지 검증합니다.
func TestAdminSessionMiddleware_Returns401AsJSON(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	req, err := http.NewRequest(http.MethodGet, srv.URL+adminStatsURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	// Act
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", adminStatsURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 401
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", resp.StatusCode, body)
	}

	// Assert — Content-Type: application/json
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want to contain \"application/json\"", ct)
	}

	// Assert — body에 "error" 필드가 존재해야 합니다.
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("response body is not valid JSON: %v — body: %s", err, body)
	}
	if errResp.Error == "" {
		t.Errorf("error field is empty; body = %s", body)
	}
}

// ---------------------------------------------------------------------------
// GET /api/admin/stats — 대시보드 통계 API
// ---------------------------------------------------------------------------

// TestAdminStats_NoSession_Returns401는 세션 없이 stats 엔드포인트에 접근하면
// 401이 반환되는지 검증합니다.
func TestAdminStats_NoSession_Returns401(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)

	// Act — 쿠키 없이 요청
	req, err := http.NewRequest(http.MethodGet, srv.URL+adminStatsURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", adminStatsURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s without session: status = %d, want 401", adminStatsURL, resp.StatusCode)
	}
}

// TestAdminStats_WithValidSession_Returns200는 유효한 세션으로 stats 엔드포인트에
// 접근하면 200이 반환되는지 검증합니다.
func TestAdminStats_WithValidSession_Returns200(t *testing.T) {
	// Arrange — 로그인하여 admin_session 쿠키를 획득합니다.
	srv, _ := testhelper.NewTestServer(t)
	client := loginAsAdmin(t, srv.URL)

	// Act
	req, err := http.NewRequest(http.MethodGet, srv.URL+adminStatsURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", adminStatsURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200; body = %s", adminStatsURL, resp.StatusCode, body)
	}
}

// TestAdminStats_ResponseHasRequiredFields는 stats 응답이
// clients, sessions, tokens, auth_24h 필드를 포함하는지 검증합니다.
func TestAdminStats_ResponseHasRequiredFields(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAsAdmin(t, srv.URL)

	// Act
	req, err := http.NewRequest(http.MethodGet, srv.URL+adminStatsURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", adminStatsURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	// Assert — Content-Type: application/json
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want to contain \"application/json\"", ct)
	}

	// Assert — 응답 body를 raw map으로 파싱하여 모든 필드 존재 여부를 확인합니다.
	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("json.Decode raw map: %v", err)
	}

	requiredFields := []string{"clients", "sessions", "tokens", "auth_24h"}
	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("stats response missing field %q; got keys: %v", field, keysOf(raw))
		}
	}
}

// TestAdminStats_ClientsCountReflectsSeededClients는 stats의 clients 수가
// 실제 seeded 클라이언트 수를 반영하는지 검증합니다.
//
// testhelper.NewTestServer는 4개의 클라이언트를 seed합니다:
// test-client, public-client, cc-client, device-client, dc-client (5개).
func TestAdminStats_ClientsCountReflectsSeededClients(t *testing.T) {
	// Arrange
	srv, _ := testhelper.NewTestServer(t)
	client := loginAsAdmin(t, srv.URL)

	// Act
	req, err := http.NewRequest(http.MethodGet, srv.URL+adminStatsURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", adminStatsURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	var stats adminStatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("json.Decode: %v", err)
	}

	// Assert — NewTestServer가 seed한 클라이언트 수와 일치해야 합니다.
	// seedTestClient는 5개의 클라이언트를 삽입합니다:
	// test-client, public-client, cc-client, device-client, dc-client
	const expectedMinClients = 5
	if stats.Clients < expectedMinClients {
		t.Errorf("stats.clients = %d, want >= %d", stats.Clients, expectedMinClients)
	}
}

// TestAdminStats_EmptyDatabase_Returns200WithZeroCounts는 빈 DB(세션/토큰 없음) 상태에서
// stats가 0을 반환하는지 검증합니다.
func TestAdminStats_EmptyDatabase_Returns200WithZeroCounts(t *testing.T) {
	// Arrange — 새 테스트 서버는 세션/토큰이 없는 상태로 시작합니다.
	srv, _ := testhelper.NewTestServer(t)
	client := loginAsAdmin(t, srv.URL)

	// Act
	req, err := http.NewRequest(http.MethodGet, srv.URL+adminStatsURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", adminStatsURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	var stats adminStatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("json.Decode: %v", err)
	}

	// Assert — 세션/토큰이 없으므로 0이어야 합니다.
	if stats.Sessions != 0 {
		t.Errorf("stats.sessions = %d, want 0 (empty DB)", stats.Sessions)
	}
	if stats.Tokens != 0 {
		t.Errorf("stats.tokens = %d, want 0 (empty DB)", stats.Tokens)
	}
	if stats.Auth24h != 0 {
		t.Errorf("stats.auth_24h = %d, want 0 (empty DB)", stats.Auth24h)
	}
}

// ---------------------------------------------------------------------------
// 내부 헬퍼
// ---------------------------------------------------------------------------

// keysOf는 map의 키 목록을 슬라이스로 반환합니다 (에러 메시지 출력용).
func keysOf(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
