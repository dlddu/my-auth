// Package handler_test — Admin SPA HTTP 핸들러 통합 테스트 (TDD Red Phase)
//
// 이 테스트들은 다음 기능이 구현되기 전에 작성되었으므로
// 현재 실패 상태가 정상입니다.
//
// 구현이 필요한 항목:
//
//  1. Admin SPA 로그인 핸들러 (internal/handler/admin_spa.go):
//     func NewAdminSPALoginHandler(cfg *config.Config, db *sql.DB) http.HandlerFunc
//     - POST /api/admin/auth/login
//     - JSON body: {"username": "...", "password": "..."}
//     - 성공 시: 200 OK + JSON {"token": "<session-value>"} + Set-Cookie admin_session=...
//     - 실패 시: 401 Unauthorized + JSON {"error": "invalid credentials"}
//
//  2. Admin 세션 미들웨어 (internal/handler/admin_spa.go):
//     func NewAdminSessionMiddleware(cfg *config.Config, db *sql.DB) func(http.Handler) http.Handler
//     - admin_session 쿠키로 인증 (기존 OAuth2 session 쿠키와 구분)
//     - 쿠키 없거나 유효하지 않으면 401 JSON
//
//  3. Admin 대시보드 통계 핸들러 (internal/handler/admin_spa.go):
//     func NewAdminDashboardStatsHandler(store AdminSessionTokenStore, db *sql.DB) http.HandlerFunc
//     - GET /api/admin/dashboard/stats
//     - admin_session 쿠키 인증 필요
//     - 반환: {"clients": N, "active_sessions": N, "tokens": N, "auth_24h": N}
//
//  4. Admin 대시보드 최근 활동 핸들러 (internal/handler/admin_spa.go):
//     func NewAdminDashboardActivityHandler(db *sql.DB) http.HandlerFunc
//     - GET /api/admin/dashboard/activity
//     - admin_session 쿠키 인증 필요
//     - 반환: [{"time": "...", "action": "...", "client_name": "...", "type": "..."}]
//
//  5. Admin SPA 정적 파일 핸들러 (internal/handler/admin_spa.go):
//     func NewAdminSPAHandler() http.Handler
//     - GET /admin/* — go:embed된 React SPA 파일 서빙
//     - SPA 라우팅 폴백: URL에 확장자가 없으면 index.html 반환
//
//  6. 라우트 등록 (internal/testhelper/server.go buildRouter()):
//     - POST /api/admin/auth/login → handler.NewAdminSPALoginHandler(cfg, db)
//     - /api/admin/dashboard/* 그룹에 handler.NewAdminSessionMiddleware(cfg, db)
//       r.Get("/stats", handler.NewAdminDashboardStatsHandler(store, db))
//       r.Get("/activity", handler.NewAdminDashboardActivityHandler(db))
//     - r.Handle("/admin/*", handler.NewAdminSPAHandler())
//
// 테스트 커버리지:
//   - Admin 로그인 성공: 200 + token JSON + Set-Cookie admin_session
//   - Admin 로그인 실패 (잘못된 비밀번호): 401 + error JSON
//   - Admin 로그인 실패 (잘못된 사용자명): 401 + error JSON
//   - Admin 로그인 실패 (빈 body): 400 or 401
//   - Dashboard stats: 인증 없음 → 401
//   - Dashboard stats: 유효한 세션 쿠키 → 200 + 통계 JSON
//   - Dashboard stats: 올바른 필드 포함 확인
//   - Dashboard activity: 인증 없음 → 401
//   - Dashboard activity: 유효한 세션 쿠키 → 200 + JSON 배열
//   - Admin SPA: GET /admin/ → 200 + HTML (index.html)
//   - Admin SPA: GET /admin/login → 200 + HTML (SPA 라우팅 폴백)
//   - Admin SPA: GET /admin/dashboard → 200 + HTML (SPA 라우팅 폴백)
//   - Admin SPA: GET /admin/static/app.js → 정적 파일 서빙 (파일 없으면 404)
package handler_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/dlddu/my-auth/internal/config"
	"github.com/dlddu/my-auth/internal/database"
	"github.com/dlddu/my-auth/internal/handler"
	"github.com/dlddu/my-auth/internal/storage"
	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// URL 상수
// ---------------------------------------------------------------------------

const adminSPALoginURL = "/api/admin/auth/login"
const adminDashboardStatsURL = "/api/admin/dashboard/stats"
const adminDashboardActivityURL = "/api/admin/dashboard/activity"
const adminSPABaseURL = "/admin"

// ---------------------------------------------------------------------------
// 응답 구조체
// ---------------------------------------------------------------------------

// adminSPALoginResponse는 POST /api/admin/auth/login 성공 응답입니다.
type adminSPALoginResponse struct {
	Token string `json:"token"`
}

// adminDashboardStatsResponse는 GET /api/admin/dashboard/stats 응답입니다.
type adminDashboardStatsResponse struct {
	Clients        int `json:"clients"`
	ActiveSessions int `json:"active_sessions"`
	Tokens         int `json:"tokens"`
	Auth24h        int `json:"auth_24h"`
}

// adminDashboardActivityItem은 GET /api/admin/dashboard/activity 응답의 각 항목입니다.
type adminDashboardActivityItem struct {
	Time       string `json:"time"`
	Action     string `json:"action"`
	ClientName string `json:"client_name"`
	Type       string `json:"type"`
}

// ---------------------------------------------------------------------------
// 테스트 라우터 빌더 헬퍼
//
// testhelper.buildRouter는 패키지 외부에서 접근 불가능하므로,
// Admin SPA 핸들러만 포함한 최소 라우터를 직접 구성합니다.
// ---------------------------------------------------------------------------

// buildAdminSPARouter는 Admin SPA 관련 엔드포인트만 포함한 테스트용 라우터를 반환합니다.
// cfg와 db를 직접 주입하여 핸들러 시그니처를 검증합니다.
func buildAdminSPARouter(cfg *config.Config, db *sql.DB) http.Handler {
	r := chi.NewRouter()

	store := storage.New(db)

	// Admin SPA 로그인 (세션 쿠키 발급)
	r.Post(adminSPALoginURL, handler.NewAdminSPALoginHandler(cfg, db))

	// Admin 대시보드 API (admin_session 쿠키 인증)
	r.Route("/api/admin/dashboard", func(r chi.Router) {
		r.Use(handler.NewAdminSessionMiddleware(cfg, db))
		r.Get("/stats", handler.NewAdminDashboardStatsHandler(store, db))
		r.Get("/activity", handler.NewAdminDashboardActivityHandler(db))
	})

	// Admin SPA 정적 파일 서빙
	r.Handle("/admin/*", handler.NewAdminSPAHandler())
	r.Handle("/admin", handler.NewAdminSPAHandler())

	return r
}

// newAdminSPATestServer는 Admin SPA 핸들러만 포함한 httptest.Server를 반환합니다.
func newAdminSPATestServer(t *testing.T) (*httptest.Server, *http.Client, *config.Config, *sql.DB) {
	t.Helper()

	dsn := testhelper.NewTestDB(t)
	cfg := testhelper.NewTestConfig(t, dsn)

	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("newAdminSPATestServer: database.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Logf("newAdminSPATestServer cleanup: db.Close: %v", err)
		}
	})

	h := buildAdminSPARouter(cfg, db)
	srv := httptest.NewServer(h)
	t.Cleanup(func() { srv.Close() })

	return srv, srv.Client(), cfg, db
}

// doAdminSPALoginRequest는 POST /api/admin/auth/login 요청을 수행합니다.
// 리다이렉트를 따르지 않는 클라이언트를 사용합니다.
func doAdminSPALoginRequest(
	t *testing.T,
	srvURL string,
	username, password string,
) *http.Response {
	t.Helper()

	payload := map[string]string{
		"username": username,
		"password": password,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("doAdminSPALoginRequest: json.Marshal: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, srvURL+adminSPALoginURL, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("doAdminSPALoginRequest: http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// 리다이렉트를 따르지 않는 클라이언트
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("doAdminSPALoginRequest: POST %s: %v", adminSPALoginURL, err)
	}
	return resp
}

// extractAdminSessionCookie는 응답에서 admin_session 쿠키 값을 추출합니다.
// 쿠키가 없으면 빈 문자열을 반환합니다.
func extractAdminSessionCookie(resp *http.Response) string {
	for _, c := range resp.Cookies() {
		if c.Name == "admin_session" {
			return c.Value
		}
	}
	return ""
}

// doAdminDashboardRequest는 admin_session 쿠키를 포함한 대시보드 API 요청을 수행합니다.
func doAdminDashboardRequest(
	t *testing.T,
	client *http.Client,
	srvURL, path string,
	sessionCookieValue string,
) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, srvURL+path, nil)
	if err != nil {
		t.Fatalf("doAdminDashboardRequest: http.NewRequest: %v", err)
	}
	if sessionCookieValue != "" {
		req.AddCookie(&http.Cookie{
			Name:  "admin_session",
			Value: sessionCookieValue,
		})
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("doAdminDashboardRequest: GET %s: %v", path, err)
	}
	return resp
}

// loginAsAdminSPA는 테스트 사용자로 로그인하여 admin_session 쿠키 값을 반환합니다.
// 로그인 실패 시 테스트를 즉시 중단합니다.
func loginAsAdminSPA(t *testing.T, srvURL string) string {
	t.Helper()

	resp := doAdminSPALoginRequest(t, srvURL, "admin@test.local", "test-password")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("loginAsAdminSPA: POST %s status = %d, want 200; body = %s",
			adminSPALoginURL, resp.StatusCode, body)
	}

	cookieValue := extractAdminSessionCookie(resp)
	if cookieValue == "" {
		t.Fatal("loginAsAdminSPA: admin_session cookie not found in login response")
	}
	return cookieValue
}

// ---------------------------------------------------------------------------
// Admin SPA 로그인 API 테스트
// POST /api/admin/auth/login
// ---------------------------------------------------------------------------

// TestAdminSPALogin_ValidCredentials_Returns200 verifies that a valid login
// request returns 200 OK with a JSON token and sets the admin_session cookie.
func TestAdminSPALogin_ValidCredentials_Returns200(t *testing.T) {
	// Arrange
	srv, _, _, _ := newAdminSPATestServer(t)

	// Act
	resp := doAdminSPALoginRequest(t, srv.URL, "admin@test.local", "test-password")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s with valid credentials: status = %d, want 200; body = %s",
			adminSPALoginURL, resp.StatusCode, body)
	}

	// Assert — Content-Type: application/json
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want to contain \"application/json\"", ct)
	}
}

// TestAdminSPALogin_ValidCredentials_ReturnsTokenJSON verifies that the login
// response body contains a non-empty "token" field.
func TestAdminSPALogin_ValidCredentials_ReturnsTokenJSON(t *testing.T) {
	// Arrange
	srv, _, _, _ := newAdminSPATestServer(t)

	// Act
	resp := doAdminSPALoginRequest(t, srv.URL, "admin@test.local", "test-password")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s status = %d, want 200; body = %s",
			adminSPALoginURL, resp.StatusCode, body)
	}

	var result adminSPALoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}

	// Assert — "token" 필드가 비어있지 않아야 함
	if result.Token == "" {
		t.Error("response.token is empty, want a non-empty session token value")
	}
}

// TestAdminSPALogin_ValidCredentials_SetsAdminSessionCookie verifies that the
// login response sets the admin_session cookie.
func TestAdminSPALogin_ValidCredentials_SetsAdminSessionCookie(t *testing.T) {
	// Arrange
	srv, _, _, _ := newAdminSPATestServer(t)

	// Act
	resp := doAdminSPALoginRequest(t, srv.URL, "admin@test.local", "test-password")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s status = %d, want 200", adminSPALoginURL, resp.StatusCode)
	}

	// Assert — admin_session 쿠키가 설정되어야 함
	cookieValue := extractAdminSessionCookie(resp)
	if cookieValue == "" {
		t.Error("admin_session cookie not found in Set-Cookie header, want non-empty value")
	}
}

// TestAdminSPALogin_ValidCredentials_TokenMatchesCookie verifies that the
// token in the JSON body matches the admin_session cookie value.
func TestAdminSPALogin_ValidCredentials_TokenMatchesCookie(t *testing.T) {
	// Arrange
	srv, _, _, _ := newAdminSPATestServer(t)

	// Act
	resp := doAdminSPALoginRequest(t, srv.URL, "admin@test.local", "test-password")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s status = %d, want 200", adminSPALoginURL, resp.StatusCode)
	}

	var result adminSPALoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}

	cookieValue := extractAdminSessionCookie(resp)

	// Assert — JSON token과 쿠키 값이 일치해야 함
	if result.Token == "" {
		t.Fatal("response.token is empty")
	}
	if cookieValue == "" {
		t.Fatal("admin_session cookie not found")
	}
	if result.Token != cookieValue {
		t.Errorf("response.token = %q does not match admin_session cookie = %q",
			result.Token, cookieValue)
	}
}

// TestAdminSPALogin_WrongPassword_Returns401 verifies that an incorrect
// password results in 401 Unauthorized with an error JSON body.
func TestAdminSPALogin_WrongPassword_Returns401(t *testing.T) {
	// Arrange
	srv, _, _, _ := newAdminSPATestServer(t)

	// Act
	resp := doAdminSPALoginRequest(t, srv.URL, "admin@test.local", "wrong-password")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST %s with wrong password: status = %d, want 401; body = %s",
			adminSPALoginURL, resp.StatusCode, body)
	}

	// Assert — JSON error 필드 포함
	var errResp struct {
		Error string `json:"error"`
	}
	if jsonErr := json.Unmarshal(body, &errResp); jsonErr != nil {
		t.Fatalf("response body is not valid JSON: %v — body: %s", jsonErr, body)
	}
	if errResp.Error == "" {
		t.Errorf("error field is empty; body = %s", body)
	}
}

// TestAdminSPALogin_WrongUsername_Returns401 verifies that an incorrect
// username results in 401 Unauthorized.
func TestAdminSPALogin_WrongUsername_Returns401(t *testing.T) {
	// Arrange
	srv, _, _, _ := newAdminSPATestServer(t)

	// Act
	resp := doAdminSPALoginRequest(t, srv.URL, "wrong@example.com", "test-password")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST %s with wrong username: status = %d, want 401",
			adminSPALoginURL, resp.StatusCode)
	}
}

// TestAdminSPALogin_WrongCredentials_ErrorMessageIsInvalidCredentials verifies
// that the error message in the 401 response is "invalid credentials".
func TestAdminSPALogin_WrongCredentials_ErrorMessageIsInvalidCredentials(t *testing.T) {
	// Arrange
	srv, _, _, _ := newAdminSPATestServer(t)

	// Act
	resp := doAdminSPALoginRequest(t, srv.URL, "admin@test.local", "wrong-password")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 401
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST %s status = %d, want 401; body = %s",
			adminSPALoginURL, resp.StatusCode, body)
	}

	// Assert — error 메시지가 "invalid credentials"이어야 함
	var errResp struct {
		Error string `json:"error"`
	}
	if jsonErr := json.Unmarshal(body, &errResp); jsonErr != nil {
		t.Fatalf("response body is not valid JSON: %v — body: %s", jsonErr, body)
	}
	if errResp.Error != "invalid credentials" {
		t.Errorf("error = %q, want \"invalid credentials\"", errResp.Error)
	}
}

// TestAdminSPALogin_EmptyBody_ReturnsClientError verifies that an empty or
// malformed JSON body results in a 400 Bad Request response.
func TestAdminSPALogin_EmptyBody_ReturnsClientError(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)

	req, err := http.NewRequest(http.MethodPost, srv.URL+adminSPALoginURL, strings.NewReader(""))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Act
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", adminSPALoginURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — 400 or 401 (구현에 따라 다를 수 있으나 2xx이 아니어야 함)
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		t.Errorf("POST %s with empty body: status = %d, want 4xx (client error)",
			adminSPALoginURL, resp.StatusCode)
	}
}

// TestAdminSPALogin_DoesNotSetOAuthSessionCookie verifies that the admin login
// does NOT set the regular OAuth2 "session" cookie (only "admin_session").
func TestAdminSPALogin_DoesNotSetOAuthSessionCookie(t *testing.T) {
	// Arrange
	srv, _, _, _ := newAdminSPATestServer(t)

	// Act
	resp := doAdminSPALoginRequest(t, srv.URL, "admin@test.local", "test-password")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s status = %d, want 200", adminSPALoginURL, resp.StatusCode)
	}

	// Assert — "session" 쿠키(기존 OAuth2 쿠키)가 설정되지 않아야 함
	for _, c := range resp.Cookies() {
		if c.Name == "session" {
			t.Errorf("OAuth2 session cookie was set; admin login must only set admin_session cookie")
		}
	}
}

// ---------------------------------------------------------------------------
// Admin 대시보드 Stats API 테스트
// GET /api/admin/dashboard/stats
// ---------------------------------------------------------------------------

// TestAdminDashboardStats_NoAuth_Returns401 verifies that a request without
// the admin_session cookie returns 401 Unauthorized.
func TestAdminDashboardStats_NoAuth_Returns401(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)

	// Act — admin_session 쿠키 없음
	resp := doAdminDashboardRequest(t, client, srv.URL, adminDashboardStatsURL, "")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s without cookie: status = %d, want 401",
			adminDashboardStatsURL, resp.StatusCode)
	}
}

// TestAdminDashboardStats_NoAuth_ReturnsJSONError verifies that the 401
// response contains a valid JSON error body.
func TestAdminDashboardStats_NoAuth_ReturnsJSONError(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)

	// Act
	resp := doAdminDashboardRequest(t, client, srv.URL, adminDashboardStatsURL, "")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 401
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET %s status = %d, want 401; body = %s",
			adminDashboardStatsURL, resp.StatusCode, body)
	}

	// Assert — Content-Type: application/json
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want to contain \"application/json\"", ct)
	}

	// Assert — JSON에 "error" 필드 포함
	var errResp struct {
		Error string `json:"error"`
	}
	if jsonErr := json.Unmarshal(body, &errResp); jsonErr != nil {
		t.Fatalf("response body is not valid JSON: %v — body: %s", jsonErr, body)
	}
	if errResp.Error == "" {
		t.Errorf("error field is empty; body = %s", body)
	}
}

// TestAdminDashboardStats_WithValidSession_Returns200 verifies that a request
// with a valid admin_session cookie returns 200 OK.
func TestAdminDashboardStats_WithValidSession_Returns200(t *testing.T) {
	// Arrange — 로그인하여 유효한 세션 획득
	srv, client, _, _ := newAdminSPATestServer(t)
	sessionCookie := loginAsAdminSPA(t, srv.URL)

	// Act
	resp := doAdminDashboardRequest(t, client, srv.URL, adminDashboardStatsURL, sessionCookie)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s with valid session: status = %d, want 200; body = %s",
			adminDashboardStatsURL, resp.StatusCode, body)
	}
}

// TestAdminDashboardStats_WithValidSession_ReturnsStatsJSON verifies that the
// response body is valid JSON with the required fields.
func TestAdminDashboardStats_WithValidSession_ReturnsStatsJSON(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)
	sessionCookie := loginAsAdminSPA(t, srv.URL)

	// Act
	resp := doAdminDashboardRequest(t, client, srv.URL, adminDashboardStatsURL, sessionCookie)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s status = %d, want 200; body = %s",
			adminDashboardStatsURL, resp.StatusCode, body)
	}

	// Assert — JSON으로 파싱 가능
	var stats adminDashboardStatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
}

// TestAdminDashboardStats_WithValidSession_HasRequiredFields verifies that the
// stats response contains clients, active_sessions, tokens, and auth_24h fields.
func TestAdminDashboardStats_WithValidSession_HasRequiredFields(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)
	sessionCookie := loginAsAdminSPA(t, srv.URL)

	// Act
	resp := doAdminDashboardRequest(t, client, srv.URL, adminDashboardStatsURL, sessionCookie)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s status = %d, want 200; body = %s",
			adminDashboardStatsURL, resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 응답에 필수 필드가 JSON 키로 존재해야 함
	var raw map[string]interface{}
	if jsonErr := json.Unmarshal(body, &raw); jsonErr != nil {
		t.Fatalf("response body is not valid JSON: %v — body: %s", jsonErr, body)
	}

	requiredFields := []string{"clients", "active_sessions", "tokens", "auth_24h"}
	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("stats response missing field %q; body = %s", field, body)
		}
	}
}

// TestAdminDashboardStats_WithInvalidSessionCookie_Returns401 verifies that
// an invalid or expired session cookie is rejected with 401.
func TestAdminDashboardStats_WithInvalidSessionCookie_Returns401(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)

	// Act — 유효하지 않은 세션 쿠키 사용
	resp := doAdminDashboardRequest(t, client, srv.URL, adminDashboardStatsURL,
		"invalid-session-token-xyz")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s with invalid session cookie: status = %d, want 401",
			adminDashboardStatsURL, resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Admin 대시보드 Activity API 테스트
// GET /api/admin/dashboard/activity
// ---------------------------------------------------------------------------

// TestAdminDashboardActivity_NoAuth_Returns401 verifies that a request without
// the admin_session cookie returns 401 Unauthorized.
func TestAdminDashboardActivity_NoAuth_Returns401(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)

	// Act — admin_session 쿠키 없음
	resp := doAdminDashboardRequest(t, client, srv.URL, adminDashboardActivityURL, "")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s without cookie: status = %d, want 401",
			adminDashboardActivityURL, resp.StatusCode)
	}
}

// TestAdminDashboardActivity_WithValidSession_Returns200 verifies that a
// request with a valid admin_session cookie returns 200 OK.
func TestAdminDashboardActivity_WithValidSession_Returns200(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)
	sessionCookie := loginAsAdminSPA(t, srv.URL)

	// Act
	resp := doAdminDashboardRequest(t, client, srv.URL, adminDashboardActivityURL, sessionCookie)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s with valid session: status = %d, want 200; body = %s",
			adminDashboardActivityURL, resp.StatusCode, body)
	}
}

// TestAdminDashboardActivity_WithValidSession_ReturnsJSONArray verifies that
// the response body is a valid JSON array.
func TestAdminDashboardActivity_WithValidSession_ReturnsJSONArray(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)
	sessionCookie := loginAsAdminSPA(t, srv.URL)

	// Act
	resp := doAdminDashboardRequest(t, client, srv.URL, adminDashboardActivityURL, sessionCookie)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s status = %d, want 200; body = %s",
			adminDashboardActivityURL, resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — JSON 배열로 파싱 가능
	var activities []adminDashboardActivityItem
	if jsonErr := json.Unmarshal(body, &activities); jsonErr != nil {
		t.Fatalf("response body is not a JSON array: %v — body: %s", jsonErr, body)
	}
}

// TestAdminDashboardActivity_WithInvalidSession_Returns401 verifies that an
// invalid session cookie is rejected with 401.
func TestAdminDashboardActivity_WithInvalidSession_Returns401(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)

	// Act
	resp := doAdminDashboardRequest(t, client, srv.URL, adminDashboardActivityURL,
		"invalid-session-xyz")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s with invalid session: status = %d, want 401",
			adminDashboardActivityURL, resp.StatusCode)
	}
}

// TestAdminDashboardActivity_ContentType_IsJSON verifies that the response
// Content-Type is application/json.
func TestAdminDashboardActivity_ContentType_IsJSON(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)
	sessionCookie := loginAsAdminSPA(t, srv.URL)

	// Act
	resp := doAdminDashboardRequest(t, client, srv.URL, adminDashboardActivityURL, sessionCookie)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", adminDashboardActivityURL, resp.StatusCode)
	}

	// Assert — Content-Type: application/json
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want to contain \"application/json\"", ct)
	}
}

// ---------------------------------------------------------------------------
// Admin SPA 정적 파일 서빙 테스트
// GET /admin/*
// ---------------------------------------------------------------------------

// TestAdminSPA_GetRootPath_Returns200WithHTML verifies that GET /admin/
// returns 200 OK with HTML content (index.html).
func TestAdminSPA_GetRootPath_Returns200WithHTML(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)

	// Act
	resp, err := client.Get(srv.URL + adminSPABaseURL + "/")
	if err != nil {
		t.Fatalf("GET /admin/: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/: status = %d, want 200; body = %s",
			resp.StatusCode, body)
	}

	// Assert — Content-Type에 text/html 포함
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("GET /admin/: Content-Type = %q, want to contain \"text/html\"", ct)
	}
}

// TestAdminSPA_GetLoginPath_ReturnsSPAFallback verifies that GET /admin/login
// (no file extension) returns 200 OK with HTML (SPA routing fallback).
func TestAdminSPA_GetLoginPath_ReturnsSPAFallback(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)

	// Act
	resp, err := client.Get(srv.URL + adminSPABaseURL + "/login")
	if err != nil {
		t.Fatalf("GET /admin/login: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK (404가 아닌 index.html 폴백)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/login (SPA fallback): status = %d, want 200; body = %s",
			resp.StatusCode, body)
	}

	// Assert — HTML 반환
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("GET /admin/login: Content-Type = %q, want to contain \"text/html\"", ct)
	}
}

// TestAdminSPA_GetDashboardPath_ReturnsSPAFallback verifies that GET
// /admin/dashboard (no file extension) returns index.html via SPA fallback.
func TestAdminSPA_GetDashboardPath_ReturnsSPAFallback(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)

	// Act
	resp, err := client.Get(srv.URL + adminSPABaseURL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /admin/dashboard: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK (SPA 라우팅 폴백)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/dashboard (SPA fallback): status = %d, want 200; body = %s",
			resp.StatusCode, body)
	}

	// Assert — HTML 반환
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("GET /admin/dashboard: Content-Type = %q, want to contain \"text/html\"", ct)
	}
}

// TestAdminSPA_GetNestedPath_ReturnsSPAFallback verifies that GET
// /admin/clients/123 (nested path without extension) returns index.html.
func TestAdminSPA_GetNestedPath_ReturnsSPAFallback(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)

	// Act
	resp, err := client.Get(srv.URL + adminSPABaseURL + "/clients/123")
	if err != nil {
		t.Fatalf("GET /admin/clients/123: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK (SPA 라우팅 폴백)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/clients/123 (SPA fallback): status = %d, want 200; body = %s",
			resp.StatusCode, body)
	}

	// Assert — HTML 반환
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("GET /admin/clients/123: Content-Type = %q, want to contain \"text/html\"", ct)
	}
}

// TestAdminSPA_IndexHTML_ContainsHTMLStructure verifies that the returned HTML
// contains basic HTML structure (indicating index.html is served).
func TestAdminSPA_IndexHTML_ContainsHTMLStructure(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)

	// Act
	resp, err := client.Get(srv.URL + adminSPABaseURL + "/")
	if err != nil {
		t.Fatalf("GET /admin/: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/: status = %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	bodyStr := string(body)

	// Assert — 기본 HTML 구조 포함 확인
	if !strings.Contains(bodyStr, "<html") && !strings.Contains(bodyStr, "<!DOCTYPE") {
		t.Errorf("GET /admin/: response body does not contain HTML structure; body = %.200s", bodyStr)
	}
}

// TestAdminSPA_StaticFileWithExtension_ServedDirectly verifies that requests
// for files with known extensions (e.g. .js, .css) are served directly and
// NOT routed to the SPA fallback. If the file doesn't exist, 404 is expected.
func TestAdminSPA_StaticFileWithExtension_ServedDirectly(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)

	// Act — 존재하지 않는 .js 파일 요청
	resp, err := client.Get(srv.URL + adminSPABaseURL + "/assets/nonexistent-file.js")
	if err != nil {
		t.Fatalf("GET /admin/assets/nonexistent-file.js: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — 확장자가 있는 경우 SPA 폴백(index.html)이 반환되지 않아야 함:
	// 즉 404 Not Found이어야 함 (파일이 없으므로).
	// 만약 200이 반환된다면, 이는 .js 요청도 index.html로 폴백된 것으로 잘못된 동작입니다.
	if resp.StatusCode == http.StatusOK {
		// index.html이 반환되었다면 Content-Type을 확인하여 HTML이 아닌지 검증
		ct := resp.Header.Get("Content-Type")
		if strings.Contains(ct, "text/html") {
			t.Errorf("GET /admin/assets/nonexistent-file.js returned text/html (index.html fallback), "+
				"want 404 for non-existent static files with extension; status = %d, Content-Type = %q",
				resp.StatusCode, ct)
		}
	} else if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /admin/assets/nonexistent-file.js: status = %d, want 404 (file not found)",
			resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Admin 세션 미들웨어 격리 테스트
// admin_session 쿠키와 기존 OAuth2 session 쿠키의 분리 검증
// ---------------------------------------------------------------------------

// TestAdminSessionMiddleware_OAuthSessionCookie_IsRejected verifies that the
// regular OAuth2 "session" cookie is NOT accepted by the admin session
// middleware protecting the dashboard endpoints.
func TestAdminSessionMiddleware_OAuthSessionCookie_IsRejected(t *testing.T) {
	// Arrange
	srv, client, _, _ := newAdminSPATestServer(t)

	// OAuth2 session 쿠키 값 (admin_session이 아님)
	req, err := http.NewRequest(http.MethodGet, srv.URL+adminDashboardStatsURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	// OAuth2 session 쿠키를 admin_session 위치에 전달하는 것이 아니라
	// 잘못된 쿠키 이름으로 전달
	req.AddCookie(&http.Cookie{
		Name:  "session",           // OAuth2 세션 쿠키 이름
		Value: "some-valid-looking-value",
	})

	// Act
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", adminDashboardStatsURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — OAuth2 session 쿠키는 admin_session 미들웨어에서 거부되어야 함
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s with OAuth2 session cookie (not admin_session): status = %d, want 401",
			adminDashboardStatsURL, resp.StatusCode)
	}
}
