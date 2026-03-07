// Package handler_test — Admin SPA 서빙 핸들러 통합 테스트 (TDD Red Phase)
//
// 이 테스트들은 다음 기능이 구현되기 전에 작성되었으므로
// 현재 컴파일/실패 상태가 정상입니다.
//
// 구현이 필요한 항목:
//
//  1. Admin SPA 서빙 핸들러 (internal/handler/admin_spa.go):
//     //go:embed admin/dist
//     var adminDistFS embed.FS
//
//     func NewAdminSPAHandler() http.HandlerFunc
//     - GET /admin           → admin/dist/index.html 서빙
//     - GET /admin/login     → admin/dist/index.html 서빙 (SPA 클라이언트 라우팅)
//     - GET /admin/clients   → admin/dist/index.html 서빙 (SPA 클라이언트 라우팅)
//     - GET /admin/assets/*  → embed된 정적 파일 서빙
//     - /api/* 경로는 SPA fallback 대상이 아님
//
//  2. embed 파일 시스템 구조 (internal/handler/admin/dist/):
//     - index.html           (SPA 진입점)
//     - assets/main.js       (번들된 JS)
//     - assets/main.css      (번들된 CSS, 선택적)
//
//  3. 라우트 등록 (internal/testhelper/server.go buildRouter()):
//     spaHandler := handler.NewAdminSPAHandler()
//     r.Get("/admin", spaHandler)
//     r.Get("/admin/*", spaHandler)
//
// 테스트 커버리지:
//   - GET /admin               → 200 OK + text/html + index.html 내용
//   - GET /admin/login         → 200 OK + text/html (SPA fallback)
//   - GET /admin/clients       → 200 OK + text/html (SPA fallback)
//   - GET /admin/settings      → 200 OK + text/html (SPA fallback, 알 수 없는 경로)
//   - GET /admin/assets/main.js → 200 OK + JS Content-Type + 실제 파일
//   - GET /admin/nonexistent   → 200 OK + text/html (SPA fallback, 404 대신 index.html)
//   - /api/* 경로는 SPA가 처리하지 않음 (404 or handler 응답)
//   - SPA HTML 응답에 <html> 태그 포함 여부
//   - 정적 파일은 캐시 관련 헤더를 포함 (Content-Type 확인)
package handler_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// URL 상수
// ---------------------------------------------------------------------------

const adminRootURL = "/admin"
const adminLoginPageURL = "/admin/login"
const adminClientsPageURL = "/admin/clients"
const adminSettingsPageURL = "/admin/settings"
const adminAssetsMainJSURL = "/admin/assets/main.js"
const adminNonexistentURL = "/admin/this-page-does-not-exist"

// ---------------------------------------------------------------------------
// GET /admin — 루트 대시보드 페이지
// ---------------------------------------------------------------------------

// TestAdminSPA_Root_Returns200은 GET /admin이 200 OK를 반환하는지 검증합니다.
func TestAdminSPA_Root_Returns200(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp, err := client.Get(srv.URL + adminRootURL)
	if err != nil {
		t.Fatalf("GET %s: %v", adminRootURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s: status = %d, want 200", adminRootURL, resp.StatusCode)
	}
}

// TestAdminSPA_Root_ContentTypeIsHTML은 GET /admin 응답의 Content-Type이
// text/html을 포함하는지 검증합니다.
func TestAdminSPA_Root_ContentTypeIsHTML(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp, err := client.Get(srv.URL + adminRootURL)
	if err != nil {
		t.Fatalf("GET %s: %v", adminRootURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — Content-Type: text/html
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("GET %s: Content-Type = %q, want to contain \"text/html\"", adminRootURL, ct)
	}
}

// TestAdminSPA_Root_BodyContainsHTML은 GET /admin 응답 body에
// HTML 마크업(<html> 태그)이 포함되어 있는지 검증합니다.
func TestAdminSPA_Root_BodyContainsHTML(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp, err := client.Get(srv.URL + adminRootURL)
	if err != nil {
		t.Fatalf("GET %s: %v", adminRootURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — body에 HTML 마크업이 포함되어야 합니다.
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "<html") {
		t.Errorf("GET %s: body does not contain <html tag; body = %.200s...", adminRootURL, bodyStr)
	}
}

// ---------------------------------------------------------------------------
// GET /admin/login — SPA 클라이언트 라우팅 (index.html fallback)
// ---------------------------------------------------------------------------

// TestAdminSPA_LoginPage_Returns200은 GET /admin/login이 200 OK를 반환하는지
// 검증합니다 (SPA index.html fallback).
func TestAdminSPA_LoginPage_Returns200(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp, err := client.Get(srv.URL + adminLoginPageURL)
	if err != nil {
		t.Fatalf("GET %s: %v", adminLoginPageURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — 200 OK (SPA fallback으로 index.html 서빙)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s: status = %d, want 200", adminLoginPageURL, resp.StatusCode)
	}
}

// TestAdminSPA_LoginPage_ContentTypeIsHTML은 GET /admin/login 응답이
// text/html을 반환하는지 검증합니다.
func TestAdminSPA_LoginPage_ContentTypeIsHTML(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp, err := client.Get(srv.URL + adminLoginPageURL)
	if err != nil {
		t.Fatalf("GET %s: %v", adminLoginPageURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — Content-Type: text/html
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("GET %s: Content-Type = %q, want to contain \"text/html\"", adminLoginPageURL, ct)
	}
}

// TestAdminSPA_LoginPage_ServesIndexHTML은 /admin/login이 /admin과 동일한
// index.html 내용을 서빙하는지 검증합니다 (SPA의 클라이언트 사이드 라우팅).
func TestAdminSPA_LoginPage_ServesIndexHTML(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act — /admin과 /admin/login이 동일한 HTML을 서빙하는지 비교합니다.
	rootResp, err := client.Get(srv.URL + adminRootURL)
	if err != nil {
		t.Fatalf("GET %s: %v", adminRootURL, err)
	}
	defer rootResp.Body.Close()
	rootBody, err := io.ReadAll(rootResp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll (root): %v", err)
	}

	loginResp, err := client.Get(srv.URL + adminLoginPageURL)
	if err != nil {
		t.Fatalf("GET %s: %v", adminLoginPageURL, err)
	}
	defer loginResp.Body.Close()
	loginBody, err := io.ReadAll(loginResp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll (login): %v", err)
	}

	// Assert — 두 응답의 내용이 동일해야 합니다 (동일한 index.html).
	if rootResp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", adminRootURL, rootResp.StatusCode)
	}
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", adminLoginPageURL, loginResp.StatusCode)
	}

	if string(rootBody) != string(loginBody) {
		t.Errorf("GET %s and GET %s serve different content; SPA fallback must serve same index.html",
			adminRootURL, adminLoginPageURL)
	}
}

// ---------------------------------------------------------------------------
// GET /admin/clients — SPA 클라이언트 라우팅 (index.html fallback)
// ---------------------------------------------------------------------------

// TestAdminSPA_ClientsPage_Returns200은 GET /admin/clients가 200을 반환하는지
// 검증합니다 (SPA fallback).
func TestAdminSPA_ClientsPage_Returns200(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp, err := client.Get(srv.URL + adminClientsPageURL)
	if err != nil {
		t.Fatalf("GET %s: %v", adminClientsPageURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s: status = %d, want 200 (SPA fallback)", adminClientsPageURL, resp.StatusCode)
	}
}

// TestAdminSPA_SettingsPage_Returns200은 정의되지 않은 /admin/settings 경로에
// 접근했을 때 SPA fallback으로 200을 반환하는지 검증합니다.
func TestAdminSPA_SettingsPage_Returns200(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp, err := client.Get(srv.URL + adminSettingsPageURL)
	if err != nil {
		t.Fatalf("GET %s: %v", adminSettingsPageURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — 200 OK (알 수 없는 경로도 SPA fallback으로 처리)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s: status = %d, want 200 (SPA fallback)", adminSettingsPageURL, resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// GET /admin/nonexistent — 알 수 없는 경로 (SPA fallback)
// ---------------------------------------------------------------------------

// TestAdminSPA_UnknownPath_Returns200WithIndexHTML은 /admin 하위의 알 수 없는
// 경로에 접근하면 404 대신 index.html을 서빙하는지 검증합니다.
// SPA 라우팅에서 클라이언트가 모든 경로를 처리하므로 서버는 항상 index.html을
// 반환해야 합니다.
func TestAdminSPA_UnknownPath_Returns200WithIndexHTML(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp, err := client.Get(srv.URL + adminNonexistentURL)
	if err != nil {
		t.Fatalf("GET %s: %v", adminNonexistentURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 404가 아닌 200 OK 여야 합니다.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s: status = %d, want 200 (SPA fallback, not 404); body = %.200s",
			adminNonexistentURL, resp.StatusCode, body)
	}

	// Assert — HTML 내용이어야 합니다.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("GET %s: Content-Type = %q, want to contain \"text/html\"",
			adminNonexistentURL, ct)
	}
}

// ---------------------------------------------------------------------------
// GET /admin/assets/main.js — 정적 파일 서빙
// ---------------------------------------------------------------------------

// TestAdminSPA_StaticAsset_Returns200은 GET /admin/assets/main.js가
// 200 OK를 반환하는지 검증합니다.
func TestAdminSPA_StaticAsset_Returns200(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp, err := client.Get(srv.URL + adminAssetsMainJSURL)
	if err != nil {
		t.Fatalf("GET %s: %v", adminAssetsMainJSURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — 200 OK (정적 파일이 embed되어 있어야 함)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s: status = %d, want 200", adminAssetsMainJSURL, resp.StatusCode)
	}
}

// TestAdminSPA_StaticAsset_ContentTypeIsJavaScript는 main.js 응답의
// Content-Type이 JavaScript 관련 MIME 타입인지 검증합니다.
func TestAdminSPA_StaticAsset_ContentTypeIsJavaScript(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp, err := client.Get(srv.URL + adminAssetsMainJSURL)
	if err != nil {
		t.Fatalf("GET %s: %v", adminAssetsMainJSURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status = %d, want 200", adminAssetsMainJSURL, resp.StatusCode)
	}

	// Assert — Content-Type이 JavaScript MIME 타입이어야 합니다.
	// application/javascript 또는 text/javascript 모두 허용합니다.
	ct := resp.Header.Get("Content-Type")
	isJS := strings.Contains(ct, "javascript") || strings.Contains(ct, "application/js")
	if !isJS {
		t.Errorf("GET %s: Content-Type = %q, want JavaScript MIME type (e.g. application/javascript)",
			adminAssetsMainJSURL, ct)
	}
}

// TestAdminSPA_StaticAsset_BodyIsNotIndexHTML은 정적 파일 요청이
// index.html이 아닌 실제 JS 파일 내용을 반환하는지 검증합니다.
func TestAdminSPA_StaticAsset_BodyIsNotIndexHTML(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act — index.html 내용을 가져옵니다.
	rootResp, err := client.Get(srv.URL + adminRootURL)
	if err != nil {
		t.Fatalf("GET %s: %v", adminRootURL, err)
	}
	defer rootResp.Body.Close()
	rootBody, err := io.ReadAll(rootResp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll (root): %v", err)
	}

	// Act — main.js 내용을 가져옵니다.
	jsResp, err := client.Get(srv.URL + adminAssetsMainJSURL)
	if err != nil {
		t.Fatalf("GET %s: %v", adminAssetsMainJSURL, err)
	}
	defer jsResp.Body.Close()
	jsBody, err := io.ReadAll(jsResp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll (js): %v", err)
	}

	if rootResp.StatusCode != http.StatusOK || jsResp.StatusCode != http.StatusOK {
		t.Skip("skipping body comparison: one or both endpoints returned non-200")
	}

	// Assert — main.js 내용이 index.html과 달라야 합니다.
	if string(rootBody) == string(jsBody) {
		t.Errorf("GET %s and GET %s returned identical content; JS file should not be index.html fallback",
			adminRootURL, adminAssetsMainJSURL)
	}
}

// ---------------------------------------------------------------------------
// /api/* 경로는 SPA 대상이 아님
// ---------------------------------------------------------------------------

// TestAdminSPA_APIPathsNotHandledBySPA는 /api/ 하위 경로가 SPA에 의해
// index.html로 fallback되지 않는지 검증합니다.
// API 경로는 고유한 핸들러 또는 404를 반환해야 합니다.
func TestAdminSPA_APIPathsNotHandledBySPA(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act — 존재하지 않는 API 경로에 접근합니다.
	resp, err := client.Get(srv.URL + "/api/admin/nonexistent-api-endpoint")
	if err != nil {
		t.Fatalf("GET /api/admin/nonexistent-api-endpoint: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — /api/ 경로는 SPA fallback으로 index.html을 반환하면 안 됩니다.
	// SPA가 처리하지 않으므로 404를 반환하거나 JSON error를 반환해야 합니다.
	// index.html을 반환하는 것은 잘못된 동작입니다.
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/html") && resp.StatusCode == http.StatusOK {
		bodyStr := string(body)
		if strings.Contains(bodyStr, "<html") {
			t.Errorf("GET /api/admin/nonexistent: API path returned HTML (SPA index.html), "+
				"want 404 or JSON error; status = %d, Content-Type = %q",
				resp.StatusCode, ct)
		}
	}
}

// TestAdminSPA_APILoginNotHandledBySPA는 POST /api/admin/login이
// SPA에 의해 가로채이지 않는지 확인합니다.
// API 엔드포인트는 SPA가 아닌 전용 핸들러가 처리해야 합니다.
func TestAdminSPA_APILoginNotHandledBySPA(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act — POST /api/admin/login 요청 (올바른 credentials)
	resp := doAdminLogin(t, client, srv.URL, "admin@test.local", "test-password")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — HTML이 아닌 JSON 응답이어야 합니다.
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/html") {
		t.Errorf("POST %s returned HTML (SPA fallback), want JSON; Content-Type = %q; body = %.200s",
			adminLoginURL, ct, body)
	}
}

// ---------------------------------------------------------------------------
// SPA 서빙 일관성 검증
// ---------------------------------------------------------------------------

// TestAdminSPA_MultipleSubPaths_AllReturnHTML은 여러 /admin/* 하위 경로가
// 모두 HTML을 반환하는지 한 번에 검증합니다.
func TestAdminSPA_MultipleSubPaths_AllReturnHTML(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	spaPaths := []string{
		"/admin",
		"/admin/login",
		"/admin/clients",
		"/admin/settings",
		"/admin/unknown-route",
	}

	for _, path := range spaPaths {
		path := path // capture range variable
		t.Run(path, func(t *testing.T) {
			// Act
			resp, err := client.Get(srv.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("io.ReadAll: %v", err)
			}

			// Assert — 200 OK
			if resp.StatusCode != http.StatusOK {
				t.Errorf("GET %s: status = %d, want 200; body = %.200s",
					path, resp.StatusCode, body)
			}

			// Assert — HTML 응답
			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(ct, "text/html") {
				t.Errorf("GET %s: Content-Type = %q, want text/html", path, ct)
			}
		})
	}
}
