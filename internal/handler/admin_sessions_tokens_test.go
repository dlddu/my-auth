// Package handler_test — Admin Session & Token management HTTP 핸들러 통합 테스트 (TDD Red Phase)
//
// 이 테스트들은 다음 기능이 구현되기 전에 작성되었으므로
// 현재 실패 상태가 정상입니다.
//
// 구현이 필요한 항목:
//
//  1. AdminSessionTokenStore 인터페이스 (internal/handler/admin_sessions_tokens.go):
//
//     type AdminSessionTokenStore interface {
//         ListSessions(ctx context.Context) ([]SessionInfo, error)
//         DeleteSession(ctx context.Context, id string) error
//         DeleteAllSessions(ctx context.Context) error
//         ListTokens(ctx context.Context) ([]TokenInfo, error)
//         DeleteToken(ctx context.Context, signature string) error
//         DeleteAllTokens(ctx context.Context) error
//     }
//
//  2. 응답 구조체 (internal/handler/admin_sessions_tokens.go):
//
//     type SessionInfo struct {
//         ID        string `json:"id"`
//         ClientID  string `json:"client_id"`
//         Subject   string `json:"subject"`
//         Scopes    string `json:"scopes"`
//         ExpiresAt string `json:"expires_at"`
//         CreatedAt string `json:"created_at"`
//     }
//     type TokenInfo struct {
//         Signature string `json:"signature"`
//         RequestID string `json:"request_id"`
//         ClientID  string `json:"client_id"`
//         Subject   string `json:"subject"`
//         Scopes    string `json:"scopes"`
//         ExpiresAt string `json:"expires_at"`
//         CreatedAt string `json:"created_at"`
//     }
//
//  3. 핸들러 함수 (internal/handler/admin_sessions_tokens.go):
//     - GET    /api/admin/sessions      → NewListSessionsHandler(store)
//     - DELETE /api/admin/sessions/{id} → NewDeleteSessionHandler(store)
//     - DELETE /api/admin/sessions      → NewDeleteAllSessionsHandler(store)
//     - GET    /api/admin/tokens        → NewListTokensHandler(store)
//     - DELETE /api/admin/tokens/{id}   → NewDeleteTokenHandler(store)
//     - DELETE /api/admin/tokens        → NewDeleteAllTokensHandler(store)
//
//  4. 스토리지 메서드 (internal/storage/store.go):
//     - ListSessions(ctx) ([]SessionInfo, error)
//     - DeleteSession(ctx, id string) error
//     - DeleteAllSessions(ctx) error
//     - ListTokens(ctx) ([]TokenInfo, error)
//     - DeleteToken(ctx, signature string) error
//     - DeleteAllTokens(ctx) error
//
//  5. 라우트 등록 (internal/testhelper/server.go buildRouter() — 이미 추가됨):
//     r.Get("/sessions", handler.NewListSessionsHandler(store))
//     r.Delete("/sessions", handler.NewDeleteAllSessionsHandler(store))
//     r.Delete("/sessions/{id}", handler.NewDeleteSessionHandler(store))
//     r.Get("/tokens", handler.NewListTokensHandler(store))
//     r.Delete("/tokens", handler.NewDeleteAllTokensHandler(store))
//     r.Delete("/tokens/{id}", handler.NewDeleteTokenHandler(store))
//
//  6. testhelper 확장 (internal/testhelper/server.go):
//     testhelper.NewTestServerWithDSN(t, dsn) 함수를 추가하면
//     테스트 코드와 서버가 동일한 DB를 공유할 수 있습니다.
//
// 테스트 커버리지:
//   - GET  /api/admin/sessions: 인증 없음 → 401
//   - GET  /api/admin/sessions: 빈 목록 → 200, 빈 배열
//   - GET  /api/admin/sessions: 세션 존재 시 → 200, 필드 포함
//   - DELETE /api/admin/sessions/{id}: 존재하는 세션 → 204
//   - DELETE /api/admin/sessions/{id}: 없는 세션 → 404
//   - DELETE /api/admin/sessions: 전체 폐기 → 204, 이후 목록 비어있음
//   - GET  /api/admin/tokens: 인증 없음 → 401
//   - GET  /api/admin/tokens: 빈 목록 → 200, 빈 배열
//   - GET  /api/admin/tokens: 토큰 존재 시 → 200, 필드 포함
//   - DELETE /api/admin/tokens/{id}: 존재하는 토큰 → 204
//   - DELETE /api/admin/tokens/{id}: 없는 토큰 → 404
//   - DELETE /api/admin/tokens: 전체 폐기 → 204, 이후 목록 비어있음
package handler_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dlddu/my-auth/internal/database"
	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// URL 상수
// ---------------------------------------------------------------------------

const adminSessionsURL = "/api/admin/sessions"
const adminTokensURL = "/api/admin/tokens"

// ---------------------------------------------------------------------------
// 응답 구조체 (구현이 반환할 JSON 형태를 반영)
// ---------------------------------------------------------------------------

// adminSessionItem은 GET /api/admin/sessions 응답의 각 세션 항목입니다.
type adminSessionItem struct {
	ID        string `json:"id"`
	ClientID  string `json:"client_id"`
	Subject   string `json:"subject"`
	Scopes    string `json:"scopes"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

// adminTokenItem은 GET /api/admin/tokens 응답의 각 토큰 항목입니다.
type adminTokenItem struct {
	Signature string `json:"signature"`
	RequestID string `json:"request_id"`
	ClientID  string `json:"client_id"`
	Subject   string `json:"subject"`
	Scopes    string `json:"scopes"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

// ---------------------------------------------------------------------------
// 테스트 데이터 시딩 헬퍼
// ---------------------------------------------------------------------------

// seedSession은 authorization_codes 테이블에 테스트용 세션 레코드를 직접 INSERT합니다.
// used=1로 설정하여 완료된 인증 세션을 시뮬레이션합니다.
// request_data에는 request_id (id 필드)가 포함되어 DeleteSession 시 토큰 revocation에 사용됩니다.
// clientID는 사전에 clients 테이블에 존재해야 합니다.
func seedSession(t *testing.T, db *sql.DB, id, clientID, subject, scopes string, expiresAt time.Time) {
	t.Helper()

	_, err := db.ExecContext(context.Background(),
		`INSERT INTO authorization_codes (code, client_id, subject, redirect_uri, scopes, expires_at, used, request_data)
		 VALUES (?, ?, ?, ?, ?, ?, 1, ?)`,
		id,
		clientID,
		subject,
		"",
		scopes,
		expiresAt.UTC().Format(time.RFC3339),
		fmt.Sprintf(`{"id":"%s"}`, id),
	)
	if err != nil {
		t.Fatalf("seedSession: INSERT authorization_codes code=%q: %v", id, err)
	}
}

// seedToken은 tokens 테이블에 테스트용 토큰 레코드를 직접 INSERT합니다.
// clientID는 사전에 clients 테이블에 존재해야 합니다.
func seedToken(t *testing.T, db *sql.DB, signature, requestID, clientID, subject, scopes string, expiresAt time.Time) {
	t.Helper()

	_, err := db.ExecContext(context.Background(),
		`INSERT INTO tokens (signature, request_id, client_id, subject, scopes, expires_at, request_data)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		signature,
		requestID,
		clientID,
		subject,
		scopes,
		expiresAt.UTC().Format(time.RFC3339),
		"{}",
	)
	if err != nil {
		t.Fatalf("seedToken: INSERT tokens signature=%q: %v", signature, err)
	}
}

// seedTestClientForSessionToken은 sessions/tokens 테이블의 FOREIGN KEY
// 제약 조건을 만족시키기 위해 clients 테이블에 "test-client" 레코드를 삽입합니다.
// newServerWithDirectDB가 반환하는 DB(서버와 분리된 시딩용 DB)에서만 사용합니다.
func seedTestClientForSessionToken(t *testing.T, db *sql.DB) {
	t.Helper()

	_, err := db.ExecContext(context.Background(),
		`INSERT INTO clients (id, secret, redirect_uris, grant_types, response_types, scopes, token_endpoint_auth_method, is_public)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"test-client",
		"",
		`["http://localhost:9000/callback"]`,
		`["authorization_code","refresh_token"]`,
		`["code"]`,
		"openid profile email",
		"client_secret_basic",
		false,
	)
	if err != nil {
		t.Fatalf("seedTestClientForSessionToken: INSERT clients: %v", err)
	}
}

// newServerWithDirectDB는 서버와 직접 데이터를 공유할 수 있는 *sql.DB를 함께
// 반환하는 테스트 헬퍼입니다.
//
// 현재 상태 (TDD Red Phase):
//   - testhelper.NewTestServer는 내부에서 독립적인 DSN을 생성하므로,
//     반환된 *sql.DB와 서버 DB가 서로 다른 파일을 가리킵니다.
//   - 따라서 이 헬퍼로 시딩한 데이터는 HTTP 요청을 통해 서버에서 보이지 않습니다.
//   - 이것은 의도된 Red Phase 동작입니다: 핸들러 + testhelper 확장이 완료되면
//     아래 구현 방향에 따라 연결하여 테스트를 통과시킬 수 있습니다.
//
// Green Phase 구현 방향:
//  1. testhelper 패키지에 NewTestServerWithDSN(t, dsn) 함수를 추가합니다.
//  2. 이 헬퍼에서 NewTestServerWithDSN(t, dsn)을 호출하도록 교체합니다.
//  3. seedTestClientForSessionToken 호출은 제거합니다
//     (NewTestServerWithDSN이 내부에서 seedTestClient를 호출하기 때문).
func newServerWithDirectDB(t *testing.T) (*httptest.Server, *http.Client, *sql.DB) {
	t.Helper()

	// 마이그레이션이 완료된 DSN을 생성합니다.
	dsn := testhelper.NewTestDB(t)

	// 시딩용 DB 연결 — 서버와 동일한 DSN을 공유하므로 데이터가 보입니다.
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("newServerWithDirectDB: database.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Logf("newServerWithDirectDB cleanup: db.Close: %v", err)
		}
	})

	// Green Phase: NewTestServerWithDSN을 사용하여 서버와 DB를 공유합니다.
	// seedTestClient는 NewTestServerWithDSN 내부에서 호출되므로 여기서는 불필요합니다.
	srv, client := testhelper.NewTestServerWithDSN(t, dsn)

	return srv, client, db
}

// ---------------------------------------------------------------------------
// 세션 관리 테스트
// ---------------------------------------------------------------------------

// TestListSessions_NoAuth_Returns401은 Authorization 헤더 없이
// GET /api/admin/sessions를 요청하면 401이 반환되는지 검증합니다.
func TestListSessions_NoAuth_Returns401(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act — Authorization 헤더 없음
	resp := doAdminRequestWithToken(t, client, http.MethodGet,
		srv.URL+adminSessionsURL, "")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s without auth: status = %d, want 401", adminSessionsURL, resp.StatusCode)
	}
}

// TestListSessions_EmptyList_Returns200은 세션이 없을 때
// GET /api/admin/sessions가 200과 빈 JSON 배열을 반환하는지 검증합니다.
func TestListSessions_EmptyList_Returns200(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminSessionsURL, nil)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200; body = %s",
			adminSessionsURL, resp.StatusCode, body)
	}

	// Assert — 응답이 JSON 배열로 파싱되어야 함
	var list []adminSessionItem
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("response is not a JSON array: %v — body: %s", err, body)
	}

	// Assert — 빈 배열이어야 함
	if len(list) != 0 {
		t.Errorf("GET %s: len(list) = %d, want 0; body = %s",
			adminSessionsURL, len(list), body)
	}
}

// TestListSessions_WithSession_Returns200WithFields는 세션이 존재할 때
// GET /api/admin/sessions가 200과 id, client_id, expires_at 필드를 포함한
// 배열을 반환하는지 검증합니다.
//
// 데이터 시딩: sessions 테이블에 직접 INSERT합니다.
// Red Phase 주의: newServerWithDirectDB는 서버와 DB를 공유하지 않으므로
// 이 테스트는 testhelper.NewTestServerWithDSN 구현 후 통과합니다.
func TestListSessions_WithSession_Returns200WithFields(t *testing.T) {
	// Arrange
	srv, client, db := newServerWithDirectDB(t)

	expiresAt := time.Now().Add(1 * time.Hour)
	seedSession(t, db, "sess-list-001", "test-client", "user@example.com",
		"openid profile", expiresAt)

	// Act
	resp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminSessionsURL, nil)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200; body = %s",
			adminSessionsURL, resp.StatusCode, body)
	}

	// Assert — JSON 배열로 파싱 가능
	var list []adminSessionItem
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("response is not a JSON array: %v — body: %s", err, body)
	}

	// Assert — 시딩한 세션이 목록에 존재
	if len(list) == 0 {
		t.Fatalf("GET %s: list is empty, want at least 1 session; body = %s",
			adminSessionsURL, body)
	}

	// Assert — 필수 필드 검증
	var found *adminSessionItem
	for i := range list {
		if list[i].ID == "sess-list-001" {
			found = &list[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("GET %s: seeded session %q not found in response; body = %s",
			adminSessionsURL, "sess-list-001", body)
	}
	if found.ClientID == "" {
		t.Errorf("session.client_id is empty, want %q", "test-client")
	}
	if found.ExpiresAt == "" {
		t.Errorf("session.expires_at is empty, want non-empty RFC3339 timestamp")
	}
}

// TestDeleteSession_ExistingID_Returns204는 존재하는 세션을
// DELETE /api/admin/sessions/{id}로 폐기하면 204가 반환되는지 검증합니다.
//
// Red Phase 주의: newServerWithDirectDB는 서버와 DB를 공유하지 않으므로
// 이 테스트는 testhelper.NewTestServerWithDSN 구현 후 통과합니다.
func TestDeleteSession_ExistingID_Returns204(t *testing.T) {
	// Arrange
	srv, client, db := newServerWithDirectDB(t)

	expiresAt := time.Now().Add(1 * time.Hour)
	seedSession(t, db, "sess-del-001", "test-client", "user@example.com",
		"openid", expiresAt)

	// Act
	resp := doAdminRequest(t, client, http.MethodDelete,
		fmt.Sprintf("%s%s/%s", srv.URL, adminSessionsURL, "sess-del-001"), nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE %s/sess-del-001 status = %d, want 204",
			adminSessionsURL, resp.StatusCode)
	}
}

// TestDeleteSession_NonExistentID_Returns404는 존재하지 않는 세션 ID로
// DELETE /api/admin/sessions/{id}를 요청하면 404가 반환되는지 검증합니다.
func TestDeleteSession_NonExistentID_Returns404(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequest(t, client, http.MethodDelete,
		fmt.Sprintf("%s%s/%s", srv.URL, adminSessionsURL, "does-not-exist-sess-xyz"), nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE %s/does-not-exist-sess-xyz status = %d, want 404",
			adminSessionsURL, resp.StatusCode)
	}
}

// TestDeleteAllSessions_Returns204AndListBecomesEmpty는 전체 세션 일괄 폐기 후
// 204가 반환되고 이후 목록 조회가 빈 배열을 반환하는지 검증합니다.
//
// Red Phase 주의: newServerWithDirectDB는 서버와 DB를 공유하지 않으므로
// 이 테스트는 testhelper.NewTestServerWithDSN 구현 후 통과합니다.
func TestDeleteAllSessions_Returns204AndListBecomesEmpty(t *testing.T) {
	// Arrange — 세션 2개 삽입
	srv, client, db := newServerWithDirectDB(t)

	expiresAt := time.Now().Add(1 * time.Hour)
	seedSession(t, db, "sess-bulk-001", "test-client", "user1@example.com",
		"openid", expiresAt)
	seedSession(t, db, "sess-bulk-002", "test-client", "user2@example.com",
		"profile", expiresAt)

	// Act — 전체 폐기
	delResp := doAdminRequest(t, client, http.MethodDelete,
		srv.URL+adminSessionsURL, nil)
	defer delResp.Body.Close()
	_, _ = io.Copy(io.Discard, delResp.Body)

	// Assert — 204 No Content
	if delResp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE %s (bulk) status = %d, want 204", adminSessionsURL, delResp.StatusCode)
	}

	// Assert — 이후 목록이 비어있음
	listResp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminSessionsURL, nil)
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("GET %s after bulk delete: status = %d, want 200; body = %s",
			adminSessionsURL, listResp.StatusCode, body)
	}

	var list []adminSessionItem
	readJSONBody(t, listResp, &list)

	if len(list) != 0 {
		t.Errorf("GET %s after bulk delete: len(list) = %d, want 0",
			adminSessionsURL, len(list))
	}
}

// ---------------------------------------------------------------------------
// 토큰 관리 테스트
// ---------------------------------------------------------------------------

// TestListTokens_NoAuth_Returns401은 Authorization 헤더 없이
// GET /api/admin/tokens를 요청하면 401이 반환되는지 검증합니다.
func TestListTokens_NoAuth_Returns401(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act — Authorization 헤더 없음
	resp := doAdminRequestWithToken(t, client, http.MethodGet,
		srv.URL+adminTokensURL, "")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s without auth: status = %d, want 401", adminTokensURL, resp.StatusCode)
	}
}

// TestListTokens_EmptyList_Returns200은 토큰이 없을 때
// GET /api/admin/tokens가 200과 빈 JSON 배열을 반환하는지 검증합니다.
func TestListTokens_EmptyList_Returns200(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminTokensURL, nil)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200; body = %s",
			adminTokensURL, resp.StatusCode, body)
	}

	// Assert — 응답이 JSON 배열로 파싱되어야 함
	var list []adminTokenItem
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("response is not a JSON array: %v — body: %s", err, body)
	}

	// Assert — 빈 배열이어야 함
	if len(list) != 0 {
		t.Errorf("GET %s: len(list) = %d, want 0; body = %s",
			adminTokensURL, len(list), body)
	}
}

// TestListTokens_WithToken_Returns200WithFields는 토큰이 존재할 때
// GET /api/admin/tokens가 200과 signature, client_id, expires_at 필드를 포함한
// 배열을 반환하는지 검증합니다.
//
// 데이터 시딩: tokens 테이블에 직접 INSERT합니다.
// Red Phase 주의: newServerWithDirectDB는 서버와 DB를 공유하지 않으므로
// 이 테스트는 testhelper.NewTestServerWithDSN 구현 후 통과합니다.
func TestListTokens_WithToken_Returns200WithFields(t *testing.T) {
	// Arrange
	srv, client, db := newServerWithDirectDB(t)

	expiresAt := time.Now().Add(1 * time.Hour)
	seedToken(t, db, "tok-list-sig-001", "req-list-001", "test-client",
		"user@example.com", "openid profile", expiresAt)

	// Act
	resp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminTokensURL, nil)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200; body = %s",
			adminTokensURL, resp.StatusCode, body)
	}

	// Assert — JSON 배열로 파싱 가능
	var list []adminTokenItem
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("response is not a JSON array: %v — body: %s", err, body)
	}

	// Assert — 시딩한 토큰이 목록에 존재
	if len(list) == 0 {
		t.Fatalf("GET %s: list is empty, want at least 1 token; body = %s",
			adminTokensURL, body)
	}

	// Assert — 필수 필드 검증
	var found *adminTokenItem
	for i := range list {
		if list[i].Signature == "tok-list-sig-001" {
			found = &list[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("GET %s: seeded token %q not found in response; body = %s",
			adminTokensURL, "tok-list-sig-001", body)
	}
	if found.ClientID == "" {
		t.Errorf("token.client_id is empty, want %q", "test-client")
	}
	if found.ExpiresAt == "" {
		t.Errorf("token.expires_at is empty, want non-empty RFC3339 timestamp")
	}
}

// TestDeleteToken_ExistingSignature_Returns204는 존재하는 토큰을
// DELETE /api/admin/tokens/{id}로 폐기하면 204가 반환되는지 검증합니다.
//
// Red Phase 주의: newServerWithDirectDB는 서버와 DB를 공유하지 않으므로
// 이 테스트는 testhelper.NewTestServerWithDSN 구현 후 통과합니다.
func TestDeleteToken_ExistingSignature_Returns204(t *testing.T) {
	// Arrange
	srv, client, db := newServerWithDirectDB(t)

	expiresAt := time.Now().Add(1 * time.Hour)
	seedToken(t, db, "tok-del-sig-001", "req-del-001", "test-client",
		"user@example.com", "openid", expiresAt)

	// Act
	resp := doAdminRequest(t, client, http.MethodDelete,
		fmt.Sprintf("%s%s/%s", srv.URL, adminTokensURL, "tok-del-sig-001"), nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE %s/tok-del-sig-001 status = %d, want 204",
			adminTokensURL, resp.StatusCode)
	}
}

// TestDeleteToken_NonExistentSignature_Returns404는 존재하지 않는 서명으로
// DELETE /api/admin/tokens/{id}를 요청하면 404가 반환되는지 검증합니다.
func TestDeleteToken_NonExistentSignature_Returns404(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequest(t, client, http.MethodDelete,
		fmt.Sprintf("%s%s/%s", srv.URL, adminTokensURL, "does-not-exist-tok-xyz"), nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE %s/does-not-exist-tok-xyz status = %d, want 404",
			adminTokensURL, resp.StatusCode)
	}
}

// TestDeleteAllTokens_Returns204AndListBecomesEmpty는 전체 토큰 일괄 폐기 후
// 204가 반환되고 이후 목록 조회가 빈 배열을 반환하는지 검증합니다.
//
// Red Phase 주의: newServerWithDirectDB는 서버와 DB를 공유하지 않으므로
// 이 테스트는 testhelper.NewTestServerWithDSN 구현 후 통과합니다.
func TestDeleteAllTokens_Returns204AndListBecomesEmpty(t *testing.T) {
	// Arrange — 토큰 2개 삽입
	srv, client, db := newServerWithDirectDB(t)

	expiresAt := time.Now().Add(1 * time.Hour)
	seedToken(t, db, "tok-bulk-sig-001", "req-bulk-001", "test-client",
		"user1@example.com", "openid", expiresAt)
	seedToken(t, db, "tok-bulk-sig-002", "req-bulk-002", "test-client",
		"user2@example.com", "profile", expiresAt)

	// Act — 전체 폐기
	delResp := doAdminRequest(t, client, http.MethodDelete,
		srv.URL+adminTokensURL, nil)
	defer delResp.Body.Close()
	_, _ = io.Copy(io.Discard, delResp.Body)

	// Assert — 204 No Content
	if delResp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE %s (bulk) status = %d, want 204", adminTokensURL, delResp.StatusCode)
	}

	// Assert — 이후 목록이 비어있음
	listResp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminTokensURL, nil)
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("GET %s after bulk delete: status = %d, want 200; body = %s",
			adminTokensURL, listResp.StatusCode, body)
	}

	var list []adminTokenItem
	readJSONBody(t, listResp, &list)

	if len(list) != 0 {
		t.Errorf("GET %s after bulk delete: len(list) = %d, want 0",
			adminTokensURL, len(list))
	}
}
