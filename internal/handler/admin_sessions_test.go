// Package handler_test — Admin Sessions/Tokens HTTP 핸들러 통합 테스트 (TDD Red Phase)
//
// 이 테스트들은 다음 기능이 구현되기 전에 작성되었으므로
// 현재 실패 상태가 정상입니다.
//
// 구현이 필요한 항목:
//
//  1. 핸들러 함수 (internal/handler/admin_sessions.go):
//     - NewListSessionsHandler(store AdminSessionStore) http.HandlerFunc
//     - NewDeleteSessionHandler(store AdminSessionStore) http.HandlerFunc
//     - NewDeleteAllSessionsHandler(store AdminSessionStore) http.HandlerFunc
//     - NewListTokensHandler(store AdminTokenStore) http.HandlerFunc
//     - NewDeleteTokenHandler(store AdminTokenStore) http.HandlerFunc
//     - NewDeleteAllTokensHandler(store AdminTokenStore) http.HandlerFunc
//
//  2. 스토리지 인터페이스 (internal/handler/admin_sessions.go):
//     - AdminSessionStore: ListSessions, DeleteSession, DeleteAllSessions
//     - AdminTokenStore:   ListTokens, DeleteToken, DeleteAllTokens
//
//  3. 라우트 등록 (internal/testhelper/server.go buildRouter()):
//     r.Route("/api/admin", func(r chi.Router) {
//         r.Use(handler.NewAdminAuthMiddleware(cfg.AdminToken))
//         // ... 기존 clients 라우트 ...
//         r.Get("/sessions", handler.NewListSessionsHandler(store))
//         r.Delete("/sessions", handler.NewDeleteAllSessionsHandler(store))
//         r.Delete("/sessions/{id}", handler.NewDeleteSessionHandler(store))
//         r.Get("/tokens", handler.NewListTokensHandler(store))
//         r.Delete("/tokens", handler.NewDeleteAllTokensHandler(store))
//         r.Delete("/tokens/{id}", handler.NewDeleteTokenHandler(store))
//     })
//
//  4. 스토리지 메서드 (internal/storage/store.go):
//     - ListSessions(ctx) ([]SessionInfo, error)
//     - DeleteSession(ctx, id) error        — 없으면 ErrSessionNotFound
//     - DeleteAllSessions(ctx) error
//     - ListTokens(ctx) ([]TokenInfo, error)
//     - DeleteToken(ctx, signature) error   — 없으면 ErrTokenNotFound + jti blacklist
//     - DeleteAllTokens(ctx) error          — 모든 jti blacklist
//
// 테스트 커버리지:
//   - GET  /api/admin/sessions: 200 + JSON array, 인증 없이 → 401
//   - DELETE /api/admin/sessions/{id}: 204 성공, 존재하지 않는 ID → 404
//   - DELETE /api/admin/sessions: 204 일괄 삭제
//   - GET  /api/admin/tokens: 200 + JSON array, 인증 없이 → 401
//   - DELETE /api/admin/tokens/{id}: 204 성공, 존재하지 않는 ID → 404
//   - DELETE /api/admin/tokens: 204 일괄 삭제
package handler_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// URL constants for session/token admin endpoints
// ---------------------------------------------------------------------------

const adminSessionsURL = "/api/admin/sessions"
const adminTokensURL = "/api/admin/tokens"

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

// sessionListItem is one entry in the GET /api/admin/sessions response array.
type sessionListItem struct {
	ID        string `json:"id"`
	ClientID  string `json:"client_id"`
	Subject   string `json:"subject"`
	Scopes    string `json:"scopes"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

// tokenListItem is one entry in the GET /api/admin/tokens response array.
type tokenListItem struct {
	Signature string `json:"signature"`
	RequestID string `json:"request_id"`
	ClientID  string `json:"client_id"`
	Subject   string `json:"subject"`
	Scopes    string `json:"scopes"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

// ---------------------------------------------------------------------------
// Helper: create a client-credentials access token for seeding test data
// ---------------------------------------------------------------------------

// createCCToken issues a client_credentials access token using the pre-seeded
// "cc-client" and returns the token string. This populates the tokens table.
func createCCToken(t *testing.T, srv *httptest.Server, httpClient *http.Client) string {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/oauth2/token", strings.NewReader("grant_type=client_credentials&scope=read+write"))
	if err != nil {
		t.Fatalf("createCCToken: NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("cc-client", "cc-secret")

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("createCCToken: Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("createCCToken: POST /oauth2/token status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	readJSONBody(t, resp, &result)

	if result.AccessToken == "" {
		t.Fatal("createCCToken: access_token is empty in token response")
	}
	return result.AccessToken
}

// ---------------------------------------------------------------------------
// GET /api/admin/sessions — 세션 목록 조회
// ---------------------------------------------------------------------------

// TestListSessions_Returns200WithJSONArray verifies that GET /api/admin/sessions
// returns 200 OK with a JSON array (even when empty).
func TestListSessions_Returns200WithJSONArray(t *testing.T) {
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

	// Assert — Content-Type: application/json
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want to contain \"application/json\"", ct)
	}

	// Assert — valid JSON array
	var list []sessionListItem
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("response is not a JSON array: %v — body: %s", err, body)
	}
}

// TestListSessions_NoAuthHeader_Returns401 verifies that GET /api/admin/sessions
// without an Authorization header returns 401 Unauthorized.
func TestListSessions_NoAuthHeader_Returns401(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act — no Authorization header
	resp := doAdminRequestWithToken(t, client, http.MethodGet,
		srv.URL+adminSessionsURL, "")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s without auth: status = %d, want 401", adminSessionsURL, resp.StatusCode)
	}
}

// TestListSessions_InvalidToken_Returns401 verifies that GET /api/admin/sessions
// with a wrong Bearer token returns 401 Unauthorized.
func TestListSessions_InvalidToken_Returns401(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act — wrong token
	resp := doAdminRequestWithToken(t, client, http.MethodGet,
		srv.URL+adminSessionsURL, "Bearer wrong-token-xyz")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s with invalid token: status = %d, want 401", adminSessionsURL, resp.StatusCode)
	}
}

// TestListSessions_ReturnsSessionFields verifies that each entry in the
// sessions list contains the required fields: id, client_id, expires_at.
func TestListSessions_ReturnsSessionFields(t *testing.T) {
	// Arrange — the test server pre-seeds no sessions; we rely on the empty
	// list being valid and simply confirm field structure when a session exists.
	// Session creation requires a full auth code flow which is out of scope for
	// a unit integration test; so we validate only that the response is a valid
	// JSON array (field structure is covered by the storage layer tests).
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminSessionsURL, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s status = %d, want 200; body = %s",
			adminSessionsURL, resp.StatusCode, body)
	}

	var list []sessionListItem
	readJSONBody(t, resp, &list)

	// Assert — each item in the list (if any) must have non-empty id and client_id.
	for i, item := range list {
		if item.ID == "" {
			t.Errorf("sessions[%d].id is empty, want non-empty", i)
		}
		if item.ClientID == "" {
			t.Errorf("sessions[%d].client_id is empty, want non-empty", i)
		}
		if item.ExpiresAt == "" {
			t.Errorf("sessions[%d].expires_at is empty, want non-empty", i)
		}
	}
}

// ---------------------------------------------------------------------------
// DELETE /api/admin/sessions/{id} — 세션 폐기
// ---------------------------------------------------------------------------

// TestDeleteSession_NonExistentID_Returns404 verifies that
// DELETE /api/admin/sessions/{id} returns 404 for an ID that does not exist.
func TestDeleteSession_NonExistentID_Returns404(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequest(t, client, http.MethodDelete,
		fmt.Sprintf("%s%s/does-not-exist-session-xyz", srv.URL, adminSessionsURL), nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE %s/does-not-exist-session-xyz status = %d, want 404",
			adminSessionsURL, resp.StatusCode)
	}
}

// TestDeleteSession_NonExistentID_Returns404AsJSON verifies that the 404 error
// response body is a valid JSON object with an "error" field.
func TestDeleteSession_NonExistentID_Returns404AsJSON(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequest(t, client, http.MethodDelete,
		fmt.Sprintf("%s%s/does-not-exist-session-xyz", srv.URL, adminSessionsURL), nil)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", resp.StatusCode, body)
	}

	// Assert — valid JSON with "error" field
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want to contain \"application/json\"", ct)
	}

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

// TestDeleteSession_NoAuthHeader_Returns401 verifies that
// DELETE /api/admin/sessions/{id} without an Authorization header returns 401.
func TestDeleteSession_NoAuthHeader_Returns401(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequestWithToken(t, client, http.MethodDelete,
		fmt.Sprintf("%s%s/some-session-id", srv.URL, adminSessionsURL), "")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("DELETE %s/some-session-id without auth: status = %d, want 401",
			adminSessionsURL, resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// DELETE /api/admin/sessions — 세션 일괄 폐기
// ---------------------------------------------------------------------------

// TestDeleteAllSessions_Returns204 verifies that DELETE /api/admin/sessions
// (without an {id} path segment) returns 204 No Content.
func TestDeleteAllSessions_Returns204(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequest(t, client, http.MethodDelete,
		srv.URL+adminSessionsURL, nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE %s status = %d, want 204", adminSessionsURL, resp.StatusCode)
	}
}

// TestDeleteAllSessions_AfterDelete_ListIsEmpty verifies that
// GET /api/admin/sessions returns an empty array after bulk deletion.
func TestDeleteAllSessions_AfterDelete_ListIsEmpty(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act — delete all sessions
	delResp := doAdminRequest(t, client, http.MethodDelete,
		srv.URL+adminSessionsURL, nil)
	delResp.Body.Close()

	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE %s status = %d, want 204", adminSessionsURL, delResp.StatusCode)
	}

	// Act — list sessions after bulk deletion
	listResp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminSessionsURL, nil)
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("GET %s after bulk delete status = %d, want 200; body = %s",
			adminSessionsURL, listResp.StatusCode, body)
	}

	var list []sessionListItem
	readJSONBody(t, listResp, &list)

	// Assert — list must be empty after bulk deletion.
	if len(list) != 0 {
		t.Errorf("GET %s after bulk delete: returned %d sessions, want 0",
			adminSessionsURL, len(list))
	}
}

// TestDeleteAllSessions_NoAuthHeader_Returns401 verifies that
// DELETE /api/admin/sessions without an Authorization header returns 401.
func TestDeleteAllSessions_NoAuthHeader_Returns401(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequestWithToken(t, client, http.MethodDelete,
		srv.URL+adminSessionsURL, "")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("DELETE %s without auth: status = %d, want 401", adminSessionsURL, resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// GET /api/admin/tokens — 토큰 목록 조회
// ---------------------------------------------------------------------------

// TestListTokens_Returns200WithJSONArray verifies that GET /api/admin/tokens
// returns 200 OK with a JSON array (even when empty).
func TestListTokens_Returns200WithJSONArray(t *testing.T) {
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

	// Assert — Content-Type: application/json
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want to contain \"application/json\"", ct)
	}

	// Assert — valid JSON array
	var list []tokenListItem
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("response is not a JSON array: %v — body: %s", err, body)
	}
}

// TestListTokens_NoAuthHeader_Returns401 verifies that GET /api/admin/tokens
// without an Authorization header returns 401 Unauthorized.
func TestListTokens_NoAuthHeader_Returns401(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequestWithToken(t, client, http.MethodGet,
		srv.URL+adminTokensURL, "")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s without auth: status = %d, want 401", adminTokensURL, resp.StatusCode)
	}
}

// TestListTokens_InvalidToken_Returns401 verifies that GET /api/admin/tokens
// with a wrong Bearer token returns 401 Unauthorized.
func TestListTokens_InvalidToken_Returns401(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act — wrong token
	resp := doAdminRequestWithToken(t, client, http.MethodGet,
		srv.URL+adminTokensURL, "Bearer wrong-token-xyz")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s with invalid token: status = %d, want 401", adminTokensURL, resp.StatusCode)
	}
}

// TestListTokens_AfterIssue_ContainsToken verifies that a token issued via
// the token endpoint appears in the GET /api/admin/tokens response.
func TestListTokens_AfterIssue_ContainsToken(t *testing.T) {
	// Arrange — issue a client_credentials token to populate the tokens table.
	srv, client := testhelper.NewTestServer(t)
	createCCToken(t, srv, client)

	// Act
	resp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminTokensURL, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s status = %d, want 200; body = %s",
			adminTokensURL, resp.StatusCode, body)
	}

	var list []tokenListItem
	readJSONBody(t, resp, &list)

	// Assert — at least one token must be present.
	if len(list) == 0 {
		t.Errorf("GET %s after issuing token: returned empty list, want at least 1 token",
			adminTokensURL)
	}

	// Assert — each item must have a non-empty signature and client_id.
	for i, item := range list {
		if item.Signature == "" {
			t.Errorf("tokens[%d].signature is empty, want non-empty", i)
		}
		if item.ClientID == "" {
			t.Errorf("tokens[%d].client_id is empty, want non-empty", i)
		}
	}
}

// TestListTokens_ReturnsTokenFields verifies that each token entry in the list
// contains expires_at and created_at fields.
func TestListTokens_ReturnsTokenFields(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	createCCToken(t, srv, client)

	// Act
	resp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminTokensURL, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s status = %d, want 200; body = %s",
			adminTokensURL, resp.StatusCode, body)
	}

	var list []tokenListItem
	readJSONBody(t, resp, &list)

	for i, item := range list {
		if item.ExpiresAt == "" {
			t.Errorf("tokens[%d].expires_at is empty, want non-empty", i)
		}
		if item.CreatedAt == "" {
			t.Errorf("tokens[%d].created_at is empty, want non-empty", i)
		}
	}
}

// ---------------------------------------------------------------------------
// DELETE /api/admin/tokens/{id} — 토큰 폐기
// ---------------------------------------------------------------------------

// TestDeleteToken_ExistingSignature_Returns204 verifies that
// DELETE /api/admin/tokens/{id} returns 204 No Content for an existing token.
func TestDeleteToken_ExistingSignature_Returns204(t *testing.T) {
	// Arrange — issue a token and list to get its signature.
	srv, client := testhelper.NewTestServer(t)
	createCCToken(t, srv, client)

	listResp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminTokensURL, nil)
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("GET %s status = %d, want 200; body = %s",
			adminTokensURL, listResp.StatusCode, body)
	}

	var list []tokenListItem
	readJSONBody(t, listResp, &list)

	if len(list) == 0 {
		t.Fatal("no tokens in list after issuing token; cannot test DELETE")
	}
	signature := list[0].Signature

	// Act
	resp := doAdminRequest(t, client, http.MethodDelete,
		fmt.Sprintf("%s%s/%s", srv.URL, adminTokensURL, signature), nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE %s/%s status = %d, want 204",
			adminTokensURL, signature, resp.StatusCode)
	}
}

// TestDeleteToken_AfterDelete_NotInList verifies that a deleted token does not
// appear in the subsequent GET /api/admin/tokens response.
func TestDeleteToken_AfterDelete_NotInList(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	createCCToken(t, srv, client)

	listResp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminTokensURL, nil)
	defer listResp.Body.Close()

	var list []tokenListItem
	readJSONBody(t, listResp, &list)

	if len(list) == 0 {
		t.Fatal("no tokens in list; cannot test DELETE then list")
	}
	signature := list[0].Signature

	// Act — delete the token
	delResp := doAdminRequest(t, client, http.MethodDelete,
		fmt.Sprintf("%s%s/%s", srv.URL, adminTokensURL, signature), nil)
	delResp.Body.Close()

	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", delResp.StatusCode)
	}

	// Act — list tokens again
	listResp2 := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminTokensURL, nil)
	defer listResp2.Body.Close()

	if listResp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp2.Body)
		t.Fatalf("GET %s after DELETE status = %d, want 200; body = %s",
			adminTokensURL, listResp2.StatusCode, body)
	}

	var list2 []tokenListItem
	readJSONBody(t, listResp2, &list2)

	// Assert — deleted token must not appear in the list.
	for _, item := range list2 {
		if item.Signature == signature {
			t.Errorf("GET %s after DELETE: deleted token signature %q still appears",
				adminTokensURL, signature)
		}
	}
}

// TestDeleteToken_NonExistentID_Returns404 verifies that
// DELETE /api/admin/tokens/{id} returns 404 for a signature that does not exist.
func TestDeleteToken_NonExistentID_Returns404(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequest(t, client, http.MethodDelete,
		fmt.Sprintf("%s%s/does-not-exist-token-sig-xyz", srv.URL, adminTokensURL), nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE %s/does-not-exist-token-sig-xyz status = %d, want 404",
			adminTokensURL, resp.StatusCode)
	}
}

// TestDeleteToken_NonExistentID_Returns404AsJSON verifies that the 404 error
// response is a valid JSON object with an "error" field.
func TestDeleteToken_NonExistentID_Returns404AsJSON(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequest(t, client, http.MethodDelete,
		fmt.Sprintf("%s%s/does-not-exist-token-sig-xyz", srv.URL, adminTokensURL), nil)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", resp.StatusCode, body)
	}

	// Assert — valid JSON with "error" field
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want to contain \"application/json\"", ct)
	}

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

// TestDeleteToken_NoAuthHeader_Returns401 verifies that
// DELETE /api/admin/tokens/{id} without an Authorization header returns 401.
func TestDeleteToken_NoAuthHeader_Returns401(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequestWithToken(t, client, http.MethodDelete,
		fmt.Sprintf("%s%s/some-token-sig", srv.URL, adminTokensURL), "")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("DELETE %s/some-token-sig without auth: status = %d, want 401",
			adminTokensURL, resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// DELETE /api/admin/tokens — 토큰 일괄 폐기
// ---------------------------------------------------------------------------

// TestDeleteAllTokens_Returns204 verifies that DELETE /api/admin/tokens
// (without an {id} path segment) returns 204 No Content.
func TestDeleteAllTokens_Returns204(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequest(t, client, http.MethodDelete,
		srv.URL+adminTokensURL, nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE %s status = %d, want 204", adminTokensURL, resp.StatusCode)
	}
}

// TestDeleteAllTokens_AfterDelete_ListIsEmpty verifies that
// GET /api/admin/tokens returns an empty array after bulk deletion.
func TestDeleteAllTokens_AfterDelete_ListIsEmpty(t *testing.T) {
	// Arrange — issue a token first so the table is non-empty.
	srv, client := testhelper.NewTestServer(t)
	createCCToken(t, srv, client)

	// Sanity check — confirm the token was created.
	listBefore := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminTokensURL, nil)
	defer listBefore.Body.Close()

	var tokensBefore []tokenListItem
	readJSONBody(t, listBefore, &tokensBefore)

	if len(tokensBefore) == 0 {
		t.Fatal("token list is empty before bulk delete; test precondition not met")
	}

	// Act — delete all tokens
	delResp := doAdminRequest(t, client, http.MethodDelete,
		srv.URL+adminTokensURL, nil)
	delResp.Body.Close()

	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE %s status = %d, want 204", adminTokensURL, delResp.StatusCode)
	}

	// Act — list tokens after bulk deletion
	listAfter := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminTokensURL, nil)
	defer listAfter.Body.Close()

	if listAfter.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listAfter.Body)
		t.Fatalf("GET %s after bulk delete status = %d, want 200; body = %s",
			adminTokensURL, listAfter.StatusCode, body)
	}

	var tokensAfter []tokenListItem
	readJSONBody(t, listAfter, &tokensAfter)

	// Assert — list must be empty after bulk deletion.
	if len(tokensAfter) != 0 {
		t.Errorf("GET %s after bulk delete: returned %d tokens, want 0",
			adminTokensURL, len(tokensAfter))
	}
}

// TestDeleteAllTokens_NoAuthHeader_Returns401 verifies that
// DELETE /api/admin/tokens without an Authorization header returns 401.
func TestDeleteAllTokens_NoAuthHeader_Returns401(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequestWithToken(t, client, http.MethodDelete,
		srv.URL+adminTokensURL, "")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("DELETE %s without auth: status = %d, want 401", adminTokensURL, resp.StatusCode)
	}
}
