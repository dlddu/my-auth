// Package handler_test — Admin Client CRUD HTTP 핸들러 통합 테스트 (TDD Red Phase)
//
// 이 테스트들은 다음 기능이 구현되기 전에 작성되었으므로
// 현재 실패 상태가 정상입니다.
//
// 구현이 필요한 항목:
//
//  1. Admin Bearer Token 인증 미들웨어:
//     func NewAdminAuthMiddleware(adminToken string) func(http.Handler) http.Handler
//     - Authorization: Bearer {token} 헤더 검증
//     - 유효하지 않은 토큰 → 401 Unauthorized (JSON)
//
//  2. Client CRUD 핸들러 (internal/handler/admin_clients.go):
//     - POST   /api/admin/clients        → NewCreateClientHandler(store)
//     - GET    /api/admin/clients        → NewListClientsHandler(store)
//     - GET    /api/admin/clients/{id}   → NewGetClientHandler(store)
//     - PUT    /api/admin/clients/{id}   → NewUpdateClientHandler(store)
//     - DELETE /api/admin/clients/{id}   → NewDeleteClientHandler(store)
//
//  3. 스토리지 메서드 추가 (internal/storage/store.go):
//     - ListClients(ctx) ([]fosite.Client, error)
//     - UpdateClient(ctx, client) error
//     - DeleteClient(ctx, id) error
//
//  4. 라우트 등록 (internal/testhelper/server.go buildRouter()):
//     r.Route("/api/admin", func(r chi.Router) {
//         r.Use(handler.NewAdminAuthMiddleware(cfg.AdminToken))
//         r.Post("/clients", handler.NewCreateClientHandler(store))
//         r.Get("/clients", handler.NewListClientsHandler(store))
//         r.Get("/clients/{id}", handler.NewGetClientHandler(store))
//         r.Put("/clients/{id}", handler.NewUpdateClientHandler(store))
//         r.Delete("/clients/{id}", handler.NewDeleteClientHandler(store))
//     })
//
//  5. Config에 AdminToken 필드 추가 (internal/config/config.go):
//     AdminToken string `yaml:"admin_token"`
//
//  6. testhelper/config.go의 NewTestConfig에 AdminToken 설정:
//     cfg.AdminToken = "admin-bearer-token-placeholder-dld682"
//
// 테스트 커버리지:
//   - Admin 인증 미들웨어: 토큰 없음 → 401, 잘못된 토큰 → 401, 올바른 토큰 → 통과
//   - POST /api/admin/clients: 생성 성공 (client_secret 평문 포함), 잘못된 입력 → 400
//   - GET /api/admin/clients: 목록 반환, client_secret 미포함
//   - GET /api/admin/clients/{id}: 상세 반환, client_secret 미포함, 없는 ID → 404
//   - PUT /api/admin/clients/{id}: 수정 성공, 없는 ID → 404
//   - DELETE /api/admin/clients/{id}: 삭제 성공, 삭제 후 조회 → 404, 없는 ID → 404
//   - 입력 검증: 잘못된 redirect_uri → 400, 잘못된 grant_type → 400
package handler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// adminBearerToken is the Bearer token used for all admin endpoint tests.
// It matches the value in testhelper/config.go and the E2E test constant.
const adminBearerToken = "admin-bearer-token-placeholder-dld682"

// adminClientsURL is the base path for the admin clients API.
const adminClientsURL = "/api/admin/clients"

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// doAdminRequest performs an HTTP request to the admin API with the correct
// Authorization header. It returns the raw *http.Response.
// The caller is responsible for closing resp.Body.
func doAdminRequest(
	t *testing.T,
	client *http.Client,
	method, url string,
	body interface{},
) *http.Response {
	t.Helper()

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("doAdminRequest: json.Marshal body: %v", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		t.Fatalf("doAdminRequest: http.NewRequest %s %s: %v", method, url, err)
	}
	req.Header.Set("Authorization", "Bearer "+adminBearerToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("doAdminRequest: %s %s: %v", method, url, err)
	}
	return resp
}

// doAdminRequestWithToken performs an HTTP request with a custom Authorization
// header value (used to test invalid/missing tokens).
func doAdminRequestWithToken(
	t *testing.T,
	client *http.Client,
	method, url string,
	authHeader string,
) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("doAdminRequestWithToken: http.NewRequest: %v", err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("doAdminRequestWithToken: %s %s: %v", method, url, err)
	}
	return resp
}

// readJSONBody decodes the response body as JSON into v.
func readJSONBody(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("readJSONBody: io.ReadAll: %v", err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("readJSONBody: json.Unmarshal: %v — body: %s", err, body)
	}
}

// createClientRequest is the JSON payload for POST /api/admin/clients.
type createClientRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scopes                  []string `json:"scopes"`
	IsPublic                bool     `json:"is_public"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// createClientResponse is the expected JSON body of a successful
// POST /api/admin/clients response.
type createClientResponse struct {
	ClientID                string   `json:"id"`
	ClientSecret            string   `json:"client_secret"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scopes                  []string `json:"scopes"`
	IsPublic                bool     `json:"is_public"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// listClientItem is one entry in the GET /api/admin/clients response array.
type listClientItem struct {
	ClientID                string   `json:"id"`
	ClientSecret            string   `json:"client_secret"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scopes                  []string `json:"scopes"`
	IsPublic                bool     `json:"is_public"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// updateClientRequest is the JSON payload for PUT /api/admin/clients/{id}.
type updateClientRequest struct {
	RedirectURIs  []string `json:"redirect_uris"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	Scopes        []string `json:"scopes"`
}

// validCreateClientPayload returns a minimal valid createClientRequest for use
// in tests that need a successfully created client.
func validCreateClientPayload() createClientRequest {
	return createClientRequest{
		RedirectURIs:            []string{"https://app.example.com/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email"},
		IsPublic:                false,
		TokenEndpointAuthMethod: "client_secret_basic",
	}
}

// createValidClient is a test helper that creates a client via POST and returns
// the parsed response. The test is fatally stopped if the request fails.
func createValidClient(t *testing.T, srv *httptest.Server, httpClient *http.Client) createClientResponse {
	t.Helper()

	resp := doAdminRequest(t, httpClient, http.MethodPost,
		srv.URL+adminClientsURL, validCreateClientPayload())
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("createValidClient: POST %s status = %d, want 201; body = %s",
			adminClientsURL, resp.StatusCode, body)
	}

	var result createClientResponse
	readJSONBody(t, resp, &result)
	return result
}

// ---------------------------------------------------------------------------
// Admin 인증 미들웨어 테스트
// ---------------------------------------------------------------------------

// TestAdminMiddleware_NoAuthHeader_Returns401 verifies that requests to
// /api/admin/clients without an Authorization header are rejected with 401.
func TestAdminMiddleware_NoAuthHeader_Returns401(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act — no Authorization header
	resp := doAdminRequestWithToken(t, client, http.MethodGet,
		srv.URL+adminClientsURL, "")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s without auth: status = %d, want 401", adminClientsURL, resp.StatusCode)
	}
}

// TestAdminMiddleware_InvalidToken_Returns401 verifies that requests with an
// incorrect Bearer token are rejected with 401 Unauthorized.
func TestAdminMiddleware_InvalidToken_Returns401(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act — wrong token
	resp := doAdminRequestWithToken(t, client, http.MethodGet,
		srv.URL+adminClientsURL, "Bearer wrong-token-value")
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s with invalid token: status = %d, want 401", adminClientsURL, resp.StatusCode)
	}
}

// TestAdminMiddleware_WrongScheme_Returns401 verifies that requests using an
// incorrect authorization scheme (e.g. Basic instead of Bearer) are rejected.
func TestAdminMiddleware_WrongScheme_Returns401(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act — Basic auth instead of Bearer
	resp := doAdminRequestWithToken(t, client, http.MethodGet,
		srv.URL+adminClientsURL, "Basic "+adminBearerToken)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET %s with Basic scheme: status = %d, want 401", adminClientsURL, resp.StatusCode)
	}
}

// TestAdminMiddleware_ValidToken_AllowsRequest verifies that requests with the
// correct Bearer token are allowed through to the handler.
func TestAdminMiddleware_ValidToken_AllowsRequest(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act — valid Bearer token
	resp := doAdminRequest(t, client, http.MethodGet, srv.URL+adminClientsURL, nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert — must NOT be 401
	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("GET %s with valid token: status = 401, want non-401", adminClientsURL)
	}
}

// TestAdminMiddleware_Returns401AsJSON verifies that the 401 error response
// is valid JSON with an "error" field.
func TestAdminMiddleware_Returns401AsJSON(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequestWithToken(t, client, http.MethodGet,
		srv.URL+adminClientsURL, "")
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

	// Assert — body has "error" field
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

// ---------------------------------------------------------------------------
// POST /api/admin/clients — 클라이언트 생성
// ---------------------------------------------------------------------------

// TestCreateClient_ValidInput_Returns201 verifies that a valid POST request
// returns 201 Created with the created client in the response body.
func TestCreateClient_ValidInput_Returns201(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	payload := validCreateClientPayload()

	// Act
	resp := doAdminRequest(t, client, http.MethodPost,
		srv.URL+adminClientsURL, payload)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 201 Created
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST %s status = %d, want 201; body = %s",
			adminClientsURL, resp.StatusCode, body)
	}

	// Assert — Content-Type: application/json
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want to contain \"application/json\"", ct)
	}
}

// TestCreateClient_ResponseContainsClientID verifies that the creation
// response includes a non-empty client_id field.
func TestCreateClient_ResponseContainsClientID(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	payload := validCreateClientPayload()

	// Act
	resp := doAdminRequest(t, client, http.MethodPost,
		srv.URL+adminClientsURL, payload)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 201; body = %s", resp.StatusCode, body)
	}

	var result createClientResponse
	readJSONBody(t, resp, &result)

	// Assert — client_id must be non-empty (generated by server)
	if result.ClientID == "" {
		t.Error("response.client_id is empty, want a non-empty generated ID")
	}
}

// TestCreateClient_ResponseContainsPlaintextSecret verifies that the creation
// response includes the plain-text client_secret (shown only at creation time).
// For confidential clients only.
func TestCreateClient_ResponseContainsPlaintextSecret(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	payload := validCreateClientPayload() // is_public = false

	// Act
	resp := doAdminRequest(t, client, http.MethodPost,
		srv.URL+adminClientsURL, payload)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 201; body = %s", resp.StatusCode, body)
	}

	var result createClientResponse
	readJSONBody(t, resp, &result)

	// Assert — client_secret must be present in the creation response.
	// This is a one-time exposure of the plain-text secret before bcrypt hashing.
	if result.ClientSecret == "" {
		t.Error("response.client_secret is empty for confidential client, want plain-text secret")
	}
}

// TestCreateClient_PublicClient_NoSecret verifies that a public client
// creation response does not include a client_secret.
func TestCreateClient_PublicClient_NoSecret(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	payload := createClientRequest{
		RedirectURIs:            []string{"https://spa.example.com/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile"},
		IsPublic:                true,
		TokenEndpointAuthMethod: "none",
	}

	// Act
	resp := doAdminRequest(t, client, http.MethodPost,
		srv.URL+adminClientsURL, payload)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 201; body = %s", resp.StatusCode, body)
	}

	var result createClientResponse
	readJSONBody(t, resp, &result)

	// Assert — public client must not have a client_secret in the response.
	if result.ClientSecret != "" {
		t.Errorf("response.client_secret = %q for public client, want empty", result.ClientSecret)
	}
}

// TestCreateClient_InvalidRedirectURI_Returns400 verifies that a request with
// an invalid redirect_uri (not a URL) is rejected with 400 Bad Request.
func TestCreateClient_InvalidRedirectURI_Returns400(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	payload := createClientRequest{
		RedirectURIs:  []string{"not-a-valid-url"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		IsPublic:      false,
	}

	// Act
	resp := doAdminRequest(t, client, http.MethodPost,
		srv.URL+adminClientsURL, payload)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Assert
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST %s with invalid redirect_uri: status = %d, want 400; body = %s",
			adminClientsURL, resp.StatusCode, body)
	}
}

// TestCreateClient_HTTPRedirectURI_Returns400 verifies that a non-localhost
// http:// redirect_uri is rejected with 400 Bad Request.
func TestCreateClient_HTTPRedirectURI_Returns400(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	payload := createClientRequest{
		RedirectURIs:  []string{"http://example.com/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		IsPublic:      false,
	}

	// Act
	resp := doAdminRequest(t, client, http.MethodPost,
		srv.URL+adminClientsURL, payload)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Assert
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST %s with http:// redirect_uri: status = %d, want 400; body = %s",
			adminClientsURL, resp.StatusCode, body)
	}
}

// TestCreateClient_LocalhostHTTP_Returns201 verifies that http://localhost
// redirect URIs are allowed per RFC 8252.
func TestCreateClient_LocalhostHTTP_Returns201(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	payload := createClientRequest{
		RedirectURIs:            []string{"http://localhost:9000/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid"},
		IsPublic:                false,
		TokenEndpointAuthMethod: "client_secret_basic",
	}

	// Act
	resp := doAdminRequest(t, client, http.MethodPost,
		srv.URL+adminClientsURL, payload)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Assert
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("POST %s with http://localhost redirect_uri: status = %d, want 201; body = %s",
			adminClientsURL, resp.StatusCode, body)
	}
}

// TestCreateClient_FragmentInRedirectURI_Returns400 verifies that a redirect_uri
// containing a fragment (#) is rejected with 400 per RFC 6749 §3.1.2.
func TestCreateClient_FragmentInRedirectURI_Returns400(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	payload := createClientRequest{
		RedirectURIs:  []string{"https://example.com/callback#fragment"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		IsPublic:      false,
	}

	// Act
	resp := doAdminRequest(t, client, http.MethodPost,
		srv.URL+adminClientsURL, payload)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Assert
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST %s with fragment in redirect_uri: status = %d, want 400; body = %s",
			adminClientsURL, resp.StatusCode, body)
	}
}

// TestCreateClient_InvalidGrantType_Returns400 verifies that a request with
// an unrecognised grant_type is rejected with 400 Bad Request.
func TestCreateClient_InvalidGrantType_Returns400(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	payload := createClientRequest{
		RedirectURIs:  []string{"https://app.example.com/callback"},
		GrantTypes:    []string{"not_a_real_grant_type"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		IsPublic:      false,
	}

	// Act
	resp := doAdminRequest(t, client, http.MethodPost,
		srv.URL+adminClientsURL, payload)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Assert
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST %s with invalid grant_type: status = %d, want 400; body = %s",
			adminClientsURL, resp.StatusCode, body)
	}
}

// TestCreateClient_EmptyRedirectURIs_Returns400 verifies that a request with
// no redirect_uris is rejected with 400 for confidential clients.
func TestCreateClient_EmptyRedirectURIs_Returns400(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	payload := createClientRequest{
		RedirectURIs:  []string{},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
		IsPublic:      false,
	}

	// Act
	resp := doAdminRequest(t, client, http.MethodPost,
		srv.URL+adminClientsURL, payload)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Assert — empty redirect URIs for authorization_code grant must be rejected.
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST %s with empty redirect_uris: status = %d, want 400; body = %s",
			adminClientsURL, resp.StatusCode, body)
	}
}

// TestCreateClient_TwoRequests_ProduceDistinctClientIDs verifies that two
// successive POST requests produce distinct client_id values.
func TestCreateClient_TwoRequests_ProduceDistinctClientIDs(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp1 := doAdminRequest(t, client, http.MethodPost,
		srv.URL+adminClientsURL, validCreateClientPayload())
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp1.Body)
		t.Fatalf("request 1: status = %d, want 201; body = %s", resp1.StatusCode, body)
	}
	var r1 createClientResponse
	readJSONBody(t, resp1, &r1)

	resp2 := doAdminRequest(t, client, http.MethodPost,
		srv.URL+adminClientsURL, validCreateClientPayload())
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("request 2: status = %d, want 201; body = %s", resp2.StatusCode, body)
	}
	var r2 createClientResponse
	readJSONBody(t, resp2, &r2)

	// Assert — client IDs must be distinct.
	if r1.ClientID == r2.ClientID {
		t.Errorf("two POST requests produced the same client_id %q, want distinct IDs", r1.ClientID)
	}
}

// ---------------------------------------------------------------------------
// GET /api/admin/clients — 목록 조회
// ---------------------------------------------------------------------------

// TestListClients_EmptyList_Returns200 verifies that GET /api/admin/clients
// returns 200 OK with an empty JSON array when no clients have been created.
func TestListClients_EmptyList_Returns200(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminClientsURL, nil)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200; body = %s",
			adminClientsURL, resp.StatusCode, body)
	}

	// Assert — valid JSON array
	var list []listClientItem
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("response is not a JSON array: %v — body: %s", err, body)
	}
}

// TestListClients_AfterCreate_ReturnsCreatedClient verifies that a client
// created via POST appears in the subsequent GET list response.
func TestListClients_AfterCreate_ReturnsCreatedClient(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	created := createValidClient(t, srv, client)

	// Act
	resp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminClientsURL, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s status = %d, want 200; body = %s",
			adminClientsURL, resp.StatusCode, body)
	}

	var list []listClientItem
	readJSONBody(t, resp, &list)

	// Assert — the created client must appear in the list.
	found := false
	for _, item := range list {
		if item.ClientID == created.ClientID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GET %s: created client %q not found in list", adminClientsURL, created.ClientID)
	}
}

// TestListClients_DoesNotExposeClientSecret verifies that the list response
// does NOT include the client_secret field for any client.
func TestListClients_DoesNotExposeClientSecret(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	// Create a confidential client so the secret exists in storage.
	createValidClient(t, srv, client)

	// Act
	resp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminClientsURL, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s status = %d, want 200; body = %s",
			adminClientsURL, resp.StatusCode, body)
	}

	var list []listClientItem
	readJSONBody(t, resp, &list)

	// Assert — no item must have a non-empty client_secret.
	for _, item := range list {
		if item.ClientSecret != "" {
			t.Errorf("GET %s: item %q has non-empty client_secret = %q, want empty",
				adminClientsURL, item.ClientID, item.ClientSecret)
		}
	}
}

// ---------------------------------------------------------------------------
// GET /api/admin/clients/{id} — 상세 조회
// ---------------------------------------------------------------------------

// TestGetClient_ExistingID_Returns200 verifies that GET /api/admin/clients/{id}
// returns 200 OK with the client data for a registered client.
func TestGetClient_ExistingID_Returns200(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	created := createValidClient(t, srv, client)

	// Act
	resp := doAdminRequest(t, client, http.MethodGet,
		fmt.Sprintf("%s%s/%s", srv.URL, adminClientsURL, created.ClientID), nil)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s/%s status = %d, want 200; body = %s",
			adminClientsURL, created.ClientID, resp.StatusCode, body)
	}

	// Assert — response contains the correct client_id
	var result listClientItem
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("response is not valid JSON: %v — body: %s", err, body)
	}
	if result.ClientID != created.ClientID {
		t.Errorf("response.client_id = %q, want %q", result.ClientID, created.ClientID)
	}
}

// TestGetClient_DoesNotExposeClientSecret verifies that the detail response
// does NOT include the client_secret.
func TestGetClient_DoesNotExposeClientSecret(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	created := createValidClient(t, srv, client)

	// Act
	resp := doAdminRequest(t, client, http.MethodGet,
		fmt.Sprintf("%s%s/%s", srv.URL, adminClientsURL, created.ClientID), nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body = %s", resp.StatusCode, body)
	}

	var result listClientItem
	readJSONBody(t, resp, &result)

	// Assert — client_secret must be absent (empty) in the detail response.
	if result.ClientSecret != "" {
		t.Errorf("GET %s/%s: client_secret = %q, want empty (must not be exposed)",
			adminClientsURL, created.ClientID, result.ClientSecret)
	}
}

// TestGetClient_NonExistentID_Returns404 verifies that GET /api/admin/clients/{id}
// returns 404 Not Found for an unregistered client ID.
func TestGetClient_NonExistentID_Returns404(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequest(t, client, http.MethodGet,
		fmt.Sprintf("%s%s/does-not-exist-xyz", srv.URL, adminClientsURL), nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET %s/does-not-exist-xyz status = %d, want 404",
			adminClientsURL, resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// PUT /api/admin/clients/{id} — 수정
// ---------------------------------------------------------------------------

// TestUpdateClient_ValidInput_Returns200 verifies that a valid PUT request
// returns 200 OK.
func TestUpdateClient_ValidInput_Returns200(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	created := createValidClient(t, srv, client)

	updatePayload := updateClientRequest{
		RedirectURIs:  []string{"https://updated.example.com/callback"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile"},
	}

	// Act
	resp := doAdminRequest(t, client, http.MethodPut,
		fmt.Sprintf("%s%s/%s", srv.URL, adminClientsURL, created.ClientID),
		updatePayload)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PUT %s/%s status = %d, want 200; body = %s",
			adminClientsURL, created.ClientID, resp.StatusCode, body)
	}
}

// TestUpdateClient_ChangesArePersisted verifies that changes made via PUT are
// actually persisted and visible in a subsequent GET request.
func TestUpdateClient_ChangesArePersisted(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	created := createValidClient(t, srv, client)

	newRedirectURI := "https://changed.example.com/callback"
	updatePayload := updateClientRequest{
		RedirectURIs:  []string{newRedirectURI},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
	}

	// Act — update the client
	putResp := doAdminRequest(t, client, http.MethodPut,
		fmt.Sprintf("%s%s/%s", srv.URL, adminClientsURL, created.ClientID),
		updatePayload)
	putResp.Body.Close()

	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200", putResp.StatusCode)
	}

	// Act — fetch the updated client
	getResp := doAdminRequest(t, client, http.MethodGet,
		fmt.Sprintf("%s%s/%s", srv.URL, adminClientsURL, created.ClientID), nil)
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(getResp.Body)
		t.Fatalf("GET after PUT status = %d, want 200; body = %s", getResp.StatusCode, body)
	}

	var result listClientItem
	readJSONBody(t, getResp, &result)

	// Assert — the redirect URI must have been updated.
	found := false
	for _, u := range result.RedirectURIs {
		if u == newRedirectURI {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GET after PUT: redirect_uris = %v, want to contain %q",
			result.RedirectURIs, newRedirectURI)
	}
}

// TestUpdateClient_NonExistentID_Returns404 verifies that PUT returns 404 for
// an unregistered client ID.
func TestUpdateClient_NonExistentID_Returns404(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	updatePayload := updateClientRequest{
		RedirectURIs:  []string{"https://app.example.com/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
	}

	// Act
	resp := doAdminRequest(t, client, http.MethodPut,
		fmt.Sprintf("%s%s/does-not-exist-xyz", srv.URL, adminClientsURL),
		updatePayload)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("PUT %s/does-not-exist-xyz status = %d, want 404",
			adminClientsURL, resp.StatusCode)
	}
}

// TestUpdateClient_InvalidRedirectURI_Returns400 verifies that PUT with an
// invalid redirect_uri returns 400 Bad Request.
func TestUpdateClient_InvalidRedirectURI_Returns400(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	created := createValidClient(t, srv, client)

	updatePayload := updateClientRequest{
		RedirectURIs:  []string{"not-a-url"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
	}

	// Act
	resp := doAdminRequest(t, client, http.MethodPut,
		fmt.Sprintf("%s%s/%s", srv.URL, adminClientsURL, created.ClientID),
		updatePayload)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// Assert
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("PUT with invalid redirect_uri: status = %d, want 400; body = %s",
			resp.StatusCode, body)
	}
}

// ---------------------------------------------------------------------------
// DELETE /api/admin/clients/{id} — 삭제
// ---------------------------------------------------------------------------

// TestDeleteClient_ExistingID_Returns204 verifies that DELETE returns 204
// No Content for a registered client.
func TestDeleteClient_ExistingID_Returns204(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	created := createValidClient(t, srv, client)

	// Act
	resp := doAdminRequest(t, client, http.MethodDelete,
		fmt.Sprintf("%s%s/%s", srv.URL, adminClientsURL, created.ClientID), nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE %s/%s status = %d, want 204",
			adminClientsURL, created.ClientID, resp.StatusCode)
	}
}

// TestDeleteClient_AfterDelete_GetReturns404 verifies the core acceptance
// criterion: after DELETE, GET /api/admin/clients/{id} must return 404.
func TestDeleteClient_AfterDelete_GetReturns404(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	created := createValidClient(t, srv, client)
	clientURL := fmt.Sprintf("%s%s/%s", srv.URL, adminClientsURL, created.ClientID)

	// Act — delete the client
	delResp := doAdminRequest(t, client, http.MethodDelete, clientURL, nil)
	delResp.Body.Close()

	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", delResp.StatusCode)
	}

	// Act — try to GET the deleted client
	getResp := doAdminRequest(t, client, http.MethodGet, clientURL, nil)
	defer getResp.Body.Close()
	_, _ = io.Copy(io.Discard, getResp.Body)

	// Assert — must return 404 after deletion.
	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("GET after DELETE status = %d, want 404", getResp.StatusCode)
	}
}

// TestDeleteClient_AfterDelete_NotInList verifies that a deleted client does
// not appear in the GET /api/admin/clients list.
func TestDeleteClient_AfterDelete_NotInList(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Create two clients: one to keep, one to delete.
	keep := createValidClient(t, srv, client)
	del := createValidClient(t, srv, client)

	// Act — delete one client
	delResp := doAdminRequest(t, client, http.MethodDelete,
		fmt.Sprintf("%s%s/%s", srv.URL, adminClientsURL, del.ClientID), nil)
	delResp.Body.Close()

	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", delResp.StatusCode)
	}

	// Act — list clients
	listResp := doAdminRequest(t, client, http.MethodGet,
		srv.URL+adminClientsURL, nil)
	defer listResp.Body.Close()

	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("GET list status = %d, want 200; body = %s", listResp.StatusCode, body)
	}

	var list []listClientItem
	readJSONBody(t, listResp, &list)

	// Assert — deleted client must not appear; kept client must still be present.
	for _, item := range list {
		if item.ClientID == del.ClientID {
			t.Errorf("GET list after DELETE: deleted client %q still appears in list",
				del.ClientID)
		}
	}

	foundKeep := false
	for _, item := range list {
		if item.ClientID == keep.ClientID {
			foundKeep = true
			break
		}
	}
	if !foundKeep {
		t.Errorf("GET list after DELETE: kept client %q missing from list", keep.ClientID)
	}
}

// TestDeleteClient_NonExistentID_Returns404 verifies that DELETE returns 404
// for an unregistered client ID.
func TestDeleteClient_NonExistentID_Returns404(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)

	// Act
	resp := doAdminRequest(t, client, http.MethodDelete,
		fmt.Sprintf("%s%s/does-not-exist-xyz", srv.URL, adminClientsURL), nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Assert
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DELETE %s/does-not-exist-xyz status = %d, want 404",
			adminClientsURL, resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// 입력 검증 — grant_type 허용 목록
// ---------------------------------------------------------------------------

// TestCreateClient_AllValidGrantTypes_Returns201 verifies that each allowed
// grant_type (per the acceptance criteria) is accepted individually.
func TestCreateClient_AllValidGrantTypes_Returns201(t *testing.T) {
	validGrantTypes := []string{
		"authorization_code",
		"client_credentials",
		"refresh_token",
		"urn:ietf:params:oauth:grant-type:device_code",
	}

	srv, client := testhelper.NewTestServer(t)

	for _, gt := range validGrantTypes {
		gt := gt // capture range variable
		t.Run(gt, func(t *testing.T) {
			// Some grant types do not require redirect_uris.
			redirectURIs := []string{"https://app.example.com/callback"}
			if gt == "client_credentials" || gt == "urn:ietf:params:oauth:grant-type:device_code" {
				redirectURIs = []string{}
			}

			payload := createClientRequest{
				RedirectURIs:            redirectURIs,
				GrantTypes:              []string{gt},
				ResponseTypes:           []string{"code"},
				Scopes:                  []string{"openid"},
				IsPublic:                false,
				TokenEndpointAuthMethod: "client_secret_basic",
			}

			resp := doAdminRequest(t, client, http.MethodPost,
				srv.URL+adminClientsURL, payload)
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != http.StatusCreated {
				t.Errorf("POST with grant_type=%q: status = %d, want 201; body = %s",
					gt, resp.StatusCode, body)
			}
		})
	}
}

// TestCreateClient_InvalidGrantType_ReturnsErrorJSON verifies that a 400
// response for an invalid grant_type contains a valid JSON error body.
func TestCreateClient_InvalidGrantType_ReturnsErrorJSON(t *testing.T) {
	// Arrange
	srv, client := testhelper.NewTestServer(t)
	payload := createClientRequest{
		RedirectURIs:  []string{"https://app.example.com/callback"},
		GrantTypes:    []string{"implicit"}, // not in allowed list
		ResponseTypes: []string{"token"},
		Scopes:        []string{"openid"},
		IsPublic:      false,
	}

	// Act
	resp := doAdminRequest(t, client, http.MethodPost,
		srv.URL+adminClientsURL, payload)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	// Assert — 400
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", resp.StatusCode, body)
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
