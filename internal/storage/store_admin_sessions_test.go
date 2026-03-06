// Package storage_test — Admin Sessions/Tokens 스토리지 레이어 테스트 (TDD Red Phase)
//
// 이 테스트들은 다음 메서드가 구현되기 전에 작성되었으므로
// 현재 컴파일 오류 또는 실패 상태가 정상입니다.
//
// 구현이 필요한 항목:
//
//  1. internal/storage/store.go 에 다음 타입 추가:
//     - SessionInfo struct { ID, ClientID, Subject, Scopes, ExpiresAt, CreatedAt }
//     - TokenInfo struct { Signature, RequestID, ClientID, Subject, Scopes, ExpiresAt, CreatedAt }
//
//  2. internal/storage/store.go 에 다음 메서드 추가:
//     - ListSessions(ctx context.Context) ([]SessionInfo, error)
//     - DeleteSession(ctx context.Context, id string) error
//     - DeleteAllSessions(ctx context.Context) error
//     - ListTokens(ctx context.Context) ([]TokenInfo, error)
//     - DeleteToken(ctx context.Context, signature string) error
//     - DeleteAllTokens(ctx context.Context) error
//
//  3. internal/storage/store.go 에 다음 센티넬 에러 추가:
//     - ErrSessionNotFound = errors.New("session not found")
//     - ErrTokenNotFound   = errors.New("token not found")
//
// 테스트 커버리지:
//   - ListSessions: 빈 목록 반환, 데이터 존재 시 반환, 필드 검증
//   - DeleteSession: 삭제 성공, 삭제 후 목록에서 사라짐, 존재하지 않는 ID → ErrSessionNotFound
//   - DeleteAllSessions: 모든 세션 삭제 후 빈 목록
//   - ListTokens: 빈 목록 반환, 데이터 존재 시 반환, 필드 검증
//   - DeleteToken: 삭제 성공 + jti 블랙리스트 등록, 존재하지 않는 ID → ErrTokenNotFound
//   - DeleteAllTokens: 모든 토큰 삭제 후 빈 목록 + jti 블랙리스트 등록
package storage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"

	"github.com/dlddu/my-auth/internal/storage"
	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Test data helpers
// ---------------------------------------------------------------------------

// newSessionTestClient returns a minimal fosite.DefaultOpenIDConnectClient
// suitable for seeding session-related tests.
func newSessionTestClient(clientID string) *fosite.DefaultOpenIDConnectClient {
	return &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            clientID,
			Secret:        []byte("test-session-client-secret"),
			RedirectURIs:  []string{"https://session.test.local/callback"},
			GrantTypes:    fosite.Arguments{"authorization_code", "refresh_token"},
			ResponseTypes: fosite.Arguments{"code"},
			Scopes:        fosite.Arguments{"openid", "profile"},
		},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
}

// newSessionAuthorizeRequest builds a minimal *fosite.AuthorizeRequest for
// seeding sessions in the sessions table via CreateOpenIDConnectSession.
func newSessionAuthorizeRequest(client fosite.Client) *fosite.AuthorizeRequest {
	sess := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject: "user-session-test",
		},
		Headers: &jwt.Headers{},
	}

	req := fosite.NewAuthorizeRequest()
	req.Client = client
	req.Session = sess
	req.RequestedAt = time.Now().UTC()
	req.GrantedScope = fosite.Arguments{"openid", "profile"}
	return req
}

// newTokenAuthorizeRequest builds a minimal *fosite.AuthorizeRequest for
// seeding tokens in the tokens table via CreateAccessTokenSession.
func newTokenAuthorizeRequest(client fosite.Client) *fosite.AuthorizeRequest {
	sess := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject: "user-token-test",
		},
		Headers: &jwt.Headers{},
	}

	req := fosite.NewAuthorizeRequest()
	req.Client = client
	req.Session = sess
	req.RequestedAt = time.Now().UTC()
	req.GrantedScope = fosite.Arguments{"openid"}
	return req
}

// seedSession creates a client and an OIDC session (sessions table row) and
// returns the session ID (authorize code) used as the key.
func seedSession(t *testing.T, store *storage.Store, clientID, sessionID string) {
	t.Helper()

	ctx := context.Background()

	client := newSessionTestClient(clientID)
	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("seedSession: CreateClient(%q): %v", clientID, err)
	}

	req := newSessionAuthorizeRequest(client)
	if err := store.CreateOpenIDConnectSession(ctx, sessionID, req); err != nil {
		t.Fatalf("seedSession: CreateOpenIDConnectSession(%q): %v", sessionID, err)
	}
}

// seedToken creates a client and an access token (tokens table row) and
// returns the signature used as the key.
func seedToken(t *testing.T, store *storage.Store, clientID, signature string) {
	t.Helper()

	ctx := context.Background()

	client := newSessionTestClient(clientID)
	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("seedToken: CreateClient(%q): %v", clientID, err)
	}

	req := newTokenAuthorizeRequest(client)
	if err := store.CreateAccessTokenSession(ctx, signature, req); err != nil {
		t.Fatalf("seedToken: CreateAccessTokenSession(%q): %v", signature, err)
	}
}

// ---------------------------------------------------------------------------
// ListSessions
// ---------------------------------------------------------------------------

// TestListSessions_EmptyDB_ReturnsEmptySlice verifies that ListSessions
// returns a non-nil empty slice when no sessions exist.
func TestListSessions_EmptyDB_ReturnsEmptySlice(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	// Act
	sessions, err := store.ListSessions(ctx)

	// Assert
	if err != nil {
		t.Fatalf("ListSessions() returned unexpected error: %v", err)
	}
	if sessions == nil {
		t.Error("ListSessions() returned nil, want non-nil empty slice")
	}
	if len(sessions) != 0 {
		t.Errorf("ListSessions() returned %d sessions, want 0", len(sessions))
	}
}

// TestListSessions_WithData_ReturnsAllSessions verifies that ListSessions
// returns all sessions that have been created.
func TestListSessions_WithData_ReturnsAllSessions(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	seedSession(t, store, "ls-client-001", "ls-session-001")
	seedSession(t, store, "ls-client-002", "ls-session-002")

	ctx := context.Background()

	// Act
	sessions, err := store.ListSessions(ctx)

	// Assert
	if err != nil {
		t.Fatalf("ListSessions() returned unexpected error: %v", err)
	}
	if len(sessions) != 2 {
		t.Errorf("ListSessions() returned %d sessions, want 2", len(sessions))
	}
}

// TestListSessions_FieldsArePopulated verifies that each SessionInfo returned
// by ListSessions has the required fields populated (ID, ClientID, ExpiresAt).
func TestListSessions_FieldsArePopulated(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	clientID := "ls-fields-client"
	sessionID := "ls-fields-session-001"
	seedSession(t, store, clientID, sessionID)

	ctx := context.Background()

	// Act
	sessions, err := store.ListSessions(ctx)

	// Assert
	if err != nil {
		t.Fatalf("ListSessions() returned unexpected error: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("ListSessions() returned %d sessions, want 1", len(sessions))
	}

	s := sessions[0]

	// ID must match the session ID used when creating the session.
	if s.ID != sessionID {
		t.Errorf("SessionInfo.ID = %q, want %q", s.ID, sessionID)
	}

	// ClientID must match the client that owns the session.
	if s.ClientID != clientID {
		t.Errorf("SessionInfo.ClientID = %q, want %q", s.ClientID, clientID)
	}

	// ExpiresAt must be a non-zero time in the future.
	if s.ExpiresAt.IsZero() {
		t.Error("SessionInfo.ExpiresAt is zero, want a non-zero future time")
	}

	// CreatedAt must be a non-zero time.
	if s.CreatedAt.IsZero() {
		t.Error("SessionInfo.CreatedAt is zero, want a non-zero time")
	}
}

// TestListSessions_ScopesArePopulated verifies that the Scopes field of
// SessionInfo matches the scopes that were granted when the session was created.
func TestListSessions_ScopesArePopulated(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	clientID := "ls-scopes-client"
	sessionID := "ls-scopes-session-001"
	seedSession(t, store, clientID, sessionID)

	ctx := context.Background()

	// Act
	sessions, err := store.ListSessions(ctx)

	// Assert
	if err != nil {
		t.Fatalf("ListSessions() returned unexpected error: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("ListSessions() returned %d sessions, want 1", len(sessions))
	}

	// Scopes must be non-empty (the seed uses "openid profile").
	if sessions[0].Scopes == "" {
		t.Error("SessionInfo.Scopes is empty, want non-empty scope string")
	}
}

// ---------------------------------------------------------------------------
// DeleteSession
// ---------------------------------------------------------------------------

// TestDeleteSession_ExistingID_Succeeds verifies that DeleteSession removes
// a session without returning an error.
func TestDeleteSession_ExistingID_Succeeds(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	sessionID := "ds-ok-session-001"
	seedSession(t, store, "ds-ok-client", sessionID)

	ctx := context.Background()

	// Act
	err := store.DeleteSession(ctx, sessionID)

	// Assert
	if err != nil {
		t.Errorf("DeleteSession(%q) returned unexpected error: %v", sessionID, err)
	}
}

// TestDeleteSession_AfterDelete_NotInList verifies that a deleted session
// does not appear in the ListSessions result.
func TestDeleteSession_AfterDelete_NotInList(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	keepSessionID := "ds-list-keep-session"
	deleteSessionID := "ds-list-delete-session"

	seedSession(t, store, "ds-list-keep-client", keepSessionID)
	seedSession(t, store, "ds-list-del-client", deleteSessionID)

	ctx := context.Background()

	if err := store.DeleteSession(ctx, deleteSessionID); err != nil {
		t.Fatalf("DeleteSession(%q): %v", deleteSessionID, err)
	}

	// Act
	sessions, err := store.ListSessions(ctx)

	// Assert
	if err != nil {
		t.Fatalf("ListSessions() after DeleteSession: %v", err)
	}

	for _, s := range sessions {
		if s.ID == deleteSessionID {
			t.Errorf("ListSessions() after DeleteSession: deleted session %q still present", deleteSessionID)
		}
	}

	found := false
	for _, s := range sessions {
		if s.ID == keepSessionID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListSessions() after DeleteSession: kept session %q is missing", keepSessionID)
	}
}

// TestDeleteSession_NonExistentID_ReturnsErrSessionNotFound verifies that
// DeleteSession returns ErrSessionNotFound for an ID that does not exist.
func TestDeleteSession_NonExistentID_ReturnsErrSessionNotFound(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	// Act
	err := store.DeleteSession(ctx, "session-does-not-exist-xyz")

	// Assert
	if err == nil {
		t.Error("DeleteSession() with non-existent ID returned nil error, want ErrSessionNotFound")
	}
	if !errors.Is(err, storage.ErrSessionNotFound) {
		t.Errorf("DeleteSession() error = %v, want storage.ErrSessionNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteAllSessions
// ---------------------------------------------------------------------------

// TestDeleteAllSessions_EmptyDB_Succeeds verifies that DeleteAllSessions
// does not return an error on an empty sessions table.
func TestDeleteAllSessions_EmptyDB_Succeeds(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	// Act
	err := store.DeleteAllSessions(ctx)

	// Assert
	if err != nil {
		t.Errorf("DeleteAllSessions() on empty table returned unexpected error: %v", err)
	}
}

// TestDeleteAllSessions_WithData_ClearsAllSessions verifies that after
// DeleteAllSessions, ListSessions returns an empty slice.
func TestDeleteAllSessions_WithData_ClearsAllSessions(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	seedSession(t, store, "das-client-001", "das-session-001")
	seedSession(t, store, "das-client-002", "das-session-002")
	seedSession(t, store, "das-client-003", "das-session-003")

	ctx := context.Background()

	// Act
	err := store.DeleteAllSessions(ctx)

	// Assert — no error returned
	if err != nil {
		t.Fatalf("DeleteAllSessions() returned unexpected error: %v", err)
	}

	// Assert — list must now be empty
	sessions, err := store.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions() after DeleteAllSessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("ListSessions() after DeleteAllSessions returned %d sessions, want 0", len(sessions))
	}
}

// ---------------------------------------------------------------------------
// ListTokens
// ---------------------------------------------------------------------------

// TestListTokens_EmptyDB_ReturnsEmptySlice verifies that ListTokens returns
// a non-nil empty slice when no tokens exist.
func TestListTokens_EmptyDB_ReturnsEmptySlice(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	// Act
	tokens, err := store.ListTokens(ctx)

	// Assert
	if err != nil {
		t.Fatalf("ListTokens() returned unexpected error: %v", err)
	}
	if tokens == nil {
		t.Error("ListTokens() returned nil, want non-nil empty slice")
	}
	if len(tokens) != 0 {
		t.Errorf("ListTokens() returned %d tokens, want 0", len(tokens))
	}
}

// TestListTokens_WithData_ReturnsAllTokens verifies that ListTokens returns
// all access tokens that have been created.
func TestListTokens_WithData_ReturnsAllTokens(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	seedToken(t, store, "lt-client-001", "lt-sig-001")
	seedToken(t, store, "lt-client-002", "lt-sig-002")

	ctx := context.Background()

	// Act
	tokens, err := store.ListTokens(ctx)

	// Assert
	if err != nil {
		t.Fatalf("ListTokens() returned unexpected error: %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("ListTokens() returned %d tokens, want 2", len(tokens))
	}
}

// TestListTokens_FieldsArePopulated verifies that each TokenInfo returned by
// ListTokens has the required fields populated.
func TestListTokens_FieldsArePopulated(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	clientID := "lt-fields-client"
	signature := "lt-fields-sig-001"
	seedToken(t, store, clientID, signature)

	ctx := context.Background()

	// Act
	tokens, err := store.ListTokens(ctx)

	// Assert
	if err != nil {
		t.Fatalf("ListTokens() returned unexpected error: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("ListTokens() returned %d tokens, want 1", len(tokens))
	}

	tk := tokens[0]

	// Signature must match the signature used when creating the token.
	if tk.Signature != signature {
		t.Errorf("TokenInfo.Signature = %q, want %q", tk.Signature, signature)
	}

	// ClientID must match the client that owns the token.
	if tk.ClientID != clientID {
		t.Errorf("TokenInfo.ClientID = %q, want %q", tk.ClientID, clientID)
	}

	// ExpiresAt must be a non-zero time in the future.
	if tk.ExpiresAt.IsZero() {
		t.Error("TokenInfo.ExpiresAt is zero, want a non-zero future time")
	}

	// CreatedAt must be a non-zero time.
	if tk.CreatedAt.IsZero() {
		t.Error("TokenInfo.CreatedAt is zero, want a non-zero time")
	}
}

// TestListTokens_RequestIDIsPopulated verifies that the RequestID field of
// TokenInfo is populated (it maps to the request_id column).
func TestListTokens_RequestIDIsPopulated(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	clientID := "lt-reqid-client"
	signature := "lt-reqid-sig-001"
	seedToken(t, store, clientID, signature)

	ctx := context.Background()

	// Act
	tokens, err := store.ListTokens(ctx)

	// Assert
	if err != nil {
		t.Fatalf("ListTokens() returned unexpected error: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("ListTokens() returned %d tokens, want 1", len(tokens))
	}

	// RequestID must be non-empty; fosite populates it from req.GetID().
	if tokens[0].RequestID == "" {
		t.Error("TokenInfo.RequestID is empty, want non-empty request ID from fosite")
	}
}

// ---------------------------------------------------------------------------
// DeleteToken
// ---------------------------------------------------------------------------

// TestDeleteToken_ExistingSignature_Succeeds verifies that DeleteToken removes
// a token without returning an error.
func TestDeleteToken_ExistingSignature_Succeeds(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	signature := "dt-ok-sig-001"
	seedToken(t, store, "dt-ok-client", signature)

	ctx := context.Background()

	// Act
	err := store.DeleteToken(ctx, signature)

	// Assert
	if err != nil {
		t.Errorf("DeleteToken(%q) returned unexpected error: %v", signature, err)
	}
}

// TestDeleteToken_AfterDelete_NotInList verifies that a deleted token does
// not appear in the ListTokens result.
func TestDeleteToken_AfterDelete_NotInList(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	keepSig := "dt-list-keep-sig"
	deleteSig := "dt-list-delete-sig"

	seedToken(t, store, "dt-list-keep-client", keepSig)
	seedToken(t, store, "dt-list-del-client", deleteSig)

	ctx := context.Background()

	if err := store.DeleteToken(ctx, deleteSig); err != nil {
		t.Fatalf("DeleteToken(%q): %v", deleteSig, err)
	}

	// Act
	tokens, err := store.ListTokens(ctx)

	// Assert
	if err != nil {
		t.Fatalf("ListTokens() after DeleteToken: %v", err)
	}

	for _, tk := range tokens {
		if tk.Signature == deleteSig {
			t.Errorf("ListTokens() after DeleteToken: deleted token %q still present", deleteSig)
		}
	}

	found := false
	for _, tk := range tokens {
		if tk.Signature == keepSig {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListTokens() after DeleteToken: kept token %q is missing", keepSig)
	}
}

// TestDeleteToken_AddsJTIToRevokedTokens verifies that DeleteToken inserts the
// token's request_id (jti) into the revoked_tokens table so that introspection
// returns active: false for the revoked token.
func TestDeleteToken_AddsJTIToRevokedTokens(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	signature := "dt-jti-sig-001"
	clientID := "dt-jti-client"
	seedToken(t, store, clientID, signature)

	ctx := context.Background()

	// Retrieve the token's request_id (jti) before deletion.
	tokens, err := store.ListTokens(ctx)
	if err != nil {
		t.Fatalf("ListTokens() before DeleteToken: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("ListTokens() returned %d tokens before deletion, want 1", len(tokens))
	}
	jti := tokens[0].RequestID
	if jti == "" {
		t.Fatal("TokenInfo.RequestID is empty; cannot verify jti blacklist entry")
	}

	// Act
	if err := store.DeleteToken(ctx, signature); err != nil {
		t.Fatalf("DeleteToken(%q): %v", signature, err)
	}

	// Assert — the jti must now appear in the revoked_tokens table.
	revoked, err := store.IsJTIRevoked(ctx, jti)
	if err != nil {
		t.Fatalf("IsJTIRevoked(%q) after DeleteToken: %v", jti, err)
	}
	if !revoked {
		t.Errorf("IsJTIRevoked(%q) = false after DeleteToken, want true", jti)
	}
}

// TestDeleteToken_NonExistentSignature_ReturnsErrTokenNotFound verifies that
// DeleteToken returns ErrTokenNotFound for a signature that does not exist.
func TestDeleteToken_NonExistentSignature_ReturnsErrTokenNotFound(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	// Act
	err := store.DeleteToken(ctx, "token-sig-does-not-exist-xyz")

	// Assert
	if err == nil {
		t.Error("DeleteToken() with non-existent signature returned nil error, want ErrTokenNotFound")
	}
	if !errors.Is(err, storage.ErrTokenNotFound) {
		t.Errorf("DeleteToken() error = %v, want storage.ErrTokenNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// DeleteAllTokens
// ---------------------------------------------------------------------------

// TestDeleteAllTokens_EmptyDB_Succeeds verifies that DeleteAllTokens does not
// return an error on an empty tokens table.
func TestDeleteAllTokens_EmptyDB_Succeeds(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	// Act
	err := store.DeleteAllTokens(ctx)

	// Assert
	if err != nil {
		t.Errorf("DeleteAllTokens() on empty table returned unexpected error: %v", err)
	}
}

// TestDeleteAllTokens_WithData_ClearsAllTokens verifies that after
// DeleteAllTokens, ListTokens returns an empty slice.
func TestDeleteAllTokens_WithData_ClearsAllTokens(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	seedToken(t, store, "dat-client-001", "dat-sig-001")
	seedToken(t, store, "dat-client-002", "dat-sig-002")
	seedToken(t, store, "dat-client-003", "dat-sig-003")

	ctx := context.Background()

	// Act
	err := store.DeleteAllTokens(ctx)

	// Assert — no error returned
	if err != nil {
		t.Fatalf("DeleteAllTokens() returned unexpected error: %v", err)
	}

	// Assert — list must now be empty
	tokens, err := store.ListTokens(ctx)
	if err != nil {
		t.Fatalf("ListTokens() after DeleteAllTokens: %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("ListTokens() after DeleteAllTokens returned %d tokens, want 0", len(tokens))
	}
}

// TestDeleteAllTokens_AddsAllJTIsToRevokedTokens verifies that DeleteAllTokens
// inserts every token's request_id (jti) into the revoked_tokens blacklist
// so that introspection returns active: false for all previously-active tokens.
func TestDeleteAllTokens_AddsAllJTIsToRevokedTokens(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	seedToken(t, store, "dat-jti-client-001", "dat-jti-sig-001")
	seedToken(t, store, "dat-jti-client-002", "dat-jti-sig-002")

	ctx := context.Background()

	// Capture the request_ids (jtis) before deletion.
	tokens, err := store.ListTokens(ctx)
	if err != nil {
		t.Fatalf("ListTokens() before DeleteAllTokens: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("ListTokens() returned %d tokens, want 2", len(tokens))
	}

	jtis := make([]string, 0, len(tokens))
	for _, tk := range tokens {
		if tk.RequestID != "" {
			jtis = append(jtis, tk.RequestID)
		}
	}

	// Act
	if err := store.DeleteAllTokens(ctx); err != nil {
		t.Fatalf("DeleteAllTokens(): %v", err)
	}

	// Assert — every captured jti must now be revoked.
	for _, jti := range jtis {
		revoked, err := store.IsJTIRevoked(ctx, jti)
		if err != nil {
			t.Fatalf("IsJTIRevoked(%q) after DeleteAllTokens: %v", jti, err)
		}
		if !revoked {
			t.Errorf("IsJTIRevoked(%q) = false after DeleteAllTokens, want true", jti)
		}
	}
}

// ---------------------------------------------------------------------------
// Compile-time interface check
// ---------------------------------------------------------------------------

// Ensure *storage.Store exposes the admin session/token management methods.
// This assertion will fail at compile time if the required methods are missing.
var _ interface {
	ListSessions(ctx context.Context) ([]storage.SessionInfo, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteAllSessions(ctx context.Context) error
	ListTokens(ctx context.Context) ([]storage.TokenInfo, error)
	DeleteToken(ctx context.Context, signature string) error
	DeleteAllTokens(ctx context.Context) error
} = (*storage.Store)(nil)
