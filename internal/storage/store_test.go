// Package storage_test contains E2E tests for the fosite storage layer.
//
// All tests were activated as part of DLD-665 after the storage layer was
// implemented.
//
// Test coverage (DLD-664):
//   - fosite 인스턴스 초기화 + 테스트 클라이언트 저장·조회
//   - AuthorizeCodeStorage: Create / Get / Get-after-Invalidate / Invalidate
//   - AccessTokenStorage:   Create / Get / Delete / Get-after-Delete
//   - RefreshTokenStorage:  Create / Get / Delete / Get-after-Delete
//   - OpenIDConnectRequestStorage: Create / Get / Delete / Get-after-Delete / Get-NotFound
//
// Test coverage (DLD-671):
//   - PKCERequestStorage: Create / Get / Get-NotFound / Delete / Get-after-Delete
//   - GetClient: public 클라이언트(is_public=true) 조회 성공, IsPublic() true, TokenEndpointAuthMethod "none"
package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/dlddu/my-auth/internal/database"
	"github.com/dlddu/my-auth/internal/storage"
	"github.com/dlddu/my-auth/internal/testhelper"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestStore opens the test database identified by dsn and returns a ready
// *storage.Store. The database connection is closed automatically via t.Cleanup.
func newTestStore(t *testing.T, dsn string) *storage.Store {
	t.Helper()

	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("newTestStore: open database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Logf("newTestStore cleanup: close db: %v", err)
		}
	})

	return storage.New(db)
}

// newTestClient returns a minimal fosite.DefaultOpenIDConnectClient populated
// with deterministic values. The returned client is suitable for seeding the
// store via store.CreateClient.
func newTestClient(clientID string) *fosite.DefaultOpenIDConnectClient {
	return &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            clientID,
			Secret:        []byte("test-client-secret"),
			RedirectURIs:  []string{"https://client.test.local/callback"},
			GrantTypes:    fosite.Arguments{"authorization_code", "refresh_token"},
			ResponseTypes: fosite.Arguments{"code"},
			Scopes:        fosite.Arguments{"openid", "profile", "email"},
		},
	}
}

// newAuthorizeRequest builds a minimal *fosite.AuthorizeRequest that satisfies
// fosite.Requester. It is used as the value stored in every storage test.
func newAuthorizeRequest(client fosite.Client) *fosite.AuthorizeRequest {
	sess := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject: "user-123",
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

// ---------------------------------------------------------------------------
// fosite 인스턴스 초기화 + 테스트 클라이언트 저장·조회
// ---------------------------------------------------------------------------

// TestStore_FositeProviderInit_ClientRegistered verifies that:
//  1. A *storage.Store can be instantiated against the test database.
//  2. CreateClient persists a client that GetClient can subsequently retrieve.
//
// This is the top-level smoke test confirming the Store plumbing is correct
// before any individual storage interface test is activated.
func TestStore_FositeProviderInit_ClientRegistered(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	clientID := "test-client-init"
	client := newTestClient(clientID)
	ctx := context.Background()

	// Act — store the client and immediately retrieve it.
	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	got, err := store.GetClient(ctx, clientID)

	// Assert
	if err != nil {
		t.Fatalf("GetClient(%q): %v", clientID, err)
	}
	if got.GetID() != clientID {
		t.Errorf("GetClient().GetID() = %q, want %q", got.GetID(), clientID)
	}
}

// ---------------------------------------------------------------------------
// AuthorizeCodeStorage
// ---------------------------------------------------------------------------

// TestAuthorizeCodeStore_CreateSession verifies that CreateAuthorizeCodeSession
// persists a session without error (happy path).
func TestAuthorizeCodeStore_CreateSession(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("auth-code-client-create")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	code := "test-auth-code-create-001"

	// Act
	err := store.CreateAuthorizeCodeSession(ctx, code, req)

	// Assert
	if err != nil {
		t.Errorf("CreateAuthorizeCodeSession() returned unexpected error: %v", err)
	}
}

// TestAuthorizeCodeStore_GetSession verifies that GetAuthorizeCodeSession
// returns the requester that was stored by CreateAuthorizeCodeSession.
func TestAuthorizeCodeStore_GetSession(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("auth-code-client-get")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	code := "test-auth-code-get-001"

	if err := store.CreateAuthorizeCodeSession(ctx, code, req); err != nil {
		t.Fatalf("CreateAuthorizeCodeSession(): %v", err)
	}

	sess := &openid.DefaultSession{}

	// Act
	got, err := store.GetAuthorizeCodeSession(ctx, code, sess)

	// Assert
	if err != nil {
		t.Fatalf("GetAuthorizeCodeSession() returned unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("GetAuthorizeCodeSession() returned nil Requester, want non-nil")
	}
	if got.GetClient().GetID() != client.GetID() {
		t.Errorf("Requester.Client.ID = %q, want %q", got.GetClient().GetID(), client.GetID())
	}
}

// TestAuthorizeCodeStore_GetSession_AfterInvalidate verifies that
// GetAuthorizeCodeSession returns fosite.ErrInvalidatedAuthorizeCode after
// InvalidateAuthorizeCodeSession has been called.
//
// fosite relies on this error sentinel to distinguish a used code (invalidated)
// from a code that never existed.
func TestAuthorizeCodeStore_GetSession_AfterInvalidate(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("auth-code-client-invalidate")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	code := "test-auth-code-invalidate-001"

	if err := store.CreateAuthorizeCodeSession(ctx, code, req); err != nil {
		t.Fatalf("CreateAuthorizeCodeSession(): %v", err)
	}
	if err := store.InvalidateAuthorizeCodeSession(ctx, code); err != nil {
		t.Fatalf("InvalidateAuthorizeCodeSession(): %v", err)
	}

	sess := &openid.DefaultSession{}

	// Act
	_, err := store.GetAuthorizeCodeSession(ctx, code, sess)

	// Assert — fosite requires ErrInvalidatedAuthorizeCode, not ErrNotFound.
	if err == nil {
		t.Fatal("GetAuthorizeCodeSession() after invalidation returned nil error, want fosite.ErrInvalidatedAuthorizeCode")
	}
	if err != fosite.ErrInvalidatedAuthorizeCode {
		t.Errorf("GetAuthorizeCodeSession() error = %v, want fosite.ErrInvalidatedAuthorizeCode", err)
	}
}

// TestAuthorizeCodeStore_InvalidateSession verifies that
// InvalidateAuthorizeCodeSession succeeds when the code exists.
func TestAuthorizeCodeStore_InvalidateSession(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("auth-code-client-inv2")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	code := "test-auth-code-inv2-001"

	if err := store.CreateAuthorizeCodeSession(ctx, code, req); err != nil {
		t.Fatalf("CreateAuthorizeCodeSession(): %v", err)
	}

	// Act
	err := store.InvalidateAuthorizeCodeSession(ctx, code)

	// Assert
	if err != nil {
		t.Errorf("InvalidateAuthorizeCodeSession() returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// AccessTokenStorage
// ---------------------------------------------------------------------------

// TestAccessTokenStore_CreateSession verifies that CreateAccessTokenSession
// persists an access-token session without error (happy path).
func TestAccessTokenStore_CreateSession(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("access-token-client-create")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	signature := "access-sig-create-001"

	// Act
	err := store.CreateAccessTokenSession(ctx, signature, req)

	// Assert
	if err != nil {
		t.Errorf("CreateAccessTokenSession() returned unexpected error: %v", err)
	}
}

// TestAccessTokenStore_GetSession verifies that GetAccessTokenSession returns
// the requester stored by CreateAccessTokenSession.
func TestAccessTokenStore_GetSession(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("access-token-client-get")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	signature := "access-sig-get-001"

	if err := store.CreateAccessTokenSession(ctx, signature, req); err != nil {
		t.Fatalf("CreateAccessTokenSession(): %v", err)
	}

	sess := &openid.DefaultSession{}

	// Act
	got, err := store.GetAccessTokenSession(ctx, signature, sess)

	// Assert
	if err != nil {
		t.Fatalf("GetAccessTokenSession() returned unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("GetAccessTokenSession() returned nil Requester, want non-nil")
	}
	if got.GetClient().GetID() != client.GetID() {
		t.Errorf("Requester.Client.ID = %q, want %q", got.GetClient().GetID(), client.GetID())
	}
}

// TestAccessTokenStore_DeleteSession verifies that DeleteAccessTokenSession
// removes the session without error.
func TestAccessTokenStore_DeleteSession(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("access-token-client-delete")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	signature := "access-sig-delete-001"

	if err := store.CreateAccessTokenSession(ctx, signature, req); err != nil {
		t.Fatalf("CreateAccessTokenSession(): %v", err)
	}

	// Act
	err := store.DeleteAccessTokenSession(ctx, signature)

	// Assert
	if err != nil {
		t.Errorf("DeleteAccessTokenSession() returned unexpected error: %v", err)
	}
}

// TestAccessTokenStore_GetSession_AfterDelete verifies that
// GetAccessTokenSession returns an error after the session has been deleted.
func TestAccessTokenStore_GetSession_AfterDelete(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("access-token-client-del2")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	signature := "access-sig-del2-001"

	if err := store.CreateAccessTokenSession(ctx, signature, req); err != nil {
		t.Fatalf("CreateAccessTokenSession(): %v", err)
	}
	if err := store.DeleteAccessTokenSession(ctx, signature); err != nil {
		t.Fatalf("DeleteAccessTokenSession(): %v", err)
	}

	sess := &openid.DefaultSession{}

	// Act
	_, err := store.GetAccessTokenSession(ctx, signature, sess)

	// Assert — a deleted session must not be found.
	if err == nil {
		t.Error("GetAccessTokenSession() after deletion returned nil error, want non-nil error")
	}
}

// ---------------------------------------------------------------------------
// RefreshTokenStorage
// ---------------------------------------------------------------------------

// TestRefreshTokenStore_CreateSession verifies that CreateRefreshTokenSession
// persists a refresh-token session without error (happy path).
func TestRefreshTokenStore_CreateSession(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("refresh-token-client-create")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	signature := "refresh-sig-create-001"

	// Act
	err := store.CreateRefreshTokenSession(ctx, signature, "access-sig-for-refresh-create-001", req)

	// Assert
	if err != nil {
		t.Errorf("CreateRefreshTokenSession() returned unexpected error: %v", err)
	}
}

// TestRefreshTokenStore_GetSession verifies that GetRefreshTokenSession
// returns the requester stored by CreateRefreshTokenSession.
func TestRefreshTokenStore_GetSession(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("refresh-token-client-get")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	signature := "refresh-sig-get-001"

	if err := store.CreateRefreshTokenSession(ctx, signature, "access-sig-for-refresh-get-001", req); err != nil {
		t.Fatalf("CreateRefreshTokenSession(): %v", err)
	}

	sess := &openid.DefaultSession{}

	// Act
	got, err := store.GetRefreshTokenSession(ctx, signature, sess)

	// Assert
	if err != nil {
		t.Fatalf("GetRefreshTokenSession() returned unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("GetRefreshTokenSession() returned nil Requester, want non-nil")
	}
	if got.GetClient().GetID() != client.GetID() {
		t.Errorf("Requester.Client.ID = %q, want %q", got.GetClient().GetID(), client.GetID())
	}
}

// TestRefreshTokenStore_DeleteSession verifies that DeleteRefreshTokenSession
// removes the session without error.
func TestRefreshTokenStore_DeleteSession(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("refresh-token-client-delete")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	signature := "refresh-sig-delete-001"

	if err := store.CreateRefreshTokenSession(ctx, signature, "access-sig-for-refresh-delete-001", req); err != nil {
		t.Fatalf("CreateRefreshTokenSession(): %v", err)
	}

	// Act
	err := store.DeleteRefreshTokenSession(ctx, signature)

	// Assert
	if err != nil {
		t.Errorf("DeleteRefreshTokenSession() returned unexpected error: %v", err)
	}
}

// TestRefreshTokenStore_GetSession_AfterDelete verifies that
// GetRefreshTokenSession returns an error after the session has been deleted.
func TestRefreshTokenStore_GetSession_AfterDelete(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("refresh-token-client-del2")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	signature := "refresh-sig-del2-001"

	if err := store.CreateRefreshTokenSession(ctx, signature, "access-sig-for-refresh-del2-001", req); err != nil {
		t.Fatalf("CreateRefreshTokenSession(): %v", err)
	}
	if err := store.DeleteRefreshTokenSession(ctx, signature); err != nil {
		t.Fatalf("DeleteRefreshTokenSession(): %v", err)
	}

	sess := &openid.DefaultSession{}

	// Act
	_, err := store.GetRefreshTokenSession(ctx, signature, sess)

	// Assert — a deleted session must not be found.
	if err == nil {
		t.Error("GetRefreshTokenSession() after deletion returned nil error, want non-nil error")
	}
}

// ---------------------------------------------------------------------------
// OpenIDConnectRequestStorage
// ---------------------------------------------------------------------------

// TestOIDCStore_CreateSession verifies that CreateOpenIDConnectSession
// persists an OIDC session without error (happy path).
func TestOIDCStore_CreateSession(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("oidc-client-create")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	authorizeCode := "test-oidc-code-create-001"

	// Act
	err := store.CreateOpenIDConnectSession(ctx, authorizeCode, req)

	// Assert
	if err != nil {
		t.Errorf("CreateOpenIDConnectSession() returned unexpected error: %v", err)
	}
}

// TestOIDCStore_GetSession verifies that GetOpenIDConnectSession returns the
// session stored by CreateOpenIDConnectSession.
func TestOIDCStore_GetSession(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("oidc-client-get")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	authorizeCode := "test-oidc-code-get-001"

	if err := store.CreateOpenIDConnectSession(ctx, authorizeCode, req); err != nil {
		t.Fatalf("CreateOpenIDConnectSession(): %v", err)
	}

	// Act
	got, err := store.GetOpenIDConnectSession(ctx, authorizeCode, req)

	// Assert
	if err != nil {
		t.Fatalf("GetOpenIDConnectSession() returned unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("GetOpenIDConnectSession() returned nil Requester, want non-nil")
	}
	if got.GetClient().GetID() != client.GetID() {
		t.Errorf("Requester.Client.ID = %q, want %q", got.GetClient().GetID(), client.GetID())
	}
}

// TestOIDCStore_GetSession_NotFound verifies that GetOpenIDConnectSession
// returns fosite.ErrNotFound when no session exists for the given code.
//
// fosite relies on this sentinel to distinguish "session not yet created" from
// other storage errors.
func TestOIDCStore_GetSession_NotFound(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("oidc-client-notfound")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	nonExistentCode := "test-oidc-code-does-not-exist-999"

	// Act
	_, err := store.GetOpenIDConnectSession(ctx, nonExistentCode, req)

	// Assert — fosite requires ErrNotFound for a missing OIDC session.
	if err == nil {
		t.Fatal("GetOpenIDConnectSession() returned nil error for non-existent code, want fosite.ErrNotFound")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("GetOpenIDConnectSession() error = %v, want fosite.ErrNotFound", err)
	}
}

// TestOIDCStore_DeleteSession verifies that DeleteOpenIDConnectSession removes
// the session without error.
func TestOIDCStore_DeleteSession(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("oidc-client-delete")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	authorizeCode := "test-oidc-code-delete-001"

	if err := store.CreateOpenIDConnectSession(ctx, authorizeCode, req); err != nil {
		t.Fatalf("CreateOpenIDConnectSession(): %v", err)
	}

	// Act
	err := store.DeleteOpenIDConnectSession(ctx, authorizeCode)

	// Assert
	if err != nil {
		t.Errorf("DeleteOpenIDConnectSession() returned unexpected error: %v", err)
	}
}

// TestOIDCStore_GetSession_AfterDelete verifies that GetOpenIDConnectSession
// returns fosite.ErrNotFound after the session has been deleted.
func TestOIDCStore_GetSession_AfterDelete(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("oidc-client-del2")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	authorizeCode := "test-oidc-code-del2-001"

	if err := store.CreateOpenIDConnectSession(ctx, authorizeCode, req); err != nil {
		t.Fatalf("CreateOpenIDConnectSession(): %v", err)
	}
	if err := store.DeleteOpenIDConnectSession(ctx, authorizeCode); err != nil {
		t.Fatalf("DeleteOpenIDConnectSession(): %v", err)
	}

	// Act
	_, err := store.GetOpenIDConnectSession(ctx, authorizeCode, req)

	// Assert — after deletion the session must not be found.
	if err == nil {
		t.Fatal("GetOpenIDConnectSession() after deletion returned nil error, want fosite.ErrNotFound")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("GetOpenIDConnectSession() error = %v, want fosite.ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// PKCERequestStorage
// ---------------------------------------------------------------------------

// TestPKCEStore_CreateSession verifies that CreatePKCERequestSession persists
// a PKCE session without error (happy path).
func TestPKCEStore_CreateSession(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("pkce-client-create")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	signature := "test-pkce-sig-create-001"

	// Act
	err := store.CreatePKCERequestSession(ctx, signature, req)

	// Assert
	if err != nil {
		t.Errorf("CreatePKCERequestSession() returned unexpected error: %v", err)
	}
}

// TestPKCEStore_GetSession verifies that GetPKCERequestSession returns the
// requester stored by CreatePKCERequestSession.
func TestPKCEStore_GetSession(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("pkce-client-get")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	signature := "test-pkce-sig-get-001"

	if err := store.CreatePKCERequestSession(ctx, signature, req); err != nil {
		t.Fatalf("CreatePKCERequestSession(): %v", err)
	}

	sess := &openid.DefaultSession{}

	// Act
	got, err := store.GetPKCERequestSession(ctx, signature, sess)

	// Assert
	if err != nil {
		t.Fatalf("GetPKCERequestSession() returned unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("GetPKCERequestSession() returned nil Requester, want non-nil")
	}
	if got.GetClient().GetID() != client.GetID() {
		t.Errorf("Requester.Client.ID = %q, want %q", got.GetClient().GetID(), client.GetID())
	}
}

// TestPKCEStore_GetSession_NotFound verifies that GetPKCERequestSession
// returns fosite.ErrNotFound when no session exists for the given signature.
//
// fosite relies on this sentinel during PKCE validation to distinguish a code
// that never had a PKCE binding from other storage errors.
func TestPKCEStore_GetSession_NotFound(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	ctx := context.Background()
	sess := &openid.DefaultSession{}
	nonExistentSignature := "test-pkce-sig-does-not-exist-999"

	// Act
	_, err := store.GetPKCERequestSession(ctx, nonExistentSignature, sess)

	// Assert — fosite requires ErrNotFound for a missing PKCE session.
	if err == nil {
		t.Fatal("GetPKCERequestSession() returned nil error for non-existent signature, want fosite.ErrNotFound")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("GetPKCERequestSession() error = %v, want fosite.ErrNotFound", err)
	}
}

// TestPKCEStore_DeleteSession verifies that DeletePKCERequestSession removes
// the PKCE session without error.
func TestPKCEStore_DeleteSession(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("pkce-client-delete")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	signature := "test-pkce-sig-delete-001"

	if err := store.CreatePKCERequestSession(ctx, signature, req); err != nil {
		t.Fatalf("CreatePKCERequestSession(): %v", err)
	}

	// Act
	err := store.DeletePKCERequestSession(ctx, signature)

	// Assert
	if err != nil {
		t.Errorf("DeletePKCERequestSession() returned unexpected error: %v", err)
	}
}

// TestPKCEStore_GetSession_AfterDelete verifies that GetPKCERequestSession
// returns fosite.ErrNotFound after the session has been deleted.
func TestPKCEStore_GetSession_AfterDelete(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("pkce-client-del2")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	signature := "test-pkce-sig-del2-001"

	if err := store.CreatePKCERequestSession(ctx, signature, req); err != nil {
		t.Fatalf("CreatePKCERequestSession(): %v", err)
	}
	if err := store.DeletePKCERequestSession(ctx, signature); err != nil {
		t.Fatalf("DeletePKCERequestSession(): %v", err)
	}

	sess := &openid.DefaultSession{}

	// Act
	_, err := store.GetPKCERequestSession(ctx, signature, sess)

	// Assert — a deleted PKCE session must not be found.
	if err == nil {
		t.Fatal("GetPKCERequestSession() after deletion returned nil error, want fosite.ErrNotFound")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("GetPKCERequestSession() error = %v, want fosite.ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// GetClient — public 클라이언트
// ---------------------------------------------------------------------------

// newPublicTestClient returns a *fosite.DefaultOpenIDConnectClient configured
// as a public client: no secret, Public=true, TokenEndpointAuthMethod="none".
// This matches the RFC 6749 definition of a public client (e.g. SPA or native
// app) that cannot securely store a client secret.
func newPublicTestClient(clientID string) *fosite.DefaultOpenIDConnectClient {
	return &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            clientID,
			Secret:        nil,
			Public:        true,
			RedirectURIs:  []string{"https://spa.test.local/callback"},
			GrantTypes:    fosite.Arguments{"authorization_code"},
			ResponseTypes: fosite.Arguments{"code"},
			Scopes:        fosite.Arguments{"openid", "profile"},
		},
		TokenEndpointAuthMethod: "none",
	}
}

// TestGetClient_PublicClient_RetrievedSuccessfully verifies that a public
// client stored via CreateClient can be retrieved via GetClient without error.
//
// A public client has no client secret and uses TokenEndpointAuthMethod="none"
// as mandated by RFC 6749 §2.1 and OpenID Connect Core §9.
func TestGetClient_PublicClient_RetrievedSuccessfully(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	clientID := "public-client-retrieved"
	client := newPublicTestClient(clientID)
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	// Act
	got, err := store.GetClient(ctx, clientID)

	// Assert
	if err != nil {
		t.Fatalf("GetClient(%q): %v", clientID, err)
	}
	if got.GetID() != clientID {
		t.Errorf("GetClient().GetID() = %q, want %q", got.GetID(), clientID)
	}
}

// TestGetClient_PublicClient_IsPublicReturnsTrue verifies that a public client
// retrieved from the store reports IsPublic() == true.
//
// fosite uses IsPublic() to skip client secret verification, which is the
// correct behaviour for public clients (e.g. SPAs using PKCE).
func TestGetClient_PublicClient_IsPublicReturnsTrue(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	clientID := "public-client-ispublic"
	client := newPublicTestClient(clientID)
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	// Act
	got, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("GetClient(%q): %v", clientID, err)
	}

	// Assert — fosite.Client.IsPublic() must return true for public clients.
	if !got.IsPublic() {
		t.Errorf("GetClient(%q).IsPublic() = false, want true", clientID)
	}
}

// TestGetClient_PublicClient_TokenEndpointAuthMethodIsNone verifies that a
// public client retrieved from the store has TokenEndpointAuthMethod == "none".
//
// fosite's OpenID Connect handler checks GetTokenEndpointAuthMethod() to
// determine which authentication scheme to apply at the token endpoint. Public
// clients must return "none" so that fosite does not require a client secret.
func TestGetClient_PublicClient_TokenEndpointAuthMethodIsNone(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	clientID := "public-client-authmeth"
	client := newPublicTestClient(clientID)
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	// Act
	got, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("GetClient(%q): %v", clientID, err)
	}

	// Assert — the token endpoint auth method must be "none" for public clients.
	oidcClient, ok := got.(interface{ GetTokenEndpointAuthMethod() string })
	if !ok {
		t.Fatalf("GetClient(%q) returned %T which does not implement GetTokenEndpointAuthMethod()", clientID, got)
	}
	if method := oidcClient.GetTokenEndpointAuthMethod(); method != "none" {
		t.Errorf("GetTokenEndpointAuthMethod() = %q, want %q", method, "none")
	}
}

// ---------------------------------------------------------------------------
// RefreshTokenStorage — Token Refresh 검증 테스트 (DLD-677)
// ---------------------------------------------------------------------------

// TestRefreshTokenStore_CreateAndGet_RoundTrip verifies that a refresh token
// session stored via CreateRefreshTokenSession can be correctly retrieved via
// GetRefreshTokenSession and preserves the client identity.
//
// This is the fundamental storage round-trip test for the refresh token grant:
// fosite calls CreateRefreshTokenSession after issuing a token and then calls
// GetRefreshTokenSession when the client presents the refresh token.
func TestRefreshTokenStore_CreateAndGet_RoundTrip(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("rt-roundtrip-client")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	signature := "rt-roundtrip-sig-001"
	accessSig := "rt-roundtrip-access-sig-001"

	if err := store.CreateRefreshTokenSession(ctx, signature, accessSig, req); err != nil {
		t.Fatalf("CreateRefreshTokenSession(): %v", err)
	}

	sess := &openid.DefaultSession{}

	// Act
	got, err := store.GetRefreshTokenSession(ctx, signature, sess)

	// Assert
	if err != nil {
		t.Fatalf("GetRefreshTokenSession() returned unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("GetRefreshTokenSession() returned nil Requester, want non-nil")
	}
	if got.GetClient().GetID() != client.GetID() {
		t.Errorf("Requester.Client.ID = %q, want %q", got.GetClient().GetID(), client.GetID())
	}
}

// TestRefreshTokenStore_GetSession_NotFound verifies that GetRefreshTokenSession
// returns fosite.ErrNotFound when no session exists for the given signature.
//
// fosite relies on this sentinel to distinguish an unknown/expired refresh token
// from other storage errors during the token refresh flow.
func TestRefreshTokenStore_GetSession_NotFound(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	ctx := context.Background()
	sess := &openid.DefaultSession{}
	nonExistentSig := "rt-does-not-exist-sig-999"

	// Act
	_, err := store.GetRefreshTokenSession(ctx, nonExistentSig, sess)

	// Assert — fosite requires ErrNotFound for an unknown refresh token.
	if err == nil {
		t.Fatal("GetRefreshTokenSession() returned nil error for non-existent signature, want fosite.ErrNotFound")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("GetRefreshTokenSession() error = %v, want fosite.ErrNotFound", err)
	}
}

// TestRefreshTokenStore_DeleteSession_ThenNotFound verifies that
// GetRefreshTokenSession returns fosite.ErrNotFound after the session has been
// deleted via DeleteRefreshTokenSession.
//
// This behaviour is critical for security: once a refresh token is consumed
// or revoked, it must not be retrievable from storage.
func TestRefreshTokenStore_DeleteSession_ThenNotFound(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("rt-delete-notfound-client")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	signature := "rt-delete-notfound-sig-001"

	if err := store.CreateRefreshTokenSession(ctx, signature, "rt-delete-notfound-access-001", req); err != nil {
		t.Fatalf("CreateRefreshTokenSession(): %v", err)
	}

	if err := store.DeleteRefreshTokenSession(ctx, signature); err != nil {
		t.Fatalf("DeleteRefreshTokenSession(): %v", err)
	}

	sess := &openid.DefaultSession{}

	// Act
	_, err := store.GetRefreshTokenSession(ctx, signature, sess)

	// Assert — a deleted session must return fosite.ErrNotFound.
	if err == nil {
		t.Fatal("GetRefreshTokenSession() after deletion returned nil error, want fosite.ErrNotFound")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("GetRefreshTokenSession() error = %v, want fosite.ErrNotFound", err)
	}
}

// TestRefreshTokenStore_RotateRefreshToken_OldSignatureGone verifies that
// RotateRefreshToken removes the old refresh token signature from storage so
// that it cannot be used again.
//
// Token rotation (RFC 6819 §5.2.2.3) requires that each use of a refresh token
// produces a new token and invalidates the old one. After rotation the old
// signature must return fosite.ErrNotFound.
func TestRefreshTokenStore_RotateRefreshToken_OldSignatureGone(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("rt-rotate-client")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	oldSig := "rt-rotate-old-sig-001"
	requestID := req.GetID()

	if err := store.CreateRefreshTokenSession(ctx, oldSig, "rt-rotate-access-001", req); err != nil {
		t.Fatalf("CreateRefreshTokenSession(): %v", err)
	}

	// Act — rotate the old refresh token (simulates fosite's rotation step).
	if err := store.RotateRefreshToken(ctx, requestID, oldSig); err != nil {
		t.Fatalf("RotateRefreshToken(): %v", err)
	}

	sess := &openid.DefaultSession{}

	// Assert — the old signature must no longer be found after rotation.
	_, err := store.GetRefreshTokenSession(ctx, oldSig, sess)
	if err == nil {
		t.Fatal("GetRefreshTokenSession() after rotation returned nil error, want non-nil error (old token must be gone)")
	}
}

// TestRefreshTokenStore_RevokeRefreshToken_DeletesByRequestID verifies that
// RevokeRefreshToken removes all refresh tokens associated with the given
// request ID from storage.
//
// RFC 7009 token revocation requires that all tokens bound to a single
// authorization grant are invalidated together. fosite stores the request ID
// in the request_data JSON blob; RevokeRefreshToken must perform a LIKE-based
// lookup to find and delete them.
func TestRefreshTokenStore_RevokeRefreshToken_DeletesByRequestID(t *testing.T) {

	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)

	client := newTestClient("rt-revoke-client")
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	req := newAuthorizeRequest(client)
	requestID := req.GetID()
	signature := "rt-revoke-sig-001"

	if err := store.CreateRefreshTokenSession(ctx, signature, "rt-revoke-access-001", req); err != nil {
		t.Fatalf("CreateRefreshTokenSession(): %v", err)
	}

	// Confirm the token exists before revocation.
	sess := &openid.DefaultSession{}
	if _, err := store.GetRefreshTokenSession(ctx, signature, sess); err != nil {
		t.Fatalf("GetRefreshTokenSession() before revocation: %v (want it to exist)", err)
	}

	// Act — revoke all tokens for this request ID.
	if err := store.RevokeRefreshToken(ctx, requestID); err != nil {
		t.Fatalf("RevokeRefreshToken(): %v", err)
	}

	// Assert — the token must no longer be found after revocation.
	_, err := store.GetRefreshTokenSession(ctx, signature, sess)
	if err == nil {
		t.Fatal("GetRefreshTokenSession() after revocation returned nil error, want non-nil error (token must be gone)")
	}
}
