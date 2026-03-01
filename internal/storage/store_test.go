// Package storage_test contains E2E tests for the fosite storage layer.
//
// All tests are skipped with t.Skip("TODO: fosite storage 구현 후 활성화") and
// are activated one by one as DLD-665 implements each method.
//
// Test coverage (DLD-664):
//   - fosite 인스턴스 초기화 + 테스트 클라이언트 저장·조회
//   - AuthorizeCodeStorage: Create / Get / Get-after-Invalidate / Invalidate
//   - AccessTokenStorage:   Create / Get / Delete / Get-after-Delete
//   - RefreshTokenStorage:  Create / Get / Delete / Get-after-Delete
//   - OpenIDConnectRequestStorage: Create / Get / Delete / Get-after-Delete / Get-NotFound
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
	c := fosite.NewDefaultOpenIDConnectClient()
	c.ID = clientID
	c.Secret = []byte("test-client-secret")
	c.RedirectURIs = []string{"https://client.test.local/callback"}
	c.GrantTypes = fosite.Arguments{"authorization_code", "refresh_token"}
	c.ResponseTypes = fosite.Arguments{"code"}
	c.Scopes = fosite.Arguments{"openid", "profile", "email"}
	return c
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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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
	err := store.CreateRefreshTokenSession(ctx, signature, req)

	// Assert
	if err != nil {
		t.Errorf("CreateRefreshTokenSession() returned unexpected error: %v", err)
	}
}

// TestRefreshTokenStore_GetSession verifies that GetRefreshTokenSession
// returns the requester stored by CreateRefreshTokenSession.
func TestRefreshTokenStore_GetSession(t *testing.T) {
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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

	if err := store.CreateRefreshTokenSession(ctx, signature, req); err != nil {
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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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

	if err := store.CreateRefreshTokenSession(ctx, signature, req); err != nil {
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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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

	if err := store.CreateRefreshTokenSession(ctx, signature, req); err != nil {
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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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
	t.Skip("TODO: fosite storage 구현 후 활성화") // DLD-664

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
