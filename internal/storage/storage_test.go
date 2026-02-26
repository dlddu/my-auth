package storage_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/ory/fosite"

	"github.com/dlddu/my-auth/internal/database"
	"github.com/dlddu/my-auth/internal/storage"
	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Helpers shared across all sub-tests
// ---------------------------------------------------------------------------

// openStoreDB opens the database identified by dsn and returns a *sql.DB that
// is closed automatically when the test ends.
func openStoreDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("storage_test: open db: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Logf("storage_test: close db: %v", err)
		}
	})
	return db
}

// makeRequester builds a minimal fosite.Requester suitable for store tests.
// clientID and subject are embedded in the request and its session.
func makeRequester(clientID, subject string, scopes ...string) fosite.Requester {
	sess := &fosite.DefaultSession{
		Subject: subject,
	}
	sess.SetExpiresAt(fosite.AuthorizeCode, time.Now().Add(10*time.Minute))
	sess.SetExpiresAt(fosite.AccessToken, time.Now().Add(time.Hour))
	sess.SetExpiresAt(fosite.RefreshToken, time.Now().Add(720*time.Hour))

	req := fosite.NewRequest()
	req.Client = &storage.Client{
		ID:            clientID,
		Secret:        []byte("secret"),
		RedirectURIs:  []string{"http://localhost:9999/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email"},
	}
	req.SetSession(sess)
	req.GrantedScope = fosite.Arguments(scopes)
	return req
}

// ---------------------------------------------------------------------------
// ClientStore
// ---------------------------------------------------------------------------

// TestClientStore_GetClient_Success verifies that a client seeded in the
// database is returned correctly by GetClient.
func TestClientStore_GetClient_Success(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	testhelper.SeedTestClient(t, db)

	store := storage.NewClientStore(db)
	ctx := context.Background()

	// Act
	client, err := store.GetClient(ctx, "test-client")

	// Assert
	if err != nil {
		t.Fatalf("GetClient returned error: %v", err)
	}
	if client == nil {
		t.Fatal("GetClient returned nil client")
	}
	if client.GetID() != "test-client" {
		t.Errorf("client.GetID() = %q, want %q", client.GetID(), "test-client")
	}
}

// TestClientStore_GetClient_NotFound verifies that fosite.ErrNotFound is
// returned when the requested client does not exist.
func TestClientStore_GetClient_NotFound(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	store := storage.NewClientStore(db)
	ctx := context.Background()

	// Act
	_, err := store.GetClient(ctx, "does-not-exist")

	// Assert
	if err == nil {
		t.Fatal("GetClient expected error for missing client, got nil")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("GetClient error = %v, want fosite.ErrNotFound", err)
	}
}

// TestClientStore_GetClient_RedirectURIs verifies that redirect_uris are
// decoded correctly from their JSON representation in the database.
func TestClientStore_GetClient_RedirectURIs(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	testhelper.SeedTestClient(t, db)

	store := storage.NewClientStore(db)
	ctx := context.Background()

	// Act
	client, err := store.GetClient(ctx, "test-client")

	// Assert
	if err != nil {
		t.Fatalf("GetClient returned error: %v", err)
	}
	uris := client.GetRedirectURIs()
	if len(uris) == 0 {
		t.Fatal("GetClient returned client with no redirect_uris")
	}

	wantURI := "http://localhost:9999/callback"
	found := false
	for _, u := range uris {
		if u == wantURI {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("redirect_uris %v does not contain %q", uris, wantURI)
	}
}

// TestClientStore_GetClient_GrantTypes verifies that grant_types are decoded
// correctly.
func TestClientStore_GetClient_GrantTypes(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	testhelper.SeedTestClient(t, db)

	store := storage.NewClientStore(db)
	ctx := context.Background()

	// Act
	client, err := store.GetClient(ctx, "test-client")

	// Assert
	if err != nil {
		t.Fatalf("GetClient returned error: %v", err)
	}
	grants := client.GetGrantTypes()
	if len(grants) == 0 {
		t.Fatal("GetClient returned client with no grant_types")
	}

	found := false
	for _, g := range grants {
		if g == "authorization_code" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("grant_types %v does not contain %q", grants, "authorization_code")
	}
}

// ---------------------------------------------------------------------------
// AuthorizeCodeStore
// ---------------------------------------------------------------------------

// TestAuthorizeCodeStore_CreateAndGet_Success verifies the full
// Create → Get lifecycle for an authorize code session.
func TestAuthorizeCodeStore_CreateAndGet_Success(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	testhelper.SeedTestClient(t, db)

	store := storage.NewAuthorizeCodeStore(db)
	ctx := context.Background()
	code := "test-auth-code-001"
	req := makeRequester("test-client", "admin@test.local", "openid", "profile")

	// Act — create
	if err := store.CreateAuthorizeCodeSession(ctx, code, req); err != nil {
		t.Fatalf("CreateAuthorizeCodeSession: %v", err)
	}

	// Act — get
	sess := &fosite.DefaultSession{}
	got, err := store.GetAuthorizeCodeSession(ctx, code, sess)

	// Assert
	if err != nil {
		t.Fatalf("GetAuthorizeCodeSession: %v", err)
	}
	if got == nil {
		t.Fatal("GetAuthorizeCodeSession returned nil requester")
	}
	if got.GetSession().GetSubject() != "admin@test.local" {
		t.Errorf("subject = %q, want %q", got.GetSession().GetSubject(), "admin@test.local")
	}
}

// TestAuthorizeCodeStore_Get_NotFound verifies that fosite.ErrNotFound is
// returned for an unknown code.
func TestAuthorizeCodeStore_Get_NotFound(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	store := storage.NewAuthorizeCodeStore(db)
	ctx := context.Background()

	// Act
	sess := &fosite.DefaultSession{}
	_, err := store.GetAuthorizeCodeSession(ctx, "no-such-code", sess)

	// Assert
	if err == nil {
		t.Fatal("GetAuthorizeCodeSession expected error for missing code, got nil")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("GetAuthorizeCodeSession error = %v, want fosite.ErrNotFound", err)
	}
}

// TestAuthorizeCodeStore_Invalidate_PreventsReuse verifies that once a code
// is invalidated, GetAuthorizeCodeSession returns ErrInvalidatedAuthorizeCode.
func TestAuthorizeCodeStore_Invalidate_PreventsReuse(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	testhelper.SeedTestClient(t, db)

	store := storage.NewAuthorizeCodeStore(db)
	ctx := context.Background()
	code := "test-auth-code-002"
	req := makeRequester("test-client", "admin@test.local", "openid")

	if err := store.CreateAuthorizeCodeSession(ctx, code, req); err != nil {
		t.Fatalf("CreateAuthorizeCodeSession: %v", err)
	}

	// Act — invalidate
	if err := store.InvalidateAuthorizeCodeSession(ctx, code); err != nil {
		t.Fatalf("InvalidateAuthorizeCodeSession: %v", err)
	}

	// Act — get after invalidation
	sess := &fosite.DefaultSession{}
	_, err := store.GetAuthorizeCodeSession(ctx, code, sess)

	// Assert
	if err == nil {
		t.Fatal("GetAuthorizeCodeSession after invalidation expected error, got nil")
	}
	if err != fosite.ErrInvalidatedAuthorizeCode {
		t.Errorf("error = %v, want fosite.ErrInvalidatedAuthorizeCode", err)
	}
}

// TestAuthorizeCodeStore_Invalidate_NotFound verifies that invalidating a
// non-existent code returns fosite.ErrNotFound.
func TestAuthorizeCodeStore_Invalidate_NotFound(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	store := storage.NewAuthorizeCodeStore(db)
	ctx := context.Background()

	// Act
	err := store.InvalidateAuthorizeCodeSession(ctx, "ghost-code")

	// Assert
	if err == nil {
		t.Fatal("InvalidateAuthorizeCodeSession expected error for missing code, got nil")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("error = %v, want fosite.ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// AccessTokenStore
// ---------------------------------------------------------------------------

// TestAccessTokenStore_CreateAndGet_Success verifies the full
// Create → Get lifecycle for an access token session.
func TestAccessTokenStore_CreateAndGet_Success(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	testhelper.SeedTestClient(t, db)

	store := storage.NewAccessTokenStore(db)
	ctx := context.Background()
	sig := "access-token-sig-001"
	req := makeRequester("test-client", "admin@test.local", "openid", "email")

	// Act — create
	if err := store.CreateAccessTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}

	// Act — get
	sess := &fosite.DefaultSession{}
	got, err := store.GetAccessTokenSession(ctx, sig, sess)

	// Assert
	if err != nil {
		t.Fatalf("GetAccessTokenSession: %v", err)
	}
	if got == nil {
		t.Fatal("GetAccessTokenSession returned nil requester")
	}
	if got.GetSession().GetSubject() != "admin@test.local" {
		t.Errorf("subject = %q, want %q", got.GetSession().GetSubject(), "admin@test.local")
	}
}

// TestAccessTokenStore_Get_NotFound verifies that fosite.ErrNotFound is
// returned for an unknown signature.
func TestAccessTokenStore_Get_NotFound(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	store := storage.NewAccessTokenStore(db)
	ctx := context.Background()

	// Act
	sess := &fosite.DefaultSession{}
	_, err := store.GetAccessTokenSession(ctx, "no-such-sig", sess)

	// Assert
	if err == nil {
		t.Fatal("GetAccessTokenSession expected error for missing token, got nil")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("error = %v, want fosite.ErrNotFound", err)
	}
}

// TestAccessTokenStore_Delete_RemovesToken verifies that DeleteAccessTokenSession
// removes the token so that a subsequent Get returns ErrNotFound.
func TestAccessTokenStore_Delete_RemovesToken(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	testhelper.SeedTestClient(t, db)

	store := storage.NewAccessTokenStore(db)
	ctx := context.Background()
	sig := "access-token-sig-002"
	req := makeRequester("test-client", "admin@test.local", "openid")

	if err := store.CreateAccessTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}

	// Act — delete
	if err := store.DeleteAccessTokenSession(ctx, sig); err != nil {
		t.Fatalf("DeleteAccessTokenSession: %v", err)
	}

	// Assert — subsequent get must return ErrNotFound
	sess := &fosite.DefaultSession{}
	_, err := store.GetAccessTokenSession(ctx, sig, sess)
	if err == nil {
		t.Fatal("GetAccessTokenSession after delete expected error, got nil")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("error after delete = %v, want fosite.ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// RefreshTokenStore
// ---------------------------------------------------------------------------

// TestRefreshTokenStore_CreateAndGet_Success verifies the full
// Create → Get lifecycle for a refresh token session.
func TestRefreshTokenStore_CreateAndGet_Success(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	testhelper.SeedTestClient(t, db)

	store := storage.NewRefreshTokenStore(db)
	ctx := context.Background()
	sig := "refresh-token-sig-001"
	req := makeRequester("test-client", "admin@test.local", "openid", "offline_access")

	// Act — create
	if err := store.CreateRefreshTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	// Act — get
	sess := &fosite.DefaultSession{}
	got, err := store.GetRefreshTokenSession(ctx, sig, sess)

	// Assert
	if err != nil {
		t.Fatalf("GetRefreshTokenSession: %v", err)
	}
	if got == nil {
		t.Fatal("GetRefreshTokenSession returned nil requester")
	}
	if got.GetSession().GetSubject() != "admin@test.local" {
		t.Errorf("subject = %q, want %q", got.GetSession().GetSubject(), "admin@test.local")
	}
}

// TestRefreshTokenStore_Get_NotFound verifies that fosite.ErrNotFound is
// returned for an unknown signature.
func TestRefreshTokenStore_Get_NotFound(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	store := storage.NewRefreshTokenStore(db)
	ctx := context.Background()

	// Act
	sess := &fosite.DefaultSession{}
	_, err := store.GetRefreshTokenSession(ctx, "no-such-sig", sess)

	// Assert
	if err == nil {
		t.Fatal("GetRefreshTokenSession expected error for missing token, got nil")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("error = %v, want fosite.ErrNotFound", err)
	}
}

// TestRefreshTokenStore_Delete_RemovesToken verifies that
// DeleteRefreshTokenSession removes the token from the database.
func TestRefreshTokenStore_Delete_RemovesToken(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	testhelper.SeedTestClient(t, db)

	store := storage.NewRefreshTokenStore(db)
	ctx := context.Background()
	sig := "refresh-token-sig-002"
	req := makeRequester("test-client", "admin@test.local", "openid")

	if err := store.CreateRefreshTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	// Act — delete
	if err := store.DeleteRefreshTokenSession(ctx, sig); err != nil {
		t.Fatalf("DeleteRefreshTokenSession: %v", err)
	}

	// Assert — subsequent get must return ErrNotFound
	sess := &fosite.DefaultSession{}
	_, err := store.GetRefreshTokenSession(ctx, sig, sess)
	if err == nil {
		t.Fatal("GetRefreshTokenSession after delete expected error, got nil")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("error after delete = %v, want fosite.ErrNotFound", err)
	}
}

// TestRefreshTokenStore_Revoke_PreventsUse verifies that revoking a refresh
// token causes subsequent Get to return an error indicating it is unusable.
func TestRefreshTokenStore_Revoke_PreventsUse(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	testhelper.SeedTestClient(t, db)

	store := storage.NewRefreshTokenStore(db)
	ctx := context.Background()
	sig := "refresh-token-sig-003"
	req := makeRequester("test-client", "admin@test.local", "openid")

	if err := store.CreateRefreshTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	// Act — revoke
	if err := store.RevokeRefreshToken(ctx, sig); err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}

	// Act — get after revocation
	sess := &fosite.DefaultSession{}
	_, err := store.GetRefreshTokenSession(ctx, sig, sess)

	// Assert — revoked token must not be usable
	if err == nil {
		t.Fatal("GetRefreshTokenSession after revocation expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// OpenIDConnectRequestStore
// ---------------------------------------------------------------------------

// TestOpenIDConnectRequestStore_CreateAndGet_Success verifies the full
// Create → Get lifecycle for an OIDC session.
func TestOpenIDConnectRequestStore_CreateAndGet_Success(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	testhelper.SeedTestClient(t, db)

	store := storage.NewOpenIDConnectRequestStore(db)
	ctx := context.Background()
	authorizeCode := "oidc-code-001"
	req := makeRequester("test-client", "admin@test.local", "openid", "profile")

	// Act — create
	if err := store.CreateOpenIDConnectSession(ctx, authorizeCode, req); err != nil {
		t.Fatalf("CreateOpenIDConnectSession: %v", err)
	}

	// Act — get
	baseReq := fosite.NewRequest()
	baseReq.Client = &storage.Client{ID: "test-client"}
	baseReq.SetSession(&fosite.DefaultSession{})

	got, err := store.GetOpenIDConnectSession(ctx, authorizeCode, baseReq)

	// Assert
	if err != nil {
		t.Fatalf("GetOpenIDConnectSession: %v", err)
	}
	if got == nil {
		t.Fatal("GetOpenIDConnectSession returned nil requester")
	}
	if got.GetSession().GetSubject() != "admin@test.local" {
		t.Errorf("subject = %q, want %q", got.GetSession().GetSubject(), "admin@test.local")
	}
}

// TestOpenIDConnectRequestStore_Get_NotFound verifies that fosite.ErrNotFound
// is returned for an unknown authorize code.
func TestOpenIDConnectRequestStore_Get_NotFound(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	store := storage.NewOpenIDConnectRequestStore(db)
	ctx := context.Background()

	// Act
	baseReq := fosite.NewRequest()
	baseReq.SetSession(&fosite.DefaultSession{})
	_, err := store.GetOpenIDConnectSession(ctx, "ghost-code", baseReq)

	// Assert
	if err == nil {
		t.Fatal("GetOpenIDConnectSession expected error for missing code, got nil")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("error = %v, want fosite.ErrNotFound", err)
	}
}

// TestOpenIDConnectRequestStore_Delete_RemovesSession verifies that
// DeleteOpenIDConnectSession removes the session from the database.
func TestOpenIDConnectRequestStore_Delete_RemovesSession(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	testhelper.SeedTestClient(t, db)

	store := storage.NewOpenIDConnectRequestStore(db)
	ctx := context.Background()
	authorizeCode := "oidc-code-002"
	req := makeRequester("test-client", "admin@test.local", "openid")

	if err := store.CreateOpenIDConnectSession(ctx, authorizeCode, req); err != nil {
		t.Fatalf("CreateOpenIDConnectSession: %v", err)
	}

	// Act — delete
	if err := store.DeleteOpenIDConnectSession(ctx, authorizeCode); err != nil {
		t.Fatalf("DeleteOpenIDConnectSession: %v", err)
	}

	// Assert — subsequent get must return ErrNotFound
	baseReq := fosite.NewRequest()
	baseReq.SetSession(&fosite.DefaultSession{})
	_, err := store.GetOpenIDConnectSession(ctx, authorizeCode, baseReq)
	if err == nil {
		t.Fatal("GetOpenIDConnectSession after delete expected error, got nil")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("error after delete = %v, want fosite.ErrNotFound", err)
	}
}

// TestStore_New_ReturnsCompositeStore verifies that storage.New returns a
// non-nil composite store value.
func TestStore_New_ReturnsCompositeStore(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)

	// Act
	store := storage.New(db)

	// Assert
	if store == nil {
		t.Fatal("storage.New returned nil")
	}
}

// ---------------------------------------------------------------------------
// time helper — ensure expired tokens are rejected
// ---------------------------------------------------------------------------

// TestAccessTokenStore_Get_ExpiredToken verifies that an expired access token
// returns fosite.ErrTokenExpired instead of a valid session.
func TestAccessTokenStore_Get_ExpiredToken(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openStoreDB(t, dsn)
	testhelper.SeedTestClient(t, db)
	ctx := context.Background()

	// Insert an already-expired token directly via SQL to bypass time-setting logic.
	pastTime := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	_, err := db.ExecContext(ctx,
		`INSERT INTO tokens (signature, request_id, client_id, subject, scopes, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"expired-sig", "req-expired", "test-client", "admin@test.local", "openid", pastTime,
	)
	if err != nil {
		t.Fatalf("insert expired token: %v", err)
	}

	store := storage.NewAccessTokenStore(db)

	// Act
	sess := &fosite.DefaultSession{}
	_, err = store.GetAccessTokenSession(ctx, "expired-sig", sess)

	// Assert
	if err == nil {
		t.Fatal("GetAccessTokenSession expected error for expired token, got nil")
	}
	if err != fosite.ErrTokenExpired {
		t.Errorf("error = %v, want fosite.ErrTokenExpired", err)
	}
}
