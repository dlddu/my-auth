// Package storage_test verifies the fosite storage implementation backed by SQLite.
//
// TDD Red Phase: all tests in this file are expected to FAIL until
// internal/storage/store.go is implemented.
//
// Test structure mirrors the existing handler test pattern:
//   - package storage_test (external test package)
//   - Arrange / Act / Assert with plain if / t.Errorf (no testify)
//   - isolated SQLite databases per test via t.TempDir
package storage_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/dlddu/my-auth/internal/database"
	"github.com/dlddu/my-auth/internal/storage"
	"github.com/ory/fosite"
	fositeOAuth2 "github.com/ory/fosite/handler/oauth2"
	fositeOIDC "github.com/ory/fosite/handler/openid"
)

// ---------------------------------------------------------------------------
// Test infrastructure helpers
// ---------------------------------------------------------------------------

// newTestDB opens a temporary SQLite database with all migrations applied.
// It is scoped to each test via t.Cleanup.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=ON", dbPath)

	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("newTestDB: open database: %v", err)
	}

	migrationsDir, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		db.Close()
		t.Fatalf("newTestDB: resolve migrations path: %v", err)
	}

	if err := database.Migrate(db, migrationsDir); err != nil {
		db.Close()
		t.Fatalf("newTestDB: run migrations: %v", err)
	}

	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Logf("newTestDB cleanup: %v", err)
		}
	})

	return db
}

// insertTestClient inserts a minimal OAuth2 client row so that foreign-key
// constraints on authorization_codes, tokens, sessions, and refresh_tokens
// are satisfied.
func insertTestClient(t *testing.T, db *sql.DB, clientID string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO clients
		   (id, secret, redirect_uris, grant_types, response_types, scopes)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		clientID,
		"test-secret-hash",
		`["http://localhost:9999/callback"]`,
		`["authorization_code","refresh_token"]`,
		`["code"]`,
		"openid profile email",
	)
	if err != nil {
		t.Fatalf("insertTestClient(%q): %v", clientID, err)
	}
}

// newMockRequest constructs a minimal fosite.Request with the given fields so
// that storage methods have a well-formed Requester to persist.
func newMockRequest(requestID, clientID, subject string, scopes fosite.Arguments) fosite.Requester {
	session := &fositeOIDC.DefaultSession{
		Subject: subject,
		Claims:  &fositeOIDC.IDTokenClaims{},
		Headers: &fositeOIDC.Headers{},
	}
	req := &fosite.Request{
		ID:             requestID,
		RequestedAt:    time.Now().UTC(),
		Client:         &fosite.DefaultClient{ID: clientID},
		RequestedScope: scopes,
		GrantedScope:   scopes,
		Session:        session,
		Form:           make(map[string][]string),
	}
	return req
}

// ---------------------------------------------------------------------------
// Compile-time interface satisfaction checks
//
// These blank-identifier assignments verify at compile time that *storage.Store
// satisfies every fosite interface required by the OAuth2 / OIDC flows.
// They will produce a compiler error if an interface is not fully implemented.
// ---------------------------------------------------------------------------

var (
	_ fosite.ClientManager                       = (*storage.Store)(nil)
	_ fositeOAuth2.AuthorizeCodeStorage          = (*storage.Store)(nil)
	_ fositeOAuth2.AccessTokenStorage            = (*storage.Store)(nil)
	_ fositeOAuth2.RefreshTokenStorage           = (*storage.Store)(nil)
	_ fositeOAuth2.TokenRevocationStorage        = (*storage.Store)(nil)
	_ fositeOIDC.OpenIDConnectRequestStorage     = (*storage.Store)(nil)
)

// ---------------------------------------------------------------------------
// ClientStore tests
// ---------------------------------------------------------------------------

// TestClientStore_GetClient_ReturnsClientForExistingID verifies that a client
// inserted into the clients table can be retrieved by its ID.
func TestClientStore_GetClient_ReturnsClientForExistingID(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	insertTestClient(t, db, "client-get-test")
	store := storage.New(db)
	ctx := context.Background()

	// Act
	client, err := store.GetClient(ctx, "client-get-test")

	// Assert
	if err != nil {
		t.Fatalf("GetClient: unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("GetClient: returned nil client, want non-nil")
	}
	if client.GetID() != "client-get-test" {
		t.Errorf("GetClient: ID = %q, want %q", client.GetID(), "client-get-test")
	}
}

// TestClientStore_GetClient_ReturnsErrorForUnknownID verifies that requesting
// a non-existent client returns an error.
func TestClientStore_GetClient_ReturnsErrorForUnknownID(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	store := storage.New(db)
	ctx := context.Background()

	// Act
	client, err := store.GetClient(ctx, "does-not-exist")

	// Assert
	if err == nil {
		t.Errorf("GetClient: expected error for unknown ID, got nil (client=%v)", client)
	}
}

// TestClientStore_GetClient_RedirectURIsArePresent verifies that redirect_uris
// stored as a JSON array are correctly deserialised and non-empty.
func TestClientStore_GetClient_RedirectURIsArePresent(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	insertTestClient(t, db, "client-redirect-test")
	store := storage.New(db)
	ctx := context.Background()

	// Act
	client, err := store.GetClient(ctx, "client-redirect-test")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}

	// Assert
	uris := client.GetRedirectURIs()
	if len(uris) == 0 {
		t.Error("GetClient: redirect_uris is empty, want at least one URI")
	}
}

// TestClientStore_GetClient_ScopesArePresent verifies that scopes are returned
// as a non-empty slice.
func TestClientStore_GetClient_ScopesArePresent(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	insertTestClient(t, db, "client-scopes-test")
	store := storage.New(db)
	ctx := context.Background()

	// Act
	client, err := store.GetClient(ctx, "client-scopes-test")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}

	// Assert
	scopes := client.GetScopes()
	if len(scopes) == 0 {
		t.Error("GetClient: scopes is empty, want at least one scope")
	}
}

// ---------------------------------------------------------------------------
// AuthorizeCodeStore tests
// ---------------------------------------------------------------------------

// TestAuthorizeCodeStore_CreateAndGet_HappyPath verifies that a code session
// can be created and then retrieved with the correct request ID.
func TestAuthorizeCodeStore_CreateAndGet_HappyPath(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	insertTestClient(t, db, "ac-client")
	store := storage.New(db)
	ctx := context.Background()

	code := "auth-code-happy-001"
	req := newMockRequest("req-ac-happy-001", "ac-client", "user@example.com",
		fosite.Arguments{"openid", "profile"})

	// Act — create
	err := store.CreateAuthorizeCodeSession(ctx, code, req)
	if err != nil {
		t.Fatalf("CreateAuthorizeCodeSession: %v", err)
	}

	// Act — get
	session := &fositeOIDC.DefaultSession{}
	gotReq, err := store.GetAuthorizeCodeSession(ctx, code, session)

	// Assert
	if err != nil {
		t.Fatalf("GetAuthorizeCodeSession: unexpected error: %v", err)
	}
	if gotReq == nil {
		t.Fatal("GetAuthorizeCodeSession: returned nil requester")
	}
	if gotReq.GetID() != req.GetID() {
		t.Errorf("GetAuthorizeCodeSession: ID = %q, want %q", gotReq.GetID(), req.GetID())
	}
}

// TestAuthorizeCodeStore_GetUnknownCode_ReturnsError verifies that retrieving
// a code that was never stored returns an error.
func TestAuthorizeCodeStore_GetUnknownCode_ReturnsError(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	store := storage.New(db)
	ctx := context.Background()

	// Act
	session := &fositeOIDC.DefaultSession{}
	gotReq, err := store.GetAuthorizeCodeSession(ctx, "never-stored-code", session)

	// Assert
	if err == nil {
		t.Errorf("GetAuthorizeCodeSession: expected error for unknown code, got nil (req=%v)", gotReq)
	}
}

// TestAuthorizeCodeStore_InvalidateCode_ReturnsErrInvalidatedAuthorizeCode
// verifies that after InvalidateAuthorizeCodeSession the code is marked used
// and subsequent Get returns fosite.ErrInvalidatedAuthorizeCode.
func TestAuthorizeCodeStore_InvalidateCode_ReturnsErrInvalidatedAuthorizeCode(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	insertTestClient(t, db, "ac-invalidate-client")
	store := storage.New(db)
	ctx := context.Background()

	code := "auth-code-invalidate-001"
	req := newMockRequest("req-ac-invalidate-001", "ac-invalidate-client", "user@example.com",
		fosite.Arguments{"openid"})

	if err := store.CreateAuthorizeCodeSession(ctx, code, req); err != nil {
		t.Fatalf("CreateAuthorizeCodeSession: %v", err)
	}

	// Act
	err := store.InvalidateAuthorizeCodeSession(ctx, code)

	// Assert — invalidation must not return an error
	if err != nil {
		t.Fatalf("InvalidateAuthorizeCodeSession: %v", err)
	}

	// Assert — Get must return ErrInvalidatedAuthorizeCode
	session := &fositeOIDC.DefaultSession{}
	_, getErr := store.GetAuthorizeCodeSession(ctx, code, session)
	if getErr == nil {
		t.Fatal("GetAuthorizeCodeSession after invalidation: expected ErrInvalidatedAuthorizeCode, got nil")
	}
	if getErr != fosite.ErrInvalidatedAuthorizeCode {
		t.Errorf("GetAuthorizeCodeSession after invalidation: error = %v, want fosite.ErrInvalidatedAuthorizeCode", getErr)
	}
}

// TestAuthorizeCodeStore_InvalidateUnknownCode_ReturnsError verifies that
// invalidating a code that does not exist returns an error.
func TestAuthorizeCodeStore_InvalidateUnknownCode_ReturnsError(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	store := storage.New(db)
	ctx := context.Background()

	// Act
	err := store.InvalidateAuthorizeCodeSession(ctx, "no-such-code")

	// Assert
	if err == nil {
		t.Error("InvalidateAuthorizeCodeSession: expected error for unknown code, got nil")
	}
}

// ---------------------------------------------------------------------------
// AccessTokenStore tests
// ---------------------------------------------------------------------------

// TestAccessTokenStore_CreateAndGet_HappyPath verifies create + get round-trip.
func TestAccessTokenStore_CreateAndGet_HappyPath(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	insertTestClient(t, db, "at-client")
	store := storage.New(db)
	ctx := context.Background()

	sig := "access-token-sig-happy-001"
	req := newMockRequest("req-at-happy-001", "at-client", "user@example.com",
		fosite.Arguments{"openid", "email"})

	// Act — create
	err := store.CreateAccessTokenSession(ctx, sig, req)
	if err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}

	// Act — get
	session := &fositeOIDC.DefaultSession{}
	gotReq, err := store.GetAccessTokenSession(ctx, sig, session)

	// Assert
	if err != nil {
		t.Fatalf("GetAccessTokenSession: %v", err)
	}
	if gotReq == nil {
		t.Fatal("GetAccessTokenSession: returned nil requester")
	}
	if gotReq.GetID() != req.GetID() {
		t.Errorf("GetAccessTokenSession: ID = %q, want %q", gotReq.GetID(), req.GetID())
	}
}

// TestAccessTokenStore_GetUnknownSignature_ReturnsError verifies that
// retrieving a signature that was never stored returns an error.
func TestAccessTokenStore_GetUnknownSignature_ReturnsError(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	store := storage.New(db)
	ctx := context.Background()

	// Act
	session := &fositeOIDC.DefaultSession{}
	gotReq, err := store.GetAccessTokenSession(ctx, "never-stored-sig", session)

	// Assert
	if err == nil {
		t.Errorf("GetAccessTokenSession: expected error for unknown signature, got nil (req=%v)", gotReq)
	}
}

// TestAccessTokenStore_DeleteSession_RemovesToken verifies that after deletion
// the token can no longer be retrieved.
func TestAccessTokenStore_DeleteSession_RemovesToken(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	insertTestClient(t, db, "at-delete-client")
	store := storage.New(db)
	ctx := context.Background()

	sig := "access-token-sig-delete-001"
	req := newMockRequest("req-at-delete-001", "at-delete-client", "user@example.com",
		fosite.Arguments{"openid"})

	if err := store.CreateAccessTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}

	// Act
	err := store.DeleteAccessTokenSession(ctx, sig)
	if err != nil {
		t.Fatalf("DeleteAccessTokenSession: %v", err)
	}

	// Assert — subsequent Get must fail
	session := &fositeOIDC.DefaultSession{}
	gotReq, getErr := store.GetAccessTokenSession(ctx, sig, session)
	if getErr == nil {
		t.Errorf("GetAccessTokenSession after delete: expected error, got nil (req=%v)", gotReq)
	}
}

// TestAccessTokenStore_RevokeAccessToken_DeletesByRequestID verifies that
// RevokeAccessToken removes all tokens associated with a given request ID.
func TestAccessTokenStore_RevokeAccessToken_DeletesByRequestID(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	insertTestClient(t, db, "at-revoke-client")
	store := storage.New(db)
	ctx := context.Background()

	sig := "access-token-sig-revoke-001"
	req := newMockRequest("req-at-revoke-001", "at-revoke-client", "user@example.com",
		fosite.Arguments{"openid"})

	if err := store.CreateAccessTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}

	// Act
	err := store.RevokeAccessToken(ctx, req.GetID())
	if err != nil {
		t.Fatalf("RevokeAccessToken: %v", err)
	}

	// Assert — token must be gone
	session := &fositeOIDC.DefaultSession{}
	gotReq, getErr := store.GetAccessTokenSession(ctx, sig, session)
	if getErr == nil {
		t.Errorf("GetAccessTokenSession after RevokeAccessToken: expected error, got nil (req=%v)", gotReq)
	}
}

// ---------------------------------------------------------------------------
// RefreshTokenStore tests
// ---------------------------------------------------------------------------

// TestRefreshTokenStore_CreateAndGet_HappyPath verifies create + get round-trip.
func TestRefreshTokenStore_CreateAndGet_HappyPath(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	insertTestClient(t, db, "rt-client")
	store := storage.New(db)
	ctx := context.Background()

	sig := "refresh-token-sig-happy-001"
	req := newMockRequest("req-rt-happy-001", "rt-client", "user@example.com",
		fosite.Arguments{"openid", "offline_access"})

	// Act — create
	err := store.CreateRefreshTokenSession(ctx, sig, req)
	if err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	// Act — get
	session := &fositeOIDC.DefaultSession{}
	gotReq, err := store.GetRefreshTokenSession(ctx, sig, session)

	// Assert
	if err != nil {
		t.Fatalf("GetRefreshTokenSession: %v", err)
	}
	if gotReq == nil {
		t.Fatal("GetRefreshTokenSession: returned nil requester")
	}
	if gotReq.GetID() != req.GetID() {
		t.Errorf("GetRefreshTokenSession: ID = %q, want %q", gotReq.GetID(), req.GetID())
	}
}

// TestRefreshTokenStore_GetUnknownSignature_ReturnsError verifies that
// retrieving an unstored signature returns an error.
func TestRefreshTokenStore_GetUnknownSignature_ReturnsError(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	store := storage.New(db)
	ctx := context.Background()

	// Act
	session := &fositeOIDC.DefaultSession{}
	gotReq, err := store.GetRefreshTokenSession(ctx, "never-stored-rt-sig", session)

	// Assert
	if err == nil {
		t.Errorf("GetRefreshTokenSession: expected error for unknown signature, got nil (req=%v)", gotReq)
	}
}

// TestRefreshTokenStore_DeleteSession_RemovesToken verifies that deletion
// prevents subsequent retrieval.
func TestRefreshTokenStore_DeleteSession_RemovesToken(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	insertTestClient(t, db, "rt-delete-client")
	store := storage.New(db)
	ctx := context.Background()

	sig := "refresh-token-sig-delete-001"
	req := newMockRequest("req-rt-delete-001", "rt-delete-client", "user@example.com",
		fosite.Arguments{"openid"})

	if err := store.CreateRefreshTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	// Act
	err := store.DeleteRefreshTokenSession(ctx, sig)
	if err != nil {
		t.Fatalf("DeleteRefreshTokenSession: %v", err)
	}

	// Assert
	session := &fositeOIDC.DefaultSession{}
	gotReq, getErr := store.GetRefreshTokenSession(ctx, sig, session)
	if getErr == nil {
		t.Errorf("GetRefreshTokenSession after delete: expected error, got nil (req=%v)", gotReq)
	}
}

// TestRefreshTokenStore_RevokeRefreshToken_MarksByRequestID verifies that
// RevokeRefreshToken marks all refresh tokens for a request ID as revoked,
// after which GetRefreshTokenSession returns an error.
func TestRefreshTokenStore_RevokeRefreshToken_MarksByRequestID(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	insertTestClient(t, db, "rt-revoke-client")
	store := storage.New(db)
	ctx := context.Background()

	sig := "refresh-token-sig-revoke-001"
	req := newMockRequest("req-rt-revoke-001", "rt-revoke-client", "user@example.com",
		fosite.Arguments{"openid"})

	if err := store.CreateRefreshTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	// Act
	err := store.RevokeRefreshToken(ctx, req.GetID())
	if err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}

	// Assert — revoked token must not be returned as a valid session
	session := &fositeOIDC.DefaultSession{}
	gotReq, getErr := store.GetRefreshTokenSession(ctx, sig, session)
	if getErr == nil {
		t.Errorf("GetRefreshTokenSession after RevokeRefreshToken: expected error, got nil (req=%v)", gotReq)
	}
}

// TestRefreshTokenStore_RevokeRefreshTokenMaybeGracePeriod_RevokesToken
// verifies that RevokeRefreshTokenMaybeGracePeriod revokes the specific
// signature supplied, after which it can no longer be retrieved.
func TestRefreshTokenStore_RevokeRefreshTokenMaybeGracePeriod_RevokesToken(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	insertTestClient(t, db, "rt-grace-client")
	store := storage.New(db)
	ctx := context.Background()

	sig := "refresh-token-sig-grace-001"
	req := newMockRequest("req-rt-grace-001", "rt-grace-client", "user@example.com",
		fosite.Arguments{"openid"})

	if err := store.CreateRefreshTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	// Act — pass the specific signature to revoke
	err := store.RevokeRefreshTokenMaybeGracePeriod(ctx, req.GetID(), sig)
	if err != nil {
		t.Fatalf("RevokeRefreshTokenMaybeGracePeriod: %v", err)
	}

	// Assert — token must be revoked / unretrievable
	session := &fositeOIDC.DefaultSession{}
	gotReq, getErr := store.GetRefreshTokenSession(ctx, sig, session)
	if getErr == nil {
		t.Errorf("GetRefreshTokenSession after RevokeRefreshTokenMaybeGracePeriod: expected error, got nil (req=%v)", gotReq)
	}
}

// ---------------------------------------------------------------------------
// OpenIDConnectRequestStore tests
// ---------------------------------------------------------------------------

// TestOpenIDConnectRequestStore_CreateAndGet_HappyPath verifies create + get
// round-trip using the OpenID Connect session store.
func TestOpenIDConnectRequestStore_CreateAndGet_HappyPath(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	insertTestClient(t, db, "oidc-client")
	store := storage.New(db)
	ctx := context.Background()

	authorizeCode := "oidc-auth-code-happy-001"
	req := newMockRequest("req-oidc-happy-001", "oidc-client", "user@example.com",
		fosite.Arguments{"openid"})

	// Act — create
	err := store.CreateOpenIDConnectSession(ctx, authorizeCode, req)
	if err != nil {
		t.Fatalf("CreateOpenIDConnectSession: %v", err)
	}

	// Act — get (second arg is the incoming authorize request per fosite spec)
	gotReq, err := store.GetOpenIDConnectSession(ctx, authorizeCode, req)

	// Assert
	if err != nil {
		t.Fatalf("GetOpenIDConnectSession: %v", err)
	}
	if gotReq == nil {
		t.Fatal("GetOpenIDConnectSession: returned nil requester")
	}
	if gotReq.GetID() != req.GetID() {
		t.Errorf("GetOpenIDConnectSession: ID = %q, want %q", gotReq.GetID(), req.GetID())
	}
}

// TestOpenIDConnectRequestStore_GetUnknownCode_ReturnsError verifies that
// retrieving a code that was never stored returns an error.
func TestOpenIDConnectRequestStore_GetUnknownCode_ReturnsError(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	store := storage.New(db)
	ctx := context.Background()
	dummyReq := newMockRequest("req-oidc-dummy", "oidc-client", "user@example.com",
		fosite.Arguments{"openid"})

	// Act
	gotReq, err := store.GetOpenIDConnectSession(ctx, "no-such-oidc-code", dummyReq)

	// Assert
	if err == nil {
		t.Errorf("GetOpenIDConnectSession: expected error for unknown code, got nil (req=%v)", gotReq)
	}
}

// TestOpenIDConnectRequestStore_DeleteSession_RemovesSession verifies that
// DeleteOpenIDConnectSession removes the session so it can no longer be retrieved.
func TestOpenIDConnectRequestStore_DeleteSession_RemovesSession(t *testing.T) {
	// Arrange
	db := newTestDB(t)
	insertTestClient(t, db, "oidc-delete-client")
	store := storage.New(db)
	ctx := context.Background()

	authorizeCode := "oidc-auth-code-delete-001"
	req := newMockRequest("req-oidc-delete-001", "oidc-delete-client", "user@example.com",
		fosite.Arguments{"openid"})

	if err := store.CreateOpenIDConnectSession(ctx, authorizeCode, req); err != nil {
		t.Fatalf("CreateOpenIDConnectSession: %v", err)
	}

	// Act
	err := store.DeleteOpenIDConnectSession(ctx, authorizeCode)
	if err != nil {
		t.Fatalf("DeleteOpenIDConnectSession: %v", err)
	}

	// Assert — session must be gone
	gotReq, getErr := store.GetOpenIDConnectSession(ctx, authorizeCode, req)
	if getErr == nil {
		t.Errorf("GetOpenIDConnectSession after delete: expected error, got nil (req=%v)", gotReq)
	}
}
