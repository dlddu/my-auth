// Package storage_test contains integration tests for the fosite-compatible
// SQLite storage layer.  All tests operate against a real (temporary) SQLite
// database created by testhelper.NewTestDB so that SQL correctness is verified
// without mocking.
//
// TDD Red Phase: these tests are written before the implementation exists.
// They will fail until internal/storage is implemented.
package storage_test

import (
	"context"
	"database/sql"
	"net/url"
	"testing"
	"time"

	"github.com/ory/fosite"

	"github.com/dlddu/my-auth/internal/database"
	"github.com/dlddu/my-auth/internal/storage"
	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// openDB opens a *sql.DB from the DSN returned by testhelper.NewTestDB.
func openDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := testhelper.NewTestDB(t)
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// insertTestClient inserts a minimal OAuth2 client into the clients table so
// that foreign-key constraints are satisfied when creating tokens / codes.
func insertTestClient(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO clients (id, secret, redirect_uris, grant_types, response_types, scopes)
		VALUES (?, ?, ?, ?, ?, ?)`,
		"test-client",
		"test-secret",
		`["http://localhost:9999/callback"]`,
		`["authorization_code","refresh_token"]`,
		`["code"]`,
		"openid profile email",
	)
	if err != nil {
		t.Fatalf("insertTestClient: %v", err)
	}
}

// newStore creates a *storage.Store backed by db.
// This will fail to compile until internal/storage is implemented.
func newStore(t *testing.T, db *sql.DB) *storage.Store {
	t.Helper()
	s, err := storage.New(db)
	if err != nil {
		t.Fatalf("storage.New: %v", err)
	}
	return s
}

// futureTime returns a time in the future, suitable for non-expired tokens.
func futureTime() time.Time { return time.Now().Add(time.Hour) }

// testDefaultClient returns a *fosite.DefaultClient pre-populated with the
// canonical test client values.
func testDefaultClient() *fosite.DefaultClient {
	return &fosite.DefaultClient{
		ID:            "test-client",
		Secret:        []byte("test-secret"),
		RedirectURIs:  []string{"http://localhost:9999/callback"},
		GrantTypes:    fosite.Arguments{"authorization_code", "refresh_token"},
		ResponseTypes: fosite.Arguments{"code"},
		Scopes:        fosite.Arguments{"openid", "profile", "email"},
	}
}

// newAuthorizeRequest builds an *fosite.AuthorizeRequest for use in
// authorize-code and OIDC store tests.
func newAuthorizeRequest(requestID string) *fosite.AuthorizeRequest {
	sess := &fosite.DefaultSession{}
	sess.SetExpiresAt(fosite.AuthorizeCode, futureTime())

	req := &fosite.AuthorizeRequest{
		Request: fosite.Request{
			ID:                requestID,
			RequestedAt:       time.Now(),
			Client:            testDefaultClient(),
			RequestedScope:    fosite.Arguments{"openid", "profile", "email"},
			GrantedScope:      fosite.Arguments{"openid", "profile", "email"},
			Session:           sess,
			RequestedAudience: fosite.Arguments{},
			GrantedAudience:   fosite.Arguments{},
		},
		RedirectURI:  mustParseURL("http://localhost:9999/callback"),
		ResponseTypes: fosite.Arguments{"code"},
	}
	return req
}

// newAccessRequest builds a *fosite.AccessRequest for use in access/refresh
// token store tests.
func newAccessRequest(requestID string) *fosite.AccessRequest {
	sess := &fosite.DefaultSession{}
	sess.SetExpiresAt(fosite.AccessToken, futureTime())
	sess.SetExpiresAt(fosite.RefreshToken, futureTime())

	return &fosite.AccessRequest{
		GrantTypes: fosite.Arguments{"authorization_code"},
		Request: fosite.Request{
			ID:                requestID,
			RequestedAt:       time.Now(),
			Client:            testDefaultClient(),
			RequestedScope:    fosite.Arguments{"openid", "profile", "email"},
			GrantedScope:      fosite.Arguments{"openid", "profile", "email"},
			Session:           sess,
			RequestedAudience: fosite.Arguments{},
			GrantedAudience:   fosite.Arguments{},
		},
	}
}

// mustParseURL parses rawURL and panics on error (test-only helper).
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic("mustParseURL: " + err.Error())
	}
	return u
}

// ---------------------------------------------------------------------------
// ClientStore — GetClient
// ---------------------------------------------------------------------------

// TestClientStore_GetClient_ReturnsClient verifies that GetClient retrieves an
// existing client from the database.
func TestClientStore_GetClient_ReturnsClient(t *testing.T) {
	// Arrange
	db := openDB(t)
	insertTestClient(t, db)
	s := newStore(t, db)
	ctx := context.Background()

	// Act
	client, err := s.GetClient(ctx, "test-client")

	// Assert
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if client == nil {
		t.Fatal("GetClient returned nil client, want non-nil")
	}
	if client.GetID() != "test-client" {
		t.Errorf("client.GetID() = %q, want %q", client.GetID(), "test-client")
	}
}

// TestClientStore_GetClient_ReturnsErrorForUnknownID verifies that GetClient
// returns a non-nil error when the client ID does not exist.
func TestClientStore_GetClient_ReturnsErrorForUnknownID(t *testing.T) {
	// Arrange
	db := openDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	// Act
	_, err := s.GetClient(ctx, "nonexistent-client")

	// Assert
	if err == nil {
		t.Fatal("GetClient: expected error for unknown client ID, got nil")
	}
}

// TestClientStore_GetClient_ClientHasCorrectRedirectURIs checks that the
// returned client exposes the redirect URIs stored in the database.
func TestClientStore_GetClient_ClientHasCorrectRedirectURIs(t *testing.T) {
	// Arrange
	db := openDB(t)
	insertTestClient(t, db)
	s := newStore(t, db)
	ctx := context.Background()

	// Act
	client, err := s.GetClient(ctx, "test-client")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}

	// Assert
	uris := client.GetRedirectURIs()
	if len(uris) == 0 {
		t.Fatal("client.GetRedirectURIs() returned empty slice, want at least one URI")
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
		t.Errorf("client.GetRedirectURIs() = %v, want to contain %q", uris, wantURI)
	}
}

// TestClientStore_GetClient_ClientHasCorrectScopes checks that the returned
// client exposes the scopes stored in the database.
func TestClientStore_GetClient_ClientHasCorrectScopes(t *testing.T) {
	// Arrange
	db := openDB(t)
	insertTestClient(t, db)
	s := newStore(t, db)
	ctx := context.Background()

	// Act
	client, err := s.GetClient(ctx, "test-client")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}

	// Assert — fosite clients expose scopes via GetScopes() which returns
	// fosite.Arguments ([]string).
	scopes := client.GetScopes()
	if len(scopes) == 0 {
		t.Fatal("client.GetScopes() returned empty slice, want openid profile email")
	}
}

// ---------------------------------------------------------------------------
// AuthorizeCodeStore
// ---------------------------------------------------------------------------

// TestAuthorizeCodeStore_CreateAndGet verifies the full round-trip:
// CreateAuthorizeCodeSession → GetAuthorizeCodeSession returns the same data.
func TestAuthorizeCodeStore_CreateAndGet(t *testing.T) {
	// Arrange
	db := openDB(t)
	insertTestClient(t, db)
	s := newStore(t, db)
	ctx := context.Background()
	code := "auth-code-001"
	req := newAuthorizeRequest("req-auth-001")

	// Act — create
	if err := s.CreateAuthorizeCodeSession(ctx, code, req); err != nil {
		t.Fatalf("CreateAuthorizeCodeSession: %v", err)
	}

	// Act — retrieve
	got, err := s.GetAuthorizeCodeSession(ctx, code, &fosite.DefaultSession{})
	if err != nil {
		t.Fatalf("GetAuthorizeCodeSession: %v", err)
	}

	// Assert
	if got == nil {
		t.Fatal("GetAuthorizeCodeSession returned nil, want non-nil")
	}
	if got.GetID() != req.GetID() {
		t.Errorf("request ID = %q, want %q", got.GetID(), req.GetID())
	}
}

// TestAuthorizeCodeStore_GetReturnsErrorForUnknownCode verifies that
// GetAuthorizeCodeSession returns an error for a code that was never stored.
func TestAuthorizeCodeStore_GetReturnsErrorForUnknownCode(t *testing.T) {
	// Arrange
	db := openDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	// Act
	_, err := s.GetAuthorizeCodeSession(ctx, "nonexistent-code", &fosite.DefaultSession{})

	// Assert
	if err == nil {
		t.Fatal("GetAuthorizeCodeSession: expected error for unknown code, got nil")
	}
}

// TestAuthorizeCodeStore_InvalidateMarksCodeAsUsed verifies that after calling
// InvalidateAuthorizeCodeSession the code can no longer be retrieved as active.
func TestAuthorizeCodeStore_InvalidateMarksCodeAsUsed(t *testing.T) {
	// Arrange
	db := openDB(t)
	insertTestClient(t, db)
	s := newStore(t, db)
	ctx := context.Background()
	code := "auth-code-002"
	req := newAuthorizeRequest("req-auth-002")

	if err := s.CreateAuthorizeCodeSession(ctx, code, req); err != nil {
		t.Fatalf("CreateAuthorizeCodeSession: %v", err)
	}

	// Act — invalidate (marks used=1 in DB)
	if err := s.InvalidateAuthorizeCodeSession(ctx, code); err != nil {
		t.Fatalf("InvalidateAuthorizeCodeSession: %v", err)
	}

	// Assert — subsequent Get should return fosite.ErrInvalidatedAuthorizeCode
	_, err := s.GetAuthorizeCodeSession(ctx, code, &fosite.DefaultSession{})
	if err == nil {
		t.Fatal("GetAuthorizeCodeSession after invalidation: expected error, got nil")
	}
}

// TestAuthorizeCodeStore_CreateDuplicateCodeReturnsError verifies that storing
// the same code twice is rejected (PRIMARY KEY constraint).
func TestAuthorizeCodeStore_CreateDuplicateCodeReturnsError(t *testing.T) {
	// Arrange
	db := openDB(t)
	insertTestClient(t, db)
	s := newStore(t, db)
	ctx := context.Background()
	code := "auth-code-dup"
	req := newAuthorizeRequest("req-auth-dup")

	if err := s.CreateAuthorizeCodeSession(ctx, code, req); err != nil {
		t.Fatalf("first CreateAuthorizeCodeSession: %v", err)
	}

	// Act
	err := s.CreateAuthorizeCodeSession(ctx, code, req)

	// Assert
	if err == nil {
		t.Fatal("CreateAuthorizeCodeSession with duplicate code: expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// AccessTokenStore
// ---------------------------------------------------------------------------

// TestAccessTokenStore_CreateAndGet verifies round-trip persistence of an
// access token session.
func TestAccessTokenStore_CreateAndGet(t *testing.T) {
	// Arrange
	db := openDB(t)
	insertTestClient(t, db)
	s := newStore(t, db)
	ctx := context.Background()
	sig := "access-sig-001"
	req := newAccessRequest("req-access-001")

	// Act
	if err := s.CreateAccessTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}

	got, err := s.GetAccessTokenSession(ctx, sig, &fosite.DefaultSession{})
	if err != nil {
		t.Fatalf("GetAccessTokenSession: %v", err)
	}

	// Assert
	if got == nil {
		t.Fatal("GetAccessTokenSession returned nil, want non-nil")
	}
	if got.GetID() != req.GetID() {
		t.Errorf("request ID = %q, want %q", got.GetID(), req.GetID())
	}
}

// TestAccessTokenStore_GetReturnsErrorForUnknownSignature verifies that
// GetAccessTokenSession returns an error for an unknown signature.
func TestAccessTokenStore_GetReturnsErrorForUnknownSignature(t *testing.T) {
	// Arrange
	db := openDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	// Act
	_, err := s.GetAccessTokenSession(ctx, "nonexistent-sig", &fosite.DefaultSession{})

	// Assert
	if err == nil {
		t.Fatal("GetAccessTokenSession: expected error for unknown signature, got nil")
	}
}

// TestAccessTokenStore_DeleteRemovesToken verifies that
// DeleteAccessTokenSession makes a token unretrievable.
func TestAccessTokenStore_DeleteRemovesToken(t *testing.T) {
	// Arrange
	db := openDB(t)
	insertTestClient(t, db)
	s := newStore(t, db)
	ctx := context.Background()
	sig := "access-sig-002"
	req := newAccessRequest("req-access-002")

	if err := s.CreateAccessTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}

	// Act
	if err := s.DeleteAccessTokenSession(ctx, sig); err != nil {
		t.Fatalf("DeleteAccessTokenSession: %v", err)
	}

	// Assert
	_, err := s.GetAccessTokenSession(ctx, sig, &fosite.DefaultSession{})
	if err == nil {
		t.Fatal("GetAccessTokenSession after delete: expected error, got nil")
	}
}

// TestAccessTokenStore_RevokeAccessToken verifies that RevokeAccessToken
// removes tokens associated with the given request ID.
func TestAccessTokenStore_RevokeAccessToken(t *testing.T) {
	// Arrange
	db := openDB(t)
	insertTestClient(t, db)
	s := newStore(t, db)
	ctx := context.Background()
	sig := "access-sig-003"
	req := newAccessRequest("req-access-003")

	if err := s.CreateAccessTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}

	// Act
	if err := s.RevokeAccessToken(ctx, req.GetID()); err != nil {
		t.Fatalf("RevokeAccessToken: %v", err)
	}

	// Assert — token should no longer be retrievable
	_, err := s.GetAccessTokenSession(ctx, sig, &fosite.DefaultSession{})
	if err == nil {
		t.Fatal("GetAccessTokenSession after revoke: expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// RefreshTokenStore
// ---------------------------------------------------------------------------

// TestRefreshTokenStore_CreateAndGet verifies round-trip persistence of a
// refresh token session.
func TestRefreshTokenStore_CreateAndGet(t *testing.T) {
	// Arrange
	db := openDB(t)
	insertTestClient(t, db)
	s := newStore(t, db)
	ctx := context.Background()
	sig := "refresh-sig-001"
	req := newAccessRequest("req-refresh-001")

	// Act
	if err := s.CreateRefreshTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	got, err := s.GetRefreshTokenSession(ctx, sig, &fosite.DefaultSession{})
	if err != nil {
		t.Fatalf("GetRefreshTokenSession: %v", err)
	}

	// Assert
	if got == nil {
		t.Fatal("GetRefreshTokenSession returned nil, want non-nil")
	}
	if got.GetID() != req.GetID() {
		t.Errorf("request ID = %q, want %q", got.GetID(), req.GetID())
	}
}

// TestRefreshTokenStore_GetReturnsErrorForUnknownSignature verifies that
// GetRefreshTokenSession returns an error for an unknown signature.
func TestRefreshTokenStore_GetReturnsErrorForUnknownSignature(t *testing.T) {
	// Arrange
	db := openDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	// Act
	_, err := s.GetRefreshTokenSession(ctx, "nonexistent-sig", &fosite.DefaultSession{})

	// Assert
	if err == nil {
		t.Fatal("GetRefreshTokenSession: expected error for unknown signature, got nil")
	}
}

// TestRefreshTokenStore_DeleteRemovesToken verifies that DeleteRefreshTokenSession
// makes a token unretrievable.
func TestRefreshTokenStore_DeleteRemovesToken(t *testing.T) {
	// Arrange
	db := openDB(t)
	insertTestClient(t, db)
	s := newStore(t, db)
	ctx := context.Background()
	sig := "refresh-sig-002"
	req := newAccessRequest("req-refresh-002")

	if err := s.CreateRefreshTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	// Act
	if err := s.DeleteRefreshTokenSession(ctx, sig); err != nil {
		t.Fatalf("DeleteRefreshTokenSession: %v", err)
	}

	// Assert
	_, err := s.GetRefreshTokenSession(ctx, sig, &fosite.DefaultSession{})
	if err == nil {
		t.Fatal("GetRefreshTokenSession after delete: expected error, got nil")
	}
}

// TestRefreshTokenStore_RevokeRefreshToken verifies that RevokeRefreshToken
// marks the token as revoked, making it unretrievable.
func TestRefreshTokenStore_RevokeRefreshToken(t *testing.T) {
	// Arrange
	db := openDB(t)
	insertTestClient(t, db)
	s := newStore(t, db)
	ctx := context.Background()
	sig := "refresh-sig-003"
	req := newAccessRequest("req-refresh-003")

	if err := s.CreateRefreshTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	// Act
	if err := s.RevokeRefreshToken(ctx, req.GetID()); err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}

	// Assert — fosite expects ErrTokenRevoked or similar for a revoked token
	_, err := s.GetRefreshTokenSession(ctx, sig, &fosite.DefaultSession{})
	if err == nil {
		t.Fatal("GetRefreshTokenSession after revoke: expected error, got nil")
	}
}

// TestRefreshTokenStore_RevokeRefreshToken_SetsRevokedFlag verifies that
// RevokeRefreshToken sets the revoked=1 flag in the database row.
func TestRefreshTokenStore_RevokeRefreshToken_SetsRevokedFlag(t *testing.T) {
	// Arrange
	db := openDB(t)
	insertTestClient(t, db)
	s := newStore(t, db)
	ctx := context.Background()
	sig := "refresh-sig-004"
	req := newAccessRequest("req-refresh-004")

	if err := s.CreateRefreshTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	// Act — revoke by request ID
	if err := s.RevokeRefreshToken(ctx, req.GetID()); err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}

	// Assert — the DB row should now have revoked=1
	var revoked int
	row := db.QueryRow(`SELECT revoked FROM refresh_tokens WHERE signature = ?`, sig)
	if err := row.Scan(&revoked); err != nil {
		t.Fatalf("SELECT revoked: %v", err)
	}
	if revoked != 1 {
		t.Errorf("refresh_tokens.revoked = %d, want 1", revoked)
	}
}

// ---------------------------------------------------------------------------
// OpenIDConnectRequestStore
// ---------------------------------------------------------------------------

// TestOpenIDConnectStore_CreateAndGet verifies round-trip persistence of an
// OIDC connect session.
func TestOpenIDConnectStore_CreateAndGet(t *testing.T) {
	// Arrange
	db := openDB(t)
	insertTestClient(t, db)
	s := newStore(t, db)
	ctx := context.Background()
	authorizeCode := "oidc-auth-code-001"
	req := newAuthorizeRequest("req-oidc-001")

	// Act
	if err := s.CreateOpenIDConnectSession(ctx, authorizeCode, req); err != nil {
		t.Fatalf("CreateOpenIDConnectSession: %v", err)
	}

	accessReq := newAccessRequest("req-access-for-oidc")
	got, err := s.GetOpenIDConnectSession(ctx, authorizeCode, accessReq)
	if err != nil {
		t.Fatalf("GetOpenIDConnectSession: %v", err)
	}

	// Assert
	if got == nil {
		t.Fatal("GetOpenIDConnectSession returned nil, want non-nil")
	}
	if got.GetID() != req.GetID() {
		t.Errorf("request ID = %q, want %q", got.GetID(), req.GetID())
	}
}

// TestOpenIDConnectStore_GetReturnsErrorForUnknownCode verifies that
// GetOpenIDConnectSession returns an error for an unknown authorize code.
func TestOpenIDConnectStore_GetReturnsErrorForUnknownCode(t *testing.T) {
	// Arrange
	db := openDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	// Act
	accessReq := newAccessRequest("req-access-oidc-unknown")
	_, err := s.GetOpenIDConnectSession(ctx, "nonexistent-code", accessReq)

	// Assert
	if err == nil {
		t.Fatal("GetOpenIDConnectSession: expected error for unknown code, got nil")
	}
}

// TestOpenIDConnectStore_DeleteRemovesSession verifies that
// DeleteOpenIDConnectSession makes the session unretrievable.
func TestOpenIDConnectStore_DeleteRemovesSession(t *testing.T) {
	// Arrange
	db := openDB(t)
	insertTestClient(t, db)
	s := newStore(t, db)
	ctx := context.Background()
	authorizeCode := "oidc-auth-code-002"
	req := newAuthorizeRequest("req-oidc-002")

	if err := s.CreateOpenIDConnectSession(ctx, authorizeCode, req); err != nil {
		t.Fatalf("CreateOpenIDConnectSession: %v", err)
	}

	// Act
	if err := s.DeleteOpenIDConnectSession(ctx, authorizeCode); err != nil {
		t.Fatalf("DeleteOpenIDConnectSession: %v", err)
	}

	// Assert
	accessReq := newAccessRequest("req-access-after-delete")
	_, err := s.GetOpenIDConnectSession(ctx, authorizeCode, accessReq)
	if err == nil {
		t.Fatal("GetOpenIDConnectSession after delete: expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Store satisfies fosite.Storage (compile-time interface assertion)
// ---------------------------------------------------------------------------

// TestStore_ImplementsFositeStorage is a compile-time check that *storage.Store
// satisfies all fosite storage interfaces required by the OAuth2+OIDC flows.
// This test always passes at runtime; the real value is that the package will
// not compile if the interface is not satisfied.
func TestStore_ImplementsFositeStorage(t *testing.T) {
	db := openDB(t)
	s := newStore(t, db)

	// These interface assertions will cause a compile error if *storage.Store
	// does not implement the interfaces.
	var _ fosite.ClientManager = s
	var _ fosite.AuthorizeCodeStorage = s
	var _ fosite.AccessTokenStorage = s
	var _ fosite.RefreshTokenStorage = s
	var _ fosite.OpenIDConnectRequestStorage = s

	// Runtime sanity: the store must not be nil.
	if s == nil {
		t.Fatal("storage.New returned nil store")
	}
}
