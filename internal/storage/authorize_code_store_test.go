package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/dlddu/my-auth/internal/storage"
	"github.com/dlddu/my-auth/internal/testhelper"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newTestAuthorizeRequest builds a minimal fosite.AuthorizeRequest that is
// sufficient for round-trip storage tests.
func newTestAuthorizeRequest(clientID, requestID string) fosite.Requester {
	session := &openid.DefaultSession{
		Subject: "user@test.local",
		Claims: &openid.IDTokenClaims{
			Issuer:    "https://auth.test.local",
			Subject:   "user@test.local",
			Audience:  []string{clientID},
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}

	req := fosite.NewAuthorizeRequest()
	req.ID = requestID
	req.RequestedAt = time.Now()
	req.GrantedScopes = fosite.Arguments{"openid", "profile"}
	req.RequestedScopes = fosite.Arguments{"openid", "profile"}
	req.Client = &fosite.DefaultClient{
		ID:            clientID,
		Secret:        []byte("test-secret"),
		RedirectURIs:  []string{"http://localhost:9999/callback"},
		GrantTypes:    fosite.Arguments{"authorization_code"},
		ResponseTypes: fosite.Arguments{"code"},
		Scopes:        fosite.Arguments{"openid", "profile"},
	}
	req.Session = session
	return req
}

// ---------------------------------------------------------------------------
// AuthorizeCodeStore.CreateAuthorizeCodeSession — happy path
// ---------------------------------------------------------------------------

func TestAuthorizeCodeStore_CreateAndGetSession_RoundTrip(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewAuthorizeCodeStore(db)
	ctx := context.Background()
	code := "test-auth-code-abc123"
	req := newTestAuthorizeRequest("test-client", "req-001")

	// Act — create
	err := store.CreateAuthorizeCodeSession(ctx, code, req)
	if err != nil {
		t.Fatalf("CreateAuthorizeCodeSession: %v", err)
	}

	// Act — retrieve
	got, err := store.GetAuthorizeCodeSession(ctx, code, &openid.DefaultSession{})
	if err != nil {
		t.Fatalf("GetAuthorizeCodeSession: %v", err)
	}

	// Assert
	if got == nil {
		t.Fatal("GetAuthorizeCodeSession: returned nil requester")
	}
	if got.GetID() != "req-001" {
		t.Errorf("requester ID = %q, want %q", got.GetID(), "req-001")
	}
}

// ---------------------------------------------------------------------------
// AuthorizeCodeStore.GetAuthorizeCodeSession — unknown code returns error
// ---------------------------------------------------------------------------

func TestAuthorizeCodeStore_GetSession_UnknownCodeReturnsError(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)

	store := storage.NewAuthorizeCodeStore(db)
	ctx := context.Background()

	// Act
	_, err := store.GetAuthorizeCodeSession(ctx, "no-such-code", &openid.DefaultSession{})

	// Assert
	if err == nil {
		t.Fatal("GetAuthorizeCodeSession: expected error for unknown code, got nil")
	}
}

// ---------------------------------------------------------------------------
// AuthorizeCodeStore.InvalidateAuthorizeCodeSession — marks code as used
// ---------------------------------------------------------------------------

func TestAuthorizeCodeStore_InvalidateSession_PreventsReuse(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewAuthorizeCodeStore(db)
	ctx := context.Background()
	code := "one-time-code-xyz"
	req := newTestAuthorizeRequest("test-client", "req-002")

	if err := store.CreateAuthorizeCodeSession(ctx, code, req); err != nil {
		t.Fatalf("CreateAuthorizeCodeSession: %v", err)
	}

	// Act — invalidate
	if err := store.InvalidateAuthorizeCodeSession(ctx, code); err != nil {
		t.Fatalf("InvalidateAuthorizeCodeSession: %v", err)
	}

	// Assert — a subsequent Get must return fosite.ErrInvalidatedAuthorizeCode
	// or any error indicating the code is no longer usable.
	_, err := store.GetAuthorizeCodeSession(ctx, code, &openid.DefaultSession{})
	if err == nil {
		t.Fatal("GetAuthorizeCodeSession: expected error after invalidation, got nil")
	}
}

// ---------------------------------------------------------------------------
// AuthorizeCodeStore.GetAuthorizeCodeSession — granted scopes are preserved
// ---------------------------------------------------------------------------

func TestAuthorizeCodeStore_GetSession_PreservesGrantedScopes(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewAuthorizeCodeStore(db)
	ctx := context.Background()
	code := "scope-test-code"
	req := newTestAuthorizeRequest("test-client", "req-003")

	if err := store.CreateAuthorizeCodeSession(ctx, code, req); err != nil {
		t.Fatalf("CreateAuthorizeCodeSession: %v", err)
	}

	// Act
	got, err := store.GetAuthorizeCodeSession(ctx, code, &openid.DefaultSession{})
	if err != nil {
		t.Fatalf("GetAuthorizeCodeSession: %v", err)
	}

	// Assert — the granted scopes must survive the round-trip
	scopes := got.GetGrantedScopes()
	if !scopes.Has("openid") {
		t.Errorf("granted scopes = %v, want to contain \"openid\"", scopes)
	}
}

// ---------------------------------------------------------------------------
// AuthorizeCodeStore.GetAuthorizeCodeSession — client ID is preserved
// ---------------------------------------------------------------------------

func TestAuthorizeCodeStore_GetSession_PreservesClientID(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewAuthorizeCodeStore(db)
	ctx := context.Background()
	code := "client-id-test-code"
	req := newTestAuthorizeRequest("test-client", "req-004")

	if err := store.CreateAuthorizeCodeSession(ctx, code, req); err != nil {
		t.Fatalf("CreateAuthorizeCodeSession: %v", err)
	}

	// Act
	got, err := store.GetAuthorizeCodeSession(ctx, code, &openid.DefaultSession{})
	if err != nil {
		t.Fatalf("GetAuthorizeCodeSession: %v", err)
	}

	// Assert
	if got.GetClient().GetID() != "test-client" {
		t.Errorf("client ID = %q, want %q", got.GetClient().GetID(), "test-client")
	}
}
