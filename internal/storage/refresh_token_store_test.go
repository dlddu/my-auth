package storage_test

import (
	"context"
	"testing"

	"github.com/dlddu/my-auth/internal/storage"
	"github.com/dlddu/my-auth/internal/testhelper"
	"github.com/ory/fosite/handler/openid"
)

// ---------------------------------------------------------------------------
// RefreshTokenStore.CreateRefreshTokenSession — happy path (create + get)
// ---------------------------------------------------------------------------

func TestRefreshTokenStore_CreateAndGet_RoundTrip(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewRefreshTokenStore(db)
	ctx := context.Background()
	sig := "refresh-token-sig-abc"
	req := newTestAccessRequest("test-client", "req-rt-001")

	// Act — create
	err := store.CreateRefreshTokenSession(ctx, sig, "", req)
	if err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	// Act — retrieve
	got, err := store.GetRefreshTokenSession(ctx, sig, &openid.DefaultSession{})
	if err != nil {
		t.Fatalf("GetRefreshTokenSession: %v", err)
	}

	// Assert
	if got == nil {
		t.Fatal("GetRefreshTokenSession: returned nil requester")
	}
	if got.GetID() != "req-rt-001" {
		t.Errorf("requester ID = %q, want %q", got.GetID(), "req-rt-001")
	}
}

// ---------------------------------------------------------------------------
// RefreshTokenStore.GetRefreshTokenSession — unknown signature returns error
// ---------------------------------------------------------------------------

func TestRefreshTokenStore_GetSession_UnknownSignatureReturnsError(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)

	store := storage.NewRefreshTokenStore(db)
	ctx := context.Background()

	// Act
	_, err := store.GetRefreshTokenSession(ctx, "no-such-sig", &openid.DefaultSession{})

	// Assert
	if err == nil {
		t.Fatal("GetRefreshTokenSession: expected error for unknown signature, got nil")
	}
}

// ---------------------------------------------------------------------------
// RefreshTokenStore.DeleteRefreshTokenSession — removes the token
// ---------------------------------------------------------------------------

func TestRefreshTokenStore_Delete_RemovesToken(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewRefreshTokenStore(db)
	ctx := context.Background()
	sig := "delete-refresh-sig"
	req := newTestAccessRequest("test-client", "req-rt-002")

	if err := store.CreateRefreshTokenSession(ctx, sig, "", req); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	// Act
	if err := store.DeleteRefreshTokenSession(ctx, sig); err != nil {
		t.Fatalf("DeleteRefreshTokenSession: %v", err)
	}

	// Assert — token must no longer be retrievable
	_, err := store.GetRefreshTokenSession(ctx, sig, &openid.DefaultSession{})
	if err == nil {
		t.Fatal("GetRefreshTokenSession: expected error after deletion, got nil")
	}
}

// ---------------------------------------------------------------------------
// RefreshTokenStore.RevokeRefreshToken — revokes all tokens by request ID
// ---------------------------------------------------------------------------

func TestRefreshTokenStore_RevokeRefreshToken_ByRequestID(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewRefreshTokenStore(db)
	ctx := context.Background()

	const requestID = "req-rt-revoke"
	sig1 := "refresh-revoke-sig-1"
	sig2 := "refresh-revoke-sig-2"

	req1 := newTestAccessRequest("test-client", requestID)
	req2 := newTestAccessRequest("test-client", requestID)

	if err := store.CreateRefreshTokenSession(ctx, sig1, "", req1); err != nil {
		t.Fatalf("CreateRefreshTokenSession (sig1): %v", err)
	}
	if err := store.CreateRefreshTokenSession(ctx, sig2, "", req2); err != nil {
		t.Fatalf("CreateRefreshTokenSession (sig2): %v", err)
	}

	// Act
	if err := store.RevokeRefreshToken(ctx, requestID); err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}

	// Assert — revoked tokens must return an error
	_, err1 := store.GetRefreshTokenSession(ctx, sig1, &openid.DefaultSession{})
	_, err2 := store.GetRefreshTokenSession(ctx, sig2, &openid.DefaultSession{})
	if err1 == nil || err2 == nil {
		t.Error("GetRefreshTokenSession: expected errors after revocation, but at least one token was still accessible")
	}
}

// ---------------------------------------------------------------------------
// RefreshTokenStore.RevokeRefreshToken — no-op for unknown request ID
// ---------------------------------------------------------------------------

func TestRefreshTokenStore_RevokeRefreshToken_UnknownRequestIDIsNoOp(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)

	store := storage.NewRefreshTokenStore(db)
	ctx := context.Background()

	// Act — revoking an unknown request ID must not return an error
	err := store.RevokeRefreshToken(ctx, "nonexistent-request-id")

	// Assert
	if err != nil {
		t.Errorf("RevokeRefreshToken: unexpected error for unknown request ID: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RefreshTokenStore.CreateRefreshTokenSession — granted scopes are preserved
// ---------------------------------------------------------------------------

func TestRefreshTokenStore_GetSession_PreservesGrantedScopes(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewRefreshTokenStore(db)
	ctx := context.Background()
	sig := "scope-refresh-sig"
	req := newTestAccessRequest("test-client", "req-rt-003")

	if err := store.CreateRefreshTokenSession(ctx, sig, "", req); err != nil {
		t.Fatalf("CreateRefreshTokenSession: %v", err)
	}

	// Act
	got, err := store.GetRefreshTokenSession(ctx, sig, &openid.DefaultSession{})
	if err != nil {
		t.Fatalf("GetRefreshTokenSession: %v", err)
	}

	// Assert
	if !got.GetGrantedScopes().Has("openid") {
		t.Errorf("granted scopes = %v, want to contain \"openid\"", got.GetGrantedScopes())
	}
}
