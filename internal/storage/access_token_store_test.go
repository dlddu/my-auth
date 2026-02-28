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

// newTestAccessRequest builds a minimal fosite.AccessRequester for token
// storage round-trip tests.
func newTestAccessRequest(clientID, requestID string) fosite.Requester {
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

	req := fosite.NewAccessRequest(session)
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
	return req
}

// ---------------------------------------------------------------------------
// AccessTokenStore.CreateAccessTokenSession — happy path
// ---------------------------------------------------------------------------

func TestAccessTokenStore_CreateAndGet_RoundTrip(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewAccessTokenStore(db)
	ctx := context.Background()
	sig := "access-token-signature-abc"
	req := newTestAccessRequest("test-client", "req-at-001")

	// Act — create
	err := store.CreateAccessTokenSession(ctx, sig, req)
	if err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}

	// Act — retrieve
	got, err := store.GetAccessTokenSession(ctx, sig, &openid.DefaultSession{})
	if err != nil {
		t.Fatalf("GetAccessTokenSession: %v", err)
	}

	// Assert
	if got == nil {
		t.Fatal("GetAccessTokenSession: returned nil requester")
	}
	if got.GetID() != "req-at-001" {
		t.Errorf("requester ID = %q, want %q", got.GetID(), "req-at-001")
	}
}

// ---------------------------------------------------------------------------
// AccessTokenStore.GetAccessTokenSession — unknown signature returns error
// ---------------------------------------------------------------------------

func TestAccessTokenStore_GetSession_UnknownSignatureReturnsError(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)

	store := storage.NewAccessTokenStore(db)
	ctx := context.Background()

	// Act
	_, err := store.GetAccessTokenSession(ctx, "no-such-sig", &openid.DefaultSession{})

	// Assert
	if err == nil {
		t.Fatal("GetAccessTokenSession: expected error for unknown signature, got nil")
	}
}

// ---------------------------------------------------------------------------
// AccessTokenStore.DeleteAccessTokenSession — removes the token
// ---------------------------------------------------------------------------

func TestAccessTokenStore_Delete_RemovesToken(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewAccessTokenStore(db)
	ctx := context.Background()
	sig := "delete-me-sig"
	req := newTestAccessRequest("test-client", "req-at-002")

	if err := store.CreateAccessTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}

	// Act
	if err := store.DeleteAccessTokenSession(ctx, sig); err != nil {
		t.Fatalf("DeleteAccessTokenSession: %v", err)
	}

	// Assert — token must no longer be retrievable
	_, err := store.GetAccessTokenSession(ctx, sig, &openid.DefaultSession{})
	if err == nil {
		t.Fatal("GetAccessTokenSession: expected error after deletion, got nil")
	}
}

// ---------------------------------------------------------------------------
// AccessTokenStore.RevokeAccessToken — revokes tokens by request ID
// ---------------------------------------------------------------------------

func TestAccessTokenStore_RevokeAccessToken_ByRequestID(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewAccessTokenStore(db)
	ctx := context.Background()

	const requestID = "req-to-revoke"
	sig1 := "sig-revoke-1"
	sig2 := "sig-revoke-2"

	req1 := newTestAccessRequest("test-client", requestID)
	req2 := newTestAccessRequest("test-client", requestID)

	if err := store.CreateAccessTokenSession(ctx, sig1, req1); err != nil {
		t.Fatalf("CreateAccessTokenSession (sig1): %v", err)
	}
	if err := store.CreateAccessTokenSession(ctx, sig2, req2); err != nil {
		t.Fatalf("CreateAccessTokenSession (sig2): %v", err)
	}

	// Act — revoke all tokens associated with the request ID
	if err := store.RevokeAccessToken(ctx, requestID); err != nil {
		t.Fatalf("RevokeAccessToken: %v", err)
	}

	// Assert — both tokens must no longer be retrievable
	_, err1 := store.GetAccessTokenSession(ctx, sig1, &openid.DefaultSession{})
	_, err2 := store.GetAccessTokenSession(ctx, sig2, &openid.DefaultSession{})
	if err1 == nil || err2 == nil {
		t.Error("GetAccessTokenSession: expected errors after revocation, but at least one token was still accessible")
	}
}

// ---------------------------------------------------------------------------
// AccessTokenStore.CreateAccessTokenSession — scopes are preserved
// ---------------------------------------------------------------------------

func TestAccessTokenStore_GetSession_PreservesGrantedScopes(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewAccessTokenStore(db)
	ctx := context.Background()
	sig := "scope-check-sig"
	req := newTestAccessRequest("test-client", "req-at-003")

	if err := store.CreateAccessTokenSession(ctx, sig, req); err != nil {
		t.Fatalf("CreateAccessTokenSession: %v", err)
	}

	// Act
	got, err := store.GetAccessTokenSession(ctx, sig, &openid.DefaultSession{})
	if err != nil {
		t.Fatalf("GetAccessTokenSession: %v", err)
	}

	// Assert
	if !got.GetGrantedScopes().Has("openid") {
		t.Errorf("granted scopes = %v, want to contain \"openid\"", got.GetGrantedScopes())
	}
}
