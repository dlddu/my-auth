package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/dlddu/my-auth/internal/storage"
	"github.com/dlddu/my-auth/internal/testhelper"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// newTestOIDCRequest builds a minimal fosite.Requester with an OIDC session
// that is sufficient for OpenIDConnectRequestStore tests.
func newTestOIDCRequest(clientID, requestID string) fosite.Requester {
	session := &openid.DefaultSession{
		Subject: "user@test.local",
		Claims: &jwt.IDTokenClaims{
			Issuer:    "https://auth.test.local",
			Subject:   "user@test.local",
			Audience:  []string{clientID},
			Nonce:     "test-nonce-value",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}

	req := fosite.NewAuthorizeRequest()
	req.ID = requestID
	req.RequestedAt = time.Now()
	req.GrantedScope = fosite.Arguments{"openid", "profile"}
	req.RequestedScope = fosite.Arguments{"openid", "profile"}
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
// OpenIDConnectRequestStore.CreateOpenIDConnectSession — happy path
// ---------------------------------------------------------------------------

func TestOIDCSessionStore_CreateAndGet_RoundTrip(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewOpenIDConnectSessionStore(db)
	ctx := context.Background()
	authorizeCode := "oidc-authorize-code-001"
	req := newTestOIDCRequest("test-client", "req-oidc-001")

	// Act — create
	err := store.CreateOpenIDConnectSession(ctx, authorizeCode, req)
	if err != nil {
		t.Fatalf("CreateOpenIDConnectSession: %v", err)
	}

	// Act — retrieve
	got, err := store.GetOpenIDConnectSession(ctx, authorizeCode, req)
	if err != nil {
		t.Fatalf("GetOpenIDConnectSession: %v", err)
	}

	// Assert
	if got == nil {
		t.Fatal("GetOpenIDConnectSession: returned nil requester")
	}
	if got.GetID() != "req-oidc-001" {
		t.Errorf("requester ID = %q, want %q", got.GetID(), "req-oidc-001")
	}
}

// ---------------------------------------------------------------------------
// OpenIDConnectRequestStore.GetOpenIDConnectSession — unknown code returns error
// ---------------------------------------------------------------------------

func TestOIDCSessionStore_GetSession_UnknownCodeReturnsError(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)

	store := storage.NewOpenIDConnectSessionStore(db)
	ctx := context.Background()

	req := newTestOIDCRequest("test-client", "req-oidc-missing")

	// Act
	_, err := store.GetOpenIDConnectSession(ctx, "nonexistent-code", req)

	// Assert
	if err == nil {
		t.Fatal("GetOpenIDConnectSession: expected error for unknown code, got nil")
	}
}

// ---------------------------------------------------------------------------
// OpenIDConnectRequestStore.DeleteOpenIDConnectSession — removes the session
// ---------------------------------------------------------------------------

func TestOIDCSessionStore_Delete_RemovesSession(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewOpenIDConnectSessionStore(db)
	ctx := context.Background()
	authorizeCode := "delete-oidc-code"
	req := newTestOIDCRequest("test-client", "req-oidc-002")

	if err := store.CreateOpenIDConnectSession(ctx, authorizeCode, req); err != nil {
		t.Fatalf("CreateOpenIDConnectSession: %v", err)
	}

	// Act
	if err := store.DeleteOpenIDConnectSession(ctx, authorizeCode); err != nil {
		t.Fatalf("DeleteOpenIDConnectSession: %v", err)
	}

	// Assert — session must no longer be retrievable
	_, err := store.GetOpenIDConnectSession(ctx, authorizeCode, req)
	if err == nil {
		t.Fatal("GetOpenIDConnectSession: expected error after deletion, got nil")
	}
}

// ---------------------------------------------------------------------------
// OpenIDConnectRequestStore — nonce is preserved in the session
// ---------------------------------------------------------------------------

func TestOIDCSessionStore_GetSession_PreservesNonce(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewOpenIDConnectSessionStore(db)
	ctx := context.Background()
	authorizeCode := "nonce-test-code"
	req := newTestOIDCRequest("test-client", "req-oidc-003")

	if err := store.CreateOpenIDConnectSession(ctx, authorizeCode, req); err != nil {
		t.Fatalf("CreateOpenIDConnectSession: %v", err)
	}

	// Act
	got, err := store.GetOpenIDConnectSession(ctx, authorizeCode, req)
	if err != nil {
		t.Fatalf("GetOpenIDConnectSession: %v", err)
	}

	// Assert — the OIDC session must carry the original nonce
	oidcSession, ok := got.GetSession().(*openid.DefaultSession)
	if !ok {
		t.Fatalf("session type = %T, want *openid.DefaultSession", got.GetSession())
	}
	if oidcSession.Claims == nil {
		t.Fatal("oidcSession.Claims is nil")
	}
	if oidcSession.Claims.Nonce != "test-nonce-value" {
		t.Errorf("nonce = %q, want %q", oidcSession.Claims.Nonce, "test-nonce-value")
	}
}

// ---------------------------------------------------------------------------
// OpenIDConnectRequestStore — subject is preserved in the session
// ---------------------------------------------------------------------------

func TestOIDCSessionStore_GetSession_PreservesSubject(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewOpenIDConnectSessionStore(db)
	ctx := context.Background()
	authorizeCode := "subject-test-code"
	req := newTestOIDCRequest("test-client", "req-oidc-004")

	if err := store.CreateOpenIDConnectSession(ctx, authorizeCode, req); err != nil {
		t.Fatalf("CreateOpenIDConnectSession: %v", err)
	}

	// Act
	got, err := store.GetOpenIDConnectSession(ctx, authorizeCode, req)
	if err != nil {
		t.Fatalf("GetOpenIDConnectSession: %v", err)
	}

	// Assert
	oidcSession, ok := got.GetSession().(*openid.DefaultSession)
	if !ok {
		t.Fatalf("session type = %T, want *openid.DefaultSession", got.GetSession())
	}
	if oidcSession.Subject != "user@test.local" {
		t.Errorf("subject = %q, want %q", oidcSession.Subject, "user@test.local")
	}
}
