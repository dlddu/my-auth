// Package storage_test contains integration tests for the SQLite-backed fosite
// storage implementations. All tests use testhelper.NewTestDB to obtain an
// isolated, fully-migrated database for each test run.
//
// The tests are written in the Red Phase of TDD: the storage package does not
// yet exist, so the build will fail until the implementation is in place.
package storage_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/dlddu/my-auth/internal/storage"
	"github.com/dlddu/my-auth/internal/testhelper"
	"github.com/ory/fosite"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// insertTestClient inserts a minimal client row directly into the database.
// It bypasses the store layer so that GetClient tests have a known state.
func insertTestClient(t *testing.T, db *sql.DB, id, secret string) {
	t.Helper()

	_, err := db.ExecContext(context.Background(),
		`INSERT INTO clients
		    (id, secret, redirect_uris, grant_types, response_types, scopes)
		 VALUES
		    (?, ?, ?, ?, ?, ?)`,
		id, secret,
		`["http://localhost:9999/callback"]`,
		`["authorization_code", "refresh_token"]`,
		`["code"]`,
		`openid profile email`,
	)
	if err != nil {
		t.Fatalf("insertTestClient: %v", err)
	}
}

// openTestDB opens a second *sql.DB handle to the DSN returned by
// testhelper.NewTestDB. The handle is closed via t.Cleanup.
func openTestDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("openTestDB: sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// ---------------------------------------------------------------------------
// ClientStore.GetClient — happy path
// ---------------------------------------------------------------------------

func TestClientStore_GetClient_ReturnsExistingClient(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "test-client", "test-secret")

	store := storage.NewClientStore(db)
	ctx := context.Background()

	// Act
	client, err := store.GetClient(ctx, "test-client")

	// Assert
	if err != nil {
		t.Fatalf("GetClient: unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("GetClient: returned nil client, want non-nil")
	}
	if client.GetID() != "test-client" {
		t.Errorf("client.GetID() = %q, want %q", client.GetID(), "test-client")
	}
}

// ---------------------------------------------------------------------------
// ClientStore.GetClient — client not found
// ---------------------------------------------------------------------------

func TestClientStore_GetClient_ReturnsErrorForUnknownID(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)

	store := storage.NewClientStore(db)
	ctx := context.Background()

	// Act
	client, err := store.GetClient(ctx, "nonexistent-client")

	// Assert — must return an error and a nil client
	if err == nil {
		t.Fatal("GetClient: expected error for unknown client ID, got nil")
	}
	if client != nil {
		t.Errorf("GetClient: expected nil client for unknown ID, got %v", client)
	}
}

// ---------------------------------------------------------------------------
// ClientStore.GetClient — redirect URIs are populated
// ---------------------------------------------------------------------------

func TestClientStore_GetClient_HasRedirectURIs(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "client-uris", "secret")

	store := storage.NewClientStore(db)
	ctx := context.Background()

	// Act
	client, err := store.GetClient(ctx, "client-uris")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}

	// Assert — at least one redirect URI must be present
	uris := client.GetRedirectURIs()
	if len(uris) == 0 {
		t.Error("GetClient: client has no redirect URIs, want at least one")
	}
}

// ---------------------------------------------------------------------------
// ClientStore.GetClient — scopes are populated
// ---------------------------------------------------------------------------

func TestClientStore_GetClient_HasScopes(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "client-scopes", "secret")

	store := storage.NewClientStore(db)
	ctx := context.Background()

	// Act
	client, err := store.GetClient(ctx, "client-scopes")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}

	// Assert — the client must expose its registered scopes
	scopes := client.GetScopes()
	if len(scopes) == 0 {
		t.Error("GetClient: client has no scopes, want at least one")
	}
}

// ---------------------------------------------------------------------------
// ClientStore.GetClient — grant types are populated
// ---------------------------------------------------------------------------

func TestClientStore_GetClient_HasGrantTypes(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "client-grants", "secret")

	store := storage.NewClientStore(db)
	ctx := context.Background()

	// Act
	client, err := store.GetClient(ctx, "client-grants")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}

	// Assert
	grantTypes := client.GetGrantTypes()
	if len(grantTypes) == 0 {
		t.Error("GetClient: client has no grant types, want at least one")
	}
}

// ---------------------------------------------------------------------------
// ClientStore.GetClient — returned type satisfies fosite.Client interface
// ---------------------------------------------------------------------------

func TestClientStore_GetClient_ImplementsFositeClient(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	db := openTestDB(t, dsn)
	insertTestClient(t, db, "client-iface", "secret")

	store := storage.NewClientStore(db)
	ctx := context.Background()

	// Act
	c, err := store.GetClient(ctx, "client-iface")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}

	// Assert — compile-time and runtime check that the returned value
	// satisfies fosite.Client
	var _ fosite.Client = c
}
