package testhelper

import (
	"database/sql"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// testClientID is the OAuth2 client ID used in all integration tests.
const testClientID = "test-client"

// testClientSecret is the plain-text secret for the test OAuth2 client.
const testClientSecret = "test-secret"

// testRedirectURI is the redirect URI registered for the test OAuth2 client.
const testRedirectURI = "http://localhost:9999/callback"

// testClientScopes is the space-separated scope list for the test OAuth2 client.
const testClientScopes = "openid profile email"

// SeedTestClient inserts the canonical test OAuth2 client into the clients
// table of db. It is idempotent: if the client already exists the insert is
// silently skipped via INSERT OR IGNORE.
//
// The client secret is stored as a bcrypt hash so that fosite's bcrypt-based
// secret comparison works correctly during the token endpoint exchange.
//
// Call this helper in any test that exercises OAuth2 flows so that fosite's
// ClientStore can resolve "test-client".
func SeedTestClient(t *testing.T, db *sql.DB) {
	t.Helper()

	// Generate a bcrypt hash of the plain-text secret at cost 10.
	// bcrypt cost 10 is fast enough for tests while still being valid.
	hash, err := bcrypt.GenerateFromPassword([]byte(testClientSecret), 10)
	if err != nil {
		t.Fatalf("testhelper.SeedTestClient: bcrypt hash secret: %v", err)
	}

	_, err = db.Exec(
		`INSERT OR IGNORE INTO clients
		    (id, secret, redirect_uris, grant_types, response_types, scopes)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		testClientID,
		string(hash),
		`["http://localhost:9999/callback"]`,
		`["authorization_code","refresh_token"]`,
		`["code"]`,
		testClientScopes,
	)
	if err != nil {
		t.Fatalf("testhelper.SeedTestClient: insert test client: %v", err)
	}
}
