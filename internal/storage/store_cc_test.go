// Package storage_test — Client Credentials grant storage unit tests (DLD-672).
//
// These tests verify that the storage layer correctly persists and retrieves
// OAuth2 clients configured for the client_credentials grant type.
//
// The storage layer itself (GetClient / CreateClient) does not need to change:
// grant_types are already serialised as a JSON array and read back on GetClient.
// These tests confirm that a cc-client seeded with grant_types=["client_credentials"]
// is faithfully round-tripped through the store so that fosite's grant-type
// validation (performed in the token handler) can work correctly.
//
// Test coverage (DLD-672):
//   - CreateClient + GetClient: cc-client with grant_types=["client_credentials"]
//   - GetGrantTypes() returns slice containing "client_credentials"
//   - GetGrantTypes() does NOT contain "authorization_code" for a cc-only client
//   - GetGrantTypes() does NOT contain "client_credentials" for auth-code-only client
//   - Scopes ["read","write"] are persisted and retrieved correctly
//   - cc-client is a confidential client (IsPublic() == false)
//   - cc-client uses client_secret_basic token endpoint auth method
package storage_test

import (
	"context"
	"testing"

	"github.com/ory/fosite"

	"github.com/dlddu/my-auth/internal/storage"
	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Test helpers — cc-client factory
// ---------------------------------------------------------------------------

// newCCTestClient returns a *fosite.DefaultOpenIDConnectClient configured
// for the client_credentials grant only. This matches the cc-client that
// must be seeded by testhelper.NewTestServer for the token handler tests.
//
// Fields:
//   - grant_types:   ["client_credentials"]
//   - scopes:        ["read", "write"]
//   - secret:        "cc-secret" (stored as plain-text; bcrypt is applied by
//     the handler layer, not the storage layer in tests)
//   - Public:        false (confidential client)
//   - TokenEndpointAuthMethod: "client_secret_basic"
func newCCTestClient(clientID string) *fosite.DefaultOpenIDConnectClient {
	return &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            clientID,
			Secret:        []byte("cc-secret"),
			Public:        false,
			RedirectURIs:  []string{},
			GrantTypes:    fosite.Arguments{"client_credentials"},
			ResponseTypes: fosite.Arguments{"token"},
			Scopes:        fosite.Arguments{"read", "write"},
		},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
}

// newCCTestStore is a convenience wrapper that creates a test DB and returns
// both the DSN and a ready *storage.Store. The DB is cleaned up automatically.
func newCCTestStore(t *testing.T) *storage.Store {
	t.Helper()
	dsn := testhelper.NewTestDB(t)
	return newTestStore(t, dsn)
}

// ---------------------------------------------------------------------------
// 1. TestGetClient_CCClient_RetrievedSuccessfully
//    Smoke test: a cc-client stored via CreateClient can be retrieved via
//    GetClient without error and returns the correct client ID.
// ---------------------------------------------------------------------------

func TestGetClient_CCClient_RetrievedSuccessfully(t *testing.T) {
	// Arrange
	store := newCCTestStore(t)
	clientID := "cc-client-smoke"
	client := newCCTestClient(clientID)
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(%q): %v", clientID, err)
	}

	// Act
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
// 2. TestGetClient_CCClient_GrantTypesContainsClientCredentials
//    The grant_types field persisted as ["client_credentials"] must be read
//    back via GetGrantTypes() and include "client_credentials".
//
//    fosite uses GetGrantTypes() to verify that the requested grant type is
//    allowed for the client. Without "client_credentials" in the list fosite
//    will return error=unauthorized_client.
// ---------------------------------------------------------------------------

func TestGetClient_CCClient_GrantTypesContainsClientCredentials(t *testing.T) {
	// Arrange
	store := newCCTestStore(t)
	clientID := "cc-client-grant-types"
	client := newCCTestClient(clientID)
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(%q): %v", clientID, err)
	}

	// Act
	got, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("GetClient(%q): %v", clientID, err)
	}

	// Assert — grant_types must contain "client_credentials".
	grantTypes := got.GetGrantTypes()
	found := false
	for _, gt := range grantTypes {
		if gt == "client_credentials" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GetGrantTypes() = %v, want it to contain \"client_credentials\"", grantTypes)
	}
}

// ---------------------------------------------------------------------------
// 3. TestGetClient_CCClient_GrantTypesDoesNotContainAuthorizationCode
//    A cc-only client must NOT have "authorization_code" in its grant_types.
//    This verifies that the storage layer faithfully round-trips the grant_types
//    without adding extra entries.
// ---------------------------------------------------------------------------

func TestGetClient_CCClient_GrantTypesDoesNotContainAuthorizationCode(t *testing.T) {
	// Arrange
	store := newCCTestStore(t)
	clientID := "cc-client-no-auth-code"
	client := newCCTestClient(clientID)
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(%q): %v", clientID, err)
	}

	// Act
	got, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("GetClient(%q): %v", clientID, err)
	}

	// Assert — grant_types must NOT contain "authorization_code".
	for _, gt := range got.GetGrantTypes() {
		if gt == "authorization_code" {
			t.Errorf("GetGrantTypes() = %v, want it NOT to contain \"authorization_code\"", got.GetGrantTypes())
			break
		}
	}
}

// ---------------------------------------------------------------------------
// 4. TestGetClient_AuthCodeClient_GrantTypesDoesNotContainClientCredentials
//    The existing "test-client" (authorization_code + refresh_token) must NOT
//    have "client_credentials" in its grant_types after being stored.
//
//    This validates the negative case: the storage layer must not pollute a
//    client's grant_types with values it was not registered with.
//    fosite relies on this exclusion to produce error=unauthorized_client.
// ---------------------------------------------------------------------------

func TestGetClient_AuthCodeClient_GrantTypesDoesNotContainClientCredentials(t *testing.T) {
	// Arrange
	store := newCCTestStore(t)
	clientID := "auth-code-only-client-cc-neg"

	// Deliberately register a client with only authorization_code + refresh_token.
	authCodeClient := &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            clientID,
			Secret:        []byte("some-secret"),
			Public:        false,
			RedirectURIs:  []string{"http://localhost:9000/callback"},
			GrantTypes:    fosite.Arguments{"authorization_code", "refresh_token"},
			ResponseTypes: fosite.Arguments{"code"},
			Scopes:        fosite.Arguments{"openid", "profile"},
		},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	ctx := context.Background()

	if err := store.CreateClient(ctx, authCodeClient); err != nil {
		t.Fatalf("CreateClient(%q): %v", clientID, err)
	}

	// Act
	got, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("GetClient(%q): %v", clientID, err)
	}

	// Assert — grant_types must NOT contain "client_credentials".
	for _, gt := range got.GetGrantTypes() {
		if gt == "client_credentials" {
			t.Errorf("GetGrantTypes() = %v, want it NOT to contain \"client_credentials\"", got.GetGrantTypes())
			break
		}
	}
}

// ---------------------------------------------------------------------------
// 5. TestGetClient_CCClient_ScopesPersistedCorrectly
//    The scopes ["read","write"] registered for the cc-client must be
//    faithfully round-tripped through the storage layer.
//
//    fosite checks GetScopes() during token issuance to validate that the
//    client is allowed to request the submitted scope values.
// ---------------------------------------------------------------------------

func TestGetClient_CCClient_ScopesPersistedCorrectly(t *testing.T) {
	// Arrange
	store := newCCTestStore(t)
	clientID := "cc-client-scopes"
	client := newCCTestClient(clientID)
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(%q): %v", clientID, err)
	}

	// Act
	got, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("GetClient(%q): %v", clientID, err)
	}

	// Assert — scopes must contain "read" and "write".
	scopes := got.GetScopes()
	wantScopes := []string{"read", "write"}
	for _, want := range wantScopes {
		found := false
		for _, s := range scopes {
			if s == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetScopes() = %v, want it to contain %q", scopes, want)
		}
	}
}

// ---------------------------------------------------------------------------
// 6. TestGetClient_CCClient_IsConfidential
//    The cc-client must be a confidential client (IsPublic() == false).
//    Confidential clients are required to authenticate at the token endpoint,
//    which is mandatory for the client_credentials grant (RFC 6749 §4.4).
// ---------------------------------------------------------------------------

func TestGetClient_CCClient_IsConfidential(t *testing.T) {
	// Arrange
	store := newCCTestStore(t)
	clientID := "cc-client-confidential"
	client := newCCTestClient(clientID)
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(%q): %v", clientID, err)
	}

	// Act
	got, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("GetClient(%q): %v", clientID, err)
	}

	// Assert — IsPublic() must return false for confidential clients.
	if got.IsPublic() {
		t.Errorf("GetClient(%q).IsPublic() = true, want false (cc-client must be confidential)", clientID)
	}
}

// ---------------------------------------------------------------------------
// 7. TestGetClient_CCClient_TokenEndpointAuthMethodIsClientSecretBasic
//    The cc-client must use "client_secret_basic" as the token endpoint auth
//    method. fosite's client authentication handler checks this value to
//    determine whether to accept HTTP Basic Auth credentials.
// ---------------------------------------------------------------------------

func TestGetClient_CCClient_TokenEndpointAuthMethodIsClientSecretBasic(t *testing.T) {
	// Arrange
	store := newCCTestStore(t)
	clientID := "cc-client-auth-method"
	client := newCCTestClient(clientID)
	ctx := context.Background()

	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(%q): %v", clientID, err)
	}

	// Act
	got, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("GetClient(%q): %v", clientID, err)
	}

	// Assert — token endpoint auth method must be "client_secret_basic".
	oidcClient, ok := got.(interface{ GetTokenEndpointAuthMethod() string })
	if !ok {
		t.Fatalf("GetClient(%q) returned %T which does not implement GetTokenEndpointAuthMethod()", clientID, got)
	}
	if method := oidcClient.GetTokenEndpointAuthMethod(); method != "client_secret_basic" {
		t.Errorf("GetTokenEndpointAuthMethod() = %q, want \"client_secret_basic\"", method)
	}
}
