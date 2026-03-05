// Package storage_test — Admin Client CRUD 스토리지 레이어 테스트 (TDD Red Phase)
//
// 이 테스트들은 ListClients, UpdateClient, DeleteClient 메서드가 구현되기 전에
// 작성되었으므로 현재 컴파일 오류 또는 실패 상태가 정상입니다.
//
// 구현이 필요한 항목:
//
//  1. internal/storage/store.go 에 다음 메서드 추가:
//     - ListClients(ctx context.Context) ([]fosite.Client, error)
//     - UpdateClient(ctx context.Context, client fosite.Client) error
//     - DeleteClient(ctx context.Context, id string) error
//
// 테스트 커버리지:
//   - ListClients: 빈 목록 반환, 여러 클라이언트 반환, secret 필드 포함 여부
//   - UpdateClient: redirect_uris, grant_types, scopes 수정, 존재하지 않는 ID 처리
//   - DeleteClient: 삭제 성공, 삭제 후 GetClient ErrNotFound, 존재하지 않는 ID 처리
package storage_test

import (
	"context"
	"testing"

	"github.com/ory/fosite"

	"github.com/dlddu/my-auth/internal/storage"
	"github.com/dlddu/my-auth/internal/testhelper"
)

// newConfidentialClient returns a *fosite.DefaultOpenIDConnectClient configured
// as a confidential client with deterministic test values.
func newConfidentialClient(clientID string) *fosite.DefaultOpenIDConnectClient {
	return &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            clientID,
			Secret:        []byte("$2a$04$hashed-secret-placeholder"),
			Public:        false,
			RedirectURIs:  []string{"https://app.test.local/callback"},
			GrantTypes:    fosite.Arguments{"authorization_code", "refresh_token"},
			ResponseTypes: fosite.Arguments{"code"},
			Scopes:        fosite.Arguments{"openid", "profile", "email"},
		},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
}

// ---------------------------------------------------------------------------
// ListClients
// ---------------------------------------------------------------------------

// TestListClients_EmptyDB_ReturnsEmptySlice verifies that ListClients returns
// an empty (non-nil) slice when no clients are registered.
func TestListClients_EmptyDB_ReturnsEmptySlice(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	// Act
	clients, err := store.ListClients(ctx)

	// Assert
	if err != nil {
		t.Fatalf("ListClients() returned unexpected error: %v", err)
	}
	if clients == nil {
		t.Error("ListClients() returned nil, want non-nil empty slice")
	}
	if len(clients) != 0 {
		t.Errorf("ListClients() returned %d clients, want 0", len(clients))
	}
}

// TestListClients_MultipleClients_ReturnsAll verifies that ListClients returns
// all registered clients.
func TestListClients_MultipleClients_ReturnsAll(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	client1 := newConfidentialClient("list-client-001")
	client2 := newConfidentialClient("list-client-002")
	client3 := newPublicTestClient("list-client-public-003")

	if err := store.CreateClient(ctx, client1); err != nil {
		t.Fatalf("CreateClient(client1): %v", err)
	}
	if err := store.CreateClient(ctx, client2); err != nil {
		t.Fatalf("CreateClient(client2): %v", err)
	}
	if err := store.CreateClient(ctx, client3); err != nil {
		t.Fatalf("CreateClient(client3): %v", err)
	}

	// Act
	clients, err := store.ListClients(ctx)

	// Assert
	if err != nil {
		t.Fatalf("ListClients() returned unexpected error: %v", err)
	}
	if len(clients) != 3 {
		t.Errorf("ListClients() returned %d clients, want 3", len(clients))
	}
}

// TestListClients_ReturnsCorrectClientIDs verifies that the client IDs
// returned by ListClients match the IDs that were registered.
func TestListClients_ReturnsCorrectClientIDs(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	wantIDs := map[string]bool{
		"list-ids-client-a": true,
		"list-ids-client-b": true,
	}

	for id := range wantIDs {
		c := newConfidentialClient(id)
		if err := store.CreateClient(ctx, c); err != nil {
			t.Fatalf("CreateClient(%q): %v", id, err)
		}
	}

	// Act
	clients, err := store.ListClients(ctx)

	// Assert
	if err != nil {
		t.Fatalf("ListClients() returned unexpected error: %v", err)
	}

	gotIDs := make(map[string]bool, len(clients))
	for _, c := range clients {
		gotIDs[c.GetID()] = true
	}

	for id := range wantIDs {
		if !gotIDs[id] {
			t.Errorf("ListClients() missing client %q in result", id)
		}
	}
}

// TestListClients_SecretIsIncluded verifies that ListClients includes the
// client secret (bcrypt hash) so the storage layer has full client data.
// The handler layer is responsible for stripping secrets from API responses.
func TestListClients_SecretIsIncluded(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	client := newConfidentialClient("list-secret-client")
	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	// Act
	clients, err := store.ListClients(ctx)

	// Assert
	if err != nil {
		t.Fatalf("ListClients() returned unexpected error: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("ListClients() returned %d clients, want 1", len(clients))
	}

	// The returned client must have a non-empty secret (bcrypt hash).
	dc, ok := clients[0].(*fosite.DefaultOpenIDConnectClient)
	if !ok {
		t.Fatalf("ListClients()[0] type = %T, want *fosite.DefaultOpenIDConnectClient", clients[0])
	}
	if len(dc.Secret) == 0 {
		t.Error("ListClients()[0].Secret is empty, want the stored bcrypt hash")
	}
}

// ---------------------------------------------------------------------------
// UpdateClient
// ---------------------------------------------------------------------------

// TestUpdateClient_ChangesRedirectURIs verifies that UpdateClient correctly
// updates the redirect_uris field in storage.
func TestUpdateClient_ChangesRedirectURIs(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	clientID := "update-redirect-client"
	original := newConfidentialClient(clientID)
	if err := store.CreateClient(ctx, original); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	// Build updated client with different redirect URIs.
	updated := &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            clientID,
			Secret:        original.Secret,
			Public:        false,
			RedirectURIs:  []string{"https://new.app.test.local/callback", "https://new.app.test.local/callback2"},
			GrantTypes:    original.GetGrantTypes(),
			ResponseTypes: original.GetResponseTypes(),
			Scopes:        original.GetScopes(),
		},
		TokenEndpointAuthMethod: original.TokenEndpointAuthMethod,
	}

	// Act
	err := store.UpdateClient(ctx, updated)

	// Assert — no error from UpdateClient.
	if err != nil {
		t.Fatalf("UpdateClient() returned unexpected error: %v", err)
	}

	// Assert — GetClient returns the updated redirect URIs.
	got, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("GetClient() after UpdateClient: %v", err)
	}

	gotURIs := got.GetRedirectURIs()
	if len(gotURIs) != 2 {
		t.Errorf("GetClient().GetRedirectURIs() len = %d, want 2", len(gotURIs))
	}
	wantURI := "https://new.app.test.local/callback"
	found := false
	for _, u := range gotURIs {
		if u == wantURI {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GetClient().GetRedirectURIs() = %v, want to contain %q", gotURIs, wantURI)
	}
}

// TestUpdateClient_ChangesGrantTypes verifies that UpdateClient correctly
// updates the grant_types field.
func TestUpdateClient_ChangesGrantTypes(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	clientID := "update-grants-client"
	original := newConfidentialClient(clientID)
	if err := store.CreateClient(ctx, original); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	updated := &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            clientID,
			Secret:        original.Secret,
			Public:        false,
			RedirectURIs:  original.GetRedirectURIs(),
			GrantTypes:    fosite.Arguments{"client_credentials"},
			ResponseTypes: fosite.Arguments{"token"},
			Scopes:        original.GetScopes(),
		},
		TokenEndpointAuthMethod: original.TokenEndpointAuthMethod,
	}

	// Act
	err := store.UpdateClient(ctx, updated)

	// Assert
	if err != nil {
		t.Fatalf("UpdateClient() returned unexpected error: %v", err)
	}

	got, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("GetClient() after UpdateClient: %v", err)
	}

	grantTypes := got.GetGrantTypes()
	if len(grantTypes) != 1 || grantTypes[0] != "client_credentials" {
		t.Errorf("GetClient().GetGrantTypes() = %v, want [client_credentials]", grantTypes)
	}
}

// TestUpdateClient_ChangesScopes verifies that UpdateClient correctly updates
// the scopes field.
func TestUpdateClient_ChangesScopes(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	clientID := "update-scopes-client"
	original := newConfidentialClient(clientID)
	if err := store.CreateClient(ctx, original); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	updated := &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            clientID,
			Secret:        original.Secret,
			Public:        false,
			RedirectURIs:  original.GetRedirectURIs(),
			GrantTypes:    original.GetGrantTypes(),
			ResponseTypes: original.GetResponseTypes(),
			Scopes:        fosite.Arguments{"read", "write"},
		},
		TokenEndpointAuthMethod: original.TokenEndpointAuthMethod,
	}

	// Act
	err := store.UpdateClient(ctx, updated)

	// Assert
	if err != nil {
		t.Fatalf("UpdateClient() returned unexpected error: %v", err)
	}

	got, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("GetClient() after UpdateClient: %v", err)
	}

	scopes := got.GetScopes()
	wantScopes := map[string]bool{"read": true, "write": true}
	if len(scopes) != 2 {
		t.Errorf("GetClient().GetScopes() = %v, want [read write]", scopes)
	}
	for _, s := range scopes {
		if !wantScopes[s] {
			t.Errorf("GetClient().GetScopes() contains unexpected scope %q", s)
		}
	}
}

// TestUpdateClient_NonExistentID_ReturnsError verifies that UpdateClient
// returns an error when the client ID does not exist in storage.
func TestUpdateClient_NonExistentID_ReturnsError(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	nonExistent := &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            "does-not-exist-client",
			Secret:        []byte("$2a$04$irrelevant"),
			RedirectURIs:  []string{"https://app.test.local/callback"},
			GrantTypes:    fosite.Arguments{"authorization_code"},
			ResponseTypes: fosite.Arguments{"code"},
			Scopes:        fosite.Arguments{"openid"},
		},
		TokenEndpointAuthMethod: "client_secret_basic",
	}

	// Act
	err := store.UpdateClient(ctx, nonExistent)

	// Assert — updating a non-existent client must return an error.
	if err == nil {
		t.Error("UpdateClient() with non-existent ID returned nil error, want non-nil error")
	}
}

// ---------------------------------------------------------------------------
// DeleteClient
// ---------------------------------------------------------------------------

// TestDeleteClient_ExistingID_Succeeds verifies that DeleteClient removes a
// registered client without returning an error.
func TestDeleteClient_ExistingID_Succeeds(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	clientID := "delete-client-ok"
	client := newConfidentialClient(clientID)
	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	// Act
	err := store.DeleteClient(ctx, clientID)

	// Assert
	if err != nil {
		t.Errorf("DeleteClient(%q) returned unexpected error: %v", clientID, err)
	}
}

// TestDeleteClient_AfterDelete_GetClientReturnsNotFound verifies that
// GetClient returns fosite.ErrNotFound after the client has been deleted.
func TestDeleteClient_AfterDelete_GetClientReturnsNotFound(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	clientID := "delete-then-notfound-client"
	client := newConfidentialClient(clientID)
	if err := store.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}
	if err := store.DeleteClient(ctx, clientID); err != nil {
		t.Fatalf("DeleteClient(): %v", err)
	}

	// Act
	_, err := store.GetClient(ctx, clientID)

	// Assert — deleted client must not be found.
	if err == nil {
		t.Fatal("GetClient() after DeleteClient returned nil error, want fosite.ErrNotFound")
	}
	if err != fosite.ErrNotFound {
		t.Errorf("GetClient() after DeleteClient error = %v, want fosite.ErrNotFound", err)
	}
}

// TestDeleteClient_AfterDelete_NotInListClients verifies that a deleted client
// does not appear in the ListClients result.
func TestDeleteClient_AfterDelete_NotInListClients(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	keepID := "delete-list-keep"
	deleteID := "delete-list-remove"

	if err := store.CreateClient(ctx, newConfidentialClient(keepID)); err != nil {
		t.Fatalf("CreateClient(keep): %v", err)
	}
	if err := store.CreateClient(ctx, newConfidentialClient(deleteID)); err != nil {
		t.Fatalf("CreateClient(delete): %v", err)
	}

	if err := store.DeleteClient(ctx, deleteID); err != nil {
		t.Fatalf("DeleteClient(): %v", err)
	}

	// Act
	clients, err := store.ListClients(ctx)

	// Assert
	if err != nil {
		t.Fatalf("ListClients() after DeleteClient: %v", err)
	}
	if len(clients) != 1 {
		t.Errorf("ListClients() returned %d clients after deletion, want 1", len(clients))
	}
	if clients[0].GetID() != keepID {
		t.Errorf("ListClients()[0].GetID() = %q, want %q", clients[0].GetID(), keepID)
	}
}

// TestDeleteClient_NonExistentID_ReturnsError verifies that DeleteClient
// returns an error when the client ID does not exist.
func TestDeleteClient_NonExistentID_ReturnsError(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	// Act
	err := store.DeleteClient(ctx, "does-not-exist-at-all")

	// Assert — deleting a non-existent client must return an error.
	if err == nil {
		t.Error("DeleteClient() with non-existent ID returned nil error, want non-nil error")
	}
}

// ---------------------------------------------------------------------------
// UpdateClient — secret 업데이트 (비밀번호 변경 시나리오)
// ---------------------------------------------------------------------------

// TestUpdateClient_ChangesSecret verifies that UpdateClient correctly updates
// the stored secret when a new bcrypt hash is provided.
func TestUpdateClient_ChangesSecret(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)
	store := newTestStore(t, dsn)
	ctx := context.Background()

	clientID := "update-secret-client"
	original := newConfidentialClient(clientID)
	if err := store.CreateClient(ctx, original); err != nil {
		t.Fatalf("CreateClient(): %v", err)
	}

	newSecret := []byte("$2a$04$new-hashed-secret-placeholder")
	updated := &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            clientID,
			Secret:        newSecret,
			Public:        false,
			RedirectURIs:  original.GetRedirectURIs(),
			GrantTypes:    original.GetGrantTypes(),
			ResponseTypes: original.GetResponseTypes(),
			Scopes:        original.GetScopes(),
		},
		TokenEndpointAuthMethod: original.TokenEndpointAuthMethod,
	}

	// Act
	err := store.UpdateClient(ctx, updated)

	// Assert
	if err != nil {
		t.Fatalf("UpdateClient() returned unexpected error: %v", err)
	}

	// Verify the secret was actually changed in storage.
	got, err := store.GetClient(ctx, clientID)
	if err != nil {
		t.Fatalf("GetClient() after UpdateClient: %v", err)
	}
	dc, ok := got.(*fosite.DefaultOpenIDConnectClient)
	if !ok {
		t.Fatalf("GetClient() type = %T, want *fosite.DefaultOpenIDConnectClient", got)
	}
	if string(dc.Secret) != string(newSecret) {
		t.Errorf("GetClient().Secret = %q, want %q", dc.Secret, newSecret)
	}
}

// ---------------------------------------------------------------------------
// Compile-time interface check
// ---------------------------------------------------------------------------

// Ensure *storage.Store satisfies the AdminClientStore interface used by handlers.
// This assertion will fail at compile time if the required methods are missing.
var _ interface {
	ListClients(ctx context.Context) ([]fosite.Client, error)
	UpdateClient(ctx context.Context, client fosite.Client) error
	DeleteClient(ctx context.Context, id string) error
} = (*storage.Store)(nil)
