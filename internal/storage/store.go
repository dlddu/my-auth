// Package storage implements the fosite storage interfaces backed by SQLite.
//
// This file contains minimal stubs so that store_test.go compiles before the
// real implementation is written (TDD — DLD-664 / DLD-665).
// Every method panics with "not implemented" and will be replaced in DLD-665.
package storage

import (
	"context"
	"database/sql"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
)

// Store implements the fosite storage interfaces required by the OAuth2 /
// OpenID Connect flow:
//
//   - oauth2.AuthorizeCodeStorage
//   - oauth2.AccessTokenStorage
//   - oauth2.RefreshTokenStorage
//   - openid.OpenIDConnectRequestStorage
//   - fosite.ClientManager (GetClient + CreateClient for test seeding)
//
// It is backed by a single *sql.DB (SQLite) that is already migrated before
// the Store is constructed.
type Store struct {
	db *sql.DB
}

// New returns a new Store using the provided database connection.
// The caller is responsible for migrating the schema before calling New.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// ---------------------------------------------------------------------------
// Compile-time interface assertions
// ---------------------------------------------------------------------------

var _ oauth2.AuthorizeCodeStorage = (*Store)(nil)
var _ oauth2.AccessTokenStorage = (*Store)(nil)
var _ oauth2.RefreshTokenStorage = (*Store)(nil)
var _ openid.OpenIDConnectRequestStorage = (*Store)(nil)

// ---------------------------------------------------------------------------
// fosite.ClientManager — stubs
//
// GetClient is required by fosite's OAuth2Provider to look up registered
// clients during every request.  CreateClient is a non-interface convenience
// method used by tests to seed the database.
// ---------------------------------------------------------------------------

// GetClient retrieves a registered client by its ID.
// Returns fosite.ErrNotFound when the client is not registered.
// Not yet implemented.
func (s *Store) GetClient(_ context.Context, _ string) (fosite.Client, error) {
	panic("storage.Store.GetClient: not implemented (DLD-665)")
}

// CreateClient persists a new OAuth2 client.
// Intended for test seeding; not part of the fosite.ClientManager interface.
// Not yet implemented.
func (s *Store) CreateClient(_ context.Context, _ fosite.Client) error {
	panic("storage.Store.CreateClient: not implemented (DLD-665)")
}

// ---------------------------------------------------------------------------
// oauth2.AuthorizeCodeStorage — stubs
// ---------------------------------------------------------------------------

// CreateAuthorizeCodeSession persists an authorisation code together with its
// associated fosite.Requester. Not yet implemented.
func (s *Store) CreateAuthorizeCodeSession(_ context.Context, _ string, _ fosite.Requester) error {
	panic("storage.Store.CreateAuthorizeCodeSession: not implemented (DLD-665)")
}

// GetAuthorizeCodeSession retrieves the Requester for the given authorisation
// code. Returns fosite.ErrInvalidatedAuthorizeCode if the code has been
// invalidated. Not yet implemented.
func (s *Store) GetAuthorizeCodeSession(_ context.Context, _ string, _ fosite.Session) (fosite.Requester, error) {
	panic("storage.Store.GetAuthorizeCodeSession: not implemented (DLD-665)")
}

// InvalidateAuthorizeCodeSession marks an authorisation code as invalidated so
// that subsequent GetAuthorizeCodeSession calls return
// fosite.ErrInvalidatedAuthorizeCode. Not yet implemented.
func (s *Store) InvalidateAuthorizeCodeSession(_ context.Context, _ string) error {
	panic("storage.Store.InvalidateAuthorizeCodeSession: not implemented (DLD-665)")
}

// ---------------------------------------------------------------------------
// oauth2.AccessTokenStorage — stubs
// ---------------------------------------------------------------------------

// CreateAccessTokenSession persists an access-token signature together with
// its associated fosite.Requester. Not yet implemented.
func (s *Store) CreateAccessTokenSession(_ context.Context, _ string, _ fosite.Requester) error {
	panic("storage.Store.CreateAccessTokenSession: not implemented (DLD-665)")
}

// GetAccessTokenSession retrieves the Requester for the given access-token
// signature. Not yet implemented.
func (s *Store) GetAccessTokenSession(_ context.Context, _ string, _ fosite.Session) (fosite.Requester, error) {
	panic("storage.Store.GetAccessTokenSession: not implemented (DLD-665)")
}

// DeleteAccessTokenSession removes the access-token record identified by the
// given signature. Not yet implemented.
func (s *Store) DeleteAccessTokenSession(_ context.Context, _ string) error {
	panic("storage.Store.DeleteAccessTokenSession: not implemented (DLD-665)")
}

// ---------------------------------------------------------------------------
// oauth2.RefreshTokenStorage — stubs
// ---------------------------------------------------------------------------

// CreateRefreshTokenSession persists a refresh-token signature together with
// its associated fosite.Requester. Not yet implemented.
func (s *Store) CreateRefreshTokenSession(_ context.Context, _ string, _ fosite.Requester) error {
	panic("storage.Store.CreateRefreshTokenSession: not implemented (DLD-665)")
}

// GetRefreshTokenSession retrieves the Requester for the given refresh-token
// signature. Not yet implemented.
func (s *Store) GetRefreshTokenSession(_ context.Context, _ string, _ fosite.Session) (fosite.Requester, error) {
	panic("storage.Store.GetRefreshTokenSession: not implemented (DLD-665)")
}

// DeleteRefreshTokenSession removes the refresh-token record identified by the
// given signature. Not yet implemented.
func (s *Store) DeleteRefreshTokenSession(_ context.Context, _ string) error {
	panic("storage.Store.DeleteRefreshTokenSession: not implemented (DLD-665)")
}

// ---------------------------------------------------------------------------
// openid.OpenIDConnectRequestStorage — stubs
// ---------------------------------------------------------------------------

// CreateOpenIDConnectSession persists an OpenID Connect session keyed by the
// authorisation code. Not yet implemented.
func (s *Store) CreateOpenIDConnectSession(_ context.Context, _ string, _ fosite.Requester) error {
	panic("storage.Store.CreateOpenIDConnectSession: not implemented (DLD-665)")
}

// GetOpenIDConnectSession retrieves an OpenID Connect session for the given
// authorisation code. Returns fosite.ErrNotFound when the session does not
// exist. Not yet implemented.
func (s *Store) GetOpenIDConnectSession(_ context.Context, _ string, _ fosite.Requester) (fosite.Requester, error) {
	panic("storage.Store.GetOpenIDConnectSession: not implemented (DLD-665)")
}

// DeleteOpenIDConnectSession removes the OpenID Connect session identified by
// the given authorisation code. Not yet implemented.
func (s *Store) DeleteOpenIDConnectSession(_ context.Context, _ string) error {
	panic("storage.Store.DeleteOpenIDConnectSession: not implemented (DLD-665)")
}
