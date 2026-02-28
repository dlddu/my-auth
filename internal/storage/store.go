package storage

import (
	"database/sql"
)

// Store combines all storage interfaces into a single type for convenience
// when passing to fosite's compose.Compose.
type Store struct {
	*ClientStore
	*AuthorizeCodeStore
	*AccessTokenStore
	*RefreshTokenStore
	*OpenIDConnectSessionStore
}

// NewStore creates a Store that wraps all individual store implementations.
// All stores share the same *sql.DB connection.
func NewStore(db *sql.DB) *Store {
	return &Store{
		ClientStore:               NewClientStore(db),
		AuthorizeCodeStore:        NewAuthorizeCodeStore(db),
		AccessTokenStore:          NewAccessTokenStore(db),
		RefreshTokenStore:         NewRefreshTokenStore(db),
		OpenIDConnectSessionStore: NewOpenIDConnectSessionStore(db),
	}
}
