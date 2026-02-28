// Package storage provides fosite-compatible SQLite storage implementations
// for the my-auth OAuth2/OIDC authorization server.
package storage

import (
	"context"
	"time"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ory/fosite"
)

// ClientStore implements fosite.ClientManager backed by a SQLite database.
type ClientStore struct {
	db *sql.DB
}

// NewClientStore returns a new ClientStore using the given database connection.
func NewClientStore(db *sql.DB) *ClientStore {
	return &ClientStore{db: db}
}

// Client is a fosite.Client implementation loaded from the clients table.
type Client struct {
	id            string
	hashedSecret  []byte
	redirectURIs  []string
	grantTypes    fosite.Arguments
	responseTypes fosite.Arguments
	scopes        fosite.Arguments
	public        bool
}

// GetID returns the client identifier.
func (c *Client) GetID() string { return c.id }

// GetHashedSecret returns the bcrypt-hashed client secret.
func (c *Client) GetHashedSecret() []byte { return c.hashedSecret }

// GetRedirectURIs returns the allowed redirect URIs.
func (c *Client) GetRedirectURIs() []string { return c.redirectURIs }

// GetGrantTypes returns the allowed OAuth2 grant types.
func (c *Client) GetGrantTypes() fosite.Arguments { return c.grantTypes }

// GetResponseTypes returns the allowed OAuth2 response types.
func (c *Client) GetResponseTypes() fosite.Arguments { return c.responseTypes }

// GetScopes returns the allowed OAuth2 scopes.
func (c *Client) GetScopes() fosite.Arguments { return c.scopes }

// IsPublic returns true if the client is a public client (no secret required).
func (c *Client) IsPublic() bool { return c.public }

// GetAudience returns the allowed audience for this client.
// For simplicity we return the client's own ID as the audience.
func (c *Client) GetAudience() fosite.Arguments { return fosite.Arguments{c.id} }

// GetClient retrieves a client by its ID from the database.
// It returns fosite.ErrNotFound when the client does not exist.
func (cs *ClientStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	row := cs.db.QueryRowContext(ctx,
		`SELECT id, secret, redirect_uris, grant_types, response_types, scopes
		 FROM clients WHERE id = ?`, id,
	)

	var (
		clientID      string
		secret        string
		redirectURIs  string
		grantTypes    string
		responseTypes string
		scopes        string
	)

	if err := row.Scan(&clientID, &secret, &redirectURIs, &grantTypes, &responseTypes, &scopes); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("storage: GetClient: %w", fosite.ErrNotFound)
		}
		return nil, fmt.Errorf("storage: GetClient: scan: %w", err)
	}

	// redirect_uris is stored as a JSON array.
	var uris []string
	if err := json.Unmarshal([]byte(redirectURIs), &uris); err != nil {
		// Fall back to treating it as a single URI.
		uris = []string{redirectURIs}
	}

	// grant_types and response_types are stored as JSON arrays.
	var grants []string
	if err := json.Unmarshal([]byte(grantTypes), &grants); err != nil {
		grants = strings.Fields(grantTypes)
	}

	var responses []string
	if err := json.Unmarshal([]byte(responseTypes), &responses); err != nil {
		responses = strings.Fields(responseTypes)
	}

	// scopes is stored as a space-separated string.
	scopeList := strings.Fields(scopes)

	return &Client{
		id:            clientID,
		hashedSecret:  []byte(secret),
		redirectURIs:  uris,
		grantTypes:    fosite.Arguments(grants),
		responseTypes: fosite.Arguments(responses),
		scopes:        fosite.Arguments(scopeList),
		public:        false,
	}, nil
}

// ClientAssertionJWTValid returns nil if the JTI has not been used before,
// or an error if it is already known (replay protection).
// This implementation is a no-op stub — JWT assertion replay protection
// requires persistent storage of JTIs, which is beyond the current scope.
func (cs *ClientStore) ClientAssertionJWTValid(_ context.Context, _ string) error {
	return nil
}

// SetClientAssertionJWT marks a JTI as known to prevent token replay.
// This implementation is a no-op stub.
func (cs *ClientStore) SetClientAssertionJWT(_ context.Context, _ string, _ time.Time) error {
	return nil
}
