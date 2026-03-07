// Package storage implements the fosite storage interfaces backed by SQLite.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/pkce"

	"github.com/dlddu/my-auth/internal/session"
)

// ErrClientNotFound is returned when a client operation targets an ID
// that does not exist in storage.
var ErrClientNotFound = errors.New("client not found")

// ErrSessionNotFound is returned when a session operation targets an ID
// that does not exist in storage.
var ErrSessionNotFound = errors.New("session not found")

// ErrTokenNotFound is returned when a token operation targets a signature
// that does not exist in storage.
var ErrTokenNotFound = errors.New("token not found")

// SessionInfo holds summary information about an OpenID Connect session.
type SessionInfo struct {
	ID        string `json:"id"`
	ClientID  string `json:"client_id"`
	Subject   string `json:"subject"`
	Scopes    string `json:"scopes"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

// TokenInfo holds summary information about an access token.
type TokenInfo struct {
	Signature string `json:"signature"`
	RequestID string `json:"request_id"`
	ClientID  string `json:"client_id"`
	Subject   string `json:"subject"`
	Scopes    string `json:"scopes"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

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
var _ pkce.PKCERequestStorage = (*Store)(nil)
var _ oauth2.TokenRevocationStorage = (*Store)(nil)

// ---------------------------------------------------------------------------
// Internal: serialise / deserialise fosite.Requester
// ---------------------------------------------------------------------------

// requestJSON is an intermediate representation used to marshal/unmarshal a
// fosite.Requester into a single JSON blob stored in the request_data column.
type requestJSON struct {
	ClientID          string              `json:"client_id"`
	RequestedAt       time.Time           `json:"requested_at"`
	GrantedScope      fosite.Arguments    `json:"granted_scope"`
	RequestedScope    fosite.Arguments    `json:"requested_scope"`
	GrantedAudience   fosite.Arguments    `json:"granted_audience"`
	RequestedAudience fosite.Arguments    `json:"requested_audience"`
	Form              map[string][]string `json:"form"`
	Session           json.RawMessage     `json:"session"`
	ID                string              `json:"id"`
}

func marshalRequester(req fosite.Requester) (string, error) {
	sessBytes, err := json.Marshal(req.GetSession())
	if err != nil {
		return "", fmt.Errorf("marshal session: %w", err)
	}

	rj := requestJSON{
		ClientID:          req.GetClient().GetID(),
		RequestedAt:       req.GetRequestedAt(),
		GrantedScope:      req.GetGrantedScopes(),
		RequestedScope:    req.GetRequestedScopes(),
		GrantedAudience:   req.GetGrantedAudience(),
		RequestedAudience: req.GetRequestedAudience(),
		Session:           sessBytes,
		ID:                req.GetID(),
	}
	if ar, ok := req.(*fosite.AuthorizeRequest); ok {
		rj.Form = map[string][]string(ar.Form)
	} else if ar, ok := req.(*fosite.Request); ok {
		rj.Form = map[string][]string(ar.Form)
	}

	data, err := json.Marshal(rj)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}
	return string(data), nil
}

func unmarshalRequester(data string, session fosite.Session, client fosite.Client) (*fosite.Request, error) {
	var rj requestJSON
	if err := json.Unmarshal([]byte(data), &rj); err != nil {
		return nil, fmt.Errorf("unmarshal request: %w", err)
	}

	if session != nil {
		if err := json.Unmarshal(rj.Session, session); err != nil {
			return nil, fmt.Errorf("unmarshal session: %w", err)
		}
	}

	form := url.Values(rj.Form)

	req := &fosite.Request{
		ID:                rj.ID,
		Client:            client,
		RequestedAt:       rj.RequestedAt,
		GrantedScope:      rj.GrantedScope,
		RequestedScope:    rj.RequestedScope,
		GrantedAudience:   rj.GrantedAudience,
		RequestedAudience: rj.RequestedAudience,
		Session:           session,
		Form:              form,
	}
	return req, nil
}

// sessionExpiresAt extracts the expiry time from the session if possible,
// otherwise returns a fallback based on the requested time plus duration.
func sessionExpiresAt(req fosite.Requester, fallbackDuration time.Duration) string {
	if sess := req.GetSession(); sess != nil {
		if exp := sess.GetExpiresAt(fosite.AccessToken); !exp.IsZero() {
			return exp.UTC().Format(time.RFC3339)
		}
		if exp := sess.GetExpiresAt(fosite.AuthorizeCode); !exp.IsZero() {
			return exp.UTC().Format(time.RFC3339)
		}
	}
	return req.GetRequestedAt().Add(fallbackDuration).UTC().Format(time.RFC3339)
}

// ---------------------------------------------------------------------------
// fosite.ClientManager
// ---------------------------------------------------------------------------

// GetClient retrieves a registered client by its ID.
// Returns fosite.ErrNotFound when the client is not registered.
func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, secret, redirect_uris, grant_types, response_types, scopes, token_endpoint_auth_method, is_public FROM clients WHERE id = ?`, id)

	var (
		clientID                string
		secret                  string
		redirectURIs            string
		grantTypes              string
		responseTypes           string
		scopes                  string
		tokenEndpointAuthMethod string
		isPublic                bool
	)
	if err := row.Scan(&clientID, &secret, &redirectURIs, &grantTypes, &responseTypes, &scopes, &tokenEndpointAuthMethod, &isPublic); err != nil {
		if err == sql.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("get client %q: %w", id, err)
	}

	var redirectURIsList []string
	if err := json.Unmarshal([]byte(redirectURIs), &redirectURIsList); err != nil {
		return nil, fmt.Errorf("get client %q: unmarshal redirect_uris: %w", id, err)
	}

	var grantTypesList []string
	if err := json.Unmarshal([]byte(grantTypes), &grantTypesList); err != nil {
		return nil, fmt.Errorf("get client %q: unmarshal grant_types: %w", id, err)
	}

	var responseTypesList []string
	if err := json.Unmarshal([]byte(responseTypes), &responseTypesList); err != nil {
		return nil, fmt.Errorf("get client %q: unmarshal response_types: %w", id, err)
	}

	return &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            clientID,
			Secret:        []byte(secret),
			Public:        isPublic,
			RedirectURIs:  redirectURIsList,
			GrantTypes:    grantTypesList,
			ResponseTypes: responseTypesList,
			Scopes:        strings.Split(scopes, " "),
			// Audience is set to the client ID so that fosite's audience
			// strategy accepts granted audiences during token refresh.
			// RFC 8707: the client's own ID is always a valid audience.
			Audience:      []string{clientID},
		},
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
	}, nil
}

// ListClients retrieves all registered OAuth2 clients from storage.
// Returns a non-nil empty slice when no clients are registered.
func (s *Store) ListClients(ctx context.Context) ([]fosite.Client, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, secret, redirect_uris, grant_types, response_types, scopes, token_endpoint_auth_method, is_public FROM clients ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	defer rows.Close()

	clients := make([]fosite.Client, 0)
	for rows.Next() {
		var (
			clientID                string
			secret                  string
			redirectURIs            string
			grantTypes              string
			responseTypes           string
			scopes                  string
			tokenEndpointAuthMethod string
			isPublic                bool
		)
		if err := rows.Scan(&clientID, &secret, &redirectURIs, &grantTypes, &responseTypes, &scopes, &tokenEndpointAuthMethod, &isPublic); err != nil {
			return nil, fmt.Errorf("list clients: scan: %w", err)
		}

		var redirectURIsList []string
		if err := json.Unmarshal([]byte(redirectURIs), &redirectURIsList); err != nil {
			return nil, fmt.Errorf("list clients: unmarshal redirect_uris for %q: %w", clientID, err)
		}
		var grantTypesList []string
		if err := json.Unmarshal([]byte(grantTypes), &grantTypesList); err != nil {
			return nil, fmt.Errorf("list clients: unmarshal grant_types for %q: %w", clientID, err)
		}
		var responseTypesList []string
		if err := json.Unmarshal([]byte(responseTypes), &responseTypesList); err != nil {
			return nil, fmt.Errorf("list clients: unmarshal response_types for %q: %w", clientID, err)
		}

		c := &fosite.DefaultOpenIDConnectClient{
			DefaultClient: &fosite.DefaultClient{
				ID:            clientID,
				Secret:        []byte(secret),
				Public:        isPublic,
				RedirectURIs:  redirectURIsList,
				GrantTypes:    grantTypesList,
				ResponseTypes: responseTypesList,
				Scopes:        strings.Split(scopes, " "),
				Audience:      []string{clientID},
			},
			TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		}
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list clients: rows: %w", err)
	}
	return clients, nil
}

// UpdateClient updates an existing OAuth2 client's fields in storage.
// Returns an error if no client with the given ID exists.
func (s *Store) UpdateClient(ctx context.Context, client fosite.Client) error {
	redirectURIs, err := json.Marshal(client.GetRedirectURIs())
	if err != nil {
		return fmt.Errorf("update client: marshal redirect_uris: %w", err)
	}
	grantTypes, err := json.Marshal(client.GetGrantTypes())
	if err != nil {
		return fmt.Errorf("update client: marshal grant_types: %w", err)
	}
	responseTypes, err := json.Marshal(client.GetResponseTypes())
	if err != nil {
		return fmt.Errorf("update client: marshal response_types: %w", err)
	}
	scopes := strings.Join(client.GetScopes(), " ")

	var secret string
	if dc, ok := client.(*fosite.DefaultOpenIDConnectClient); ok {
		secret = string(dc.Secret)
	} else if dc, ok := client.(*fosite.DefaultClient); ok {
		secret = string(dc.Secret)
	}

	result, err := s.db.ExecContext(ctx,
		`UPDATE clients SET secret = ?, redirect_uris = ?, grant_types = ?, response_types = ?, scopes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		secret, string(redirectURIs), string(grantTypes), string(responseTypes), scopes, client.GetID())
	if err != nil {
		return fmt.Errorf("update client %q: %w", client.GetID(), err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update client %q: rows affected: %w", client.GetID(), err)
	}
	if n == 0 {
		return ErrClientNotFound
	}
	return nil
}

// DeleteClient removes an OAuth2 client from storage by ID.
// Returns an error if no client with the given ID exists.
func (s *Store) DeleteClient(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM clients WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete client %q: %w", id, err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete client %q: rows affected: %w", id, err)
	}
	if n == 0 {
		return ErrClientNotFound
	}
	return nil
}

// CreateClient persists a new OAuth2 client.
// Intended for test seeding; not part of the fosite.ClientManager interface.
func (s *Store) CreateClient(ctx context.Context, client fosite.Client) error {
	redirectURIs, err := json.Marshal(client.GetRedirectURIs())
	if err != nil {
		return fmt.Errorf("create client: marshal redirect_uris: %w", err)
	}
	grantTypes, err := json.Marshal(client.GetGrantTypes())
	if err != nil {
		return fmt.Errorf("create client: marshal grant_types: %w", err)
	}
	responseTypes, err := json.Marshal(client.GetResponseTypes())
	if err != nil {
		return fmt.Errorf("create client: marshal response_types: %w", err)
	}
	scopes := strings.Join(client.GetScopes(), " ")

	var secret string
	var tokenEndpointAuthMethod string
	var isPublic bool
	if dc, ok := client.(*fosite.DefaultOpenIDConnectClient); ok {
		secret = string(dc.Secret)
		tokenEndpointAuthMethod = dc.TokenEndpointAuthMethod
		isPublic = dc.Public
	} else if dc, ok := client.(*fosite.DefaultClient); ok {
		secret = string(dc.Secret)
		isPublic = dc.Public
	}
	if tokenEndpointAuthMethod == "" {
		tokenEndpointAuthMethod = "client_secret_basic"
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO clients (id, secret, redirect_uris, grant_types, response_types, scopes, token_endpoint_auth_method, is_public) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		client.GetID(), secret, string(redirectURIs), string(grantTypes), string(responseTypes), scopes, tokenEndpointAuthMethod, isPublic)
	return err
}

// ---------------------------------------------------------------------------
// oauth2.AuthorizeCodeStorage
// ---------------------------------------------------------------------------

// CreateAuthorizeCodeSession persists an authorisation code together with its
// associated fosite.Requester.
func (s *Store) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	requestData, err := marshalRequester(req)
	if err != nil {
		return err
	}

	expiresAt := sessionExpiresAt(req, 10*time.Minute)

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO authorization_codes (code, client_id, subject, redirect_uri, scopes, expires_at, request_data)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		code,
		req.GetClient().GetID(),
		"",
		"",
		strings.Join(req.GetGrantedScopes(), " "),
		expiresAt,
		requestData,
	)
	return err
}

// GetAuthorizeCodeSession retrieves the Requester for the given authorisation
// code. Returns fosite.ErrInvalidatedAuthorizeCode if the code has been
// invalidated.
func (s *Store) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT client_id, used, request_data FROM authorization_codes WHERE code = ?`, code)

	var (
		clientID    string
		used        int
		requestData string
	)
	if err := row.Scan(&clientID, &used, &requestData); err != nil {
		if err == sql.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	req, err := unmarshalRequester(requestData, session, client)
	if err != nil {
		return nil, err
	}

	if used != 0 {
		return req, fosite.ErrInvalidatedAuthorizeCode
	}

	return req, nil
}

// InvalidateAuthorizeCodeSession marks an authorisation code as invalidated so
// that subsequent GetAuthorizeCodeSession calls return
// fosite.ErrInvalidatedAuthorizeCode.
func (s *Store) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE authorization_codes SET used = 1 WHERE code = ?`, code)
	return err
}

// ---------------------------------------------------------------------------
// oauth2.AccessTokenStorage
// ---------------------------------------------------------------------------

// CreateAccessTokenSession persists an access-token signature together with
// its associated fosite.Requester.
func (s *Store) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	requestData, err := marshalRequester(req)
	if err != nil {
		return err
	}

	expiresAt := sessionExpiresAt(req, 1*time.Hour)

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO tokens (signature, request_id, client_id, subject, scopes, expires_at, request_data)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		signature,
		req.GetID(),
		req.GetClient().GetID(),
		"",
		strings.Join(req.GetGrantedScopes(), " "),
		expiresAt,
		requestData,
	)
	return err
}

// GetAccessTokenSession retrieves the Requester for the given access-token
// signature.
func (s *Store) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT client_id, request_data FROM tokens WHERE signature = ?`, signature)

	var (
		clientID    string
		requestData string
	)
	if err := row.Scan(&clientID, &requestData); err != nil {
		if err == sql.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	return unmarshalRequester(requestData, session, client)
}

// DeleteAccessTokenSession removes the access-token record identified by the
// given signature.
func (s *Store) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM tokens WHERE signature = ?`, signature)
	return err
}

// ---------------------------------------------------------------------------
// oauth2.RefreshTokenStorage
// ---------------------------------------------------------------------------

// CreateRefreshTokenSession persists a refresh-token signature together with
// its associated fosite.Requester.
func (s *Store) CreateRefreshTokenSession(ctx context.Context, signature string, accessTokenSignature string, req fosite.Requester) error {
	requestData, err := marshalRequester(req)
	if err != nil {
		return err
	}

	expiresAt := sessionExpiresAt(req, 24*time.Hour)

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (signature, client_id, subject, scopes, expires_at, request_data, access_token_signature, request_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		signature,
		req.GetClient().GetID(),
		"",
		strings.Join(req.GetGrantedScopes(), " "),
		expiresAt,
		requestData,
		accessTokenSignature,
		req.GetID(),
	)
	return err
}

// GetRefreshTokenSession retrieves the Requester for the given refresh-token
// signature.
func (s *Store) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT client_id, request_data FROM refresh_tokens WHERE signature = ?`, signature)

	var (
		clientID    string
		requestData string
	)
	if err := row.Scan(&clientID, &requestData); err != nil {
		if err == sql.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	return unmarshalRequester(requestData, session, client)
}

// DeleteRefreshTokenSession removes the refresh-token record identified by the
// given signature.
func (s *Store) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE signature = ?`, signature)
	return err
}

// RotateRefreshToken rotates the refresh token identified by the given
// requestID and refreshTokenSignature.
//
// The requestID parameter is accepted to satisfy the fosite
// oauth2.RefreshTokenStorage interface but is not used in this
// implementation; the old token is identified solely by its signature.
func (s *Store) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE signature = ?`, refreshTokenSignature)
	return err
}

// ---------------------------------------------------------------------------
// openid.OpenIDConnectRequestStorage
// ---------------------------------------------------------------------------

// CreateOpenIDConnectSession persists an OpenID Connect session keyed by the
// authorisation code.
func (s *Store) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) error {
	requestData, err := marshalRequester(req)
	if err != nil {
		return err
	}

	expiresAt := sessionExpiresAt(req, 1*time.Hour)

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, client_id, subject, scopes, expires_at, request_data)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		authorizeCode,
		req.GetClient().GetID(),
		"",
		strings.Join(req.GetGrantedScopes(), " "),
		expiresAt,
		requestData,
	)
	return err
}

// GetOpenIDConnectSession retrieves an OpenID Connect session for the given
// authorisation code. Returns fosite.ErrNotFound when the session does not
// exist.
func (s *Store) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, _ fosite.Requester) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT client_id, request_data FROM sessions WHERE id = ?`, authorizeCode)

	var (
		clientID    string
		requestData string
	)
	if err := row.Scan(&clientID, &requestData); err != nil {
		if err == sql.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	sess := &session.Session{
		DefaultSession: &openid.DefaultSession{},
	}
	return unmarshalRequester(requestData, sess, client)
}

// DeleteOpenIDConnectSession removes the OpenID Connect session identified by
// the given authorisation code.
func (s *Store) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE id = ?`, authorizeCode)
	return err
}

// ---------------------------------------------------------------------------
// oauth2.TokenRevocationStorage
// ---------------------------------------------------------------------------

// RevokeRefreshToken deletes all refresh tokens for the given request ID.
// This implements the RFC 7009 token revocation requirement.
func (s *Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE request_id = ?`, requestID)
	return err
}

// RevokeAccessToken revokes all access tokens for the given request ID.
//
// It implements the JWT jti blacklist pattern: the token's jti (request ID)
// is recorded in the revoked_tokens table. The token record in the tokens
// table is intentionally preserved so that introspection can still return
// metadata (client_id, scope, sub, exp) alongside active: false.
func (s *Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO revoked_tokens (jti) VALUES (?)`, requestID)
	return err
}

// IsJTIRevoked checks whether the given jti exists in the revoked_tokens
// blacklist table.
func (s *Store) IsJTIRevoked(ctx context.Context, jti string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM revoked_tokens WHERE jti = ?`, jti).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// fosite.ClientManager — JWT assertion replay prevention
// ---------------------------------------------------------------------------

// ClientAssertionJWTValid returns nil because this server does not use
// private_key_jwt client authentication; replay prevention is therefore
// not required. Fosite calls this method as part of the ClientManager
// interface, so a no-op implementation is sufficient.
func (s *Store) ClientAssertionJWTValid(_ context.Context, _ string) error {
	return nil
}

// SetClientAssertionJWT is a no-op because this server does not use
// private_key_jwt client authentication.
func (s *Store) SetClientAssertionJWT(_ context.Context, _ string, _ time.Time) error {
	return nil
}

// ---------------------------------------------------------------------------
// pkce.PKCERequestStorage
// ---------------------------------------------------------------------------

// CreatePKCERequestSession persists a PKCE session keyed by the given
// signature (the authorisation code).
func (s *Store) CreatePKCERequestSession(ctx context.Context, signature string, req fosite.Requester) error {
	requestData, err := marshalRequester(req)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO pkce_codes (signature, request_data) VALUES (?, ?)`,
		signature,
		requestData,
	)
	return err
}

// GetPKCERequestSession retrieves the Requester for the given PKCE signature.
// Returns fosite.ErrNotFound when the session does not exist.
func (s *Store) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT request_data FROM pkce_codes WHERE signature = ?`, signature)

	var requestData string
	if err := row.Scan(&requestData); err != nil {
		if err == sql.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}

	// Extract client_id from the stored JSON so we can reconstruct the client.
	var rj struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal([]byte(requestData), &rj); err != nil {
		return nil, fmt.Errorf("get pkce session %q: unmarshal client_id: %w", signature, err)
	}

	client, err := s.GetClient(ctx, rj.ClientID)
	if err != nil {
		return nil, err
	}

	return unmarshalRequester(requestData, session, client)
}

// DeletePKCERequestSession removes the PKCE session identified by the given
// signature.
func (s *Store) DeletePKCERequestSession(ctx context.Context, signature string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM pkce_codes WHERE signature = ?`, signature)
	return err
}

// ---------------------------------------------------------------------------
// Admin: Session management
// ---------------------------------------------------------------------------

// ListSessions returns all completed authorization sessions from the
// authorization_codes table (used = 1). The authorization_codes table
// preserves rows after the auth code has been exchanged for a token,
// unlike the sessions table which fosite empties during token issuance.
// Returns a non-nil empty slice when no sessions exist.
func (s *Store) ListSessions(ctx context.Context) ([]SessionInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT code, client_id, subject, scopes, expires_at, created_at
		 FROM authorization_codes WHERE used = 1 ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	items := make([]SessionInfo, 0)
	for rows.Next() {
		var item SessionInfo
		if err := rows.Scan(&item.ID, &item.ClientID, &item.Subject, &item.Scopes, &item.ExpiresAt, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("list sessions: scan: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list sessions: rows: %w", err)
	}
	return items, nil
}

// DeleteSession removes a completed authorization session by its code (id)
// from the authorization_codes table (used = 1) and invalidates any
// associated access tokens by recording their request_ids in revoked_tokens.
// Returns ErrSessionNotFound if no used authorization code with that id exists.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	// Fetch the request_data from authorization_codes to extract the request ID.
	row := s.db.QueryRowContext(ctx,
		`SELECT request_data FROM authorization_codes WHERE code = ? AND used = 1`, id)

	var requestData string
	if err := row.Scan(&requestData); err != nil {
		if err == sql.ErrNoRows {
			return ErrSessionNotFound
		}
		return fmt.Errorf("delete session %q: fetch request_data: %w", id, err)
	}

	// Extract the request ID ("id" field) from the stored JSON.
	// This links the auth code session to the access token stored in tokens table.
	var rj struct {
		ID string `json:"id"`
	}
	if jsonErr := json.Unmarshal([]byte(requestData), &rj); jsonErr == nil && rj.ID != "" {
		// Revoke any access tokens associated with this authorization request.
		_, _ = s.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO revoked_tokens (jti)
			 SELECT request_id FROM tokens WHERE request_id = ?`, rj.ID)
	}

	// Delete the authorization code session.
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM authorization_codes WHERE code = ? AND used = 1`, id)
	if err != nil {
		return fmt.Errorf("delete session %q: %w", id, err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete session %q: rows affected: %w", id, err)
	}
	if n == 0 {
		return ErrSessionNotFound
	}
	return nil
}

// DeleteAllSessions removes all completed authorization sessions from
// authorization_codes (used = 1) and revokes their associated access tokens.
func (s *Store) DeleteAllSessions(ctx context.Context) error {
	// Step 1: Collect all request IDs from used authorization codes.
	rows, err := s.db.QueryContext(ctx,
		`SELECT request_data FROM authorization_codes WHERE used = 1`)
	if err != nil {
		return fmt.Errorf("delete all sessions: query: %w", err)
	}

	var requestIDs []string
	for rows.Next() {
		var requestData string
		if err := rows.Scan(&requestData); err != nil {
			continue
		}
		var rj struct {
			ID string `json:"id"`
		}
		if json.Unmarshal([]byte(requestData), &rj) == nil && rj.ID != "" {
			requestIDs = append(requestIDs, rj.ID)
		}
	}
	rows.Close()

	// Step 2: Revoke associated tokens (after rows are closed).
	for _, reqID := range requestIDs {
		_, _ = s.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO revoked_tokens (jti)
			 SELECT request_id FROM tokens WHERE request_id = ?`, reqID)
	}

	// Step 3: Delete all used authorization code sessions.
	_, err = s.db.ExecContext(ctx, `DELETE FROM authorization_codes WHERE used = 1`)
	if err != nil {
		return fmt.Errorf("delete all sessions: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Admin: Token management
// ---------------------------------------------------------------------------

// ListTokens returns all non-revoked access tokens from the tokens table.
// Tokens whose request_id appears in the revoked_tokens blacklist are excluded
// so that admin revocation is reflected immediately without deleting the row.
// Returns a non-nil empty slice when no active tokens exist.
func (s *Store) ListTokens(ctx context.Context) ([]TokenInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT t.signature, t.request_id, t.client_id, t.subject, t.scopes, t.expires_at, t.created_at
		 FROM tokens t
		 WHERE NOT EXISTS (SELECT 1 FROM revoked_tokens r WHERE r.jti = t.request_id)
		 ORDER BY t.created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}
	defer rows.Close()

	items := make([]TokenInfo, 0)
	for rows.Next() {
		var item TokenInfo
		if err := rows.Scan(&item.Signature, &item.RequestID, &item.ClientID, &item.Subject, &item.Scopes, &item.ExpiresAt, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("list tokens: scan: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list tokens: rows: %w", err)
	}
	return items, nil
}

// DeleteToken revokes an access token by recording its request_id in the
// revoked_tokens blacklist. The token row is intentionally kept in the tokens
// table so that fosite's introspection can still load it and then observe the
// jti blacklist, returning active: false with metadata intact.
// Returns ErrTokenNotFound if no non-revoked token with that signature exists.
func (s *Store) DeleteToken(ctx context.Context, signature string) error {
	// Verify the token exists and is not already revoked, then fetch request_id.
	row := s.db.QueryRowContext(ctx,
		`SELECT t.request_id FROM tokens t
		 WHERE t.signature = ?
		   AND NOT EXISTS (SELECT 1 FROM revoked_tokens r WHERE r.jti = t.request_id)`,
		signature)

	var requestID string
	if err := row.Scan(&requestID); err != nil {
		if err == sql.ErrNoRows {
			return ErrTokenNotFound
		}
		return fmt.Errorf("delete token %q: fetch request_id: %w", signature, err)
	}

	// Record the jti in revoked_tokens so introspection returns active: false.
	// The token row itself is NOT deleted so that fosite can still load metadata.
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO revoked_tokens (jti) VALUES (?)`, requestID); err != nil {
		return fmt.Errorf("delete token %q: revoke jti: %w", signature, err)
	}

	return nil
}

// DeleteAllTokens revokes all non-revoked access tokens by recording their
// request_ids in the revoked_tokens blacklist. Token rows are intentionally
// kept in the tokens table so that fosite's introspection can still load them
// and observe the jti blacklist, returning active: false.
func (s *Store) DeleteAllTokens(ctx context.Context) error {
	// Revoke all token JTIs that are not already revoked.
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO revoked_tokens (jti)
		 SELECT t.request_id FROM tokens t
		 WHERE NOT EXISTS (SELECT 1 FROM revoked_tokens r WHERE r.jti = t.request_id)`); err != nil {
		return fmt.Errorf("delete all tokens: revoke jtis: %w", err)
	}

	return nil
}
