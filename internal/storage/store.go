// Package storage provides a SQLite-backed implementation of the fosite
// storage interfaces required for the OAuth2 / OIDC authorization code flow.
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
	fositeOAuth2 "github.com/ory/fosite/handler/oauth2"
	fositeOIDC "github.com/ory/fosite/handler/openid"
)

// Compile-time interface satisfaction checks.
var (
	_ fosite.ClientManager                   = (*Store)(nil)
	_ fositeOAuth2.AuthorizeCodeStorage      = (*Store)(nil)
	_ fositeOAuth2.AccessTokenStorage        = (*Store)(nil)
	_ fositeOAuth2.RefreshTokenStorage       = (*Store)(nil)
	_ fositeOAuth2.TokenRevocationStorage    = (*Store)(nil)
	_ fositeOIDC.OpenIDConnectRequestStorage = (*Store)(nil)
)

// Store is a SQLite-backed fosite storage implementation.
type Store struct {
	db *sql.DB
}

// New creates a new Store backed by the provided *sql.DB.
// The caller is responsible for running all migrations before using the store.
func New(db *sql.DB) *Store {
	return &Store{db: db}
}

// ---------------------------------------------------------------------------
// serialisedRequest is the JSON structure persisted in request_data columns.
// ---------------------------------------------------------------------------

type serialisedRequest struct {
	ID             string              `json:"id"`
	RequestedAt    time.Time           `json:"requested_at"`
	ClientID       string              `json:"client_id"`
	RequestedScope []string            `json:"requested_scope"`
	GrantedScope   []string            `json:"granted_scope"`
	Subject        string              `json:"subject"`
	Session        *serialisedSession  `json:"session"`
	Form           map[string][]string `json:"form"`
}

type serialisedSession struct {
	Subject string                  `json:"subject"`
	Claims  *fositeOIDC.IDTokenClaims `json:"claims,omitempty"`
	Headers *fositeOIDC.Headers     `json:"headers,omitempty"`
}

// marshalRequest serialises a fosite.Requester to JSON bytes.
func marshalRequest(req fosite.Requester) ([]byte, error) {
	var sess *serialisedSession
	if req.GetSession() != nil {
		if oidcSess, ok := req.GetSession().(*fositeOIDC.DefaultSession); ok {
			sess = &serialisedSession{
				Subject: oidcSess.Subject,
				Claims:  oidcSess.Claims,
				Headers: oidcSess.Headers,
			}
		} else {
			// Fallback: just store the subject from the session.
			sess = &serialisedSession{
				Subject: req.GetSession().GetSubject(),
			}
		}
	}

	form := make(map[string][]string)
	if f := req.GetRequestForm(); f != nil {
		for k, v := range f {
			form[k] = v
		}
	}

	sr := serialisedRequest{
		ID:             req.GetID(),
		RequestedAt:    req.GetRequestedAt(),
		ClientID:       req.GetClient().GetID(),
		RequestedScope: []string(req.GetRequestedScopes()),
		GrantedScope:   []string(req.GetGrantedScopes()),
		Subject:        req.GetSession().GetSubject(),
		Session:        sess,
		Form:           form,
	}

	return json.Marshal(sr)
}

// unmarshalRequest deserialises JSON bytes back into a fosite.Request using
// the provided session container (which may already have a type set by the
// caller).
func unmarshalRequest(data []byte, _ fosite.Session) (fosite.Requester, error) {
	var sr serialisedRequest
	if err := json.Unmarshal(data, &sr); err != nil {
		return nil, fmt.Errorf("storage: unmarshal request: %w", err)
	}

	oidcSess := &fositeOIDC.DefaultSession{
		Subject: sr.Subject,
		Claims:  &fositeOIDC.IDTokenClaims{},
		Headers: &fositeOIDC.Headers{},
	}

	if sr.Session != nil {
		oidcSess.Subject = sr.Session.Subject
		if sr.Session.Claims != nil {
			oidcSess.Claims = sr.Session.Claims
		}
		if sr.Session.Headers != nil {
			oidcSess.Headers = sr.Session.Headers
		}
	}

	form := make(url.Values)
	for k, v := range sr.Form {
		form[k] = v
	}

	req := &fosite.Request{
		ID:             sr.ID,
		RequestedAt:    sr.RequestedAt,
		Client:         &fosite.DefaultClient{ID: sr.ClientID},
		RequestedScope: fosite.Arguments(sr.RequestedScope),
		GrantedScope:   fosite.Arguments(sr.GrantedScope),
		Session:        oidcSess,
		Form:           form,
	}

	return req, nil
}

// ---------------------------------------------------------------------------
// fosite.ClientManager
// ---------------------------------------------------------------------------

// GetClient fetches a client from the clients table by its ID.
func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, secret, redirect_uris, grant_types, response_types, scopes
		   FROM clients WHERE id = ?`, id)

	var (
		clientID      string
		secret        string
		redirectURIs  string
		grantTypes    string
		responseTypes string
		scopes        string
	)

	if err := row.Scan(&clientID, &secret, &redirectURIs, &grantTypes, &responseTypes, &scopes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetClient %q: %w", id, err)
	}

	var uris []string
	if err := json.Unmarshal([]byte(redirectURIs), &uris); err != nil {
		return nil, fmt.Errorf("storage: GetClient %q: parse redirect_uris: %w", id, err)
	}

	var grants []string
	if err := json.Unmarshal([]byte(grantTypes), &grants); err != nil {
		return nil, fmt.Errorf("storage: GetClient %q: parse grant_types: %w", id, err)
	}

	var responses []string
	if err := json.Unmarshal([]byte(responseTypes), &responses); err != nil {
		return nil, fmt.Errorf("storage: GetClient %q: parse response_types: %w", id, err)
	}

	scopeSlice := strings.Fields(scopes)

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        []byte(secret),
		RedirectURIs:  uris,
		GrantTypes:    grants,
		ResponseTypes: responses,
		Scopes:        fosite.Arguments(scopeSlice),
		Public:        false,
	}

	return client, nil
}

// ClientAssertionJWTValid is a no-op for this server (no private_key_jwt support).
func (s *Store) ClientAssertionJWTValid(_ context.Context, _ string) error {
	return nil
}

// SetClientAssertionJWT is a no-op for this server.
func (s *Store) SetClientAssertionJWT(_ context.Context, _ string, _ time.Time) error {
	return nil
}

// ---------------------------------------------------------------------------
// fositeOAuth2.AuthorizeCodeStorage
// ---------------------------------------------------------------------------

// CreateAuthorizeCodeSession persists the authorisation code and its
// associated request to the authorization_codes table.
func (s *Store) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	data, err := marshalRequest(req)
	if err != nil {
		return fmt.Errorf("storage: CreateAuthorizeCodeSession: %w", err)
	}

	subject := req.GetSession().GetSubject()
	clientID := req.GetClient().GetID()
	scopes := strings.Join(req.GetGrantedScopes(), " ")
	redirectURI := req.GetRequestForm().Get("redirect_uri")
	expiresAt := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	requestID := req.GetID()

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO authorization_codes
		   (code, client_id, subject, redirect_uri, scopes, expires_at, used, request_id, request_data)
		 VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		code, clientID, subject, redirectURI, scopes, expiresAt, requestID, string(data),
	)
	if err != nil {
		return fmt.Errorf("storage: CreateAuthorizeCodeSession: insert: %w", err)
	}

	return nil
}

// GetAuthorizeCodeSession retrieves a previously stored authorisation code
// session. If the code has been invalidated (used=1) it returns the Requester
// AND fosite.ErrInvalidatedAuthorizeCode so fosite can detect replay attempts.
func (s *Store) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT used, request_data FROM authorization_codes WHERE code = ?`, code)

	var (
		used        int
		requestData string
	)

	if err := row.Scan(&used, &requestData); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetAuthorizeCodeSession: %w", err)
	}

	req, err := unmarshalRequest([]byte(requestData), session)
	if err != nil {
		return nil, fmt.Errorf("storage: GetAuthorizeCodeSession: %w", err)
	}

	if used != 0 {
		return req, fosite.ErrInvalidatedAuthorizeCode
	}

	return req, nil
}

// InvalidateAuthorizeCodeSession marks the code as used (used=1) to prevent
// replay attacks.
func (s *Store) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE authorization_codes SET used = 1 WHERE code = ?`, code)
	if err != nil {
		return fmt.Errorf("storage: InvalidateAuthorizeCodeSession: %w", err)
	}

	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("storage: InvalidateAuthorizeCodeSession: rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("storage: InvalidateAuthorizeCodeSession: code %q not found", code)
	}

	return nil
}

// ---------------------------------------------------------------------------
// fositeOAuth2.AccessTokenStorage
// ---------------------------------------------------------------------------

// CreateAccessTokenSession persists an access token and its request.
func (s *Store) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	data, err := marshalRequest(req)
	if err != nil {
		return fmt.Errorf("storage: CreateAccessTokenSession: %w", err)
	}

	subject := req.GetSession().GetSubject()
	clientID := req.GetClient().GetID()
	scopes := strings.Join(req.GetGrantedScopes(), " ")
	expiresAt := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	requestID := req.GetID()

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO tokens
		   (signature, request_id, client_id, subject, scopes, expires_at, request_data)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		signature, requestID, clientID, subject, scopes, expiresAt, string(data),
	)
	if err != nil {
		return fmt.Errorf("storage: CreateAccessTokenSession: insert: %w", err)
	}

	return nil
}

// GetAccessTokenSession retrieves the request stored under signature.
func (s *Store) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT request_data FROM tokens WHERE signature = ?`, signature)

	var requestData string
	if err := row.Scan(&requestData); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetAccessTokenSession: %w", err)
	}

	req, err := unmarshalRequest([]byte(requestData), session)
	if err != nil {
		return nil, fmt.Errorf("storage: GetAccessTokenSession: %w", err)
	}

	return req, nil
}

// DeleteAccessTokenSession removes an access token by its signature.
func (s *Store) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM tokens WHERE signature = ?`, signature)
	if err != nil {
		return fmt.Errorf("storage: DeleteAccessTokenSession: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// fositeOAuth2.RefreshTokenStorage
// ---------------------------------------------------------------------------

// CreateRefreshTokenSession persists a refresh token and its request.
func (s *Store) CreateRefreshTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	data, err := marshalRequest(req)
	if err != nil {
		return fmt.Errorf("storage: CreateRefreshTokenSession: %w", err)
	}

	subject := req.GetSession().GetSubject()
	clientID := req.GetClient().GetID()
	scopes := strings.Join(req.GetGrantedScopes(), " ")
	expiresAt := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	requestID := req.GetID()

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens
		   (signature, client_id, subject, scopes, expires_at, revoked, request_id, request_data)
		 VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
		signature, clientID, subject, scopes, expiresAt, requestID, string(data),
	)
	if err != nil {
		return fmt.Errorf("storage: CreateRefreshTokenSession: insert: %w", err)
	}

	return nil
}

// GetRefreshTokenSession retrieves the request stored under signature.
// It returns fosite.ErrTokenRevoked if the token has been revoked.
func (s *Store) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT revoked, request_data FROM refresh_tokens WHERE signature = ?`, signature)

	var (
		revoked     int
		requestData string
	)

	if err := row.Scan(&revoked, &requestData); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetRefreshTokenSession: %w", err)
	}

	if revoked != 0 {
		return nil, fosite.ErrTokenRevoked
	}

	req, err := unmarshalRequest([]byte(requestData), session)
	if err != nil {
		return nil, fmt.Errorf("storage: GetRefreshTokenSession: %w", err)
	}

	return req, nil
}

// DeleteRefreshTokenSession removes a refresh token by its signature.
func (s *Store) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE signature = ?`, signature)
	if err != nil {
		return fmt.Errorf("storage: DeleteRefreshTokenSession: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// fositeOAuth2.TokenRevocationStorage
// ---------------------------------------------------------------------------

// RevokeRefreshToken marks all refresh tokens for the given requestID as
// revoked.
func (s *Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked = 1 WHERE request_id = ?`, requestID)
	if err != nil {
		return fmt.Errorf("storage: RevokeRefreshToken: %w", err)
	}
	return nil
}

// RevokeRefreshTokenMaybeGracePeriod revokes the specific refresh token
// identified by signature (the requestID parameter is informational).
func (s *Store) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked = 1 WHERE signature = ?`, signature)
	if err != nil {
		return fmt.Errorf("storage: RevokeRefreshTokenMaybeGracePeriod: %w", err)
	}
	return nil
}

// RevokeAccessToken deletes all access tokens for the given requestID.
func (s *Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM tokens WHERE request_id = ?`, requestID)
	if err != nil {
		return fmt.Errorf("storage: RevokeAccessToken: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// fositeOIDC.OpenIDConnectRequestStorage
// ---------------------------------------------------------------------------

// CreateOpenIDConnectSession persists an OIDC request keyed by authoriseCode.
func (s *Store) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) error {
	data, err := marshalRequest(req)
	if err != nil {
		return fmt.Errorf("storage: CreateOpenIDConnectSession: %w", err)
	}

	subject := req.GetSession().GetSubject()
	clientID := req.GetClient().GetID()
	scopes := strings.Join(req.GetGrantedScopes(), " ")
	expiresAt := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions
		   (id, client_id, subject, scopes, expires_at, request_data)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		authorizeCode, clientID, subject, scopes, expiresAt, string(data),
	)
	if err != nil {
		return fmt.Errorf("storage: CreateOpenIDConnectSession: insert: %w", err)
	}

	return nil
}

// GetOpenIDConnectSession retrieves the OIDC request keyed by authoriseCode.
func (s *Store) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT request_data FROM sessions WHERE id = ?`, authorizeCode)

	var requestData string
	if err := row.Scan(&requestData); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetOpenIDConnectSession: %w", err)
	}

	var sessionHint fosite.Session
	if req != nil {
		sessionHint = req.GetSession()
	}

	result, err := unmarshalRequest([]byte(requestData), sessionHint)
	if err != nil {
		return nil, fmt.Errorf("storage: GetOpenIDConnectSession: %w", err)
	}

	return result, nil
}

// DeleteOpenIDConnectSession removes the OIDC session keyed by authoriseCode.
func (s *Store) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE id = ?`, authorizeCode)
	if err != nil {
		return fmt.Errorf("storage: DeleteOpenIDConnectSession: %w", err)
	}
	return nil
}
