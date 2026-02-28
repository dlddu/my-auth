package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ory/fosite"
)

// AuthorizeCodeStore implements oauth2.AuthorizeCodeStorage backed by SQLite.
type AuthorizeCodeStore struct {
	db          *sql.DB
	clientStore *ClientStore
}

// NewAuthorizeCodeStore returns a new AuthorizeCodeStore.
func NewAuthorizeCodeStore(db *sql.DB) *AuthorizeCodeStore {
	return &AuthorizeCodeStore{
		db:          db,
		clientStore: NewClientStore(db),
	}
}

// CreateAuthorizeCodeSession persists an authorization code session.
func (s *AuthorizeCodeStore) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	data, err := serializeRequest(req)
	if err != nil {
		return fmt.Errorf("storage: CreateAuthorizeCodeSession: %w", err)
	}

	expiresAt := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	clientID := req.GetClient().GetID()
	subject := ""
	if sess := req.GetSession(); sess != nil {
		if oidcSess, ok := sess.(interface{ GetSubject() string }); ok {
			subject = oidcSess.GetSubject()
		}
	}

	redirectURI := ""
	if ar, ok := req.(*fosite.AuthorizeRequest); ok {
		if ar.RedirectURI != nil {
			redirectURI = ar.RedirectURI.String()
		}
	}

	scopes := strings.Join([]string(req.GetRequestedScopes()), " ")
	grantedScopes := strings.Join([]string(req.GetGrantedScopes()), " ")
	requestID := req.GetID()

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO authorization_codes
		    (code, client_id, subject, redirect_uri, scopes, expires_at, used, session_data, request_id, granted_scopes)
		 VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
		code, clientID, subject, redirectURI, scopes, expiresAt, string(data), requestID, grantedScopes,
	)
	if err != nil {
		return fmt.Errorf("storage: CreateAuthorizeCodeSession: insert: %w", err)
	}
	return nil
}

// GetAuthorizeCodeSession retrieves an authorization code session.
// Returns fosite.ErrInvalidatedAuthorizeCode if the code has been used.
// Returns fosite.ErrNotFound if the code does not exist.
func (s *AuthorizeCodeStore) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT session_data, used FROM authorization_codes WHERE code = ?`, code,
	)

	var sessionData string
	var used int
	if err := row.Scan(&sessionData, &used); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("storage: GetAuthorizeCodeSession: %w", fosite.ErrNotFound)
		}
		return nil, fmt.Errorf("storage: GetAuthorizeCodeSession: scan: %w", err)
	}

	if used == 1 {
		// Reconstruct the request even for invalidated codes (fosite needs it).
		req, err := deserializeRequest([]byte(sessionData), session, s.clientStore)
		if err != nil {
			return nil, fmt.Errorf("storage: GetAuthorizeCodeSession: deserialize: %w", err)
		}
		return req, fosite.ErrInvalidatedAuthorizeCode
	}

	req, err := deserializeRequest([]byte(sessionData), session, s.clientStore)
	if err != nil {
		return nil, fmt.Errorf("storage: GetAuthorizeCodeSession: deserialize: %w", err)
	}
	return req, nil
}

// InvalidateAuthorizeCodeSession marks an authorization code as used (consumed).
func (s *AuthorizeCodeStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE authorization_codes SET used = 1 WHERE code = ?`, code,
	)
	if err != nil {
		return fmt.Errorf("storage: InvalidateAuthorizeCodeSession: %w", err)
	}

	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("storage: InvalidateAuthorizeCodeSession: rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("storage: InvalidateAuthorizeCodeSession: %w", fosite.ErrNotFound)
	}
	return nil
}
