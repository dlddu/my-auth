package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ory/fosite"
)

// AccessTokenStore implements oauth2.AccessTokenStorage backed by SQLite.
type AccessTokenStore struct {
	db          *sql.DB
	clientStore *ClientStore
}

// NewAccessTokenStore returns a new AccessTokenStore.
func NewAccessTokenStore(db *sql.DB) *AccessTokenStore {
	return &AccessTokenStore{
		db:          db,
		clientStore: NewClientStore(db),
	}
}

// CreateAccessTokenSession persists an access token session.
func (s *AccessTokenStore) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	data, err := serializeRequest(req)
	if err != nil {
		return fmt.Errorf("storage: CreateAccessTokenSession: %w", err)
	}

	expiresAt := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	clientID := req.GetClient().GetID()
	subject := ""
	if sess := req.GetSession(); sess != nil {
		if oidcSess, ok := sess.(interface{ GetSubject() string }); ok {
			subject = oidcSess.GetSubject()
		}
	}

	scopes := strings.Join([]string(req.GetRequestedScopes()), " ")
	grantedScopes := strings.Join([]string(req.GetGrantedScopes()), " ")
	requestID := req.GetID()

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO tokens
		    (signature, request_id, client_id, subject, scopes, expires_at, session_data, granted_scopes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		signature, requestID, clientID, subject, scopes, expiresAt, string(data), grantedScopes,
	)
	if err != nil {
		return fmt.Errorf("storage: CreateAccessTokenSession: insert: %w", err)
	}
	return nil
}

// GetAccessTokenSession retrieves an access token session by signature.
func (s *AccessTokenStore) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT session_data FROM tokens WHERE signature = ?`, signature,
	)

	var sessionData string
	if err := row.Scan(&sessionData); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("storage: GetAccessTokenSession: %w", fosite.ErrNotFound)
		}
		return nil, fmt.Errorf("storage: GetAccessTokenSession: scan: %w", err)
	}

	req, err := deserializeRequest([]byte(sessionData), session, s.clientStore)
	if err != nil {
		return nil, fmt.Errorf("storage: GetAccessTokenSession: deserialize: %w", err)
	}
	return req, nil
}

// DeleteAccessTokenSession removes a single access token by signature.
func (s *AccessTokenStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM tokens WHERE signature = ?`, signature,
	)
	if err != nil {
		return fmt.Errorf("storage: DeleteAccessTokenSession: %w", err)
	}
	return nil
}

// RevokeAccessToken removes all access tokens associated with the given request ID.
func (s *AccessTokenStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM tokens WHERE request_id = ?`, requestID,
	)
	if err != nil {
		return fmt.Errorf("storage: RevokeAccessToken: %w", err)
	}
	return nil
}
