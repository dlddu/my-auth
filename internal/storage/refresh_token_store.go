package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ory/fosite"
)

// RefreshTokenStore implements oauth2.RefreshTokenStorage backed by SQLite.
type RefreshTokenStore struct {
	db          *sql.DB
	clientStore *ClientStore
}

// NewRefreshTokenStore returns a new RefreshTokenStore.
func NewRefreshTokenStore(db *sql.DB) *RefreshTokenStore {
	return &RefreshTokenStore{
		db:          db,
		clientStore: NewClientStore(db),
	}
}

// CreateRefreshTokenSession persists a refresh token session.
func (s *RefreshTokenStore) CreateRefreshTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	data, err := serializeRequest(req)
	if err != nil {
		return fmt.Errorf("storage: CreateRefreshTokenSession: %w", err)
	}

	expiresAt := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
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
		`INSERT INTO refresh_tokens
		    (signature, client_id, subject, scopes, expires_at, revoked, session_data, request_id, granted_scopes)
		 VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)`,
		signature, clientID, subject, scopes, expiresAt, string(data), requestID, grantedScopes,
	)
	if err != nil {
		return fmt.Errorf("storage: CreateRefreshTokenSession: insert: %w", err)
	}
	return nil
}

// GetRefreshTokenSession retrieves a refresh token session by signature.
// Returns an error if the token has been revoked or does not exist.
func (s *RefreshTokenStore) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT session_data, revoked FROM refresh_tokens WHERE signature = ?`, signature,
	)

	var sessionData string
	var revoked int
	if err := row.Scan(&sessionData, &revoked); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("storage: GetRefreshTokenSession: %w", fosite.ErrNotFound)
		}
		return nil, fmt.Errorf("storage: GetRefreshTokenSession: scan: %w", err)
	}

	if revoked == 1 {
		return nil, fmt.Errorf("storage: GetRefreshTokenSession: %w", fosite.ErrTokenRevoked)
	}

	req, err := deserializeRequest([]byte(sessionData), session, s.clientStore)
	if err != nil {
		return nil, fmt.Errorf("storage: GetRefreshTokenSession: deserialize: %w", err)
	}
	return req, nil
}

// DeleteRefreshTokenSession removes a single refresh token by signature.
func (s *RefreshTokenStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE signature = ?`, signature,
	)
	if err != nil {
		return fmt.Errorf("storage: DeleteRefreshTokenSession: %w", err)
	}
	return nil
}

// RevokeRefreshToken marks all refresh tokens associated with the given request ID as revoked.
// It returns nil if no tokens are found (idempotent).
func (s *RefreshTokenStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked = 1 WHERE request_id = ?`, requestID,
	)
	if err != nil {
		return fmt.Errorf("storage: RevokeRefreshToken: %w", err)
	}
	return nil
}

// RevokeRefreshTokenMaybeGracePeriod revokes a refresh token, ignoring any grace period.
// This implementation delegates to RevokeRefreshToken.
func (s *RefreshTokenStore) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	return s.RevokeRefreshToken(ctx, requestID)
}
