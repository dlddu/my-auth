package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ory/fosite"
)

// PKCEStore implements pkce.PKCERequestStorage backed by SQLite.
// PKCE sessions are stored in the pkce_requests table (created by migration).
type PKCEStore struct {
	db          *sql.DB
	clientStore *ClientStore
}

// NewPKCEStore returns a new PKCEStore.
func NewPKCEStore(db *sql.DB) *PKCEStore {
	return &PKCEStore{
		db:          db,
		clientStore: NewClientStore(db),
	}
}

// CreatePKCERequestSession persists a PKCE code_challenge alongside the
// authorize code signature.
func (s *PKCEStore) CreatePKCERequestSession(ctx context.Context, signature string, req fosite.Requester) error {
	data, err := serializeRequest(req)
	if err != nil {
		return fmt.Errorf("storage: CreatePKCERequestSession: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO pkce_requests (signature, session_data) VALUES (?, ?)`,
		signature, string(data),
	)
	if err != nil {
		return fmt.Errorf("storage: CreatePKCERequestSession: insert: %w", err)
	}
	return nil
}

// GetPKCERequestSession retrieves a PKCE session by the authorize code signature.
func (s *PKCEStore) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT session_data FROM pkce_requests WHERE signature = ?`, signature,
	)

	var sessionData string
	if err := row.Scan(&sessionData); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("storage: GetPKCERequestSession: %w", fosite.ErrNotFound)
		}
		return nil, fmt.Errorf("storage: GetPKCERequestSession: scan: %w", err)
	}

	req, err := deserializeRequest([]byte(sessionData), session, s.clientStore)
	if err != nil {
		return nil, fmt.Errorf("storage: GetPKCERequestSession: deserialize: %w", err)
	}
	return req, nil
}

// DeletePKCERequestSession removes the PKCE session for the given signature.
func (s *PKCEStore) DeletePKCERequestSession(ctx context.Context, signature string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM pkce_requests WHERE signature = ?`, signature,
	)
	if err != nil {
		return fmt.Errorf("storage: DeletePKCERequestSession: %w", err)
	}
	return nil
}
