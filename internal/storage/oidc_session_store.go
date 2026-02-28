package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ory/fosite"
)

// OpenIDConnectSessionStore implements openid.OpenIDConnectRequestStorage backed by SQLite.
// It uses the sessions table to store OIDC session data keyed by authorize code.
type OpenIDConnectSessionStore struct {
	db          *sql.DB
	clientStore *ClientStore
}

// NewOpenIDConnectSessionStore returns a new OpenIDConnectSessionStore.
func NewOpenIDConnectSessionStore(db *sql.DB) *OpenIDConnectSessionStore {
	return &OpenIDConnectSessionStore{
		db:          db,
		clientStore: NewClientStore(db),
	}
}

// CreateOpenIDConnectSession persists an OIDC session keyed by authorizeCode.
func (s *OpenIDConnectSessionStore) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) error {
	data, err := serializeRequest(req)
	if err != nil {
		return fmt.Errorf("storage: CreateOpenIDConnectSession: %w", err)
	}

	expiresAt := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
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
		`INSERT INTO sessions
		    (id, client_id, subject, scopes, expires_at, session_data, request_id, scopes_data, granted_scopes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		authorizeCode, clientID, subject, scopes, expiresAt, string(data), requestID, scopes, grantedScopes,
	)
	if err != nil {
		return fmt.Errorf("storage: CreateOpenIDConnectSession: insert: %w", err)
	}
	return nil
}

// GetOpenIDConnectSession retrieves an OIDC session by authorize code.
// The requester parameter's session is used as the target for deserialization.
func (s *OpenIDConnectSessionStore) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT session_data FROM sessions WHERE id = ?`, authorizeCode,
	)

	var sessionData string
	if err := row.Scan(&sessionData); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("storage: GetOpenIDConnectSession: %w", fosite.ErrNotFound)
		}
		return nil, fmt.Errorf("storage: GetOpenIDConnectSession: scan: %w", err)
	}

	// Use the session from the incoming requester as the deserialization target.
	var sess fosite.Session
	if requester != nil && requester.GetSession() != nil {
		sess = requester.GetSession()
	}
	if sess == nil {
		return nil, fmt.Errorf("storage: GetOpenIDConnectSession: no session container provided")
	}

	req, err := deserializeRequest([]byte(sessionData), sess, s.clientStore)
	if err != nil {
		return nil, fmt.Errorf("storage: GetOpenIDConnectSession: deserialize: %w", err)
	}
	return req, nil
}

// DeleteOpenIDConnectSession removes an OIDC session by authorize code.
func (s *OpenIDConnectSessionStore) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE id = ?`, authorizeCode,
	)
	if err != nil {
		return fmt.Errorf("storage: DeleteOpenIDConnectSession: %w", err)
	}
	return nil
}
