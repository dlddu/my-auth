// Package storage provides the fosite-compatible OAuth2/OIDC storage layer
// backed by SQLite.
//
// Interfaces implemented:
//   - fosite.ClientManager                (GetClient, ClientAssertionJWTValid, SetClientAssertionJWT)
//   - oauth2storage.AuthorizeCodeStorage  (Create/Get/InvalidateAuthorizeCodeSession)
//   - oauth2storage.AccessTokenStorage    (Create/Get/Delete/RevokeAccessToken)
//   - oauth2storage.RefreshTokenStorage   (Create/Get/Delete/RotateRefreshToken)
//   - oauth2storage.TokenRevocationStorage (RevokeRefreshToken/RevokeAccessToken)
//   - openid.OpenIDConnectRequestStorage  (Create/Get/DeleteOpenIDConnectSession)
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
	oauth2storage "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// Store is the SQLite-backed implementation of all fosite storage interfaces.
// The zero value is not usable; use New to construct a Store.
type Store struct {
	db *sql.DB
}

// New creates a new Store backed by db.
// It returns an error if db is nil.
func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("storage.New: db must not be nil")
	}
	return &Store{db: db}, nil
}

// ---------------------------------------------------------------------------
// CombinedSession
// ---------------------------------------------------------------------------

// CombinedSession embeds openid.DefaultSession (for OIDC id_token generation)
// and adds JWTSessionContainer methods (for JWT access token generation).
// It is defined here (in storage) to be shared with the handler package
// without creating a circular import.
type CombinedSession struct {
	*openid.DefaultSession
	JWTClaims *jwt.JWTClaims `json:"jwt_claims"`
	JWTHeader *jwt.Headers   `json:"jwt_header"`
}

// GetJWTClaims implements oauth2.JWTSessionContainer.
func (s *CombinedSession) GetJWTClaims() jwt.JWTClaimsContainer {
	if s.JWTClaims == nil {
		s.JWTClaims = &jwt.JWTClaims{}
	}
	return s.JWTClaims
}

// GetJWTHeader implements oauth2.JWTSessionContainer.
func (s *CombinedSession) GetJWTHeader() *jwt.Headers {
	if s.JWTHeader == nil {
		s.JWTHeader = &jwt.Headers{}
	}
	return s.JWTHeader
}

// Clone implements fosite.Session.
func (s *CombinedSession) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	clonedDefault := s.DefaultSession.Clone().(*openid.DefaultSession)
	var clonedClaims *jwt.JWTClaims
	if s.JWTClaims != nil {
		c := *s.JWTClaims
		clonedClaims = &c
	}
	var clonedHeader *jwt.Headers
	if s.JWTHeader != nil {
		h := *s.JWTHeader
		clonedHeader = &h
	}
	return &CombinedSession{
		DefaultSession: clonedDefault,
		JWTClaims:      clonedClaims,
		JWTHeader:      clonedHeader,
	}
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

// requestData is the JSON-serializable representation of a fosite.Requester.
type requestData struct {
	ID                string          `json:"id"`
	RequestedAt       time.Time       `json:"requested_at"`
	ClientID          string          `json:"client_id"`
	RequestedScope    []string        `json:"requested_scope"`
	GrantedScope      []string        `json:"granted_scope"`
	RequestedAudience []string        `json:"requested_audience"`
	GrantedAudience   []string        `json:"granted_audience"`
	Form              url.Values      `json:"form"`
	Session           json.RawMessage `json:"session"`
}

// marshalRequest serializes a fosite.Requester to JSON bytes.
func marshalRequest(req fosite.Requester) ([]byte, error) {
	sess := req.GetSession()
	sessBytes, err := json.Marshal(sess)
	if err != nil {
		return nil, fmt.Errorf("storage: marshal session: %w", err)
	}

	rd := requestData{
		ID:                req.GetID(),
		RequestedAt:       req.GetRequestedAt(),
		ClientID:          req.GetClient().GetID(),
		RequestedScope:    []string(req.GetRequestedScopes()),
		GrantedScope:      []string(req.GetGrantedScopes()),
		RequestedAudience: []string(req.GetRequestedAudience()),
		GrantedAudience:   []string(req.GetGrantedAudience()),
		Form:              req.GetRequestForm(),
		Session:           json.RawMessage(sessBytes),
	}

	if rd.RequestedScope == nil {
		rd.RequestedScope = []string{}
	}
	if rd.GrantedScope == nil {
		rd.GrantedScope = []string{}
	}
	if rd.RequestedAudience == nil {
		rd.RequestedAudience = []string{}
	}
	if rd.GrantedAudience == nil {
		rd.GrantedAudience = []string{}
	}

	return json.Marshal(rd)
}

// unmarshalRequest deserializes JSON bytes into a fosite.Request,
// loading client data from the database and using openid.DefaultSession
// for the session type.
func (s *Store) unmarshalRequest(ctx context.Context, data []byte) (*fosite.Request, error) {
	var rd requestData
	if err := json.Unmarshal(data, &rd); err != nil {
		return nil, fmt.Errorf("storage: unmarshal request data: %w", err)
	}

	// Load the client from DB so we get a proper fosite.Client.
	client, err := s.GetClient(ctx, rd.ClientID)
	if err != nil {
		return nil, fmt.Errorf("storage: load client %q: %w", rd.ClientID, err)
	}

	// Deserialize the session as CombinedSession (supports both OIDC and JWT access token sessions).
	sess := &CombinedSession{
		DefaultSession: openid.NewDefaultSession(),
	}
	if len(rd.Session) > 0 && string(rd.Session) != "null" {
		if err := json.Unmarshal(rd.Session, sess); err != nil {
			// Fall back to an empty session if unmarshal fails.
			sess = &CombinedSession{
				DefaultSession: openid.NewDefaultSession(),
			}
		}
	}

	req := &fosite.Request{
		ID:                rd.ID,
		RequestedAt:       rd.RequestedAt,
		Client:            client,
		RequestedScope:    fosite.Arguments(rd.RequestedScope),
		GrantedScope:      fosite.Arguments(rd.GrantedScope),
		RequestedAudience: fosite.Arguments(rd.RequestedAudience),
		GrantedAudience:   fosite.Arguments(rd.GrantedAudience),
		Form:              rd.Form,
		Session:           sess,
	}

	if req.Form == nil {
		req.Form = url.Values{}
	}

	return req, nil
}

// ---------------------------------------------------------------------------
// ClientManager — GetClient, ClientAssertionJWTValid, SetClientAssertionJWT
// ---------------------------------------------------------------------------

// GetClient retrieves an OAuth2 client from the clients table by ID.
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
		return nil, fmt.Errorf("storage: parse redirect_uris for %q: %w", id, err)
	}

	var grants []string
	if err := json.Unmarshal([]byte(grantTypes), &grants); err != nil {
		return nil, fmt.Errorf("storage: parse grant_types for %q: %w", id, err)
	}

	var responses []string
	if err := json.Unmarshal([]byte(responseTypes), &responses); err != nil {
		return nil, fmt.Errorf("storage: parse response_types for %q: %w", id, err)
	}

	scopeList := strings.Fields(scopes)

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        []byte(secret),
		RedirectURIs:  uris,
		GrantTypes:    fosite.Arguments(grants),
		ResponseTypes: fosite.Arguments(responses),
		Scopes:        fosite.Arguments(scopeList),
	}

	return client, nil
}

// ClientAssertionJWTValid returns nil if the JTI is not known (no-op implementation).
// A production implementation should check a blocklist in persistent storage.
func (s *Store) ClientAssertionJWTValid(_ context.Context, _ string) error {
	return nil
}

// SetClientAssertionJWT marks a JTI as known for the given expiry time (no-op implementation).
// A production implementation should persist the JTI to prevent replay attacks.
func (s *Store) SetClientAssertionJWT(_ context.Context, _ string, _ time.Time) error {
	return nil
}

// ---------------------------------------------------------------------------
// AuthorizeCodeStorage
// ---------------------------------------------------------------------------

// CreateAuthorizeCodeSession stores an authorization code session.
func (s *Store) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	data, err := marshalRequest(req)
	if err != nil {
		return fmt.Errorf("storage: CreateAuthorizeCodeSession: %w", err)
	}

	sess := req.GetSession()
	expiresAt := time.Now().Add(10 * time.Minute)
	if ea := sess.GetExpiresAt(fosite.AuthorizeCode); !ea.IsZero() {
		expiresAt = ea
	}

	redirectURI := ""
	if ar, ok := req.(*fosite.AuthorizeRequest); ok && ar.RedirectURI != nil {
		redirectURI = ar.RedirectURI.String()
	} else {
		redirectURI = req.GetRequestForm().Get("redirect_uri")
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO authorization_codes
			(code, client_id, subject, redirect_uri, scopes, expires_at, request_id, session_data)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		code,
		req.GetClient().GetID(),
		req.GetSession().GetSubject(),
		redirectURI,
		strings.Join(req.GetGrantedScopes(), " "),
		expiresAt.UTC().Format(time.RFC3339),
		req.GetID(),
		string(data),
	)
	if err != nil {
		return fmt.Errorf("storage: CreateAuthorizeCodeSession: %w", err)
	}

	return nil
}

// GetAuthorizeCodeSession retrieves an authorization code session.
// If the code has been invalidated (used=1), it returns fosite.ErrInvalidatedAuthorizeCode.
func (s *Store) GetAuthorizeCodeSession(ctx context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	var (
		sessionData string
		used        int
	)

	row := s.db.QueryRowContext(ctx,
		`SELECT session_data, used FROM authorization_codes WHERE code = ?`, code)
	if err := row.Scan(&sessionData, &used); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetAuthorizeCodeSession: %w", err)
	}

	if used == 1 {
		req, _ := s.unmarshalRequest(ctx, []byte(sessionData))
		if req == nil {
			return nil, fosite.ErrInvalidatedAuthorizeCode
		}
		return req, fosite.ErrInvalidatedAuthorizeCode
	}

	req, err := s.unmarshalRequest(ctx, []byte(sessionData))
	if err != nil {
		return nil, fmt.Errorf("storage: GetAuthorizeCodeSession: %w", err)
	}

	return req, nil
}

// InvalidateAuthorizeCodeSession marks the authorization code as used (sets used=1).
func (s *Store) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE authorization_codes SET used = 1 WHERE code = ?`, code)
	if err != nil {
		return fmt.Errorf("storage: InvalidateAuthorizeCodeSession: %w", err)
	}

	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("storage: InvalidateAuthorizeCodeSession rows affected: %w", err)
	}
	if n == 0 {
		return fosite.ErrNotFound
	}

	return nil
}

// ---------------------------------------------------------------------------
// AccessTokenStorage
// ---------------------------------------------------------------------------

// CreateAccessTokenSession stores an access token session.
func (s *Store) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	data, err := marshalRequest(req)
	if err != nil {
		return fmt.Errorf("storage: CreateAccessTokenSession: %w", err)
	}

	sess := req.GetSession()
	expiresAt := time.Now().Add(time.Hour)
	if ea := sess.GetExpiresAt(fosite.AccessToken); !ea.IsZero() {
		expiresAt = ea
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO tokens (signature, request_id, client_id, subject, scopes, expires_at, session_data)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		signature,
		req.GetID(),
		req.GetClient().GetID(),
		req.GetSession().GetSubject(),
		strings.Join(req.GetGrantedScopes(), " "),
		expiresAt.UTC().Format(time.RFC3339),
		string(data),
	)
	if err != nil {
		return fmt.Errorf("storage: CreateAccessTokenSession: %w", err)
	}

	return nil
}

// GetAccessTokenSession retrieves an access token session by signature.
func (s *Store) GetAccessTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	var sessionData string

	row := s.db.QueryRowContext(ctx,
		`SELECT session_data FROM tokens WHERE signature = ?`, signature)
	if err := row.Scan(&sessionData); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetAccessTokenSession: %w", err)
	}

	req, err := s.unmarshalRequest(ctx, []byte(sessionData))
	if err != nil {
		return nil, fmt.Errorf("storage: GetAccessTokenSession: %w", err)
	}

	return req, nil
}

// DeleteAccessTokenSession removes an access token by its signature.
func (s *Store) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM tokens WHERE signature = ?`, signature)
	if err != nil {
		return fmt.Errorf("storage: DeleteAccessTokenSession: %w", err)
	}
	return nil
}

// RevokeAccessToken removes all access tokens associated with the given request ID.
func (s *Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM tokens WHERE request_id = ?`, requestID)
	if err != nil {
		return fmt.Errorf("storage: RevokeAccessToken: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// RefreshTokenStorage
// ---------------------------------------------------------------------------

// CreateRefreshTokenSession stores a refresh token session.
// The accessSignature parameter is accepted to satisfy the fosite v0.49.0
// oauth2.RefreshTokenStorage interface but is not persisted by this implementation.
func (s *Store) CreateRefreshTokenSession(ctx context.Context, signature string, _ string, req fosite.Requester) error {
	data, err := marshalRequest(req)
	if err != nil {
		return fmt.Errorf("storage: CreateRefreshTokenSession: %w", err)
	}

	sess := req.GetSession()
	expiresAt := time.Now().Add(24 * time.Hour)
	if ea := sess.GetExpiresAt(fosite.RefreshToken); !ea.IsZero() {
		expiresAt = ea
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO refresh_tokens (signature, request_id, client_id, subject, scopes, expires_at, session_data)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		signature,
		req.GetID(),
		req.GetClient().GetID(),
		req.GetSession().GetSubject(),
		strings.Join(req.GetGrantedScopes(), " "),
		expiresAt.UTC().Format(time.RFC3339),
		string(data),
	)
	if err != nil {
		return fmt.Errorf("storage: CreateRefreshTokenSession: %w", err)
	}

	return nil
}

// GetRefreshTokenSession retrieves a refresh token session by signature.
// Returns fosite.ErrInactiveToken if the token has been revoked.
func (s *Store) GetRefreshTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	var (
		sessionData string
		revoked     int
	)

	row := s.db.QueryRowContext(ctx,
		`SELECT session_data, revoked FROM refresh_tokens WHERE signature = ?`, signature)
	if err := row.Scan(&sessionData, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetRefreshTokenSession: %w", err)
	}

	if revoked == 1 {
		return nil, fosite.ErrInactiveToken
	}

	req, err := s.unmarshalRequest(ctx, []byte(sessionData))
	if err != nil {
		return nil, fmt.Errorf("storage: GetRefreshTokenSession: %w", err)
	}

	return req, nil
}

// DeleteRefreshTokenSession removes a refresh token by its signature.
func (s *Store) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE signature = ?`, signature)
	if err != nil {
		return fmt.Errorf("storage: DeleteRefreshTokenSession: %w", err)
	}
	return nil
}

// RevokeRefreshToken marks all refresh tokens for the given request ID as revoked.
func (s *Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked = 1 WHERE request_id = ?`, requestID)
	if err != nil {
		return fmt.Errorf("storage: RevokeRefreshToken: %w", err)
	}
	return nil
}

// RotateRefreshToken is called during refresh token rotation. This implementation
// is a no-op because rotation is handled at the application level via
// DeleteRefreshTokenSession and CreateRefreshTokenSession.
func (s *Store) RotateRefreshToken(_ context.Context, _ string, _ string) error {
	return nil
}

// ---------------------------------------------------------------------------
// OpenIDConnectRequestStorage
// ---------------------------------------------------------------------------

// CreateOpenIDConnectSession stores an OIDC session keyed by the authorization code.
func (s *Store) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) error {
	data, err := marshalRequest(req)
	if err != nil {
		return fmt.Errorf("storage: CreateOpenIDConnectSession: %w", err)
	}

	sess := req.GetSession()
	expiresAt := time.Now().Add(10 * time.Minute)
	if ea := sess.GetExpiresAt(fosite.AuthorizeCode); !ea.IsZero() {
		expiresAt = ea
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO sessions (id, request_id, client_id, subject, scopes, expires_at, session_data)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		authorizeCode,
		req.GetID(),
		req.GetClient().GetID(),
		req.GetSession().GetSubject(),
		strings.Join(req.GetGrantedScopes(), " "),
		expiresAt.UTC().Format(time.RFC3339),
		string(data),
	)
	if err != nil {
		return fmt.Errorf("storage: CreateOpenIDConnectSession: %w", err)
	}

	return nil
}

// GetOpenIDConnectSession retrieves an OIDC session by the authorization code.
func (s *Store) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, _ fosite.Requester) (fosite.Requester, error) {
	var sessionData string

	row := s.db.QueryRowContext(ctx,
		`SELECT session_data FROM sessions WHERE id = ?`, authorizeCode)
	if err := row.Scan(&sessionData); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetOpenIDConnectSession: %w", err)
	}

	req, err := s.unmarshalRequest(ctx, []byte(sessionData))
	if err != nil {
		return nil, fmt.Errorf("storage: GetOpenIDConnectSession: %w", err)
	}

	return req, nil
}

// DeleteOpenIDConnectSession removes an OIDC session by its authorization code.
func (s *Store) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, authorizeCode)
	if err != nil {
		return fmt.Errorf("storage: DeleteOpenIDConnectSession: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Compile-time interface assertions
// ---------------------------------------------------------------------------

var (
	_ fosite.ClientManager                  = (*Store)(nil)
	_ oauth2storage.AuthorizeCodeStorage    = (*Store)(nil)
	_ oauth2storage.AccessTokenStorage      = (*Store)(nil)
	_ oauth2storage.RefreshTokenStorage     = (*Store)(nil)
	_ oauth2storage.TokenRevocationStorage  = (*Store)(nil)
	_ openid.OpenIDConnectRequestStorage    = (*Store)(nil)
)
