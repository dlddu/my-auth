// Package storage provides fosite-compatible OAuth2 storage implementations
// backed by a SQLite database. Each store type satisfies the corresponding
// fosite storage interface so that a fosite.OAuth2Provider can be assembled
// with a fully SQLite-backed persistence layer.
//
// This file contains skeleton implementations; the actual SQL logic is filled
// in during the TDD Green Phase.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

// ---------------------------------------------------------------------------
// ClientStore
// ---------------------------------------------------------------------------

// ClientStore looks up OAuth2 clients from the clients table.
type ClientStore struct {
	db *sql.DB
}

// NewClientStore returns a ClientStore backed by db.
func NewClientStore(db *sql.DB) *ClientStore {
	return &ClientStore{db: db}
}

// Client is the in-memory representation of an OAuth2 client row.
// It satisfies the fosite.Client interface.
type Client struct {
	ID            string
	Secret        []byte
	RedirectURIs  []string
	GrantTypes    []string
	ResponseTypes []string
	Scopes        []string
}

func (c *Client) GetID() string                          { return c.ID }
func (c *Client) GetHashedSecret() []byte                { return c.Secret }
func (c *Client) GetRedirectURIs() []string              { return c.RedirectURIs }
func (c *Client) GetGrantTypes() fosite.Arguments        { return c.GrantTypes }
func (c *Client) GetResponseTypes() fosite.Arguments     { return c.ResponseTypes }
func (c *Client) GetScopes() fosite.Arguments            { return c.Scopes }
func (c *Client) IsPublic() bool                         { return false }
func (c *Client) GetAudience() fosite.Arguments          { return fosite.Arguments{c.ID} }

// GetClient retrieves a fosite.Client by id from the clients table.
// Returns fosite.ErrNotFound when the client does not exist.
func (s *ClientStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
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
		if err == sql.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetClient %q: %w", id, err)
	}

	var uris, grants, responses []string
	if err := json.Unmarshal([]byte(redirectURIs), &uris); err != nil {
		return nil, fmt.Errorf("storage: GetClient decode redirect_uris: %w", err)
	}
	if err := json.Unmarshal([]byte(grantTypes), &grants); err != nil {
		return nil, fmt.Errorf("storage: GetClient decode grant_types: %w", err)
	}
	if err := json.Unmarshal([]byte(responseTypes), &responses); err != nil {
		return nil, fmt.Errorf("storage: GetClient decode response_types: %w", err)
	}

	return &Client{
		ID:            clientID,
		Secret:        []byte(secret),
		RedirectURIs:  uris,
		GrantTypes:    grants,
		ResponseTypes: responses,
		Scopes:        strings.Fields(scopes),
	}, nil
}

// ClientAssertionJWTValid returns an error if the JTI is known or the DB
// check failed. Since this server does not use JWT client assertions, we
// always return nil (JTI is never "known").
func (s *ClientStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return nil
}

// SetClientAssertionJWT marks a JTI as known for the given expiry time.
// Since this server does not use JWT client assertions, this is a no-op.
func (s *ClientStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return nil
}

// ---------------------------------------------------------------------------
// AuthorizeCodeStore
// ---------------------------------------------------------------------------

// AuthorizeCodeStore persists and retrieves fosite authorize code sessions.
type AuthorizeCodeStore struct {
	db *sql.DB
}

// NewAuthorizeCodeStore returns an AuthorizeCodeStore backed by db.
func NewAuthorizeCodeStore(db *sql.DB) *AuthorizeCodeStore {
	return &AuthorizeCodeStore{db: db}
}

// CreateAuthorizeCodeSession stores an authorize code session.
func (s *AuthorizeCodeStore) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	expiresAt := request.GetSession().GetExpiresAt(fosite.AuthorizeCode)
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(10 * time.Minute)
	}

	scopes := strings.Join(request.GetGrantedScopes(), " ")
	redirectURI := ""
	// AuthorizeRequester exposes GetRedirectURI; do a type assertion to access it safely.
	if ar, ok := request.(fosite.AuthorizeRequester); ok {
		if u := ar.GetRedirectURI(); u != nil {
			redirectURI = u.String()
		}
	}

	// Serialize session and form data.
	sessionJSON, err := json.Marshal(request.GetSession())
	if err != nil {
		return fmt.Errorf("storage: CreateAuthorizeCodeSession marshal session: %w", err)
	}
	formJSON, err := json.Marshal(map[string][]string(request.GetRequestForm()))
	if err != nil {
		return fmt.Errorf("storage: CreateAuthorizeCodeSession marshal form: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO authorization_codes (code, client_id, subject, redirect_uri, scopes, expires_at, session_data, form_data)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		code,
		request.GetClient().GetID(),
		request.GetSession().GetSubject(),
		redirectURI,
		scopes,
		expiresAt.UTC().Format(time.RFC3339),
		string(sessionJSON),
		string(formJSON),
	)
	if err != nil {
		return fmt.Errorf("storage: CreateAuthorizeCodeSession: %w", err)
	}
	return nil
}

// GetAuthorizeCodeSession retrieves an authorize code session by code.
// Returns fosite.ErrNotFound when the code does not exist.
// Returns fosite.ErrInvalidatedAuthorizeCode when the code has already been used.
func (s *AuthorizeCodeStore) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT client_id, subject, redirect_uri, scopes, expires_at, used, session_data, form_data
		   FROM authorization_codes WHERE code = ?`, code)

	var (
		clientID    string
		subject     string
		redirectURI string
		scopes      string
		expiresAt   string
		used        int
		sessionData string
		formData    string
	)

	if err := row.Scan(&clientID, &subject, &redirectURI, &scopes, &expiresAt, &used, &sessionData, &formData); err != nil {
		if err == sql.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetAuthorizeCodeSession: %w", err)
	}

	if used != 0 {
		return nil, fosite.ErrInvalidatedAuthorizeCode
	}

	expiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("storage: GetAuthorizeCodeSession parse expires_at: %w", err)
	}
	if time.Now().After(expiry) {
		return nil, fosite.ErrTokenExpired
	}

	// Restore session from stored data.
	if session != nil {
		if sessionData != "" && sessionData != "{}" {
			if err := json.Unmarshal([]byte(sessionData), session); err != nil {
				setSessionSubject(session, subject)
			}
		} else {
			setSessionSubject(session, subject)
		}
		session.SetExpiresAt(fosite.AuthorizeCode, expiry)
	}

	// Load the client so fosite can validate the client_id on the token exchange.
	clientStore := NewClientStore(s.db)
	client, err := clientStore.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("storage: GetAuthorizeCodeSession load client %q: %w", clientID, err)
	}

	req := fosite.NewRequest()
	req.SetSession(session)
	req.GrantedScope = strings.Fields(scopes)
	req.Client = client

	// Restore form data.
	if formData != "" && formData != "{}" {
		var formMap map[string][]string
		if err := json.Unmarshal([]byte(formData), &formMap); err == nil {
			req.Form = url.Values(formMap)
		}
	}

	return req, nil
}

// InvalidateAuthorizeCodeSession marks the code as used (prevents replay).
func (s *AuthorizeCodeStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE authorization_codes SET used = 1 WHERE code = ?`, code)
	if err != nil {
		return fmt.Errorf("storage: InvalidateAuthorizeCodeSession: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("storage: InvalidateAuthorizeCodeSession rows: %w", err)
	}
	if n == 0 {
		return fosite.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// AccessTokenStore
// ---------------------------------------------------------------------------

// AccessTokenStore persists and retrieves fosite access token sessions.
type AccessTokenStore struct {
	db *sql.DB
}

// NewAccessTokenStore returns an AccessTokenStore backed by db.
func NewAccessTokenStore(db *sql.DB) *AccessTokenStore {
	return &AccessTokenStore{db: db}
}

// CreateAccessTokenSession stores an access token session.
func (s *AccessTokenStore) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	expiresAt := request.GetSession().GetExpiresAt(fosite.AccessToken)
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(time.Hour)
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tokens (signature, request_id, client_id, subject, scopes, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		signature,
		request.GetID(),
		request.GetClient().GetID(),
		request.GetSession().GetSubject(),
		strings.Join(request.GetGrantedScopes(), " "),
		expiresAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("storage: CreateAccessTokenSession: %w", err)
	}
	return nil
}

// GetAccessTokenSession retrieves an access token session by signature.
// Returns fosite.ErrNotFound when the token does not exist.
func (s *AccessTokenStore) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT request_id, client_id, subject, scopes, expires_at
		   FROM tokens WHERE signature = ?`, signature)

	var (
		requestID string
		clientID  string
		subject   string
		scopes    string
		expiresAt string
	)

	if err := row.Scan(&requestID, &clientID, &subject, &scopes, &expiresAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetAccessTokenSession: %w", err)
	}

	expiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("storage: GetAccessTokenSession parse expires_at: %w", err)
	}
	if time.Now().After(expiry) {
		return nil, fosite.ErrTokenExpired
	}

	if session != nil {
		setSessionSubject(session, subject)
		session.SetExpiresAt(fosite.AccessToken, expiry)
	}

	req := fosite.NewRequest()
	req.ID = requestID
	req.SetSession(session)
	req.GrantedScope = strings.Fields(scopes)

	return req, nil
}

// DeleteAccessTokenSession removes an access token session by signature.
func (s *AccessTokenStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM tokens WHERE signature = ?`, signature)
	if err != nil {
		return fmt.Errorf("storage: DeleteAccessTokenSession: %w", err)
	}
	return nil
}

// RevokeAccessToken revokes an access token by request ID, required by oauth2.TokenRevocationStorage.
func (s *AccessTokenStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM tokens WHERE request_id = ?`, requestID)
	if err != nil {
		return fmt.Errorf("storage: RevokeAccessToken: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// RefreshTokenStore
// ---------------------------------------------------------------------------

// RefreshTokenStore persists and retrieves fosite refresh token sessions.
type RefreshTokenStore struct {
	db *sql.DB
}

// NewRefreshTokenStore returns a RefreshTokenStore backed by db.
func NewRefreshTokenStore(db *sql.DB) *RefreshTokenStore {
	return &RefreshTokenStore{db: db}
}

// CreateRefreshTokenSession stores a refresh token session.
func (s *RefreshTokenStore) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error {
	expiresAt := request.GetSession().GetExpiresAt(fosite.RefreshToken)
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(720 * time.Hour) // 30 days
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (signature, request_id, client_id, subject, scopes, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		signature,
		request.GetID(),
		request.GetClient().GetID(),
		request.GetSession().GetSubject(),
		strings.Join(request.GetGrantedScopes(), " "),
		expiresAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("storage: CreateRefreshTokenSession: %w", err)
	}
	return nil
}

// GetRefreshTokenSession retrieves a refresh token session by signature.
// Returns fosite.ErrNotFound when the token does not exist.
func (s *RefreshTokenStore) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT request_id, client_id, subject, scopes, expires_at, revoked
		   FROM refresh_tokens WHERE signature = ?`, signature)

	var (
		requestID string
		clientID  string
		subject   string
		scopes    string
		expiresAt string
		revoked   int
	)

	if err := row.Scan(&requestID, &clientID, &subject, &scopes, &expiresAt, &revoked); err != nil {
		if err == sql.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetRefreshTokenSession: %w", err)
	}

	if revoked != 0 {
		return nil, fosite.ErrTokenSignatureMismatch
	}

	expiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("storage: GetRefreshTokenSession parse expires_at: %w", err)
	}
	if time.Now().After(expiry) {
		return nil, fosite.ErrTokenExpired
	}

	if session != nil {
		setSessionSubject(session, subject)
		session.SetExpiresAt(fosite.RefreshToken, expiry)
	}

	req := fosite.NewRequest()
	req.ID = requestID
	req.SetSession(session)
	req.GrantedScope = strings.Fields(scopes)

	return req, nil
}

// DeleteRefreshTokenSession removes a refresh token session by signature.
func (s *RefreshTokenStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE signature = ?`, signature)
	if err != nil {
		return fmt.Errorf("storage: DeleteRefreshTokenSession: %w", err)
	}
	return nil
}

// RevokeRefreshToken marks a refresh token as revoked without deleting it
// (required by fosite's RevokeRefreshTokenMayRace flow).
func (s *RefreshTokenStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked = 1 WHERE request_id = ?`, requestID)
	if err != nil {
		return fmt.Errorf("storage: RevokeRefreshToken: %w", err)
	}
	return nil
}

// RevokeRefreshTokenMayRace satisfies fosite's optional interface.
func (s *RefreshTokenStore) RevokeRefreshTokenMayRace(ctx context.Context, requestID string) error {
	return s.RevokeRefreshToken(ctx, requestID)
}

// RotateRefreshToken rotates a refresh token, required by oauth2.RefreshTokenStorage.
func (s *RefreshTokenStore) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	return s.RevokeRefreshToken(ctx, requestID)
}

// ---------------------------------------------------------------------------
// OpenIDConnectRequestStore
// ---------------------------------------------------------------------------

// OpenIDConnectRequestStore persists and retrieves fosite OIDC sessions.
type OpenIDConnectRequestStore struct {
	db *sql.DB
}

// NewOpenIDConnectRequestStore returns an OpenIDConnectRequestStore backed by db.
func NewOpenIDConnectRequestStore(db *sql.DB) *OpenIDConnectRequestStore {
	return &OpenIDConnectRequestStore{db: db}
}

// CreateOpenIDConnectSession stores an OIDC session keyed by the authorize code.
func (s *OpenIDConnectRequestStore) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, request fosite.Requester) error {
	expiresAt := request.GetSession().GetExpiresAt(fosite.AuthorizeCode)
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(10 * time.Minute)
	}

	// Serialize the session as JSON so it can be fully restored later.
	sessionJSON, err := json.Marshal(request.GetSession())
	if err != nil {
		return fmt.Errorf("storage: CreateOpenIDConnectSession marshal session: %w", err)
	}

	// Serialize the request form as JSON to preserve nonce and other params.
	formJSON, err := json.Marshal(map[string][]string(request.GetRequestForm()))
	if err != nil {
		return fmt.Errorf("storage: CreateOpenIDConnectSession marshal form: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, client_id, subject, scopes, expires_at, session_data, form_data)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		authorizeCode,
		request.GetClient().GetID(),
		request.GetSession().GetSubject(),
		strings.Join(request.GetGrantedScopes(), " "),
		expiresAt.UTC().Format(time.RFC3339),
		string(sessionJSON),
		string(formJSON),
	)
	if err != nil {
		return fmt.Errorf("storage: CreateOpenIDConnectSession: %w", err)
	}
	return nil
}

// GetOpenIDConnectSession retrieves an OIDC session by authorize code.
// Returns fosite.ErrNotFound when no session exists for the code.
func (s *OpenIDConnectRequestStore) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, request fosite.Requester) (fosite.Requester, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT client_id, subject, scopes, expires_at, session_data, form_data
		   FROM sessions WHERE id = ?`, authorizeCode)

	var (
		clientID    string
		subject     string
		scopes      string
		expiresAt   string
		sessionData string
		formData    string
	)

	if err := row.Scan(&clientID, &subject, &scopes, &expiresAt, &sessionData, &formData); err != nil {
		if err == sql.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("storage: GetOpenIDConnectSession: %w", err)
	}

	expiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("storage: GetOpenIDConnectSession parse expires_at: %w", err)
	}

	// Restore the session from the incoming request (which carries the correct session type).
	sess := request.GetSession()

	// Attempt to unmarshal the stored session data into the session.
	// This restores IDTokenClaims including nonce, auth_time, etc.
	if sessionData != "" && sessionData != "{}" {
		if err := json.Unmarshal([]byte(sessionData), sess); err != nil {
			// If unmarshal fails, fall back to setting subject manually.
			setSessionSubject(sess, subject)
		}
	} else {
		setSessionSubject(sess, subject)
	}

	if sess != nil {
		sess.SetExpiresAt(fosite.AuthorizeCode, expiry)
	}

	// Load the client so fosite can access the client on OIDC token generation.
	clientStore := NewClientStore(s.db)
	client, err := clientStore.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("storage: GetOpenIDConnectSession load client %q: %w", clientID, err)
	}

	req := fosite.NewRequest()
	req.Client = client
	req.SetSession(sess)
	req.GrantedScope = strings.Fields(scopes)

	// Restore the form data so fosite can read nonce and other params.
	if formData != "" && formData != "{}" {
		var formMap map[string][]string
		if err := json.Unmarshal([]byte(formData), &formMap); err == nil {
			req.Form = url.Values(formMap)
		}
	}

	return req, nil
}

// DeleteOpenIDConnectSession removes an OIDC session by authorize code.
func (s *OpenIDConnectRequestStore) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, authorizeCode)
	if err != nil {
		return fmt.Errorf("storage: DeleteOpenIDConnectSession: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Store — composite store satisfying all fosite storage interfaces
// ---------------------------------------------------------------------------

// Store bundles all store types into a single value that can be passed to
// fosite.NewOAuth2Provider as the Storage argument.
type Store struct {
	*ClientStore
	*AuthorizeCodeStore
	*AccessTokenStore
	*RefreshTokenStore
	*OpenIDConnectRequestStore
}

// New returns a composite Store backed by db, with all tables already
// created via migrations.
func New(db *sql.DB) *Store {
	return &Store{
		ClientStore:               NewClientStore(db),
		AuthorizeCodeStore:        NewAuthorizeCodeStore(db),
		AccessTokenStore:          NewAccessTokenStore(db),
		RefreshTokenStore:         NewRefreshTokenStore(db),
		OpenIDConnectRequestStore: NewOpenIDConnectRequestStore(db),
	}
}

// setSessionSubject attempts to set the Subject field on the session through
// type assertions against known fosite session types. It also propagates the
// subject into ID token claims and JWT access token claims when available.
func setSessionSubject(session fosite.Session, subject string) {
	// Set the top-level Subject field via SetSubject if available.
	if setter, ok := session.(interface{ SetSubject(string) }); ok {
		setter.SetSubject(subject)
	}

	// Also set IDTokenClaims.Subject for OIDC id_token generation.
	if oidcSession, ok := session.(interface {
		IDTokenClaims() *jwt.IDTokenClaims
	}); ok {
		if claims := oidcSession.IDTokenClaims(); claims != nil {
			claims.Subject = subject
		}
	}

	// Also set JWTClaims.Subject for JWT access token generation.
	type jwtClaimsGetter interface {
		GetJWTClaims() jwt.JWTClaimsContainer
	}
	if jwtSession, ok := session.(jwtClaimsGetter); ok {
		if jwtClaims, ok := jwtSession.GetJWTClaims().(*jwt.JWTClaims); ok && jwtClaims != nil {
			jwtClaims.Subject = subject
		}
	}
}

