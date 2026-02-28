package handler

import (
	"crypto/rsa"
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	fositeOIDC "github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"

	"github.com/dlddu/my-auth/internal/config"
	"github.com/dlddu/my-auth/internal/storage"
)

// consentTemplates holds the parsed consent page templates.
var consentTemplates *template.Template

func init() {
	tmpl, err := template.ParseFS(templateFS, "templates/base.html", "templates/consent.html")
	if err != nil {
		panic(fmt.Sprintf("handler: parse consent templates: %v", err))
	}
	consentTemplates = tmpl
}

// consentPageData holds the data rendered into consent.html.
type consentPageData struct {
	ClientID     string
	Scopes       []string
	ResponseType string
	RedirectURI  string
	Scope        string
	State        string
	Nonce        string
}

// NewOAuth2Provider creates and returns a fosite OAuth2Provider configured
// with the authorization code, refresh token, and OIDC explicit flows.
func NewOAuth2Provider(store *storage.Store, cfg *config.Config, privateKey *rsa.PrivateKey) fosite.OAuth2Provider {
	// Derive a 32-byte HMAC secret from the session secret.
	// For production, this should come from a dedicated configuration field.
	hmacSecret := deriveHMACSecret(cfg.SessionSecret)

	fositeConfig := &fosite.Config{
		AccessTokenLifespan:   time.Hour,
		AuthorizeCodeLifespan: 10 * time.Minute,
		RefreshTokenLifespan:  24 * time.Hour,
		IDTokenIssuer:         cfg.Issuer,
		ScopeStrategy:         fosite.WildcardScopeStrategy,
		GlobalSecret:          hmacSecret,
	}

	// Wrap the RSA private key in a JWT signing strategy.
	jwkSigner := &jwt.RS256JWTStrategy{
		PrivateKey: privateKey,
	}

	// HMAC strategy for non-JWT tokens (refresh tokens, authorization codes).
	hmacStrategy := compose.NewOAuth2HMACStrategy(fositeConfig)

	// Core hybrid strategy: JWT access tokens + HMAC for auth codes / refresh tokens.
	coreStrategy := compose.NewOAuth2JWTStrategy(jwkSigner, hmacStrategy, fositeConfig)

	// OIDC token strategy for ID tokens.
	oidcStrategy := compose.NewOpenIDConnectStrategy(fositeConfig, jwkSigner)

	strategy := &compose.CommonStrategy{
		CoreStrategy:               coreStrategy,
		OpenIDConnectTokenStrategy: oidcStrategy,
	}

	provider := compose.Compose(
		fositeConfig,
		store,
		strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)

	return provider
}

// NewAuthorizeHandler returns an http.HandlerFunc that handles both
// GET /oauth2/auth (renders consent page) and POST /oauth2/auth (processes
// consent approval or denial).
func NewAuthorizeHandler(provider fosite.OAuth2Provider, cfg *config.Config, db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleAuthorizeGet(w, r, provider, cfg, db)
		case http.MethodPost:
			handleAuthorizePost(w, r, provider, cfg, db)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// handleAuthorizeGet handles GET /oauth2/auth.
// If the user is not authenticated it redirects to /login.
// Otherwise it validates the OAuth2 request and renders the consent page.
func handleAuthorizeGet(w http.ResponseWriter, r *http.Request, provider fosite.OAuth2Provider, cfg *config.Config, db *sql.DB) {
	if !IsAuthenticated(r, db, cfg.SessionSecret) {
		http.Redirect(w, r, "/login?return_to="+r.URL.RequestURI(), http.StatusFound)
		return
	}

	ctx := r.Context()

	ar, err := provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	q := r.URL.Query()
	scope := q.Get("scope")
	scopes := strings.Fields(scope)

	data := consentPageData{
		ClientID:     ar.GetClient().GetID(),
		Scopes:       scopes,
		ResponseType: q.Get("response_type"),
		RedirectURI:  q.Get("redirect_uri"),
		Scope:        scope,
		State:        q.Get("state"),
		Nonce:        q.Get("nonce"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := consentTemplates.ExecuteTemplate(w, "base", data); err != nil {
		_ = err
	}
}

// handleAuthorizePost handles POST /oauth2/auth.
// It processes the consent form submission, granting or denying access.
func handleAuthorizePost(w http.ResponseWriter, r *http.Request, provider fosite.OAuth2Provider, cfg *config.Config, db *sql.DB) {
	if !IsAuthenticated(r, db, cfg.SessionSecret) {
		http.Redirect(w, r, "/login?return_to=/oauth2/auth", http.StatusFound)
		return
	}

	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ar, err := provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	action := r.FormValue("action")

	if action != "approve" {
		// User denied consent.
		provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrAccessDenied)
		return
	}

	// User approved — build the session with the authenticated user as subject.
	subject := getSessionSubject(r, db, cfg.SessionSecret)

	mySession := &fositeOIDC.DefaultSession{
		Subject: subject,
		Claims: &fositeOIDC.IDTokenClaims{
			Issuer:      cfg.Issuer,
			Subject:     subject,
			IssuedAt:    time.Now().UTC(),
			RequestedAt: time.Now().UTC(),
			AuthTime:    time.Now().UTC(),
		},
		Headers: &fositeOIDC.Headers{},
	}

	// Grant all requested scopes.
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	resp, err := provider.NewAuthorizeResponse(ctx, ar, mySession)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	provider.WriteAuthorizeResponse(ctx, w, ar, resp)
}

// NewTokenHandler returns an http.HandlerFunc that handles POST /oauth2/token.
func NewTokenHandler(provider fosite.OAuth2Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		mySession := fositeOIDC.NewDefaultSession()

		ar, err := provider.NewAccessRequest(ctx, r, mySession)
		if err != nil {
			provider.WriteAccessError(ctx, w, ar, err)
			return
		}

		// Grant all requested scopes.
		for _, scope := range ar.GetRequestedScopes() {
			ar.GrantScope(scope)
		}

		resp, err := provider.NewAccessResponse(ctx, ar)
		if err != nil {
			provider.WriteAccessError(ctx, w, ar, err)
			return
		}

		provider.WriteAccessResponse(ctx, w, ar, resp)
	}
}

// deriveHMACSecret creates a fixed-length 32-byte slice from the session
// secret string. It is used to seed the fosite HMAC strategy.
func deriveHMACSecret(sessionSecret string) []byte {
	raw := []byte(sessionSecret)
	out := make([]byte, 32)
	copy(out, raw)
	return out
}

// getSessionSubject retrieves the username associated with the current
// session cookie. Falls back to "unknown" if the session cannot be resolved.
func getSessionSubject(r *http.Request, db *sql.DB, secret string) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "unknown"
	}

	sessionID, err := parseSessionCookie(cookie.Value, secret)
	if err != nil {
		return "unknown"
	}

	var username string
	row := db.QueryRow(
		`SELECT username FROM user_sessions WHERE id = ?`, sessionID,
	)
	if err := row.Scan(&username); err != nil {
		return "unknown"
	}

	return username
}
