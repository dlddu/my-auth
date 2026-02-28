// Package handler — OAuth2/OIDC endpoint handlers.
//
// This file wires a fosite OAuth2 provider and exposes:
//   - GET  /oauth2/auth  — consent page (requires authentication)
//   - POST /oauth2/auth  — approve or deny the authorization request
//   - POST /oauth2/token — token endpoint (authorization_code, refresh_token grants)
package handler

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"

	"github.com/dlddu/my-auth/internal/config"
	"github.com/dlddu/my-auth/internal/storage"
)

// consentTemplates is the parsed consent page template set.
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
	ClientID       string
	Scopes         []string
	ScopeStr       string
	RedirectURI    string
	RedirectDomain string
	State          string
	Nonce          string
	ResponseType   string
}

// OAuth2Handlers bundles the GET/POST /oauth2/auth and POST /oauth2/token handlers.
type OAuth2Handlers struct {
	provider fosite.OAuth2Provider
	cfg      *config.Config
	db       *sql.DB
}

// NewOAuth2Provider creates a new fosite OAuth2 provider backed by the given
// storage and RSA private key.
func NewOAuth2Provider(store *storage.Store, privateKey *rsa.PrivateKey, issuer string) fosite.OAuth2Provider {
	fositeConfig := &compose.Config{
		AccessTokenLifespan:        time.Hour,
		AuthorizeCodeLifespan:      10 * time.Minute,
		IDTokenLifespan:            time.Hour,
		IDTokenIssuer:              issuer,
		RefreshTokenLifespan:       24 * time.Hour,
		RefreshTokenScopes:         []string{},
		ScopeStrategy:              fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy:   fosite.DefaultAudienceMatchingStrategy,
		EnforcePKCE:                false,
	}

	strategy := &compose.CommonStrategy{
		CoreStrategy:               compose.NewOAuth2HMACStrategy(fositeConfig, []byte("some-super-secret-32-byte-value!"), nil),
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(fositeConfig, privateKey),
	}

	return compose.Compose(
		fositeConfig,
		store,
		strategy,
		nil, // hasher — fosite uses BCrypt by default
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)
}

// NewOAuth2Handlers creates an OAuth2Handlers bundle.
func NewOAuth2Handlers(provider fosite.OAuth2Provider, cfg *config.Config, db *sql.DB) *OAuth2Handlers {
	return &OAuth2Handlers{
		provider: provider,
		cfg:      cfg,
		db:       db,
	}
}

// AuthorizeHandler handles GET and POST /oauth2/auth.
func (h *OAuth2Handlers) AuthorizeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsAuthenticated(r, h.db, h.cfg.SessionSecret) {
			// Preserve the full request URL as return_to so the user comes back
			// to the exact authorization request after login.
			returnTo := "/oauth2/auth"
			if r.URL.RawQuery != "" {
				returnTo = "/oauth2/auth?" + r.URL.RawQuery
			}
			http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
			return
		}

		switch r.Method {
		case http.MethodGet:
			h.handleAuthorizeGet(w, r)
		case http.MethodPost:
			h.handleAuthorizePost(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// handleAuthorizeGet renders the consent page for an authenticated user.
func (h *OAuth2Handlers) handleAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ar, err := h.provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		h.provider.WriteAuthorizeError(w, ar, err)
		return
	}

	client := ar.GetClient()
	requestedScopes := ar.GetRequestedScopes()
	redirectURIStr := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")
	responseType := r.URL.Query().Get("response_type")

	// Parse redirect domain for display.
	redirectDomain := ""
	if redirectURIStr != "" {
		if u, err := url.Parse(redirectURIStr); err == nil {
			redirectDomain = u.Host
		}
	}

	data := consentPageData{
		ClientID:       client.GetID(),
		Scopes:         []string(requestedScopes),
		ScopeStr:       strings.Join(requestedScopes, " "),
		RedirectURI:    redirectURIStr,
		RedirectDomain: redirectDomain,
		State:          state,
		Nonce:          nonce,
		ResponseType:   responseType,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := consentTemplates.ExecuteTemplate(w, "base", data); err != nil {
		_ = err
	}
}

// handleAuthorizePost processes the consent form submission (approve or deny).
func (h *OAuth2Handlers) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	action := r.FormValue("action")

	// Reconstruct the authorization request from the POSTed form fields.
	syntheticR := buildSyntheticAuthorizeRequest(r)

	ar, err := h.provider.NewAuthorizeRequest(ctx, syntheticR)
	if err != nil {
		h.provider.WriteAuthorizeError(w, ar, err)
		return
	}

	if action == "deny" {
		h.provider.WriteAuthorizeError(w, ar, fosite.ErrAccessDenied)
		return
	}

	// Grant all requested scopes.
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	// Resolve the authenticated user's subject.
	subject := h.getSubject(r)

	now := time.Now()
	mySession := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      h.cfg.Issuer,
			Subject:     subject,
			Audience:    []string{ar.GetClient().GetID()},
			IssuedAt:    now,
			RequestedAt: now,
			AuthTime:    now,
			Nonce:       r.FormValue("nonce"),
			ExpiresAt:   now.Add(time.Hour),
		},
		Headers: &jwt.Headers{},
		Subject: subject,
	}

	response, err := h.provider.NewAuthorizeResponse(ctx, ar, mySession)
	if err != nil {
		h.provider.WriteAuthorizeError(w, ar, err)
		return
	}

	h.provider.WriteAuthorizeResponse(w, ar, response)
}

// TokenHandler handles POST /oauth2/token.
func (h *OAuth2Handlers) TokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		mySession := &openid.DefaultSession{}

		accessRequest, err := h.provider.NewAccessRequest(ctx, r, mySession)
		if err != nil {
			h.provider.WriteAccessError(w, accessRequest, err)
			return
		}

		// Grant all requested scopes.
		for _, scope := range accessRequest.GetRequestedScopes() {
			accessRequest.GrantScope(scope)
		}

		response, err := h.provider.NewAccessResponse(ctx, accessRequest)
		if err != nil {
			h.provider.WriteAccessError(w, accessRequest, err)
			return
		}

		h.provider.WriteAccessResponse(w, accessRequest, response)
	}
}

// getSubject returns the authenticated user's identifier from the DB session.
func (h *OAuth2Handlers) getSubject(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}

	sessionID, err := parseSessionCookie(cookie.Value, h.cfg.SessionSecret)
	if err != nil {
		return ""
	}

	var username string
	row := h.db.QueryRowContext(context.Background(),
		`SELECT username FROM user_sessions WHERE id = ?`, sessionID)
	if err := row.Scan(&username); err != nil {
		return ""
	}

	return username
}

// buildSyntheticAuthorizeRequest creates an *http.Request that fosite can use
// to parse the authorization parameters from a POST form.
func buildSyntheticAuthorizeRequest(r *http.Request) *http.Request {
	q := url.Values{}
	q.Set("client_id", r.FormValue("client_id"))
	q.Set("redirect_uri", r.FormValue("redirect_uri"))
	q.Set("scope", r.FormValue("scope"))
	q.Set("state", r.FormValue("state"))
	q.Set("nonce", r.FormValue("nonce"))
	q.Set("response_type", r.FormValue("response_type"))

	syntheticURL := &url.URL{
		Scheme:   "https",
		Host:     r.Host,
		Path:     "/oauth2/auth",
		RawQuery: q.Encode(),
	}

	syntheticR, _ := http.NewRequest(http.MethodGet, syntheticURL.String(), nil)
	syntheticR = syntheticR.WithContext(r.Context())

	return syntheticR
}
