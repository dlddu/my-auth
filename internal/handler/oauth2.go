package handler

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/ory/fosite"

	"github.com/dlddu/my-auth/internal/config"
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
	ClientID    string
	ClientName  string
	Scopes      []string
	RequestedAt string
	// QueryString contains the raw OAuth2 authorize query parameters so the
	// consent form can embed them as hidden fields and POST them back to
	// /oauth2/auth for fosite to re-parse.
	QueryString string
}

// getUsernameFromSession retrieves the username associated with the session cookie.
// Returns an empty string if the session is not found or invalid.
func getUsernameFromSession(r *http.Request, db *sql.DB, secret string) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}

	sessionID, err := parseSessionCookie(cookie.Value, secret)
	if err != nil {
		return ""
	}

	var username string
	var expiresAt string
	row := db.QueryRow(
		`SELECT username, expires_at FROM user_sessions WHERE id = ?`, sessionID,
	)
	if err := row.Scan(&username, &expiresAt); err != nil {
		return ""
	}

	expiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return ""
	}

	if time.Now().After(expiry) {
		return ""
	}

	return username
}

// NewAuthorizeHandler returns an http.HandlerFunc that handles GET and POST /oauth2/auth.
//
// GET  → validates the OAuth2 request with fosite first (so invalid client_id /
//
//	redirect_uri returns 4xx per RFC 6749 §4.1.2.1); then checks authentication;
//	if not authenticated redirects to /login; if authenticated redirects to /consent.
//
// POST → processes the consent form submitted directly to /oauth2/auth (used by
//
//	unit tests that POST OAuth2 params in the request body).
func NewAuthorizeHandler(cfg *config.Config, db *sql.DB, provider fosite.OAuth2Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleAuthorizeGet(w, r, cfg, db, provider)
		case http.MethodPost:
			handleAuthorizePost(w, r, cfg, db, provider)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// NewConsentHandler returns an http.HandlerFunc that handles GET and POST /consent.
//
// GET  → renders the consent page for an authenticated user.
// POST → processes the consent decision; approve issues an authorization code;
//
//	deny redirects to the client with error=access_denied.
func NewConsentHandler(cfg *config.Config, db *sql.DB, provider fosite.OAuth2Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleConsentGet(w, r, cfg, db, provider)
		case http.MethodPost:
			handleConsentPost(w, r, cfg, db, provider)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// handleAuthorizeGet handles GET /oauth2/auth.
//
// Validation order (RFC 6749 §4.1.2.1):
//  1. Parse + validate the OAuth2 request with fosite — returns 4xx directly for
//     unknown client_id or mismatched redirect_uri (must not redirect in those cases).
//  2. Check authentication — if not authenticated redirect to /login.
//  3. Redirect authenticated users to /consent so the consent page URL contains
//     "/consent", which lets E2E tests locate the consent screen reliably.
func handleAuthorizeGet(w http.ResponseWriter, r *http.Request, cfg *config.Config, db *sql.DB, provider fosite.OAuth2Provider) {
	ctx := r.Context()

	// Step 1: Validate the OAuth2 authorize request BEFORE checking authentication.
	// fosite returns a proper 4xx when client_id is unknown or redirect_uri is
	// not registered, preventing open-redirect abuse (RFC 6749 §4.1.2.1).
	ar, err := provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Step 2: Check authentication.
	if !IsAuthenticated(r, db, cfg.SessionSecret) {
		// Preserve the full authorize query string so the flow can be resumed.
		returnTo := "/oauth2/auth?" + r.URL.RawQuery
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
		return
	}

	// Step 3: Redirect to /consent so the URL contains "/consent".
	// The consent handler will re-parse the authorize request.
	http.Redirect(w, r, "/consent?"+r.URL.RawQuery, http.StatusFound)
}

// handleConsentGet handles GET /consent.
// The user must already be authenticated. The OAuth2 parameters are expected
// in the URL query string (forwarded from /oauth2/auth).
func handleConsentGet(w http.ResponseWriter, r *http.Request, cfg *config.Config, db *sql.DB, provider fosite.OAuth2Provider) {
	// Require authentication.
	if !IsAuthenticated(r, db, cfg.SessionSecret) {
		returnTo := "/oauth2/auth?" + r.URL.RawQuery
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
		return
	}

	ctx := r.Context()

	// Build a synthetic GET request that fosite can parse for the OAuth2 params.
	// The /consent page receives the params in its own query string, but fosite
	// must see them on a /oauth2/auth URL.
	// Use a dummy host so http.NewRequestWithContext parses the URL correctly;
	// fosite reads query params from r.URL.Query(), not the host.
	proxyReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/oauth2/auth?"+r.URL.RawQuery, nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	// Copy cookies so fosite plugins that inspect the request work correctly.
	for _, c := range r.Cookies() {
		proxyReq.AddCookie(c)
	}

	ar, err := provider.NewAuthorizeRequest(ctx, proxyReq)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Render the consent page.
	scopes := make([]string, 0, len(ar.GetRequestedScopes()))
	for _, s := range ar.GetRequestedScopes() {
		scopes = append(scopes, s)
	}

	data := consentPageData{
		ClientID:   ar.GetClient().GetID(),
		ClientName: ar.GetClient().GetID(),
		Scopes:     scopes,
		// Pass the raw query string so the consent form can POST it back.
		QueryString: r.URL.RawQuery,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := consentTemplates.ExecuteTemplate(w, "base", data); err != nil {
		_ = err
	}
}

// handleConsentPost handles POST /consent (consent form submission from the
// /consent page). The consent form POSTs to /consent?{oauth2 query string}.
//
// fosite's NewAuthorizeRequest reads r.Form which — after ParseForm — already
// contains both the URL query params and the POST body. We therefore only need
// to ensure ParseForm has been called before delegating to fosite.
func handleConsentPost(w http.ResponseWriter, r *http.Request, cfg *config.Config, db *sql.DB, provider fosite.OAuth2Provider) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// After ParseForm, r.Form contains URL query params + POST body merged.
	// fosite reads r.Form (via r.FormValue / r.Form.Get), so the OAuth2 params
	// that arrived in the query string are already available.
	//
	// Build a synthetic request pointing at /oauth2/auth with the merged form
	// data so fosite can validate the authorize request correctly.
	proxyReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/oauth2/auth?"+r.URL.RawQuery, nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	proxyReq.Form = r.Form
	proxyReq.PostForm = r.PostForm
	proxyReq.Header = r.Header
	for _, c := range r.Cookies() {
		proxyReq.AddCookie(c)
	}

	ar, err := provider.NewAuthorizeRequest(ctx, proxyReq)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	action := r.FormValue("action")
	if action == "deny" {
		provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrAccessDenied)
		return
	}

	// action == "approve" (or any non-deny value).
	username := getUsernameFromSession(r, db, cfg.SessionSecret)
	if username == "" {
		// Session expired between GET and POST.
		returnTo := "/oauth2/auth?" + r.URL.RawQuery
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
		return
	}

	// Grant the requested scopes.
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	// Build an OIDC session for the authorized user.
	mySession := newOIDCSession(username, ar.GetClient().GetID(), cfg.Issuer, ar)

	// Create the authorize response (issues the code, stores session).
	resp, err := provider.NewAuthorizeResponse(ctx, ar, mySession)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	provider.WriteAuthorizeResponse(ctx, w, ar, resp)
}

// handleAuthorizePost handles POST /oauth2/auth (consent form submission).
// This handler is kept for backward-compatibility with unit tests that POST
// OAuth2 parameters directly to /oauth2/auth in the request body.
func handleAuthorizePost(w http.ResponseWriter, r *http.Request, cfg *config.Config, db *sql.DB, provider fosite.OAuth2Provider) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Merge URL query params into PostForm so fosite can read them regardless
	// of whether they were sent in the query string or the body.
	for key, values := range r.URL.Query() {
		for _, v := range values {
			if r.PostForm.Get(key) == "" {
				r.PostForm.Set(key, v)
			}
		}
	}
	for key, values := range r.PostForm {
		r.Form[key] = values
	}

	// Re-parse the authorize request from the merged form data.
	ar, err := provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	action := r.FormValue("action")
	if action == "deny" {
		provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrAccessDenied)
		return
	}

	// action == "approve" (or any non-deny value).
	// Get the authenticated user.
	username := getUsernameFromSession(r, db, cfg.SessionSecret)
	if username == "" {
		// Session expired between GET and POST.
		returnTo := "/oauth2/auth?" + r.URL.RawQuery
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
		return
	}

	// Grant the requested scopes.
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	// Build an OIDC session for the authorized user.
	mySession := newOIDCSession(username, ar.GetClient().GetID(), cfg.Issuer, ar)

	// Create the authorize response (issues the code, stores session).
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

		// Create an empty OIDC session that fosite will populate.
		mySession := newEmptyOIDCSession()

		ar, err := provider.NewAccessRequest(ctx, r, mySession)
		if err != nil {
			provider.WriteAccessError(ctx, w, ar, err)
			return
		}

		resp, err := provider.NewAccessResponse(ctx, ar)
		if err != nil {
			provider.WriteAccessError(ctx, w, ar, err)
			return
		}

		provider.WriteAccessResponse(ctx, w, ar, resp)
	}
}
