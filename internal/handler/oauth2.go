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
// GET  → checks authentication; if not authenticated redirects to /login;
//
//	if authenticated, parses the authorize request and renders the consent page.
//
// POST → processes the consent form; approve issues an authorization code;
//
//	deny redirects to the client with error=access_denied.
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

// handleAuthorizeGet handles GET /oauth2/auth.
func handleAuthorizeGet(w http.ResponseWriter, r *http.Request, cfg *config.Config, db *sql.DB, provider fosite.OAuth2Provider) {
	// Check authentication.
	if !IsAuthenticated(r, db, cfg.SessionSecret) {
		// Build the return_to URL with all query parameters preserved.
		returnTo := "/oauth2/auth?" + r.URL.RawQuery
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
		return
	}

	ctx := r.Context()

	// Parse the OAuth2 authorize request.
	ar, err := provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		provider.WriteAuthorizeError(w, ar, err)
		return
	}

	// Render the consent page.
	scopes := make([]string, 0, len(ar.GetRequestedScopes()))
	for _, s := range ar.GetRequestedScopes() {
		scopes = append(scopes, s)
	}

	data := consentPageData{
		ClientID:    ar.GetClient().GetID(),
		ClientName:  ar.GetClient().GetID(),
		Scopes:      scopes,
		QueryString: r.URL.RawQuery,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := consentTemplates.ExecuteTemplate(w, "base", data); err != nil {
		_ = err
	}
}

// handleAuthorizePost handles POST /oauth2/auth (consent form submission).
func handleAuthorizePost(w http.ResponseWriter, r *http.Request, cfg *config.Config, db *sql.DB, provider fosite.OAuth2Provider) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Re-parse the authorize request from the form data.
	ar, err := provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		provider.WriteAuthorizeError(w, ar, err)
		return
	}

	action := r.FormValue("action")
	if action == "deny" {
		provider.WriteAuthorizeError(w, ar, fosite.ErrAccessDenied)
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
		provider.WriteAuthorizeError(w, ar, err)
		return
	}

	provider.WriteAuthorizeResponse(w, ar, resp)
}

// NewTokenHandler returns an http.HandlerFunc that handles POST /oauth2/token.
func NewTokenHandler(provider fosite.OAuth2Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Create an empty OIDC session that fosite will populate.
		mySession := newEmptyOIDCSession()

		ar, err := provider.NewAccessRequest(ctx, r, mySession)
		if err != nil {
			provider.WriteAccessError(w, ar, err)
			return
		}

		resp, err := provider.NewAccessResponse(ctx, ar)
		if err != nil {
			provider.WriteAccessError(w, ar, err)
			return
		}

		provider.WriteAccessResponse(w, ar, resp)
	}
}
