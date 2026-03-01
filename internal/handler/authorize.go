package handler

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	josejwt "github.com/ory/fosite/token/jwt"

	"github.com/dlddu/my-auth/internal/config"
)

// consentTemplates holds the parsed consent page templates.
var consentTemplates *template.Template

func init() {
	tmpl, err := template.ParseFS(templateFS, "templates/base.html", "templates/consent.html")
	if err != nil {
		// Templates are embedded at compile time; a parse error is a programmer error.
		panic(fmt.Sprintf("handler: parse consent templates: %v", err))
	}
	consentTemplates = tmpl
}

// consentPageData holds the data rendered into consent.html.
type consentPageData struct {
	// ClientID is the OAuth2 client identifier displayed on the consent page.
	ClientID string
	// Scopes is the list of scopes requested by the client.
	Scopes []string
	// AuthURL is the full authorization URL with query string used as the form action.
	AuthURL string
}

// NewAuthorizeHandler returns an http.HandlerFunc that handles GET and POST /oauth2/auth.
//
// GET  → checks authentication; unauthenticated users are redirected to /login;
//
//	authenticated users see the consent page rendered by fosite.
//
// POST → processes the consent form; approve grants scopes and redirects with code;
//
//	deny writes an access_denied error response via fosite.
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
// Unauthenticated requests are redirected to /login with return_to set to the
// full original URL including query string. Authenticated requests are handed
// off to fosite for validation; on success the consent page is rendered.
func handleAuthorizeGet(w http.ResponseWriter, r *http.Request, provider fosite.OAuth2Provider, cfg *config.Config, db *sql.DB) {
	if !IsAuthenticated(r, db, cfg.SessionSecret) {
		// Preserve the full request path + query string in return_to so that
		// after login the user is sent back to the authorize endpoint with all
		// the original OAuth2 parameters intact.
		originalURL := "/oauth2/auth"
		if qs := r.URL.RawQuery; qs != "" {
			originalURL = "/oauth2/auth?" + qs
		}
		http.Redirect(w, r, "/login?return_to="+originalURL, http.StatusFound)
		return
	}

	ctx := r.Context()

	ar, err := provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Build the full authorization URL for the consent form action so that
	// the POST request carries all OAuth2 parameters in the query string as
	// fosite's NewAuthorizeRequest expects.
	authURL := "/oauth2/auth"
	if qs := r.URL.RawQuery; qs != "" {
		authURL = "/oauth2/auth?" + qs
	}

	data := consentPageData{
		ClientID: ar.GetClient().GetID(),
		Scopes:   ar.GetRequestedScopes(),
		AuthURL:  authURL,
	}

	renderConsentPage(w, http.StatusOK, data)
}

// handleAuthorizePost handles POST /oauth2/auth.
// It reads the "action" form field (approve or deny) and uses the fosite
// provider to write the appropriate authorize response or error.
func handleAuthorizePost(w http.ResponseWriter, r *http.Request, provider fosite.OAuth2Provider, cfg *config.Config, db *sql.DB) {
	if !IsAuthenticated(r, db, cfg.SessionSecret) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	ctx := r.Context()

	ar, err := provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Parse the form to read the action field.
	if err := r.ParseForm(); err != nil {
		provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrServerError.WithDebug(err.Error()))
		return
	}

	action := r.FormValue("action")

	if action == "deny" {
		provider.WriteAuthorizeError(ctx, w, ar, fosite.ErrAccessDenied)
		return
	}

	// Approve: grant all requested scopes.
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	// Retrieve the authenticated user's username from the session cookie to
	// populate the OIDC session subject.
	username := authenticatedUsername(r, db, cfg.SessionSecret)

	// Build an openid.DefaultSession populated with the authenticated subject.
	mySession := &openid.DefaultSession{
		Claims: &josejwt.IDTokenClaims{
			Subject:   username,
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
			Issuer:    cfg.Issuer,
		},
		Headers: &josejwt.Headers{},
		Subject: username,
	}

	response, err := provider.NewAuthorizeResponse(ctx, ar, mySession)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	provider.WriteAuthorizeResponse(ctx, w, ar, response)
}

// authenticatedUsername extracts the username of the currently authenticated
// user from the session cookie. It returns an empty string if no valid session
// is found; callers should ensure IsAuthenticated returned true first.
func authenticatedUsername(r *http.Request, db *sql.DB, secret string) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}

	sessionID, err := parseSessionCookie(cookie.Value, secret)
	if err != nil {
		return ""
	}

	var username string
	row := db.QueryRow(`SELECT username FROM user_sessions WHERE id = ?`, sessionID)
	if err := row.Scan(&username); err != nil {
		return ""
	}

	return username
}

// renderConsentPage writes the consent page HTML to w with the given status code.
func renderConsentPage(w http.ResponseWriter, status int, data consentPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := consentTemplates.ExecuteTemplate(w, "base", data); err != nil {
		// Headers already sent; nothing useful we can do except discard.
		_ = err
	}
}
