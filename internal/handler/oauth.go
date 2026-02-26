package handler

import (
	"database/sql"
	"net/http"
	"net/url"

	"github.com/ory/fosite"

	"github.com/dlddu/my-auth/internal/config"
)

// NewOAuth2AuthHandler returns an http.HandlerFunc that handles both the
// GET and POST /oauth2/auth endpoints.
//
// GET  /oauth2/auth  — fosite authorise request validation; redirect to /login
//
//	if the user is unauthenticated; auto-approve and redirect to callback otherwise.
//
// POST /oauth2/auth  — consent form submission fallback (approve / deny).
func NewOAuth2AuthHandler(cfg *config.Config, db *sql.DB, provider fosite.OAuth2Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleOAuth2AuthGet(w, r, cfg, db, provider)
		case http.MethodPost:
			handleOAuth2AuthPost(w, r, cfg, db, provider)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// handleOAuth2AuthGet processes GET /oauth2/auth.
// It first validates the OAuth2 request parameters via fosite so that
// invalid client_id or redirect_uri mismatches receive proper RFC 6749
// error responses before any authentication check. If the request is
// valid, unauthenticated users are redirected to /login with the full
// query string preserved so the flow can resume after login. Authenticated
// users are auto-approved since this is a single-owner OAuth2 server.
func handleOAuth2AuthGet(w http.ResponseWriter, r *http.Request, cfg *config.Config, db *sql.DB, provider fosite.OAuth2Provider) {
	ctx := r.Context()

	// Validate the OAuth2 request parameters first.
	authReq, err := provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, authReq, err)
		return
	}

	// Redirect unauthenticated users to login.
	if !IsAuthenticated(r, db, cfg.SessionSecret) {
		returnTo := "/oauth2/auth?" + r.URL.RawQuery
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
		return
	}

	// Auto-approve: single-owner server — grant all requested scopes.
	for _, scope := range authReq.GetRequestedScopes() {
		authReq.GrantScope(scope)
	}
	for _, audience := range authReq.GetRequestedAudience() {
		authReq.GrantAudience(audience)
	}

	subject := getSubjectFromSession(r, db, cfg.SessionSecret)
	mySession := newFositeSession(subject, cfg.Issuer)

	resp, err := provider.NewAuthorizeResponse(ctx, authReq, mySession)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, authReq, err)
		return
	}

	provider.WriteAuthorizeResponse(ctx, w, authReq, resp)
}

// handleOAuth2AuthPost processes POST /oauth2/auth (consent form submission).
func handleOAuth2AuthPost(w http.ResponseWriter, r *http.Request, cfg *config.Config, db *sql.DB, provider fosite.OAuth2Provider) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	action := r.FormValue("action")

	ctx := r.Context()
	authReq, err := provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, authReq, err)
		return
	}

	if action != "approve" {
		provider.WriteAuthorizeError(ctx, w, authReq, fosite.ErrAccessDenied)
		return
	}

	for _, scope := range authReq.GetRequestedScopes() {
		authReq.GrantScope(scope)
	}

	for _, audience := range authReq.GetRequestedAudience() {
		authReq.GrantAudience(audience)
	}

	subject := getSubjectFromSession(r, db, cfg.SessionSecret)
	mySession := newFositeSession(subject, cfg.Issuer)

	resp, err := provider.NewAuthorizeResponse(ctx, authReq, mySession)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, authReq, err)
		return
	}

	provider.WriteAuthorizeResponse(ctx, w, authReq, resp)
}

// NewOAuth2TokenHandler returns an http.HandlerFunc that handles POST /oauth2/token.
// It processes authorization_code grants and returns JWT access_token, id_token,
// and refresh_token.
func NewOAuth2TokenHandler(cfg *config.Config, provider fosite.OAuth2Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		accessRequest, err := provider.NewAccessRequest(ctx, r, newFositeSession("", cfg.Issuer))
		if err != nil {
			provider.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		response, err := provider.NewAccessResponse(ctx, accessRequest)
		if err != nil {
			provider.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		provider.WriteAccessResponse(ctx, w, accessRequest, response)
	}
}

// getSubjectFromSession extracts the username from the current user session.
// It returns an empty string when no valid session is found.
func getSubjectFromSession(r *http.Request, db *sql.DB, secret string) string {
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
