package handler

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"

	"github.com/ory/fosite"

	"github.com/dlddu/my-auth/internal/config"
)

// oauthTemplates holds the parsed consent page templates.
// Initialised in init() alongside loginTemplates.
var oauthTemplates *template.Template

func init() {
	tmpl, err := template.ParseFS(templateFS, "templates/base.html", "templates/consent.html")
	if err != nil {
		panic(fmt.Sprintf("handler: parse consent templates: %v", err))
	}
	oauthTemplates = tmpl
}

// consentPageData holds the data rendered into consent.html.
type consentPageData struct {
	// ClientName is the human-readable name of the OAuth2 client.
	ClientName string
	// ClientDomain is the primary domain of the client application.
	ClientDomain string
	// Scopes is the list of OAuth2 scopes the client is requesting.
	Scopes []string
	// Challenge is an opaque value that carries the fosite authorize request
	// across the GET → POST consent round-trip.
	Challenge string
	// QueryString is the raw query string from the original GET /oauth2/auth
	// request. It is appended to the consent form's POST action so that fosite
	// can re-parse the OAuth2 parameters (response_type, client_id, etc.) from
	// r.URL.Query() when handling the POST.
	QueryString string
}

// NewOAuth2AuthHandler returns an http.HandlerFunc that handles both the
// GET and POST /oauth2/auth endpoints.
//
// GET  /oauth2/auth  — fosite authorise request validation; redirect to /login
//
//	if the user is unauthenticated; render consent page otherwise.
//
// POST /oauth2/auth  — consent form submission (approve / deny).
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
// It delegates to fosite to validate the authorise request parameters, then
// either redirects unauthenticated users to /login or renders the consent page.
func handleOAuth2AuthGet(w http.ResponseWriter, r *http.Request, cfg *config.Config, db *sql.DB, provider fosite.OAuth2Provider) {
	// 미인증 사용자를 로그인 페이지로 리다이렉트한다.
	if !IsAuthenticated(r, db, cfg.SessionSecret) {
		http.Redirect(w, r, "/login?return_to=/oauth2/auth", http.StatusFound)
		return
	}

	// fosite로 인가 요청을 파싱하고 검증한다.
	ctx := r.Context()
	authReq, err := provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, authReq, err)
		return
	}

	// challenge 값을 폼에 포함시켜 POST 단계에서 fosite 요청을 복원할 수 있도록 한다.
	challenge := authReq.GetID()

	// 요청된 스코프 목록을 렌더링용으로 변환한다.
	scopes := []string(authReq.GetRequestedScopes())

	data := consentPageData{
		ClientName:   authReq.GetClient().GetID(),
		ClientDomain: "",
		Scopes:       scopes,
		Challenge:    challenge,
		QueryString:  r.URL.RawQuery,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := oauthTemplates.ExecuteTemplate(w, "base", data); err != nil {
		_ = err
	}
}

// handleOAuth2AuthPost processes POST /oauth2/auth (consent form submission).
func handleOAuth2AuthPost(w http.ResponseWriter, r *http.Request, cfg *config.Config, db *sql.DB, provider fosite.OAuth2Provider) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	action := r.FormValue("action")

	// fosite で authorize request を再構築する。
	// 実装フェーズでは challenge から復元するが、ここではスタブとして
	// NewAuthorizeRequest を再度呼び出す。
	ctx := r.Context()
	authReq, err := provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, authReq, err)
		return
	}

	if action != "approve" {
		// ユーザーが拒否した場合はエラーを返す。
		provider.WriteAuthorizeError(ctx, w, authReq, fosite.ErrAccessDenied)
		return
	}

	// ユーザーが承認した: スコープを付与して authorization code を発行する。
	for _, scope := range authReq.GetRequestedScopes() {
		authReq.GrantScope(scope)
	}

	// 認証済みユーザーのサブジェクトを取得する。
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
