package handler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dlddu/my-auth/internal/config"
)

//go:embed templates/*.html
var templateFS embed.FS

// loginTemplates holds the parsed login page templates.
var loginTemplates *template.Template

func init() {
	tmpl, err := template.ParseFS(templateFS, "templates/base.html", "templates/login.html")
	if err != nil {
		// Templates are embedded at compile time; a parse error is a programmer error.
		panic(fmt.Sprintf("handler: parse login templates: %v", err))
	}
	loginTemplates = tmpl
}

// loginPageData holds the data rendered into login.html.
type loginPageData struct {
	Error    string
	Username string
	ReturnTo string
}

// sessionCookieName is the name of the session cookie set after a successful login.
const sessionCookieName = "session"

// sessionTTL is how long a user session remains valid.
const sessionTTL = 24 * time.Hour

// NewLoginHandler returns an http.HandlerFunc that handles GET and POST /login.
//
// GET  → renders the login form.
// POST → validates credentials; on success creates a session and redirects;
//
//	on failure re-renders the form with an error message.
func NewLoginHandler(cfg *config.Config, db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleLoginGet(w, r)
		case http.MethodPost:
			handleLoginPost(w, r, cfg, db)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// handleLoginGet renders the login form for GET /login.
func handleLoginGet(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")
	data := loginPageData{
		ReturnTo: sanitizeReturnTo(returnTo),
	}
	renderLoginPage(w, http.StatusOK, data)
}

// handleLoginPost processes the login form submission for POST /login.
func handleLoginPost(w http.ResponseWriter, r *http.Request, cfg *config.Config, db *sql.DB) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	returnTo := sanitizeReturnTo(r.FormValue("return_to"))

	// Validate credentials against the owner config.
	credErr := validateCredentials(cfg, username, password)
	if credErr != nil {
		data := loginPageData{
			Error:    "Invalid username or password.",
			Username: username,
			ReturnTo: returnTo,
		}
		renderLoginPage(w, http.StatusOK, data)
		return
	}

	// Create a new user session in the database.
	sessionID, err := createUserSession(db, username)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Sign the session ID so the cookie value cannot be forged.
	cookieValue := signSessionID(sessionID, cfg.SessionSecret)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(sessionTTL),
	})

	target := returnTo
	if target == "" {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// validateCredentials checks the provided username/password against cfg.
func validateCredentials(cfg *config.Config, username, password string) error {
	if !strings.EqualFold(username, cfg.Owner.Username) {
		// Use a constant-time-equivalent path to prevent user enumeration via timing.
		// We still run bcrypt on a dummy value to keep timing consistent.
		_ = bcrypt.CompareHashAndPassword([]byte(cfg.Owner.PasswordHash), []byte(password))
		return fmt.Errorf("invalid credentials")
	}
	return bcrypt.CompareHashAndPassword([]byte(cfg.Owner.PasswordHash), []byte(password))
}

// createUserSession inserts a new row into user_sessions and returns the session ID.
func createUserSession(db *sql.DB, username string) (string, error) {
	id, err := generateSessionID()
	if err != nil {
		return "", fmt.Errorf("handler: generate session id: %w", err)
	}

	expiresAt := time.Now().Add(sessionTTL).UTC().Format(time.RFC3339)

	_, err = db.Exec(
		`INSERT INTO user_sessions (id, username, expires_at) VALUES (?, ?, ?)`,
		id, username, expiresAt,
	)
	if err != nil {
		return "", fmt.Errorf("handler: insert user session: %w", err)
	}

	return id, nil
}

// generateSessionID returns a cryptographically random 32-byte hex string.
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// signSessionID produces an HMAC-SHA256 signature over sessionID using secret
// and returns "<sessionID>.<signature>" as the cookie value.
// If secret is empty the session ID is used as-is (for zero-config test environments).
func signSessionID(sessionID, secret string) string {
	if secret == "" {
		return sessionID
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(sessionID))
	sig := hex.EncodeToString(mac.Sum(nil))
	return sessionID + "." + sig
}

// parseSessionCookie extracts and verifies the session ID from the cookie value.
// It returns the raw session ID on success or an error if the value is invalid.
func parseSessionCookie(cookieValue, secret string) (string, error) {
	if secret == "" {
		return cookieValue, nil
	}

	parts := strings.SplitN(cookieValue, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("handler: malformed session cookie")
	}

	sessionID := parts[0]
	providedSig := parts[1]

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(sessionID))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(providedSig), []byte(expectedSig)) {
		return "", fmt.Errorf("handler: invalid session cookie signature")
	}

	return sessionID, nil
}

// IsAuthenticated checks whether the request carries a valid, non-expired
// session cookie and that the corresponding row exists in user_sessions.
func IsAuthenticated(r *http.Request, db *sql.DB, secret string) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}

	sessionID, err := parseSessionCookie(cookie.Value, secret)
	if err != nil {
		return false
	}

	var expiresAt string
	row := db.QueryRow(
		`SELECT expires_at FROM user_sessions WHERE id = ?`, sessionID,
	)
	if err := row.Scan(&expiresAt); err != nil {
		return false
	}

	expiry, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return false
	}

	return time.Now().Before(expiry)
}

// sanitizeReturnTo validates that returnTo is a safe relative URL.
// It returns the sanitised value or an empty string if the URL is not safe.
func sanitizeReturnTo(returnTo string) string {
	if returnTo == "" {
		return ""
	}
	// Only allow relative paths that start with / but not //
	// (// would be protocol-relative and could redirect off-site).
	if !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") {
		return ""
	}
	return returnTo
}

// renderLoginPage writes the login page HTML to w with the given status code.
func renderLoginPage(w http.ResponseWriter, status int, data loginPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := loginTemplates.ExecuteTemplate(w, "base", data); err != nil {
		// Headers already sent; nothing useful we can do except log.
		_ = err
	}
}
