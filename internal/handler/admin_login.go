package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/dlddu/my-auth/internal/config"
)

// adminLoginInput is the JSON body accepted by POST /api/admin/login.
type adminLoginInput struct {
	ID       string `json:"id"`
	Password string `json:"password"`
}

// generateSessionToken generates a cryptographically random hex string
// suitable for use as an admin session token.
func generateSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("admin_login: rand.Read: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// NewAdminLoginHandler returns an http.HandlerFunc that handles
// POST /api/admin/login.
//
// On success it issues an admin_session cookie (HttpOnly, SameSite=Strict)
// and returns 200 JSON { "ok": true }.
// On failure it returns 401 JSON { "error": "invalid credentials" }.
// On a missing or malformed body it returns 400 JSON { "error": "invalid JSON body" }.
func NewAdminLoginHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input adminLoginInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		// Treat an empty body (both id and password are zero values) as invalid.
		if input.ID == "" && input.Password == "" {
			writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		// Verify username.
		if input.ID != cfg.Owner.Username {
			writeAdminError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		// Verify password with bcrypt.
		if err := bcrypt.CompareHashAndPassword([]byte(cfg.Owner.PasswordHash), []byte(input.Password)); err != nil {
			writeAdminError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		// Generate session token and store it.
		token := generateSessionToken()
		adminSessionStore.Set(token)

		// Set cookie.
		http.SetCookie(w, &http.Cookie{
			Name:     "admin_session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		writeAdminJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}
