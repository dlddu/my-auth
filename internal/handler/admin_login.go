package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

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
// For JSON requests (Content-Type: application/json):
// On success it issues an admin_session cookie and returns 200 JSON { "ok": true }.
// On failure it returns 401 JSON { "error": "invalid credentials" }.
// On a missing or malformed body it returns 400 JSON { "error": "invalid JSON body" }.
//
// For form requests (Content-Type: application/x-www-form-urlencoded):
// On success it issues an admin_session cookie and redirects 303 to /admin.
// On failure it sets a login_error cookie and redirects 303 to /admin/login.
func NewAdminLoginHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		isFormPost := strings.HasPrefix(ct, "application/x-www-form-urlencoded")

		var inputID, inputPassword string

		if isFormPost {
			if err := r.ParseForm(); err != nil {
				http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
				return
			}
			inputID = r.FormValue("id")
			inputPassword = r.FormValue("password")
		} else {
			var input adminLoginInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			inputID = input.ID
			inputPassword = input.Password
		}

		// Treat an empty body (both id and password are zero values) as invalid.
		if inputID == "" && inputPassword == "" {
			if isFormPost {
				http.SetCookie(w, &http.Cookie{Name: "login_error", Value: "1", Path: "/"})
				http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
				return
			}
			writeAdminError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		// Verify username.
		if inputID != cfg.Owner.Username {
			if isFormPost {
				http.SetCookie(w, &http.Cookie{Name: "login_error", Value: "1", Path: "/"})
				http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
				return
			}
			writeAdminError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		// Verify password with bcrypt.
		if err := bcrypt.CompareHashAndPassword([]byte(cfg.Owner.PasswordHash), []byte(inputPassword)); err != nil {
			if isFormPost {
				http.SetCookie(w, &http.Cookie{Name: "login_error", Value: "1", Path: "/"})
				http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
				return
			}
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

		if isFormPost {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		writeAdminJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}
