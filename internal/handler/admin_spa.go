package handler

import (
	"database/sql"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/dlddu/my-auth/internal/config"
)

//go:embed admin-spa/dist
var adminSPAFS embed.FS

// adminSessionCookieName is the name of the admin session cookie.
const adminSessionCookieName = "admin_session"

// NewAdminSPALoginHandler returns an http.HandlerFunc that handles
// POST /api/admin/auth/login.
//
// On success it creates a user session in the user_sessions table,
// signs the session ID, and returns it both as a JSON token and as
// the admin_session cookie value.
func NewAdminSPALoginHandler(cfg *config.Config, db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			writeAdminError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		if input.Username == "" && input.Password == "" {
			writeAdminError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		if err := validateCredentials(cfg, input.Username, input.Password); err != nil {
			writeAdminError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		sessionID, err := createUserSession(db, input.Username)
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		cookieValue := signSessionID(sessionID, cfg.SessionSecret)

		http.SetCookie(w, &http.Cookie{
			Name:     adminSessionCookieName,
			Value:    cookieValue,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(sessionTTL),
		})

		writeAdminJSON(w, http.StatusOK, map[string]string{
			"token": cookieValue,
		})
	}
}

// NewAdminSessionMiddleware returns a middleware that validates the
// admin_session cookie. Requests without a valid cookie receive a 401
// JSON response.
func NewAdminSessionMiddleware(cfg *config.Config, db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(adminSessionCookieName)
			if err != nil {
				writeAdminError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			sessionID, err := parseSessionCookie(cookie.Value, cfg.SessionSecret)
			if err != nil {
				writeAdminError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			var expiresAt string
			row := db.QueryRow(
				`SELECT expires_at FROM user_sessions WHERE id = ?`, sessionID,
			)
			if err := row.Scan(&expiresAt); err != nil {
				writeAdminError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			expiry, err := time.Parse(time.RFC3339, expiresAt)
			if err != nil {
				writeAdminError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			if time.Now().After(expiry) {
				writeAdminError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// adminDashboardStatsResponse is the JSON response for the dashboard stats endpoint.
type adminDashboardStatsResponse struct {
	Clients        int `json:"clients"`
	ActiveSessions int `json:"active_sessions"`
	Tokens         int `json:"tokens"`
	Auth24h        int `json:"auth_24h"`
}

// NewAdminDashboardStatsHandler returns an http.HandlerFunc that handles
// GET /api/admin/dashboard/stats.
//
// It returns a summary of clients, active sessions, tokens, and recent
// authentications (within the last 24 hours).
func NewAdminDashboardStatsHandler(store AdminSessionTokenStore, db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Count clients from the clients table directly.
		var clientCount int
		if err := db.QueryRowContext(r.Context(),
			`SELECT COUNT(*) FROM clients`).Scan(&clientCount); err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to query clients")
			return
		}

		// Count sessions from AdminSessionTokenStore.
		sessions, err := store.ListSessions(r.Context())
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to list sessions")
			return
		}

		// Count tokens from AdminSessionTokenStore.
		tokens, err := store.ListTokens(r.Context())
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to list tokens")
			return
		}

		// Count authentications in the last 24 hours from user_sessions.
		cutoff := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
		var auth24h int
		if err := db.QueryRowContext(r.Context(),
			`SELECT COUNT(*) FROM user_sessions WHERE created_at >= ?`, cutoff).Scan(&auth24h); err != nil {
			// Fallback: table may not have created_at column; return 0.
			auth24h = 0
		}

		writeAdminJSON(w, http.StatusOK, adminDashboardStatsResponse{
			Clients:        clientCount,
			ActiveSessions: len(sessions),
			Tokens:         len(tokens),
			Auth24h:        auth24h,
		})
	}
}

// adminActivityItem represents a single activity entry in the dashboard.
type adminActivityItem struct {
	Time       string `json:"time"`
	Action     string `json:"action"`
	ClientName string `json:"client_name"`
	Type       string `json:"type"`
}

// NewAdminDashboardActivityHandler returns an http.HandlerFunc that handles
// GET /api/admin/dashboard/activity.
//
// It returns recent login activity sourced from the user_sessions table.
// If no sessions exist it returns an empty JSON array.
func NewAdminDashboardActivityHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.QueryContext(r.Context(),
			`SELECT username, created_at FROM user_sessions ORDER BY created_at DESC LIMIT 20`)
		if err != nil {
			// On error return empty array.
			writeAdminJSON(w, http.StatusOK, []adminActivityItem{})
			return
		}
		defer rows.Close()

		items := make([]adminActivityItem, 0)
		for rows.Next() {
			var username, createdAt string
			if err := rows.Scan(&username, &createdAt); err != nil {
				continue
			}
			items = append(items, adminActivityItem{
				Time:       createdAt,
				Action:     "login",
				ClientName: username,
				Type:       "admin",
			})
		}

		writeAdminJSON(w, http.StatusOK, items)
	}
}

// NewAdminSPAHandler returns an http.Handler that serves the embedded React SPA.
//
// Routing rules:
//   - Requests for paths with a file extension that exist in dist/ are served directly.
//   - Requests for paths with a file extension that do NOT exist return 404.
//   - Requests for paths without a file extension (SPA routes) return index.html.
//   - GET /admin/ returns index.html.
func NewAdminSPAHandler() http.Handler {
	distFS, err := fs.Sub(adminSPAFS, "admin-spa/dist")
	if err != nil {
		panic("handler: admin spa: sub fs: " + err.Error())
	}

	// Pre-read index.html so we can serve it directly for SPA fallback
	// without going through http.FileServer (which redirects directories).
	indexHTML, err := fs.ReadFile(distFS, "index.html")
	if err != nil {
		panic("handler: admin spa: read index.html: " + err.Error())
	}

	fileServer := http.FileServer(http.FS(distFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip the /admin prefix so that the file server can find files in dist/.
		urlPath := strings.TrimPrefix(r.URL.Path, "/admin")
		if urlPath == "" {
			urlPath = "/"
		}

		// Check whether the path has a file extension.
		base := path.Base(urlPath)
		hasExtension := strings.Contains(base, ".") && !strings.HasPrefix(base, ".")

		if hasExtension {
			// Try to open the file. If it does not exist, return 404.
			f, err := distFS.Open(strings.TrimPrefix(urlPath, "/"))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			f.Close()

			// Serve the file directly.
			r2 := r.Clone(r.Context())
			r2.URL.Path = urlPath
			fileServer.ServeHTTP(w, r2)
			return
		}

		// No extension — SPA routing fallback: serve index.html directly.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(indexHTML)
	})
}
