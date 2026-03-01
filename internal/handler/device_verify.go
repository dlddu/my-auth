package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"

	"github.com/dlddu/my-auth/internal/config"
	"github.com/dlddu/my-auth/internal/storage"
)

// deviceVerifyTemplates holds the parsed device verification page templates.
var deviceVerifyTemplates *template.Template

func init() {
	tmpl, err := template.ParseFS(templateFS, "templates/base.html", "templates/device_verify.html")
	if err != nil {
		panic(fmt.Sprintf("handler: parse device_verify templates: %v", err))
	}
	deviceVerifyTemplates = tmpl
}

// deviceVerifyPageData holds the data rendered into device_verify.html.
type deviceVerifyPageData struct {
	Error    string
	UserCode string
	Success  bool
}

// NewDeviceVerifyHandler returns an http.HandlerFunc that handles
// GET and POST /device/verify.
//
// GET  → requires authentication; renders the user_code entry form.
//
// POST → requires authentication; validates the submitted user_code;
//
//	on success approves the device and renders a success page;
//	on invalid code re-renders the form with an error message.
func NewDeviceVerifyHandler(cfg *config.Config, db *sql.DB) http.HandlerFunc {
	store := storage.New(db)

	return func(w http.ResponseWriter, r *http.Request) {
		// Require an authenticated session for both GET and POST.
		if !IsAuthenticated(r, db, cfg.SessionSecret) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		switch r.Method {
		case http.MethodGet:
			handleDeviceVerifyGet(w, r)
		case http.MethodPost:
			handleDeviceVerifyPost(w, r, cfg, db, store)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}
}

// handleDeviceVerifyGet renders the user_code entry form.
func handleDeviceVerifyGet(w http.ResponseWriter, r *http.Request) {
	data := deviceVerifyPageData{}
	renderDeviceVerifyPage(w, http.StatusOK, data)
}

// handleDeviceVerifyPost processes the user_code submission.
func handleDeviceVerifyPost(w http.ResponseWriter, r *http.Request, cfg *config.Config, db *sql.DB, store *storage.Store) {
	if err := r.ParseForm(); err != nil {
		renderDeviceVerifyPage(w, http.StatusOK, deviceVerifyPageData{
			Error: "Invalid request: failed to parse form.",
		})
		return
	}

	userCode := r.FormValue("user_code")
	if userCode == "" {
		renderDeviceVerifyPage(w, http.StatusOK, deviceVerifyPageData{
			Error: "Please enter a device code.",
		})
		return
	}

	ctx := r.Context()

	// Look up the device_code associated with the submitted user_code.
	deviceCode, err := store.GetDeviceCodeByUserCode(ctx, userCode)
	if err != nil {
		renderDeviceVerifyPage(w, http.StatusOK, deviceVerifyPageData{
			Error:    "Invalid code: the code you entered was not found. Please check and try again.",
			UserCode: userCode,
		})
		return
	}

	// Retrieve the authenticated username to record as the subject.
	subject := authenticatedUsername(r, db, cfg.SessionSecret)

	// Approve the device by updating the device_code row status.
	if err := store.UpdateDeviceCodeSessionByDeviceCode(ctx, deviceCode, subject, "approved"); err != nil {
		renderDeviceVerifyPage(w, http.StatusOK, deviceVerifyPageData{
			Error:    "Internal server error: failed to approve device.",
			UserCode: userCode,
		})
		return
	}

	// Render the success page.
	renderDeviceVerifyPage(w, http.StatusOK, deviceVerifyPageData{
		Success: true,
	})
}

// renderDeviceVerifyPage writes the device verification page HTML to w.
func renderDeviceVerifyPage(w http.ResponseWriter, status int, data deviceVerifyPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := deviceVerifyTemplates.ExecuteTemplate(w, "base", data); err != nil {
		_ = err
	}
}

// NewDeviceVerifyAPIHandler returns an http.HandlerFunc that handles
// POST /oauth2/device/verify with a JSON response.
//
// This endpoint is the canonical RFC 8628 path used by API clients (including
// the Playwright E2E tests) that expect a JSON response rather than an HTML
// page.  Browser-based users continue to use POST /device/verify which renders
// HTML via NewDeviceVerifyHandler.
//
// Behaviour:
//   - Requires an authenticated session cookie (same rule as /device/verify).
//   - On success (valid user_code + action=approve): HTTP 200 JSON {"approved": true}.
//   - On invalid user_code: HTTP 400 JSON {"error": "invalid_grant", ...}.
//   - On unauthenticated request: HTTP 401 JSON {"error": "unauthorized", ...}.
func NewDeviceVerifyAPIHandler(cfg *config.Config, db *sql.DB) http.HandlerFunc {
	store := storage.New(db)

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if !IsAuthenticated(r, db, cfg.SessionSecret) {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "unauthorized",
				"error_description": "Authentication required",
			})
			return
		}

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_request",
				"error_description": "Failed to parse form",
			})
			return
		}

		userCode := r.FormValue("user_code")
		if userCode == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_request",
				"error_description": "Missing user_code",
			})
			return
		}

		ctx := r.Context()

		// Look up the device_code associated with the submitted user_code.
		deviceCode, err := store.GetDeviceCodeByUserCode(ctx, userCode)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "Unknown or expired user_code",
			})
			return
		}

		subject := authenticatedUsername(r, db, cfg.SessionSecret)

		action := r.FormValue("action")
		newStatus := "approved"
		if action == "deny" {
			newStatus = "denied"
		}

		if err := store.UpdateDeviceCodeSessionByDeviceCode(ctx, deviceCode, subject, newStatus); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "server_error",
				"error_description": "Failed to update device code status",
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"approved": newStatus == "approved",
		})
	}
}
