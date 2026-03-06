package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/dlddu/my-auth/internal/storage"
)

// AdminSessionStore defines the storage operations required by admin session handlers.
type AdminSessionStore interface {
	ListSessions(ctx context.Context) ([]storage.SessionInfo, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteAllSessions(ctx context.Context) error
}

// AdminTokenStore defines the storage operations required by admin token handlers.
type AdminTokenStore interface {
	ListTokens(ctx context.Context) ([]storage.TokenInfo, error)
	DeleteToken(ctx context.Context, signature string) error
	DeleteAllTokens(ctx context.Context) error
}

// adminSessionResponse is the JSON representation of a session for API responses.
type adminSessionResponse struct {
	ID        string `json:"id"`
	ClientID  string `json:"client_id"`
	Subject   string `json:"subject"`
	Scopes    string `json:"scopes"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

// adminTokenResponse is the JSON representation of an access token for API responses.
type adminTokenResponse struct {
	Signature string `json:"signature"`
	RequestID string `json:"request_id"`
	ClientID  string `json:"client_id"`
	Subject   string `json:"subject"`
	Scopes    string `json:"scopes"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

// NewListSessionsHandler returns an http.HandlerFunc that handles
// GET /api/admin/sessions.
func NewListSessionsHandler(store AdminSessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessions, err := store.ListSessions(r.Context())
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to list sessions")
			return
		}

		items := make([]adminSessionResponse, 0, len(sessions))
		for _, s := range sessions {
			items = append(items, adminSessionResponse{
				ID:        s.ID,
				ClientID:  s.ClientID,
				Subject:   s.Subject,
				Scopes:    s.Scopes,
				ExpiresAt: s.ExpiresAt.UTC().Format(time.RFC3339),
				CreatedAt: s.CreatedAt.UTC().Format(time.RFC3339),
			})
		}

		writeAdminJSON(w, http.StatusOK, items)
	}
}

// NewDeleteSessionHandler returns an http.HandlerFunc that handles
// DELETE /api/admin/sessions/{id}.
func NewDeleteSessionHandler(store AdminSessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")

		err := store.DeleteSession(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrSessionNotFound) {
				writeAdminError(w, http.StatusNotFound, "session not found")
				return
			}
			writeAdminError(w, http.StatusInternalServerError, "failed to delete session")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// NewDeleteAllSessionsHandler returns an http.HandlerFunc that handles
// DELETE /api/admin/sessions.
func NewDeleteAllSessionsHandler(store AdminSessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := store.DeleteAllSessions(r.Context()); err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to delete all sessions")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// NewListTokensHandler returns an http.HandlerFunc that handles
// GET /api/admin/tokens.
func NewListTokensHandler(store AdminTokenStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokens, err := store.ListTokens(r.Context())
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to list tokens")
			return
		}

		items := make([]adminTokenResponse, 0, len(tokens))
		for _, tk := range tokens {
			items = append(items, adminTokenResponse{
				Signature: tk.Signature,
				RequestID: tk.RequestID,
				ClientID:  tk.ClientID,
				Subject:   tk.Subject,
				Scopes:    tk.Scopes,
				ExpiresAt: tk.ExpiresAt.UTC().Format(time.RFC3339),
				CreatedAt: tk.CreatedAt.UTC().Format(time.RFC3339),
			})
		}

		writeAdminJSON(w, http.StatusOK, items)
	}
}

// NewDeleteTokenHandler returns an http.HandlerFunc that handles
// DELETE /api/admin/tokens/{id}.
func NewDeleteTokenHandler(store AdminTokenStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")

		err := store.DeleteToken(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrTokenNotFound) {
				writeAdminError(w, http.StatusNotFound, "token not found")
				return
			}
			writeAdminError(w, http.StatusInternalServerError, "failed to delete token")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// NewDeleteAllTokensHandler returns an http.HandlerFunc that handles
// DELETE /api/admin/tokens.
func NewDeleteAllTokensHandler(store AdminTokenStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := store.DeleteAllTokens(r.Context()); err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to delete all tokens")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
