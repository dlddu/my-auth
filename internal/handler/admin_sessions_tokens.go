package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/dlddu/my-auth/internal/storage"
)

// AdminSessionTokenStore defines the storage operations required by admin
// session and token management handlers.
type AdminSessionTokenStore interface {
	ListSessions(ctx context.Context) ([]storage.SessionInfo, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteAllSessions(ctx context.Context) error
	ListTokens(ctx context.Context) ([]storage.TokenInfo, error)
	DeleteToken(ctx context.Context, signature string) error
	DeleteAllTokens(ctx context.Context) error
}

// NewListSessionsHandler returns an http.HandlerFunc that handles
// GET /api/admin/sessions.
func NewListSessionsHandler(store AdminSessionTokenStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessions, err := store.ListSessions(r.Context())
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to list sessions")
			return
		}
		writeAdminJSON(w, http.StatusOK, sessions)
	}
}

// NewDeleteSessionHandler returns an http.HandlerFunc that handles
// DELETE /api/admin/sessions/{id}.
func NewDeleteSessionHandler(store AdminSessionTokenStore) http.HandlerFunc {
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
func NewDeleteAllSessionsHandler(store AdminSessionTokenStore) http.HandlerFunc {
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
func NewListTokensHandler(store AdminSessionTokenStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokens, err := store.ListTokens(r.Context())
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to list tokens")
			return
		}
		writeAdminJSON(w, http.StatusOK, tokens)
	}
}

// NewDeleteTokenHandler returns an http.HandlerFunc that handles
// DELETE /api/admin/tokens/{id}.
func NewDeleteTokenHandler(store AdminSessionTokenStore) http.HandlerFunc {
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
func NewDeleteAllTokensHandler(store AdminSessionTokenStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := store.DeleteAllTokens(r.Context()); err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to delete all tokens")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
