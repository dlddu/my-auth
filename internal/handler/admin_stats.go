package handler

import (
	"context"
	"net/http"

	"github.com/ory/fosite"

	"github.com/dlddu/my-auth/internal/storage"
)

// AdminStatsStore defines the storage operations required by the admin stats handler.
type AdminStatsStore interface {
	ListClients(ctx context.Context) ([]fosite.Client, error)
	ListSessions(ctx context.Context) ([]storage.SessionInfo, error)
	ListTokens(ctx context.Context) ([]storage.TokenInfo, error)
	CountAuth24h(ctx context.Context) (int, error)
}

// adminStatsResponse is the JSON shape for GET /api/admin/stats.
type adminStatsResponse struct {
	Clients  int `json:"clients"`
	Sessions int `json:"sessions"`
	Tokens   int `json:"tokens"`
	Auth24h  int `json:"auth_24h"`
}

// NewAdminStatsHandler returns an http.HandlerFunc that handles
// GET /api/admin/stats.
//
// It returns counts for clients, sessions, tokens, and auth_24h.
// Uses a detached context for database queries to prevent client
// disconnections from cancelling in-flight SQLite operations.
func NewAdminStatsHandler(store AdminStatsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithoutCancel(r.Context())

		clients, err := store.ListClients(ctx)
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to list clients")
			return
		}

		sessions, err := store.ListSessions(ctx)
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to list sessions")
			return
		}

		tokens, err := store.ListTokens(ctx)
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to list tokens")
			return
		}

		auth24h, err := store.CountAuth24h(ctx)
		if err != nil {
			writeAdminError(w, http.StatusInternalServerError, "failed to count auth 24h")
			return
		}

		writeAdminJSON(w, http.StatusOK, adminStatsResponse{
			Clients:  len(clients),
			Sessions: len(sessions),
			Tokens:   len(tokens),
			Auth24h:  auth24h,
		})
	}
}
