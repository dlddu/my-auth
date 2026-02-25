package testhelper

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// NewTestServer creates a minimal httptest.Server backed by a temporary SQLite
// database and returns both the server and a pre-configured *http.Client.
//
// The server is started immediately and registered with t.Cleanup so it is
// closed automatically when the test finishes.
//
// NOTE: cmd/server/main.go is currently a stub — the router wired here is a
// minimal chi router that serves a health-check endpoint.  Replace the body of
// buildRouter with the real application router once it is implemented.
// The function signature and setup pattern are intentionally stable so future
// refactors only need to update buildRouter.
func NewTestServer(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()

	// Create an isolated database for this test.
	dsn := NewTestDB(t)

	// Build config pointing at the test database.
	cfg := NewTestConfig(t, dsn)
	_ = cfg // cfg will be passed to the real router once it is implemented.

	// Build the HTTP handler.
	handler := buildRouter()

	// Start an unencrypted test server on a random local port.
	srv := httptest.NewServer(handler)

	t.Cleanup(func() {
		srv.Close()
	})

	// Return a plain http.Client that targets the test server.
	// Callers that need cookie/redirect tracking should use NewTestClient.
	client := srv.Client()

	return srv, client
}

// buildRouter constructs the application's http.Handler.
//
// This is a STUB — it returns a minimal chi router with a single health-check
// endpoint so the test infrastructure compiles and the CI pipeline is green
// from day one.  The real application routes will be wired here as part of
// subsequent implementation tasks.
func buildRouter() http.Handler {
	r := chi.NewRouter()

	// Health check — the only real endpoint until the server is implemented.
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return r
}
