package testhelper

import (
	"crypto/rsa"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/dlddu/my-auth/internal/config"
	"github.com/dlddu/my-auth/internal/database"
	"github.com/dlddu/my-auth/internal/handler"
	"github.com/dlddu/my-auth/internal/keygen"
	"github.com/dlddu/my-auth/internal/storage"
)

// NewTestServer creates a minimal httptest.Server backed by a temporary SQLite
// database and returns both the server and a pre-configured *http.Client.
//
// The server is started immediately and registered with t.Cleanup so it is
// closed automatically when the test finishes.
func NewTestServer(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()

	// Create an isolated database for this test.
	dsn := NewTestDB(t)

	// Build config pointing at the test database.
	cfg := NewTestConfig(t, dsn)

	// Open the database so it can be passed to handlers.
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("testhelper: open database for server: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Logf("testhelper: close server db: %v", err)
		}
	})

	// Seed the test OAuth2 client with a bcrypt-hashed secret so fosite's
	// BCrypt hasher can authenticate the client during token requests.
	seedTestClient(t, db)

	// Generate a test RSA key pair (in-memory, no disk I/O required).
	key, err := keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)
	if err != nil {
		t.Fatalf("testhelper: generate RSA key pair: %v", err)
	}

	// Build the HTTP handler.
	h := buildRouter(cfg, key, db)

	// Start an unencrypted test server on a random local port.
	srv := httptest.NewServer(h)

	t.Cleanup(func() {
		srv.Close()
	})

	// Return a plain http.Client that targets the test server.
	// Callers that need cookie/redirect tracking should use NewTestClient.
	client := srv.Client()

	return srv, client
}

// seedTestClient inserts the canonical test OAuth2 client into the clients
// table with a bcrypt-hashed secret so fosite's BCrypt hasher works correctly.
func seedTestClient(t *testing.T, db *sql.DB) {
	t.Helper()

	hash, err := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("testhelper: bcrypt test client secret: %v", err)
	}

	_, err = db.Exec(`
		INSERT OR IGNORE INTO clients (id, secret, redirect_uris, grant_types, response_types, scopes)
		VALUES (?, ?, ?, ?, ?, ?)`,
		"test-client",
		string(hash),
		`["http://localhost:9999/callback"]`,
		`["authorization_code","refresh_token"]`,
		`["code"]`,
		"openid profile email",
	)
	if err != nil {
		t.Fatalf("testhelper: seed test client: %v", err)
	}
}

// buildRouter constructs the application's http.Handler with the provided
// config, RSA private key, and database connection.
func buildRouter(cfg *config.Config, privateKey *rsa.PrivateKey, db *sql.DB) http.Handler {
	r := chi.NewRouter()

	// Health check — used by the Playwright webServer probe and future
	// load-balancer readiness checks.
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("my-auth"))
	})

	r.Get("/.well-known/openid-configuration", handler.NewOIDCDiscoveryHandler(cfg.Issuer))
	r.Get("/jwks", handler.NewJWKSHandler(privateKey))

	// Login endpoints.
	loginHandler := handler.NewLoginHandler(cfg, db)
	r.Get("/login", loginHandler)
	r.Post("/login", loginHandler)

	// Create the fosite storage and provider.
	store, err := storage.New(db)
	if err != nil {
		panic("testhelper: create storage: " + err.Error())
	}

	provider := handler.NewOAuth2Provider(store, privateKey, cfg.Issuer)
	oauth2 := handler.NewOAuth2Handlers(provider, cfg, db)

	// OAuth2 authorisation and token endpoints.
	authorizeHandler := oauth2.AuthorizeHandler()
	r.Get("/oauth2/auth", authorizeHandler)
	r.Post("/oauth2/auth", authorizeHandler)
	r.Post("/oauth2/token", oauth2.TokenHandler())

	return r
}
