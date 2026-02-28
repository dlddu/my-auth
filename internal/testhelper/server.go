package testhelper

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"

	"github.com/dlddu/my-auth/internal/config"
	"github.com/dlddu/my-auth/internal/database"
	"github.com/dlddu/my-auth/internal/handler"
	"github.com/dlddu/my-auth/internal/keygen"
	"github.com/dlddu/my-auth/internal/storage"
)

// seedTestClient inserts the standard test OAuth2 client into db if it does
// not already exist. This ensures all unit-test servers have a registered
// client so fosite can validate authorize requests.
func seedTestClient(t *testing.T, db *sql.DB) {
	t.Helper()

	_, err := db.ExecContext(context.Background(),
		`INSERT OR IGNORE INTO clients
		    (id, secret, redirect_uris, grant_types, response_types, scopes)
		 VALUES
		    (?, ?, ?, ?, ?, ?)`,
		"test-client",
		// Store the raw secret. The authorize endpoint does not verify the
		// client secret (only the token endpoint does), so any value works for
		// authorize-phase unit tests.
		"test-secret",
		`["http://localhost:9999/callback"]`,
		`["authorization_code", "refresh_token"]`,
		`["code"]`,
		`openid profile email`,
	)
	if err != nil {
		t.Fatalf("testhelper.seedTestClient: insert: %v", err)
	}
}

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

	// Generate a test RSA key pair (in-memory, no disk I/O required).
	key, err := keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)
	if err != nil {
		t.Fatalf("testhelper: generate RSA key pair: %v", err)
	}

	// Seed the standard test OAuth2 client so fosite can validate authorize
	// requests in unit tests without requiring each test to insert it manually.
	seedTestClient(t, db)

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

// buildFositeProvider initialises a fosite OAuth2Provider with JWT access tokens
// and OIDC support, backed by the given SQLite storage.
func buildFositeProvider(cfg *config.Config, privateKey *rsa.PrivateKey, store *storage.Store) fosite.OAuth2Provider {
	fositeConfig := &fosite.Config{
		AccessTokenLifespan:        3600 * time.Second,
		AuthorizeCodeLifespan:      600 * time.Second,
		IDTokenLifespan:            3600 * time.Second,
		HashCost:                   12,
		GlobalSecret:               []byte("some-super-secret-hmac-key-12345"),
		SendDebugMessagesToClients: true,
		ScopeStrategy:              fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy:   fosite.DefaultAudienceMatchingStrategy,
	}

	// keyGetter returns the RSA private key for JWT signing.
	keyGetter := func(_ context.Context) (interface{}, error) {
		return privateKey, nil
	}

	return compose.Compose(
		fositeConfig,
		store,
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2HMACStrategy(fositeConfig),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, fositeConfig),
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2PKCEFactory,
	)
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

	// Build the fosite OAuth2 provider.
	store := storage.NewStore(db)
	provider := buildFositeProvider(cfg, privateKey, store)

	// OAuth2/OIDC endpoints.
	authorizeHandler := handler.NewAuthorizeHandler(cfg, db, provider)
	r.Get("/oauth2/auth", authorizeHandler)
	r.Post("/oauth2/auth", authorizeHandler)

	// Consent endpoint — GET renders the consent page, POST processes the decision.
	consentHandler := handler.NewConsentHandler(cfg, db, provider)
	r.Get("/consent", consentHandler)
	r.Post("/consent", consentHandler)

	r.Post("/oauth2/token", handler.NewTokenHandler(provider))

	return r
}
