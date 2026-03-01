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
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"

	"github.com/dlddu/my-auth/internal/config"
	"github.com/dlddu/my-auth/internal/database"
	"github.com/dlddu/my-auth/internal/handler"
	"github.com/dlddu/my-auth/internal/keygen"
	"github.com/dlddu/my-auth/internal/storage"
)

// testClientID is the OAuth2 client ID seeded into every test server instance.
// It matches the value used by e2e/authorize.spec.ts (VALID_CLIENT_ID).
const testClientID = "test-client"

// testRedirectURI is the registered redirect URI for the test client.
// It matches the value used by e2e/authorize.spec.ts (VALID_REDIRECT_URI).
const testRedirectURI = "http://localhost:9000/callback"

// NewTestServer creates a minimal httptest.Server backed by a temporary SQLite
// database and returns both the server and a pre-configured *http.Client.
//
// The server is started immediately and registered with t.Cleanup so it is
// closed automatically when the test finishes.
//
// The test server includes a fully initialised fosite OAuth2 provider and a
// pre-seeded OAuth2 client ("test-client") so that authorize endpoint tests
// can exercise the full OAuth2 flow without additional setup.
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

	// Seed the test OAuth2 client into the database.
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

// seedTestClient inserts the standard test OAuth2 client into the database.
// The client ID matches testClientID and is used by authorize endpoint tests.
func seedTestClient(t *testing.T, db *sql.DB) {
	t.Helper()

	store := storage.New(db)
	client := &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            testClientID,
			Secret:        []byte("test-client-secret"),
			RedirectURIs:  []string{testRedirectURI},
			GrantTypes:    fosite.Arguments{"authorization_code"},
			ResponseTypes: fosite.Arguments{"code"},
			Scopes:        fosite.Arguments{"openid", "profile", "email"},
		},
	}

	if err := store.CreateClient(context.Background(), client); err != nil {
		t.Fatalf("testhelper: seed test client: %v", err)
	}
}

// fositeTestConfig returns a *fosite.Config with settings appropriate for
// integration tests. The global secret and lifespans are hard-coded so that
// tests are deterministic.
func fositeTestConfig(cfg *config.Config) *fosite.Config {
	return &fosite.Config{
		GlobalSecret:               []byte("test-global-secret-32-bytes!!!!!"),
		AuthorizeCodeLifespan:      10 * time.Minute,
		AccessTokenLifespan:        1 * time.Hour,
		RefreshTokenLifespan:       24 * time.Hour,
		IDTokenLifespan:            1 * time.Hour,
		IDTokenIssuer:              cfg.Issuer,
		SendDebugMessagesToClients: true,
	}
}

// newFositeProvider constructs a fosite.OAuth2Provider configured for the
// authorization code + OpenID Connect flow. The RSA private key is used for
// signing ID tokens.
func newFositeProvider(store *storage.Store, cfg *config.Config, privateKey *rsa.PrivateKey) fosite.OAuth2Provider {
	fositeConf := fositeTestConfig(cfg)

	// RS256 JWT strategy for signing OIDC ID tokens.
	jwtStrategy := &jwt.RS256JWTStrategy{
		PrivateKey: privateKey,
	}

	// OpenID Connect strategy wraps the JWT strategy.
	openIDStrategy := &openid.DefaultStrategy{
		Signer: jwtStrategy,
		Config: fositeConf,
	}

	return compose.Compose(
		fositeConf,
		store,
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2HMACStrategy(fositeConf),
			OpenIDConnectTokenStrategy: openIDStrategy,
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OpenIDConnectExplicitFactory,
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

	// Initialise the fosite OAuth2 provider backed by the same database.
	store := storage.New(db)
	oauth2Provider := newFositeProvider(store, cfg, privateKey)

	// OAuth2 authorisation endpoint — handles GET (consent page) and POST
	// (approve / deny) driven by the fosite provider.
	authorizeHandler := handler.NewAuthorizeHandler(oauth2Provider, cfg, db)
	r.Get("/oauth2/auth", authorizeHandler)
	r.Post("/oauth2/auth", authorizeHandler)

	return r
}
