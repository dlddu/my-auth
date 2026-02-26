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
	"github.com/ory/fosite/token/jwt"

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

	// Generate a test RSA key pair (in-memory, no disk I/O required).
	key, err := keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)
	if err != nil {
		t.Fatalf("testhelper: generate RSA key pair: %v", err)
	}

	// Seed the canonical test OAuth2 client so OAuth2 flows can resolve it.
	SeedTestClient(t, db)

	// Build the fosite OAuth2 provider backed by the test database.
	provider := newTestFositeProvider(t, key, db, cfg)

	// Build the HTTP handler.
	h := buildRouter(cfg, key, db, provider)

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

// newTestFositeProvider assembles a fosite.OAuth2Provider backed by the
// provided SQLite database and RSA private key.
//
// The provider is configured with:
//   - JWT access tokens signed with the provided RSA key
//   - OIDC id_token support
//   - Authorization Code grant
//   - Refresh Token grant
func newTestFositeProvider(t *testing.T, key *rsa.PrivateKey, db *sql.DB, cfg *config.Config) fosite.OAuth2Provider {
	t.Helper()

	store := storage.New(db)

	// fositeConfig holds all fosite configuration values.
	fositeConfig := &fosite.Config{
		GlobalSecret:                    []byte("test-global-secret-32-bytes-long!!"),
		AuthorizeCodeLifespan:           10 * time.Minute,
		AccessTokenLifespan:             time.Hour,
		RefreshTokenLifespan:            720 * time.Hour,
		IDTokenLifespan:                 time.Hour,
		IDTokenIssuer:                   cfg.Issuer,
		SendDebugMessagesToClients:      true,
		EnforcePKCE:                     false,
		EnablePKCEPlainChallengeMethod:  false,
		TokenURL:                        cfg.Issuer + "/oauth2/token",
	}

	// keyGetter returns the RSA private key for JWT signing.
	// fosite uses this to sign both access tokens (JWT) and id_tokens.
	keyGetter := func(ctx context.Context) (interface{}, error) {
		return key, nil
	}

	// Build the composite strategy: JWT access tokens + OIDC id_tokens.
	hmacStrategy := compose.NewOAuth2HMACStrategy(fositeConfig)
	jwtStrategy := compose.NewOAuth2JWTStrategy(keyGetter, hmacStrategy, fositeConfig)

	strategy := &compose.CommonStrategy{
		CoreStrategy:               jwtStrategy,
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, fositeConfig),
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: keyGetter,
		},
	}

	// Assemble the provider with Authorization Code, Refresh Token, and OIDC factories.
	provider := compose.Compose(
		fositeConfig,
		store,
		strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
	)

	return provider
}

// buildRouter constructs the application's http.Handler with the provided
// config, RSA private key, database connection, and fosite OAuth2 provider.
func buildRouter(cfg *config.Config, privateKey *rsa.PrivateKey, db *sql.DB, provider fosite.OAuth2Provider) http.Handler {
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

	// OAuth2 authorisation endpoint.
	if provider != nil {
		oauth2AuthHandler := handler.NewOAuth2AuthHandler(cfg, db, provider)
		r.Get("/oauth2/auth", oauth2AuthHandler)
		r.Post("/oauth2/auth", oauth2AuthHandler)
		r.Post("/oauth2/token", handler.NewOAuth2TokenHandler(cfg, provider))
	} else {
		// Fallback stub used when the provider is not yet assembled (Red Phase).
		r.Get("/oauth2/auth", func(w http.ResponseWriter, r *http.Request) {
			if !handler.IsAuthenticated(r, db, cfg.SessionSecret) {
				http.Redirect(w, r, "/login?return_to=/oauth2/auth", http.StatusFound)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("authorized"))
		})
	}

	return r
}
