// Package main is the entry point for the my-auth OAuth2/OIDC Authorization Server.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	jose "github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	josejwt "github.com/ory/fosite/token/jwt"
	"golang.org/x/crypto/bcrypt"

	"github.com/dlddu/my-auth/internal/config"
	"github.com/dlddu/my-auth/internal/database"
	"github.com/dlddu/my-auth/internal/handler"
	"github.com/dlddu/my-auth/internal/keygen"
	"github.com/dlddu/my-auth/internal/storage"
)

// testClientSecretHash is the bcrypt hash of "test-secret" (the E2E client
// secret defined in e2e/token.spec.ts as VALID_CLIENT_SECRET).
// Pre-computed once at package initialisation so that seedTestClient does not
// perform expensive bcrypt work on every server start. fosite's built-in
// BCrypt hasher calls bcrypt.CompareHashAndPassword when authenticating
// clients, so the stored Secret must be a valid bcrypt hash — not plaintext.
var testClientSecretHash = func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	if err != nil {
		panic("my-auth: bcrypt.GenerateFromPassword for test client secret: " + err.Error())
	}
	return h
}()

func main() {
	// 1. config 로드
	cfg, err := config.Load("config.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "my-auth: load config: %v\n", err)
		os.Exit(1)
	}

	// 2. RSA private key 로드 — 파일이 없으면 자동 생성
	privateKey, err := keygen.LoadPrivateKeyPEM(cfg.JWTKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stdout, "my-auth: key file not found, generating new RSA key pair at %s\n", cfg.JWTKeyPath)

		// 부모 디렉터리 생성
		if mkErr := os.MkdirAll(filepath.Dir(cfg.JWTKeyPath), 0700); mkErr != nil {
			fmt.Fprintf(os.Stderr, "my-auth: create key directory: %v\n", mkErr)
			os.Exit(1)
		}

		privateKey, err = keygen.GenerateRSAKeyPair(keygen.DefaultKeyBits)
		if err != nil {
			fmt.Fprintf(os.Stderr, "my-auth: generate RSA key: %v\n", err)
			os.Exit(1)
		}

		if err := keygen.SavePrivateKeyPEM(privateKey, cfg.JWTKeyPath); err != nil {
			fmt.Fprintf(os.Stderr, "my-auth: save RSA key: %v\n", err)
			os.Exit(1)
		}
	}

	// 3. 데이터베이스 열기
	db, err := database.Open("file:my-auth.db?_journal_mode=WAL&_foreign_keys=ON")
	if err != nil {
		fmt.Fprintf(os.Stderr, "my-auth: open database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	migrationsDir := "migrations"
	if err := database.Migrate(db, migrationsDir); err != nil {
		fmt.Fprintf(os.Stderr, "my-auth: migrate database: %v\n", err)
		os.Exit(1)
	}

	// 4. fosite OAuth2 provider 초기화
	// GlobalSecret は正確に 32 バイト必要。SessionSecret が短い場合はパッドする。
	globalSecret := deriveGlobalSecret(cfg.SessionSecret)

	fositeConf := &fosite.Config{
		GlobalSecret:               globalSecret,
		AuthorizeCodeLifespan:      10 * time.Minute,
		AccessTokenLifespan:        1 * time.Hour,
		RefreshTokenLifespan:       24 * time.Hour,
		IDTokenLifespan:            1 * time.Hour,
		IDTokenIssuer:              cfg.Issuer,
		SendDebugMessagesToClients: false,
		JWTScopeClaimKey:           josejwt.JWTScopeFieldString,
		RefreshTokenScopes:         []string{},
	}

	store := storage.New(db)

	// When SEED_TEST_CLIENT=1 is set (CI environment), register a predictable
	// test client so that E2E tests can use a stable client_id / redirect_uri
	// without requiring a separate client-management API.
	if os.Getenv("SEED_TEST_CLIENT") == "1" {
		if err := seedTestClient(store); err != nil {
			fmt.Fprintf(os.Stderr, "my-auth: seed test client: %v\n", err)
			os.Exit(1)
		}
	}

	// Compute kid the same way as NewJWKSHandler (handler.go:44-46)
	pubDER, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	hash := sha256.Sum256(pubDER)
	kid := base64.RawURLEncoding.EncodeToString(hash[:8])

	jwk := jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     kid,
		Use:       "sig",
		Algorithm: string(jose.RS256),
	}

	jwtSigner := &josejwt.DefaultSigner{
		GetPrivateKey: func(ctx context.Context) (interface{}, error) {
			return &jwk, nil
		},
	}

	// JWT access token strategy — issues RS256-signed JWTs as access tokens
	// so resource servers can verify them locally without introspection.
	jwtAccessStrategy := &oauth2.DefaultJWTStrategy{
		Signer:          jwtSigner,
		HMACSHAStrategy: compose.NewOAuth2HMACStrategy(fositeConf),
		Config:          fositeConf,
	}

	openIDStrategy := &openid.DefaultStrategy{
		Signer: jwtSigner,
		Config: fositeConf,
	}

	oauth2Provider := compose.Compose(
		fositeConf,
		store,
		&compose.CommonStrategy{
			CoreStrategy:               jwtAccessStrategy,
			OpenIDConnectTokenStrategy: openIDStrategy,
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
	)

	// 5. 라우터 설정
	r := chi.NewRouter()

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

	loginHandler := handler.NewLoginHandler(cfg, db)
	r.Get("/login", loginHandler)
	r.Post("/login", loginHandler)

	authorizeHandler := handler.NewAuthorizeHandler(oauth2Provider, cfg, db)
	r.Get("/oauth2/auth", authorizeHandler)
	r.Post("/oauth2/auth", authorizeHandler)

	// OAuth2 token endpoint — exchanges authorization codes for tokens.
	r.Post("/oauth2/token", handler.NewTokenHandler(oauth2Provider))

	// 6. 서버 시작
	addr := fmt.Sprintf(":%d", cfg.Port)
	fmt.Fprintf(os.Stdout, "my-auth: listening on %s\n", addr)

	if err := http.ListenAndServe(addr, r); err != nil {
		fmt.Fprintf(os.Stderr, "my-auth: server error: %v\n", err)
		os.Exit(1)
	}
}

// deriveGlobalSecret returns a 32-byte secret derived from the provided string.
// fosite requires exactly 32 bytes for its HMAC-based token strategy.
// If the input is shorter than 32 bytes it is right-padded with zeros.
// If longer it is truncated to 32 bytes.
func deriveGlobalSecret(s string) []byte {
	const size = 32
	b := make([]byte, size)
	copy(b, []byte(s))
	return b
}

// seedTestClient inserts the well-known E2E test client into the store.
// It is idempotent: if the client already exists, the error is silently
// ignored so that the server can be restarted without failure.
func seedTestClient(store *storage.Store) error {
	client := &fosite.DefaultOpenIDConnectClient{
		DefaultClient: &fosite.DefaultClient{
			ID:            "test-client",
			Secret:        testClientSecretHash,
			RedirectURIs:  []string{"http://localhost:9000/callback"},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email"},
		},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	err := store.CreateClient(context.Background(), client)
	if err != nil {
		// Ignore "already exists" / UNIQUE constraint violations so that
		// repeated server starts in CI do not cause a fatal exit.
		if isUniqueConstraintError(err) {
			return nil
		}
		return err
	}
	fmt.Fprintln(os.Stdout, "my-auth: seeded test-client")
	return nil
}

// isUniqueConstraintError reports whether err represents a SQLite UNIQUE
// constraint violation, which is the expected error when the test client has
// already been seeded.
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "already exists")
}
