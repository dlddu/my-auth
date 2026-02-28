// Package main is the entry point for the my-auth OAuth2/OIDC Authorization Server.
package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"golang.org/x/crypto/bcrypt"

	"github.com/dlddu/my-auth/internal/config"
	"github.com/dlddu/my-auth/internal/database"
	"github.com/dlddu/my-auth/internal/handler"
	"github.com/dlddu/my-auth/internal/keygen"
	"github.com/dlddu/my-auth/internal/storage"
)

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

	// 4. e2e 테스트용 test-client seed 데이터 삽입 (없는 경우에만)
	if err := seedTestClient(db); err != nil {
		fmt.Fprintf(os.Stderr, "my-auth: seed test client: %v\n", err)
		os.Exit(1)
	}

	// 5. fosite OAuth2 provider 초기화
	store := storage.NewStore(db)

	globalSecret := cfg.SessionSecret
	if globalSecret == "" {
		globalSecret = "some-super-secret-hmac-key-12345"
	}

	fositeConfig := &fosite.Config{
		AccessTokenLifespan:        3600 * time.Second,
		AuthorizeCodeLifespan:      600 * time.Second,
		IDTokenLifespan:            3600 * time.Second,
		HashCost:                   12,
		GlobalSecret:               []byte(globalSecret),
		SendDebugMessagesToClients: false,
		ScopeStrategy:              fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy:   fosite.DefaultAudienceMatchingStrategy,
	}

	jwtStrategy := &jwt.RS256JWTStrategy{
		PrivateKey: privateKey,
	}

	oidcStrategy := openid.NewDefaultStrategy(jwtStrategy, fositeConfig)

	provider := compose.Compose(
		fositeConfig,
		store,
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2HMACStrategy(fositeConfig),
			OpenIDConnectTokenStrategy: oidcStrategy,
			Signer:                     jwtStrategy,
		},
		nil,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2PKCEFactory,
	)

	// 6. 라우터 설정
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

	// OAuth2/OIDC endpoints — fosite 핸들러 사용
	authorizeHandler := handler.NewAuthorizeHandler(cfg, db, provider)
	r.Get("/oauth2/auth", authorizeHandler)
	r.Post("/oauth2/auth", authorizeHandler)
	r.Post("/oauth2/token", handler.NewTokenHandler(provider))

	// 7. 서버 시작
	addr := fmt.Sprintf(":%d", cfg.Port)
	fmt.Fprintf(os.Stdout, "my-auth: listening on %s\n", addr)

	if err := http.ListenAndServe(addr, r); err != nil {
		fmt.Fprintf(os.Stderr, "my-auth: server error: %v\n", err)
		os.Exit(1)
	}
}

// seedTestClient inserts the e2e test OAuth2 client if it does not already exist.
// The client secret "test-secret" is bcrypt-hashed before storage, as required
// by fosite's BCrypt hasher for client authentication.
func seedTestClient(db *sql.DB) error {
	// Check if test-client already exists.
	var count int
	row := db.QueryRow(`SELECT COUNT(*) FROM clients WHERE id = ?`, "test-client")
	if err := row.Scan(&count); err != nil {
		return fmt.Errorf("seedTestClient: query: %w", err)
	}
	if count > 0 {
		return nil
	}

	// Generate bcrypt hash of "test-secret".
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("seedTestClient: bcrypt: %w", err)
	}

	_, err = db.Exec(
		`INSERT INTO clients (id, secret, redirect_uris, grant_types, response_types, scopes)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"test-client",
		string(hashedSecret),
		`["http://localhost:9999/callback"]`,
		`["authorization_code", "refresh_token"]`,
		`["code"]`,
		`openid profile email`,
	)
	if err != nil {
		return fmt.Errorf("seedTestClient: insert: %w", err)
	}

	fmt.Fprintf(os.Stdout, "my-auth: seeded test-client for e2e tests\n")
	return nil
}
