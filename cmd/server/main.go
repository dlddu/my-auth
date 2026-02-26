// Package main is the entry point for the my-auth OAuth2/OIDC Authorization Server.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
	db, err := database.Open("file:my-auth.db")
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
	provider := buildFositeProvider(cfg, privateKey, db)

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

	// OAuth2 authorisation endpoints.
	oauth2AuthHandler := handler.NewOAuth2AuthHandler(cfg, db, provider)
	r.Get("/oauth2/auth", oauth2AuthHandler)
	r.Post("/oauth2/auth", oauth2AuthHandler)
	r.Post("/oauth2/token", handler.NewOAuth2TokenHandler(cfg, provider))

	// 6. 서버 시작
	addr := fmt.Sprintf(":%d", cfg.Port)
	fmt.Fprintf(os.Stdout, "my-auth: listening on %s\n", addr)

	if err := http.ListenAndServe(addr, r); err != nil {
		fmt.Fprintf(os.Stderr, "my-auth: server error: %v\n", err)
		os.Exit(1)
	}
}

// buildFositeProvider assembles a fosite.OAuth2Provider for production use.
// It uses the provided database connection to back all token/session storage.
func buildFositeProvider(cfg *config.Config, key *rsa.PrivateKey, db *sql.DB) fosite.OAuth2Provider {
	store := storage.New(db)

	// Derive a stable global secret from the session secret.
	// Minimum 32 bytes required by fosite's HMAC strategy.
	globalSecret := cfg.SessionSecret
	if globalSecret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			fmt.Fprintf(os.Stderr, "my-auth: generate session secret: %v\n", err)
			os.Exit(1)
		}
		globalSecret = hex.EncodeToString(b)
	}
	for len(globalSecret) < 32 {
		globalSecret += globalSecret
	}

	fositeConfig := &fosite.Config{
		GlobalSecret:                   []byte(globalSecret[:32]),
		AuthorizeCodeLifespan:          10 * time.Minute,
		AccessTokenLifespan:            time.Hour,
		RefreshTokenLifespan:           720 * time.Hour,
		IDTokenLifespan:                time.Hour,
		IDTokenIssuer:                  cfg.Issuer,
		SendDebugMessagesToClients:     false,
		EnforcePKCE:                    false,
		EnablePKCEPlainChallengeMethod: false,
		TokenURL:                       cfg.Issuer + "/oauth2/token",
	}

	keyGetter := func(ctx context.Context) (interface{}, error) {
		return key, nil
	}

	hmacStrategy := compose.NewOAuth2HMACStrategy(fositeConfig)
	jwtStrategy := compose.NewOAuth2JWTStrategy(keyGetter, hmacStrategy, fositeConfig)

	strategy := &compose.CommonStrategy{
		CoreStrategy:               jwtStrategy,
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, fositeConfig),
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: keyGetter,
		},
	}
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
