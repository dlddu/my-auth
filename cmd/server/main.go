// Package main is the entry point for the my-auth OAuth2/OIDC Authorization Server.
package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"

	"github.com/dlddu/my-auth/internal/config"
	"github.com/dlddu/my-auth/internal/database"
	"github.com/dlddu/my-auth/internal/handler"
	"github.com/dlddu/my-auth/internal/keygen"
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

	migrationsDir := filepath.Join(filepath.Dir(os.Args[0]), "migrations")
	if err := database.Migrate(db, migrationsDir); err != nil {
		fmt.Fprintf(os.Stderr, "my-auth: migrate database: %v\n", err)
		os.Exit(1)
	}

	// 4. 라우터 설정
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

	r.Get("/oauth2/auth", func(w http.ResponseWriter, r *http.Request) {
		if !handler.IsAuthenticated(r, db, cfg.SessionSecret) {
			http.Redirect(w, r, "/login?return_to=/oauth2/auth", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("authorized"))
	})

	// 5. 서버 시작
	addr := fmt.Sprintf(":%d", cfg.Port)
	fmt.Fprintf(os.Stdout, "my-auth: listening on %s\n", addr)

	if err := http.ListenAndServe(addr, r); err != nil {
		fmt.Fprintf(os.Stderr, "my-auth: server error: %v\n", err)
		os.Exit(1)
	}
}
