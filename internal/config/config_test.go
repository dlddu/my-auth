package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dlddu/my-auth/internal/config"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// writeTempConfig writes content to a temp file and returns its path.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writeTempConfig: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// Load — happy path
// ---------------------------------------------------------------------------

func TestLoad_ReturnsConfigWithAllFields(t *testing.T) {
	// Arrange
	yaml := `
issuer: "https://auth.example.com"
port: 8080
owner:
  username: "admin"
  password_hash: "$2a$12$examplehashvalue"
jwt_key_path: "/keys/private.pem"
`
	path := writeTempConfig(t, yaml)

	// Act
	cfg, err := config.Load(path)

	// Assert
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil Config")
	}
	if cfg.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %q, want %q", cfg.Issuer, "https://auth.example.com")
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want %d", cfg.Port, 8080)
	}
	if cfg.Owner.Username != "admin" {
		t.Errorf("Owner.Username = %q, want %q", cfg.Owner.Username, "admin")
	}
	if cfg.Owner.PasswordHash != "$2a$12$examplehashvalue" {
		t.Errorf("Owner.PasswordHash = %q, want %q", cfg.Owner.PasswordHash, "$2a$12$examplehashvalue")
	}
	if cfg.JWTKeyPath != "/keys/private.pem" {
		t.Errorf("JWTKeyPath = %q, want %q", cfg.JWTKeyPath, "/keys/private.pem")
	}
}

// ---------------------------------------------------------------------------
// Load — edge cases
// ---------------------------------------------------------------------------

func TestLoad_DefaultPort_WhenPortNotSet(t *testing.T) {
	// Arrange — port field omitted; implementation should default to 8080
	yaml := `
issuer: "https://auth.example.com"
owner:
  username: "admin"
  password_hash: "$2a$12$examplehashvalue"
jwt_key_path: "/keys/private.pem"
`
	path := writeTempConfig(t, yaml)

	// Act
	cfg, err := config.Load(path)

	// Assert
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want default 8080", cfg.Port)
	}
}

func TestLoad_IssuerTrimsTrailingSlash(t *testing.T) {
	// Arrange — issuer with trailing slash
	yaml := `
issuer: "https://auth.example.com/"
port: 8080
owner:
  username: "admin"
  password_hash: "$2a$12$examplehashvalue"
jwt_key_path: "/keys/private.pem"
`
	path := writeTempConfig(t, yaml)

	// Act
	cfg, err := config.Load(path)

	// Assert
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	// Trailing slash must be stripped so OIDC discovery URLs are canonical.
	if cfg.Issuer == "https://auth.example.com/" {
		t.Errorf("Issuer still has trailing slash: %q", cfg.Issuer)
	}
	if cfg.Issuer != "https://auth.example.com" {
		t.Errorf("Issuer = %q, want %q", cfg.Issuer, "https://auth.example.com")
	}
}

// ---------------------------------------------------------------------------
// Load — error cases
// ---------------------------------------------------------------------------

func TestLoad_ReturnsError_WhenFileNotFound(t *testing.T) {
	// Act
	_, err := config.Load("/nonexistent/path/config.yaml")

	// Assert
	if err == nil {
		t.Error("Load() expected error for missing file, got nil")
	}
}

func TestLoad_ReturnsError_WhenYAMLInvalid(t *testing.T) {
	// Arrange
	path := writeTempConfig(t, ":::invalid yaml:::")

	// Act
	_, err := config.Load(path)

	// Assert
	if err == nil {
		t.Error("Load() expected error for invalid YAML, got nil")
	}
}

// ---------------------------------------------------------------------------
// Validate — happy path
// ---------------------------------------------------------------------------

func TestValidate_ReturnsNil_WhenAllRequiredFieldsPresent(t *testing.T) {
	// Arrange
	cfg := &config.Config{
		Issuer:     "https://auth.example.com",
		Port:       8080,
		Owner:      config.OwnerCredentials{Username: "admin", PasswordHash: "$2a$12$hash"},
		JWTKeyPath: "/keys/private.pem",
	}

	// Act
	err := cfg.Validate()

	// Assert
	if err != nil {
		t.Errorf("Validate() returned unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Validate — error cases
// ---------------------------------------------------------------------------

func TestValidate_ReturnsError_WhenIssuerEmpty(t *testing.T) {
	// Arrange
	cfg := &config.Config{
		Issuer:     "",
		Port:       8080,
		Owner:      config.OwnerCredentials{Username: "admin", PasswordHash: "$2a$12$hash"},
		JWTKeyPath: "/keys/private.pem",
	}

	// Act
	err := cfg.Validate()

	// Assert
	if err == nil {
		t.Error("Validate() expected error when Issuer is empty, got nil")
	}
}

func TestValidate_ReturnsError_WhenIssuerNotHTTPS(t *testing.T) {
	// Arrange — HTTP is not acceptable for an OAuth2 issuer (except localhost)
	cfg := &config.Config{
		Issuer:     "http://example.com",
		Port:       8080,
		Owner:      config.OwnerCredentials{Username: "admin", PasswordHash: "$2a$12$hash"},
		JWTKeyPath: "/keys/private.pem",
	}

	// Act
	err := cfg.Validate()

	// Assert
	if err == nil {
		t.Error("Validate() expected error for non-HTTPS issuer, got nil")
	}
}

func TestValidate_ReturnsError_WhenOwnerUsernameEmpty(t *testing.T) {
	// Arrange
	cfg := &config.Config{
		Issuer:     "https://auth.example.com",
		Port:       8080,
		Owner:      config.OwnerCredentials{Username: "", PasswordHash: "$2a$12$hash"},
		JWTKeyPath: "/keys/private.pem",
	}

	// Act
	err := cfg.Validate()

	// Assert
	if err == nil {
		t.Error("Validate() expected error when Owner.Username is empty, got nil")
	}
}

func TestValidate_ReturnsError_WhenOwnerPasswordHashEmpty(t *testing.T) {
	// Arrange
	cfg := &config.Config{
		Issuer:     "https://auth.example.com",
		Port:       8080,
		Owner:      config.OwnerCredentials{Username: "admin", PasswordHash: ""},
		JWTKeyPath: "/keys/private.pem",
	}

	// Act
	err := cfg.Validate()

	// Assert
	if err == nil {
		t.Error("Validate() expected error when Owner.PasswordHash is empty, got nil")
	}
}

func TestValidate_ReturnsError_WhenJWTKeyPathEmpty(t *testing.T) {
	// Arrange
	cfg := &config.Config{
		Issuer:     "https://auth.example.com",
		Port:       8080,
		Owner:      config.OwnerCredentials{Username: "admin", PasswordHash: "$2a$12$hash"},
		JWTKeyPath: "",
	}

	// Act
	err := cfg.Validate()

	// Assert
	if err == nil {
		t.Error("Validate() expected error when JWTKeyPath is empty, got nil")
	}
}

func TestValidate_ReturnsError_WhenPortOutOfRange(t *testing.T) {
	// Arrange — port 0 is reserved/invalid for a listening server
	cfg := &config.Config{
		Issuer:     "https://auth.example.com",
		Port:       0,
		Owner:      config.OwnerCredentials{Username: "admin", PasswordHash: "$2a$12$hash"},
		JWTKeyPath: "/keys/private.pem",
	}

	// Act
	err := cfg.Validate()

	// Assert
	if err == nil {
		t.Error("Validate() expected error when Port is 0, got nil")
	}
}
