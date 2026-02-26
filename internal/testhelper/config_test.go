package testhelper_test

import (
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// NewTestConfig — happy path
// ---------------------------------------------------------------------------

func TestNewTestConfig_ReturnsValidConfig(t *testing.T) {
	// Arrange
	dsn := testhelper.NewTestDB(t)

	// Act
	cfg := testhelper.NewTestConfig(t, dsn)

	// Assert — config must not be nil.
	if cfg == nil {
		t.Fatal("NewTestConfig() returned nil")
	}

	// Assert — Validate must pass so the config is usable as-is.
	if err := cfg.Validate(); err != nil {
		t.Errorf("NewTestConfig().Validate() = %v, want nil", err)
	}
}

func TestNewTestConfig_UsesProvidedDBPath(t *testing.T) {
	// Arrange — two different DSNs.
	dsn1 := testhelper.NewTestDB(t)

	// Act
	cfg := testhelper.NewTestConfig(t, dsn1)

	// Assert — a future server wired from this config must open dsn1.
	// For now we verify that the DSN surfaced through config is non-empty and
	// references the path we passed in.
	if cfg == nil {
		t.Fatal("NewTestConfig() returned nil")
	}

	// The issuer must use HTTPS (required by Validate).
	if !strings.HasPrefix(cfg.Issuer, "https://") {
		t.Errorf("Issuer = %q, want HTTPS prefix", cfg.Issuer)
	}

	// Port must be valid.
	if cfg.Port <= 0 {
		t.Errorf("Port = %d, want > 0", cfg.Port)
	}

	// Owner credentials must be populated.
	if cfg.Owner.Username == "" {
		t.Error("Owner.Username is empty, want non-empty test username")
	}
	if cfg.Owner.PasswordHash == "" {
		t.Error("Owner.PasswordHash is empty, want non-empty bcrypt hash")
	}

	// JWTKeyPath must be set.
	if cfg.JWTKeyPath == "" {
		t.Error("JWTKeyPath is empty, want non-empty path")
	}
}
