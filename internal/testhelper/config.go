package testhelper

import (
	"testing"

	"github.com/dlddu/my-auth/internal/config"
)

// testOwnerUsername is the fixed owner username used in all test configs.
const testOwnerUsername = "admin@test.local"

// testOwnerPasswordHash is the bcrypt hash of "test-password" with cost 12.
// Pre-computed to avoid expensive bcrypt work in every test setup.
// Plain-text: "test-password"
const testOwnerPasswordHash = "$2a$12$f9hwtKC5D99r4BOC0UJwM.To6001PN8CS4TEVUEH.IQOGoPWuPZvy"

// testJWTKeyPath is a sentinel path for the JWT signing key in tests.
// The actual key file is not required until the server boots; test helpers
// that do not start the full server can use this value safely.
const testJWTKeyPath = "/tmp/test-jwt-key.pem"

// testIssuer is the OIDC issuer URL used in test configurations.
// It uses HTTPS to satisfy the Validate() constraint while remaining
// clearly non-production.
const testIssuer = "https://auth.test.local"

// NewTestConfig returns a *config.Config suitable for use in tests.
// It uses the provided dbPath as the SQLite data source and populates
// all required fields with deterministic test values.
//
// The returned config passes Validate() without modification.
func NewTestConfig(t *testing.T, dbPath string) *config.Config {
	t.Helper()

	cfg := &config.Config{
		Issuer: testIssuer,
		Port:   0, // 0 signals "use an ephemeral port" for test servers
		Owner: config.OwnerCredentials{
			Username:     testOwnerUsername,
			PasswordHash: testOwnerPasswordHash,
		},
		JWTKeyPath: testJWTKeyPath,
	}

	// Override Port to the default so Validate() does not reject it.
	// Test servers that need a free port will override this themselves.
	cfg.Port = 8080

	return cfg
}
