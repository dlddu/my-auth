// Package testhelper provides shared test infrastructure for my-auth e2e and
// integration tests. All exported helpers follow the standard Go testing
// conventions: they accept *testing.T, call t.Helper(), and register cleanup
// via t.Cleanup() so resources are released automatically after each test.
package testhelper

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/dlddu/my-auth/internal/database"
)

// NewTestDB creates a temporary SQLite database file, applies all migrations,
// and registers t.Cleanup to close the connection and remove the file.
// It returns the DSN string suitable for use with database.Open.
//
// Each call creates a fully isolated database so tests do not share state.
func NewTestDB(t *testing.T) string {
	t.Helper()

	// t.TempDir() returns a directory that is removed by t.Cleanup automatically.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=ON", dbPath)

	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("testhelper.NewTestDB: open database: %v", err)
	}

	// Resolve the migrations directory relative to the module root.
	// When running `go test ./...` the working directory is the package directory,
	// so we walk up to the repo root where migrations/ lives.
	migrationsDir, err := filepath.Abs(filepath.Join("..", "..", "migrations"))
	if err != nil {
		db.Close()
		t.Fatalf("testhelper.NewTestDB: resolve migrations path: %v", err)
	}

	if err := database.Migrate(db, migrationsDir); err != nil {
		db.Close()
		t.Fatalf("testhelper.NewTestDB: run migrations: %v", err)
	}

	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Logf("testhelper.NewTestDB cleanup: close db: %v", err)
		}
	})

	return dsn
}
