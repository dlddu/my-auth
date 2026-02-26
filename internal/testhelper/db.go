// Package testhelper provides shared test infrastructure for my-auth e2e and
// integration tests. All exported helpers follow the standard Go testing
// conventions: they accept *testing.T, call t.Helper(), and register cleanup
// via t.Cleanup() so resources are released automatically after each test.
package testhelper

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dlddu/my-auth/internal/database"
)

// migrationsDir returns the absolute path to the repo-root migrations/
// directory. It uses the source location of this file (db.go) to anchor
// the path, which is reliable regardless of the test package's working
// directory when running `go test ./...`.
func migrationsDir() string {
	// __file__ is the absolute path to this source file at compile time.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("testhelper: runtime.Caller failed")
	}
	// db.go lives at internal/testhelper/db.go.
	// Walk up two levels to reach the repo root, then descend into migrations/.
	repoRoot := filepath.Join(filepath.Dir(file), "..", "..")
	abs, err := filepath.Abs(filepath.Join(repoRoot, "migrations"))
	if err != nil {
		panic(fmt.Sprintf("testhelper: resolve migrations dir: %v", err))
	}
	return abs
}

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

	migrations := migrationsDir()

	// Sanity-check: the migrations directory must exist.
	if _, err := os.Stat(migrations); err != nil {
		db.Close()
		t.Fatalf("testhelper.NewTestDB: migrations dir %q: %v", migrations, err)
	}

	if err := database.Migrate(db, migrations); err != nil {
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
