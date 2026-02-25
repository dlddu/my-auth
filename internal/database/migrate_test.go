package database_test

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dlddu/my-auth/internal/database"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// tempDBPath returns a path for a temporary SQLite database file.
func tempDBPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.db")
}

// migrationPath returns the absolute path to the project migration file.
func migrationPath(t *testing.T) string {
	t.Helper()
	// Walk up from the test binary's working directory to find migrations/
	// In standard `go test ./...` the cwd is the package directory.
	path := filepath.Join("..", "..", "migrations", "001_init.sql")
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("migrationPath: %v", err)
	}
	return abs
}

// tableExists reports whether the named table exists in db.
func tableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var name string
	row := db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
	)
	err := row.Scan(&name)
	if err == sql.ErrNoRows {
		return false
	}
	if err != nil {
		t.Fatalf("tableExists(%q): %v", table, err)
	}
	return name == table
}

// ---------------------------------------------------------------------------
// Open — happy path
// ---------------------------------------------------------------------------

func TestOpen_ReturnsDB_WhenDSNValid(t *testing.T) {
	// Arrange
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=ON", tempDBPath(t))

	// Act
	db, err := database.Open(dsn)

	// Assert
	if err != nil {
		t.Fatalf("Open() returned unexpected error: %v", err)
	}
	if db == nil {
		t.Fatal("Open() returned nil *sql.DB")
	}
	defer db.Close()

	if pingErr := db.Ping(); pingErr != nil {
		t.Errorf("db.Ping() failed: %v", pingErr)
	}
}

func TestOpen_SetsMaxOpenConnsToOne(t *testing.T) {
	// Arrange
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=ON", tempDBPath(t))

	// Act
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open() returned unexpected error: %v", err)
	}
	defer db.Close()

	// Assert — SQLite requires a single writer to avoid SQLITE_BUSY errors.
	stats := db.Stats()
	if stats.MaxOpenConnections != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1", stats.MaxOpenConnections)
	}
}

func TestOpen_EnablesWALJournalMode(t *testing.T) {
	// Arrange
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=ON", tempDBPath(t))

	// Act
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open() returned unexpected error: %v", err)
	}
	defer db.Close()

	// Assert
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want %q", mode, "wal")
	}
}

func TestOpen_EnablesForeignKeys(t *testing.T) {
	// Arrange
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=ON", tempDBPath(t))

	// Act
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open() returned unexpected error: %v", err)
	}
	defer db.Close()

	// Assert
	var fkEnabled int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&fkEnabled); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if fkEnabled != 1 {
		t.Errorf("foreign_keys = %d, want 1 (enabled)", fkEnabled)
	}
}

// ---------------------------------------------------------------------------
// Open — error cases
// ---------------------------------------------------------------------------

func TestOpen_ReturnsError_WhenDSNInvalid(t *testing.T) {
	// Act — pass a directory path so the driver cannot create/open the file
	_, err := database.Open("file:///this/path/does/not/exist/db.sqlite?_journal_mode=WAL")

	// Assert
	if err == nil {
		t.Error("Open() expected error for invalid DSN, got nil")
	}
}

// ---------------------------------------------------------------------------
// Migrate — happy path
// ---------------------------------------------------------------------------

func TestMigrate_CreatesAllRequiredTables(t *testing.T) {
	// Arrange
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=ON", tempDBPath(t))
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer db.Close()

	// Act
	if err := database.Migrate(db, migrationPath(t)); err != nil {
		t.Fatalf("Migrate() returned unexpected error: %v", err)
	}

	// Assert — every required table must exist
	for _, table := range database.RequiredTables {
		if !tableExists(t, db, table) {
			t.Errorf("Migrate() did not create table %q", table)
		}
	}
}

func TestMigrate_IsIdempotent(t *testing.T) {
	// Arrange
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=ON", tempDBPath(t))
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer db.Close()

	migPath := migrationPath(t)

	// Act — run migration twice; second run must not fail
	if err := database.Migrate(db, migPath); err != nil {
		t.Fatalf("Migrate() first run: %v", err)
	}
	if err := database.Migrate(db, migPath); err != nil {
		t.Errorf("Migrate() second run (idempotency): %v", err)
	}
}

func TestMigrate_ClientsTable_HasExpectedColumns(t *testing.T) {
	// Arrange
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=ON", tempDBPath(t))
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer db.Close()
	if err := database.Migrate(db, migrationPath(t)); err != nil {
		t.Fatalf("Migrate(): %v", err)
	}

	// Act — query the column list via PRAGMA
	rows, err := db.Query("PRAGMA table_info(clients)")
	if err != nil {
		t.Fatalf("PRAGMA table_info(clients): %v", err)
	}
	defer rows.Close()

	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("rows.Scan: %v", err)
		}
		cols[name] = true
	}

	// Assert — minimum required columns
	required := []string{"id", "secret", "redirect_uris", "grant_types", "response_types", "scopes"}
	for _, col := range required {
		if !cols[col] {
			t.Errorf("clients table missing column %q", col)
		}
	}
}

// ---------------------------------------------------------------------------
// Migrate — error cases
// ---------------------------------------------------------------------------

func TestMigrate_ReturnsError_WhenMigrationFileNotFound(t *testing.T) {
	// Arrange
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=ON", tempDBPath(t))
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer db.Close()

	// Act
	err = database.Migrate(db, "/nonexistent/migration.sql")

	// Assert
	if err == nil {
		t.Error("Migrate() expected error for missing migration file, got nil")
	}
}

func TestMigrate_ReturnsError_WhenSQLInvalid(t *testing.T) {
	// Arrange
	dir := t.TempDir()
	badSQL := filepath.Join(dir, "bad.sql")
	if err := os.WriteFile(badSQL, []byte("THIS IS NOT SQL;;;"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_foreign_keys=ON", tempDBPath(t))
	db, err := database.Open(dsn)
	if err != nil {
		t.Fatalf("Open(): %v", err)
	}
	defer db.Close()

	// Act
	err = database.Migrate(db, badSQL)

	// Assert
	if err == nil {
		t.Error("Migrate() expected error for invalid SQL, got nil")
	}
}
