package testhelper_test

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/dlddu/my-auth/internal/testhelper"
)

// ---------------------------------------------------------------------------
// NewTestDB — happy path
// ---------------------------------------------------------------------------

func TestNewTestDB_CreatesAndCleansUp(t *testing.T) {
	// TODO: Activate when DLD-579 is implemented
	t.Skip("not implemented yet")

	// Arrange — capture the DSN before the test's sub-cleanup runs.
	var capturedDSN string

	// We run this as a sub-test so we can observe the effect of t.Cleanup.
	t.Run("inner", func(t *testing.T) {
		// Act
		dsn := testhelper.NewTestDB(t)
		capturedDSN = dsn

		// Assert — DSN must be non-empty and reference an existing file.
		if capturedDSN == "" {
			t.Fatal("NewTestDB() returned empty DSN")
		}
	})

	// After the sub-test finishes, t.Cleanup callbacks fire and the temp file
	// should be removed.
	// Extract the file path from the DSN ("file:<path>?...").
	filePath := strings.TrimPrefix(capturedDSN, "file:")
	if idx := strings.Index(filePath, "?"); idx != -1 {
		filePath = filePath[:idx]
	}

	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Errorf("NewTestDB cleanup: expected temp DB file %q to be removed, but it still exists (err=%v)", filePath, err)
	}
}

func TestNewTestDB_AppliesMigrations(t *testing.T) {
	// TODO: Activate when DLD-579 is implemented
	t.Skip("not implemented yet")

	// Act
	dsn := testhelper.NewTestDB(t)

	// Arrange — open a second handle to inspect the schema.
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()

	// Assert — all required tables must exist after NewTestDB.
	requiredTables := []string{
		"clients",
		"tokens",
		"sessions",
		"authorization_codes",
		"refresh_tokens",
		"device_codes",
	}

	for _, table := range requiredTables {
		var name string
		row := db.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		)
		if err := row.Scan(&name); err != nil {
			t.Errorf("NewTestDB: migration did not create table %q: %v", table, err)
		}
	}
}
