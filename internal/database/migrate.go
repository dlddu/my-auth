// Package database provides SQLite database initialisation and migration for my-auth.
package database

import (
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite" // register "sqlite" driver
)

// RequiredTables is the canonical list of table names that must exist after migration.
var RequiredTables = []string{
	"clients",
	"tokens",
	"sessions",
	"authorization_codes",
	"refresh_tokens",
	"device_codes",
}

// Open opens (or creates) a SQLite database at dsn, applies WAL journal mode,
// enables foreign keys, and limits the pool to a single writer.
// Returns the opened *sql.DB on success.
func Open(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("database: open %q: %w", dsn, err)
	}

	// SQLite requires a single writer connection to avoid SQLITE_BUSY.
	db.SetMaxOpenConns(1)

	// Ensure the database file is reachable.
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("database: ping %q: %w", dsn, err)
	}

	// Enable WAL journal mode for better concurrency.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("database: set journal_mode WAL: %w", err)
	}

	// Enable foreign key enforcement.
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("database: enable foreign_keys: %w", err)
	}

	return db, nil
}

// Migrate executes the SQL migration file at migrationPath against db.
// It creates the six required tables if they do not already exist.
func Migrate(db *sql.DB, migrationPath string) error {
	data, err := os.ReadFile(migrationPath)
	if err != nil {
		return fmt.Errorf("database: read migration file %q: %w", migrationPath, err)
	}

	if _, err := db.Exec(string(data)); err != nil {
		return fmt.Errorf("database: execute migration %q: %w", migrationPath, err)
	}

	return nil
}
