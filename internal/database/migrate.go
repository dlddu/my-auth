// Package database provides SQLite database initialisation and migration for my-auth.
package database

import (
	"database/sql"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	_ "github.com/golang-migrate/migrate/v4/source/file"
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

// Migrate applies all pending migrations from migrationsDir against db
// using golang-migrate.
func Migrate(db *sql.DB, migrationsDir string) error {
	driver, err := sqlite.WithInstance(db, &sqlite.Config{})
	if err != nil {
		return fmt.Errorf("database: create migrate driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://"+migrationsDir,
		"sqlite",
		driver,
	)
	if err != nil {
		return fmt.Errorf("database: create migrate instance: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("database: run migrations: %w", err)
	}

	return nil
}
