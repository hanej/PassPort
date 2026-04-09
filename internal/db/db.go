// Package db provides SQLite database access with WAL mode and writer/reader pool separation.
package db

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// DB wraps a writer connection (single) and reader pool (multiple) for SQLite WAL mode.
type DB struct {
	writer *sql.DB
	reader *sql.DB
	path   string
}

// Open opens a SQLite database at the given path, enables WAL mode, and returns
// a DB with separate writer and reader pools.
func Open(path string) (*DB, error) {
	// Writer: single connection, serializes all writes
	writer, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("opening writer: %w", err)
	}
	writer.SetMaxOpenConns(1)

	if err := writer.Ping(); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("pinging writer: %w", err)
	}

	// Reader: pool of connections for concurrent reads.
	// WAL mode allows readers to see committed writes without blocking.
	reader, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("opening reader: %w", err)
	}
	reader.SetMaxOpenConns(10)

	if err := reader.Ping(); err != nil {
		_ = writer.Close()
		_ = reader.Close()
		return nil, fmt.Errorf("pinging reader: %w", err)
	}

	return &DB{writer: writer, reader: reader, path: path}, nil
}

// OpenMemory opens an in-memory SQLite database (useful for testing).
// Both writer and reader point to the same connection since in-memory DBs
// are not shared across connections.
func OpenMemory() (*DB, error) {
	dsn := "file::memory:?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&cache=shared"
	writer, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening memory db: %w", err)
	}
	writer.SetMaxOpenConns(1)

	if err := writer.Ping(); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("pinging memory db: %w", err)
	}

	// For in-memory, reader shares the same connection pool
	reader, err := sql.Open("sqlite", dsn)
	if err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("opening memory reader: %w", err)
	}
	reader.SetMaxOpenConns(10)

	return &DB{writer: writer, reader: reader, path: ":memory:"}, nil
}

// Writer returns the writer database connection.
func (d *DB) Writer() *sql.DB {
	return d.writer
}

// Reader returns the reader database connection pool.
func (d *DB) Reader() *sql.DB {
	return d.reader
}

// Close closes both writer and reader connections.
func (d *DB) Close() error {
	rerr := d.reader.Close()
	werr := d.writer.Close()
	if werr != nil {
		return werr
	}
	return rerr
}

// Ping checks that both writer and reader connections are alive.
func (d *DB) Ping(ctx context.Context) error {
	if err := d.writer.PingContext(ctx); err != nil {
		return fmt.Errorf("writer ping: %w", err)
	}
	if err := d.reader.PingContext(ctx); err != nil {
		return fmt.Errorf("reader ping: %w", err)
	}
	return nil
}
