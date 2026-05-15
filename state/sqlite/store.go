// Package sqlite is the concrete SQLite-backed implementation that satisfies
// the per-consumer state interfaces defined across the codebase via Go's
// structural typing (see state/doc.go).
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"time"

	// Pure-Go SQLite driver registered under the "sqlite" name with database/sql.
	_ "modernc.org/sqlite"
)

type options struct {
	path        string
	maxConns    int
	busyTimeout time.Duration
}

type Option func(*options)

func WithPath(p string) Option { return func(o *options) { o.path = p } }

func WithMaxConns(n int) Option { return func(o *options) { o.maxConns = n } }

func WithBusyTimeout(d time.Duration) Option { return func(o *options) { o.busyTimeout = d } }

func defaultOptions() *options {
	return &options{
		path:        "/var/lib/tempogate/state.db",
		maxConns:    1,
		busyTimeout: 5 * time.Second,
	}
}

type Store struct {
	db *sql.DB
}

func New(opts ...Option) (*Store, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
	}
	if o.path == "" {
		return nil, fmt.Errorf("sqlite: empty path")
	}

	db, err := sql.Open("sqlite", dsn(o))
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	db.SetMaxOpenConns(o.maxConns)

	return &Store{db: db}, nil
}

func dsn(o *options) string {
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", o.busyTimeout.Milliseconds()))
	q.Add("_pragma", "journal_mode(wal)")
	q.Add("_pragma", "foreign_keys(on)")
	return "file:" + o.path + "?" + q.Encode()
}

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) Close() error { return s.db.Close() }
