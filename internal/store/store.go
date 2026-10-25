// Package store is netgraph's persistence: a SQLite database (pure Go,
// modernc.org/sqlite) in WAL mode with one writer and a pool of readers.
// It ingests sensor events (store/ingest.go), applies retention and keeps
// hourly rollups (retention.go), and answers model.Backend queries
// (query*.go).
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

//go:embed migrations/*.sql
var migrations embed.FS

// Config tunes a store.
type Config struct {
	// RawRetention keeps raw flows, DNS and observations this long
	// (default 14 days). Windows older than this are answered from hourly
	// rollups.
	RawRetention time.Duration
	// RollupRetention keeps hourly rollups and facts this long (default
	// 180 days).
	RollupRetention time.Duration
	// FactGap is how long a relationship may go unobserved before a new
	// observation starts a new period instead of extending the last one
	// (default 1h).
	FactGap time.Duration
	Logger  *slog.Logger
	// Now is the clock; tests set it.
	Now func() time.Time
}

func (c *Config) defaults() {
	if c.RawRetention <= 0 {
		c.RawRetention = 14 * 24 * time.Hour
	}
	if c.RollupRetention <= 0 {
		c.RollupRetention = 180 * 24 * time.Hour
	}
	if c.FactGap <= 0 {
		c.FactGap = time.Hour
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// Store is an open database.
type Store struct {
	cfg  Config
	path string
	w    *sql.DB // single connection: SQLite has one writer
	r    *sql.DB // read-only pool
	log  *slog.Logger

	mu  sync.Mutex // serialises ingest; guards ing
	ing *ingester

	nets *localNets
	sub  *broker
}

func dsn(path string, readOnly bool) string {
	q := url.Values{}
	for _, p := range []string{"busy_timeout(10000)", "journal_mode(WAL)", "synchronous(NORMAL)", "foreign_keys(0)", "cache_size(-16000)", "temp_store(MEMORY)"} {
		q.Add("_pragma", p)
	}
	if readOnly {
		q.Add("_pragma", "query_only(1)")
	}
	q.Set("_txlock", "immediate")
	return "file:" + path + "?" + q.Encode()
}

// Open opens or creates the database at path and migrates it.
func Open(path string, cfg Config) (*Store, error) {
	cfg.defaults()
	w, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	w.SetConnMaxLifetime(0)
	s := &Store{cfg: cfg, path: path, w: w, log: cfg.Logger, sub: newBroker()}
	if err := s.migrate(context.Background()); err != nil {
		w.Close()
		return nil, err
	}
	r, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(max(4, runtime.GOMAXPROCS(0)))
	s.r = r
	s.nets = newLocalNets()
	if err := s.loadSensors(context.Background()); err != nil {
		s.Close()
		return nil, err
	}
	s.ing = newIngester(s)
	if err := s.ing.warm(context.Background()); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// OpenReadOnly opens an existing database for queries only, as the CLI does
// with -db while a server may be writing to it.
func OpenReadOnly(path string, cfg Config) (*Store, error) {
	cfg.defaults()
	r, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		return nil, err
	}
	s := &Store{cfg: cfg, path: path, r: r, log: cfg.Logger, nets: newLocalNets(), sub: newBroker()}
	var v int
	if err := r.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		r.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if v == 0 {
		r.Close()
		return nil, fmt.Errorf("%s: not a netgraph database (run `netgraph serve` or `netgraph db migrate` first)", path)
	}
	if err := s.loadSensors(context.Background()); err != nil {
		r.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error {
	var err error
	if s.r != nil {
		err = s.r.Close()
	}
	if s.w != nil {
		_, _ = s.w.Exec("PRAGMA optimize")
		if e := s.w.Close(); err == nil {
			err = e
		}
	}
	return err
}

// Path is the database file.
func (s *Store) Path() string { return s.path }

func (s *Store) migrate(ctx context.Context) error {
	var version int
	if err := s.w.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version == 0 {
		// Must precede the first table: auto_vacuum cannot be switched on
		// later without a full VACUUM.
		if _, err := s.w.ExecContext(ctx, "PRAGMA auto_vacuum = INCREMENTAL"); err != nil {
			return err
		}
	}
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		n, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil || n <= version {
			continue
		}
		body, err := migrations.ReadFile("migrations/" + e.Name())
		if err != nil {
			return err
		}
		tx, err := s.w.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", e.Name(), err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", n)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		s.log.Info("migrated database", "version", n)
	}
	return nil
}

// Backup writes a consistent copy of the database to path.
func (s *Store) Backup(ctx context.Context, path string) error {
	db := s.w
	if db == nil {
		db = s.r
	}
	_, err := db.ExecContext(ctx, "VACUUM INTO ?", path)
	return err
}

// Vacuum rebuilds the database file, reclaiming all free space.
func (s *Store) Vacuum(ctx context.Context) error {
	if s.w == nil {
		return fmt.Errorf("database is open read-only")
	}
	_, err := s.w.ExecContext(ctx, "VACUUM")
	return err
}

func ms(t time.Time) int64 { return t.UnixMilli() }
