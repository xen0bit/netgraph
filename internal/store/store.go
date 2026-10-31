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

	"github.com/xen0bit/netgraph/internal/asn"
	"github.com/xen0bit/netgraph/internal/model"
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
	// ExactMax is the longest window answered from raw records; longer
	// windows use the hourly rollups (default 48h), which keeps a week's
	// or a month's view as cheap as a day's.
	ExactMax time.Duration
	// FactGap is how long a relationship may go unobserved before a new
	// observation starts a new period instead of extending the last one
	// (default 1h).
	FactGap time.Duration
	Logger  *slog.Logger
	// OnNewDevice, when set, is called after a batch commits, once per
	// device that used an address on the LAN for the first time. It runs
	// on the ingest path, so it should only hand the event off.
	OnNewDevice func(NewDevice)
	// ASN, when set, returns the current ASN table (nil when none is
	// loaded). Ingest records each remote end's network with it, and
	// EnrichASN fills in what was stored without one.
	ASN func() *asn.DB
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
	if c.ExactMax <= 0 {
		c.ExactMax = 48 * time.Hour
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
	if c.ASN == nil {
		c.ASN = func() *asn.DB { return nil }
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

	anomMu  sync.Mutex
	anomKey string
	anomAt  time.Time
	anomRep *model.AnomalyReport
}

func dsn(path string, readOnly bool) string {
	return dsnMode(path, readOnly, readOnly)
}

// dsnMode is dsn with explicit query_only control. A backup source is opened
// read-only without query_only: VACUUM INTO reads the source but creates a
// new file, which query_only would refuse.
func dsnMode(path string, readOnly, queryOnly bool) string {
	q := url.Values{}
	for _, p := range []string{"busy_timeout(10000)", "journal_mode(WAL)", "synchronous(NORMAL)", "foreign_keys(0)", "cache_size(-16000)", "temp_store(MEMORY)"} {
		q.Add("_pragma", p)
	}
	if queryOnly {
		q.Add("_pragma", "query_only(1)")
	}
	q.Set("_txlock", "immediate")
	return "file:" + path + "?" + q.Encode()
}

// schemaVersion is the migration version this binary expects.
func schemaVersion() int {
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return 0
	}
	v := 0
	for _, e := range entries {
		n, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err == nil && n > v {
			v = n
		}
	}
	return v
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
	if want := schemaVersion(); v != want {
		r.Close()
		if v < want {
			return nil, fmt.Errorf("%s: database schema is version %d, this binary needs %d (run `netgraph db migrate -db %s`)", path, v, want, path)
		}
		return nil, fmt.Errorf("%s: database schema is version %d, newer than this binary's %d (upgrade netgraph)", path, v, want)
	}
	if err := s.loadSensors(context.Background()); err != nil {
		r.Close()
		return nil, err
	}
	return s, nil
}

// OpenBackup opens an existing database for an online backup. It is
// read-only but permits VACUUM INTO, which query_only would refuse, and it
// deliberately does not require the current schema version: an old database
// can still be backed up before it is migrated.
func OpenBackup(path string, cfg Config) (*Store, error) {
	cfg.defaults()
	r, err := sql.Open("sqlite", dsnMode(path, true, false))
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
		return nil, fmt.Errorf("%s: not a netgraph database", path)
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

// invalidateAnomalies drops the short-lived anomaly report cache. New data
// or a retention pass can change what a window finds.
func (s *Store) invalidateAnomalies() {
	s.anomMu.Lock()
	s.anomRep = nil
	s.anomKey = ""
	s.anomMu.Unlock()
}

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
