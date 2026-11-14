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
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/xen0bit/netgraph/internal/asn"
	"github.com/xen0bit/netgraph/internal/geo"
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
	// MinuteRetention keeps per-minute traffic this long (default 30 days).
	MinuteRetention time.Duration
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
	// Geo, when set, returns the current local geo table.
	Geo func() *geo.DB
	// Now is the clock; tests set it.
	Now func() time.Time
	// ArchiveDir, when set, keeps hourly rollups in files as they pass retention.
	ArchiveDir string
	// ArchiveRaw also keeps raw connections and lookups, which are much larger.
	ArchiveRaw bool
	// ArchiveMaxBytes removes the archive's oldest days beyond this. Zero is no limit.
	ArchiveMaxBytes int64
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
	if c.MinuteRetention <= 0 {
		c.MinuteRetention = 30 * 24 * time.Hour
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

// Now returns the store's clock. Tests set it; production uses time.Now.
func (s *Store) Now() time.Time { return s.cfg.Now() }

// Store is an open database.
type Store struct {
	cfg  Config
	path string
	w    *sql.DB // single connection: SQLite has one writer
	r    *sql.DB // read-only pool
	log  *slog.Logger

	mu     sync.Mutex // serialises ingest; guards ing and netSig
	ing    *ingester
	netSig string // the network signature profile triggers last acted on

	nets *localNets
	sub  *broker

	types typeCache

	findMu       sync.Mutex // serialises scans; guards the two below
	findScanned  time.Time
	findLearning bool

	// dnsSelf is where netgraph's own DNS server answers (SetDNSSelf).
	dnsSelf atomic.Pointer[map[netip.Addr]bool]

	anomMu  sync.Mutex
	anomGen uint64 // bumped by invalidateAnomalies
	// anomSlots holds recent reports by cache key: a page asks for its
	// window's, the map for its own, Home and the Recorder for theirs.
	anomSlots map[string]*anomalySlot
	// anomFlight holds the report being computed per cache key, so requests
	// that arrive together (a refresh's anomaly list and its graph) share one
	// run of the checks.
	anomFlight map[string]*anomalyRun
	anomRuns   atomic.Int64 // how many times the checks ran; for tests
}

// dsn opens path in WAL mode; queryOnly refuses writes. A backup source is
// opened without query_only: VACUUM INTO reads the source but creates a new
// file, which query_only would refuse.
func dsn(path string, queryOnly bool) string {
	q := url.Values{}
	pragmas := []string{"busy_timeout(10000)", "foreign_keys(0)", "cache_size(-16000)", "temp_store(MEMORY)"}
	if !queryOnly {
		// A read-only connection must not try to switch the journal
		// mode or run WAL recovery: that is a write.
		// journal_size_limit: a burst (a retention pass, an import) grows the
		// WAL, and SQLite keeps the file at its high-water mark (428 MB was
		// seen) unless told to cut it back after a checkpoint.
		pragmas = append(pragmas, "journal_mode(WAL)", "synchronous(NORMAL)", "journal_size_limit(67108864)")
	}
	for _, p := range pragmas {
		q.Add("_pragma", p)
	}
	if queryOnly {
		q.Add("_pragma", "query_only(1)")
		q.Set("mode", "ro")
	} else {
		q.Set("_txlock", "immediate")
	}
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
	readers := max(4, runtime.GOMAXPROCS(0))
	r.SetMaxOpenConns(readers)
	// Keep every reader open: database/sql keeps 2 idle by default and closes
	// the rest after each query, and a new connection starts with an empty
	// page cache and parses the schema again.
	r.SetMaxIdleConns(readers)
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
	if err := s.recordArchiveDir(context.Background()); err != nil {
		s.Close()
		return nil, fmt.Errorf("recording the archive's location: %w", err)
	}
	return s, nil
}

// OpenReadOnly opens an existing database for queries only, as the CLI does
// with -db while a server may be writing to it.
func OpenReadOnly(path string, cfg Config) (*Store, error) {
	cfg.defaults()
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
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
	// Without query_only, opening a missing path would create it.
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	r, err := sql.Open("sqlite", dsn(path, false))
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

// BackupOptions controls an online backup.
type BackupOptions struct {
	// Force replaces an existing destination.
	Force bool
}

// Backup writes a consistent copy of the database with VACUUM INTO. The
// copy is made beside the destination and only renamed into place after an
// integrity check, so an interrupted or corrupt backup leaves no partial
// file that looks valid.
func (s *Store) Backup(ctx context.Context, path string, opts ...BackupOptions) error {
	force := len(opts) > 0 && opts[0].Force
	if filepath.Clean(path) == filepath.Clean(s.path) {
		return errors.New("backup destination is the open database")
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s exists (use -force to replace it)", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	// VACUUM INTO requires the destination not to exist.
	if err := os.Remove(tmpName); err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	db := s.w
	if db == nil {
		db = s.r
	}
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", tmpName); err != nil {
		return err
	}
	// A backup that cannot be opened and integrity-checked is not a backup.
	// Plain read-only: dsn's journal_mode(WAL) would convert the copy and
	// leave -wal/-shm files under the temporary name.
	check, err := sql.Open("sqlite", "file:"+tmpName+"?mode=ro")
	if err != nil {
		return err
	}
	var result string
	err = check.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result)
	check.Close()
	if err != nil {
		return fmt.Errorf("backup integrity check: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("backup integrity check: %s", result)
	}
	f, err := os.OpenFile(tmpName, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		if !force || runtime.GOOS != "windows" {
			return err
		}
		// Windows cannot rename over an existing file.
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(tmpName, path); err != nil {
			return err
		}
	}
	cleanup = false
	return nil
}

// invalidateAnomaliesThrottled is for the ingest path, which runs every few
// seconds: new data marks a report more than ten seconds old as stale. A stale
// report is still answered, at once, while a fresh one is computed behind it:
// recomputing every check before every answer made each page wait for all of
// them on a live server.
//
// It leaves the generation alone: bumping it would stop a running report
// being cached, and checks slower than the gap between batches would then
// never be cached at all.
func (s *Store) invalidateAnomaliesThrottled() {
	s.anomMu.Lock()
	defer s.anomMu.Unlock()
	now := s.cfg.Now()
	for _, sl := range s.anomSlots {
		if now.Sub(sl.at) >= anomalyIngestAllowance {
			sl.stale = true
		}
	}
}

// invalidateAnomalies drops every report: a person changed something (a
// label, a mute) or data was deleted, and that shows at once.
func (s *Store) invalidateAnomalies() {
	s.anomMu.Lock()
	s.anomGen++
	s.anomSlots = nil
	s.anomMu.Unlock()
}

func (s *Store) migrate(ctx context.Context) error {
	var version int
	if err := s.w.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > schemaVersion() {
		return fmt.Errorf("database schema is version %d, newer than this binary's %d (upgrade netgraph)", version, schemaVersion())
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
// Vacuum rebuilds the database file, reclaiming all free space.
func (s *Store) Vacuum(ctx context.Context) error {
	if s.w == nil {
		return fmt.Errorf("database is open read-only")
	}
	_, err := s.w.ExecContext(ctx, "VACUUM")
	return err
}

func ms(t time.Time) int64 { return t.UnixMilli() }
