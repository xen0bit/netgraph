package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/xen0bit/netgraph/internal/archive"
)

// archiveTable is a table retention can keep a copy of.
type archiveTable struct {
	name, timeCol string
	raw           bool // only with ArchiveRaw: these are much larger
}

var archiveTables = []archiveTable{
	{"traffic_hourly", "bucket", false},
	{"dns_hourly", "bucket", false},
	{"connections", "last_seen", true},
	{"dns", "ts", true},
}

// Columns that mean nothing outside this database: row numbers and entity ids, whose rows
// will be long gone. The device's MAC and label go in instead.
var archiveDropColumns = map[string]bool{"id": true, "sensor_id": true, "client_device": true, "server_device": true, "peer_device": true}

// recordArchiveDir notes where the archive is, for erasure to find later.
func (s *Store) recordArchiveDir(ctx context.Context) error {
	if s.cfg.ArchiveDir == "" || s.w == nil {
		return nil
	}
	dir, err := filepath.Abs(s.cfg.ArchiveDir)
	if err != nil {
		return err
	}
	_, err = s.w.ExecContext(ctx, `INSERT INTO archive_location (id, dir, raw, updated_at) VALUES (1, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET dir = excluded.dir, raw = excluded.raw, updated_at = excluded.updated_at`, dir, boolInt(s.cfg.ArchiveRaw), ms(s.cfg.Now()))
	return err
}

// UseRecordedArchive carries on with the archive the server set up, for a one-off retention
// pass from the command line: without it, `db retain` would delete what the server would keep.
func (s *Store) UseRecordedArchive(ctx context.Context) error {
	var dir string
	var raw bool
	err := s.r.QueryRowContext(ctx, `SELECT dir, raw FROM archive_location WHERE id = 1`).Scan(&dir, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	s.cfg.ArchiveDir, s.cfg.ArchiveRaw = dir, raw
	return nil
}

// RecordedArchive says where an archive was last set up, if anywhere.
func (s *Store) RecordedArchive(ctx context.Context) (string, error) {
	dir, ok, err := s.archiveDir(ctx)
	if err != nil || !ok {
		return "", err
	}
	return dir.Path, nil
}

// archiveDir finds the archive, whether or not this process was told about it.
func (s *Store) archiveDir(ctx context.Context) (archive.Dir, bool, error) {
	if s.cfg.ArchiveDir != "" {
		dir, err := filepath.Abs(s.cfg.ArchiveDir)
		return archive.Dir{Path: dir}, err == nil, err
	}
	var dir string
	err := s.r.QueryRowContext(ctx, `SELECT dir FROM archive_location WHERE id = 1`).Scan(&dir)
	if errors.Is(err, sql.ErrNoRows) {
		return archive.Dir{}, false, nil
	}
	if err != nil {
		return archive.Dir{}, false, err
	}
	return archive.Dir{Path: dir}, true, nil
}

// archiveExpired copies whole days older than a cutoff into the archive. It returns the
// moment before which rows may now be deleted, which is earlier than the cutoff, since a day
// is only archived once it's all past: the rest waits for the next pass. If anything goes
// wrong it returns 0, so nothing is deleted that hasn't been kept.
func (s *Store) archiveExpired(ctx context.Context, t archiveTable, cutoff int64) int64 {
	dir := archive.Dir{Path: s.cfg.ArchiveDir}
	dayCut := archive.DayOf(time.UnixMilli(cutoff)).UnixMilli()
	const dayMS = int64(24 * time.Hour / time.Millisecond)
	from := int64(-1 << 62)
	for {
		if ctx.Err() != nil {
			return 0
		}
		var first sql.NullInt64
		if err := s.r.QueryRowContext(ctx, `SELECT min(`+t.timeCol+`) FROM `+t.name+` WHERE `+t.timeCol+` >= ? AND `+t.timeCol+` < ?`, from, dayCut).Scan(&first); err != nil {
			s.log.Error("archive: finding what's expired", "table", t.name, "err", err)
			return 0
		}
		if !first.Valid {
			return dayCut
		}
		day := archive.DayOf(time.UnixMilli(first.Int64))
		next := day.UnixMilli() + dayMS
		n, err := s.archiveDay(ctx, dir, t, day, next)
		if err != nil {
			s.log.Error("archive: nothing past retention will be deleted until this works", "table", t.name, "day", day.Format("2006-01-02"), "err", err)
			return 0
		}
		if n > 0 {
			s.log.Debug("archived", "table", t.name, "day", day.Format("2006-01-02"), "rows", n)
		}
		from = next
	}
}

func (s *Store) archiveDay(ctx context.Context, dir archive.Dir, t archiveTable, day time.Time, next int64) (int, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT coalesce(e.key, ''), coalesce(nullif(e.label, ''), ''), t.* FROM `+t.name+` t
		LEFT JOIN entities e ON e.id = t.client_device AND e.kind = 'device'
		WHERE t.`+t.timeCol+` >= ? AND t.`+t.timeCol+` < ? ORDER BY t.`+t.timeCol, day.UnixMilli(), next)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	timeAt := -1
	for i, c := range cols {
		if c == t.timeCol {
			timeAt = i
		}
	}
	return dir.WriteDay(t.name, day, func() (archive.Row, bool, error) {
		if !rows.Next() {
			return nil, false, rows.Err()
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, false, err
		}
		row := archive.Row{}
		for i, c := range cols {
			if i < 2 || archiveDropColumns[c] || vals[i] == nil {
				continue
			}
			if b, ok := vals[i].([]byte); ok {
				row[c] = string(b)
			} else {
				row[c] = vals[i]
			}
		}
		if mac, _ := vals[0].(string); mac != "" {
			row[archive.DeviceKey] = mac
		}
		if label, _ := vals[1].(string); label != "" {
			row["device_label"] = label
		}
		if timeAt >= 0 {
			row[archive.TimeKey] = vals[timeAt]
		}
		return row, true, nil
	})
}

// archiveCuts archives what's about to expire, and says what each table may delete. Without
// an archive, that's just the retention cutoffs.
func (s *Store) archiveCuts(ctx context.Context, raw, roll int64) (rawConn, rawDNS, rollTraffic, rollDNS int64) {
	rawConn, rawDNS, rollTraffic, rollDNS = raw, raw, roll, roll
	if s.cfg.ArchiveDir == "" {
		return
	}
	for _, t := range archiveTables {
		if t.raw && !s.cfg.ArchiveRaw {
			continue
		}
		switch t.name {
		case "traffic_hourly":
			rollTraffic = s.archiveExpired(ctx, t, roll)
		case "dns_hourly":
			rollDNS = s.archiveExpired(ctx, t, roll)
		case "connections":
			rawConn = s.archiveExpired(ctx, t, raw)
		case "dns":
			rawDNS = s.archiveExpired(ctx, t, raw)
		}
	}
	if s.cfg.ArchiveMaxBytes > 0 {
		gone, err := archive.Dir{Path: s.cfg.ArchiveDir}.Trim(s.cfg.ArchiveMaxBytes)
		if err != nil {
			s.log.Error("archive: trimming to its limit", "err", err)
		}
		if len(gone) > 0 {
			s.log.Warn("archive over its limit: removed the oldest days", "files", len(gone), "oldest", gone[0].Day.Format("2006-01-02"))
		}
	}
	return
}

// ArchiveStatus says what's being kept.
type ArchiveStatus struct {
	Enabled bool  `json:"enabled"`
	Bytes   int64 `json:"bytes"`
	Files   int   `json:"files"`
	Oldest  int64 `json:"oldest,omitempty"`
	Newest  int64 `json:"newest,omitempty"`
}

// ArchiveStatus reads the archive's directory.
func (s *Store) ArchiveStatus(ctx context.Context) (ArchiveStatus, error) {
	var out ArchiveStatus
	dir, ok, err := s.archiveDir(ctx)
	if err != nil || !ok {
		return out, err
	}
	out.Enabled = s.cfg.ArchiveDir != ""
	files, err := dir.List()
	if err != nil {
		return out, err
	}
	out.Files = len(files)
	for _, f := range files {
		out.Bytes += f.Bytes
	}
	if len(files) > 0 {
		out.Oldest, out.Newest = files[0].Day.UnixMilli(), files[len(files)-1].Day.UnixMilli()
	}
	return out, nil
}

// eraseFromArchive applies an erasure to the archive after the database's. The database has
// changed by now, so a failure here says so plainly rather than looking like nothing happened.
func (s *Store) eraseFromArchive(ctx context.Context, erase func(archive.Dir) (int64, error)) (int64, error) {
	dir, ok, err := s.archiveDir(ctx)
	if err != nil {
		return 0, fmt.Errorf("finding the archive: %w", err)
	}
	if !ok {
		return 0, nil
	}
	n, err := erase(dir)
	if err != nil {
		return n, fmt.Errorf("the database is done, but the archive at %s isn't: %w", dir.Path, err)
	}
	return n, nil
}
