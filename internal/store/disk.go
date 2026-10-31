package store

import (
	"context"
	"errors"
	"os"
)

// Size returns the database file plus its WAL, the space a disk guard must
// consider. A WAL can grow independently of the main file.
func (s *Store) Size() int64 {
	var n int64
	for _, p := range []string{s.path, s.path + "-wal"} {
		if fi, err := os.Stat(p); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// EmergencyTrim deletes the oldest raw rows until the database is at or
// below target. It never touches rollups or facts unless allowRollups is set. It is
// deliberately separate from Retain so a full disk can be relieved without
// silently shortening the configured retention forever.
func (s *Store) EmergencyTrim(ctx context.Context, target int64, allowRollups bool) (RetentionResult, error) {
	var r RetentionResult
	if s.w == nil {
		return r, errors.New("database is open read-only")
	}
	if target <= 0 {
		return r, errors.New("target must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	deleteChunk := func(n *int64, q string) error {
		res, err := s.w.ExecContext(ctx, q)
		if err != nil {
			return err
		}
		k, _ := res.RowsAffected()
		*n += k
		return nil
	}
	for s.Size() > target {
		before := s.Size()
		steps := []struct {
			n *int64
			q string
		}{
			{&r.Flows, `DELETE FROM flows WHERE rowid IN (SELECT rowid FROM flows ORDER BY t_end LIMIT 5000)`},
			{&r.Flows, `DELETE FROM connections WHERE flow_key IN (SELECT flow_key FROM connections ORDER BY last_seen LIMIT 5000)`},
			{&r.DNS, `DELETE FROM dns WHERE rowid IN (SELECT rowid FROM dns ORDER BY ts LIMIT 5000)`},
			{&r.Answers, `DELETE FROM dns_answers WHERE rowid IN (SELECT rowid FROM dns_answers ORDER BY expires LIMIT 5000)`},
			{&r.Observations, `DELETE FROM observations WHERE rowid IN (SELECT rowid FROM observations ORDER BY ts LIMIT 5000)`},
		}
		if allowRollups {
			// Facts are kept as long as rollups (RollupRetention), so
			// they are trimmed only when rollups may be.
			steps = append(steps,
				struct {
					n *int64
					q string
				}{&r.Facts, `DELETE FROM facts WHERE rowid IN (SELECT rowid FROM facts ORDER BY last_seen LIMIT 5000)`},
				struct {
					n *int64
					q string
				}{&r.Rollups, `DELETE FROM traffic_hourly WHERE bucket IN (SELECT bucket FROM traffic_hourly ORDER BY bucket LIMIT 5000)`},
				struct {
					n *int64
					q string
				}{&r.Rollups, `DELETE FROM dns_hourly WHERE bucket IN (SELECT bucket FROM dns_hourly ORDER BY bucket LIMIT 5000)`},
			)
		}
		for _, st := range steps {
			if err := deleteChunk(st.n, st.q); err != nil {
				return r, err
			}
		}
		if _, err := s.w.ExecContext(ctx, `PRAGMA incremental_vacuum`); err != nil {
			return r, err
		}
		if _, err := s.w.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			return r, err
		}
		if s.Size() >= before {
			// Deletes no longer reclaim space; one full rebuild is the
			// only remaining option and is safe here because the guard
			// holds the ingest lock.
			if _, err := s.w.ExecContext(ctx, `VACUUM`); err != nil {
				return r, err
			}
		}
		if s.Size() >= before {
			break
		}
	}
	s.ing = newIngester(s)
	if err := s.ing.warm(ctx); err != nil {
		s.log.Error("rewarm ingest caches after emergency trim", "err", err)
	}
	s.invalidateAnomalies()
	return r, nil
}
