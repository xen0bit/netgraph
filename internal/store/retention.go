package store

import (
	"context"
	"time"
)

// RetentionResult counts what one retention pass deleted.
type RetentionResult struct {
	Flows, DNS, Answers, Observations, Facts, Rollups, Entities, Handshakes, Mutes int64
}

// Retain deletes data past its retention: raw tables after RawRetention,
// facts and hourly rollups after RollupRetention, and entities nothing
// refers to any more. Deletes run in chunks that each hold the ingest lock
// only while they run, so a large backlog does not stall ingest; freed
// pages are returned to the filesystem.
func (s *Store) Retain(ctx context.Context) (RetentionResult, error) {
	var r RetentionResult
	now := s.cfg.Now()
	raw := ms(now.Add(-s.cfg.RawRetention))
	roll := ms(now.Add(-s.cfg.RollupRetention))
	steps := []struct {
		n   *int64
		sql string
		arg int64
	}{
		{&r.Flows, `DELETE FROM flows WHERE rowid IN (SELECT rowid FROM flows WHERE t_end < ? LIMIT 5000)`, raw},
		{&r.Flows, `DELETE FROM connections WHERE flow_key IN (SELECT flow_key FROM connections WHERE last_seen < ? LIMIT 5000)`, raw},
		{&r.DNS, `DELETE FROM dns WHERE rowid IN (SELECT rowid FROM dns WHERE ts < ? LIMIT 5000)`, raw},
		{&r.Answers, `DELETE FROM dns_answers WHERE rowid IN (SELECT rowid FROM dns_answers WHERE expires < ? LIMIT 5000)`, raw},
		{&r.Observations, `DELETE FROM observations WHERE rowid IN (SELECT rowid FROM observations WHERE ts < ? LIMIT 5000)`, raw},
		{&r.Facts, `DELETE FROM facts WHERE rowid IN (SELECT rowid FROM facts WHERE last_seen < ? LIMIT 5000)`, roll},
		// The rollups are WITHOUT ROWID; they are small enough to delete
		// in one statement.
		{&r.Rollups, `DELETE FROM traffic_hourly WHERE bucket < ?`, roll},
		{&r.Rollups, `DELETE FROM dns_hourly WHERE bucket < ?`, roll},
		// A handshake's key stays valid while the client stays associated,
		// which can be months for a fixed device, so these follow the
		// rollups. Without a limit, clients with rotating private MACs
		// would grow the table (and every sensor's key sync) forever.
		{&r.Handshakes, `DELETE FROM wifi_handshakes WHERE ts < ?`, roll},
		// At most four rows per AP, and an AP that never rekeys keeps
		// its GTK for as long as it runs, so these follow the rollups too.
		{&r.Handshakes, `DELETE FROM wifi_group_keys WHERE ts < ?`, roll},
		{&r.Mutes, `DELETE FROM anomaly_mutes WHERE until < ?`, now.UnixMilli()},
	}
	// Each chunk takes the ingest lock for itself, so ingest runs between
	// them. Deleting a fact ingest still has open is harmless: a fact past
	// rollup retention is far beyond -fact-gap, so ingest starts a new
	// period rather than extend it.
	run := func(n *int64, sql string, arg int64, lock bool) error {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			if lock {
				s.mu.Lock()
			}
			res, err := s.w.ExecContext(ctx, sql, arg)
			if lock {
				s.mu.Unlock()
			}
			if err != nil {
				return err
			}
			k, _ := res.RowsAffected()
			*n += k
			if k < 5000 {
				return nil
			}
		}
	}
	for _, st := range steps {
		if err := run(st.n, st.sql, st.arg, true); err != nil {
			return r, err
		}
	}
	// Entities are another matter: ingest caches their IDs, so it must not
	// run between deleting one and dropping the cache. These deletes are
	// few, since an entity outlives its facts only briefly.
	s.mu.Lock()
	if err := run(&r.Entities, `DELETE FROM entities WHERE rowid IN (SELECT id FROM entities e WHERE e.last_seen < ?
		AND NOT EXISTS (SELECT 1 FROM facts WHERE src = e.id OR dst = e.id) LIMIT 5000)`, roll, false); err != nil {
		s.mu.Unlock()
		return r, err
	}
	if r.Entities > 0 || r.Facts > 0 {
		// Cached IDs may point at deleted rows.
		s.ing = newIngester(s)
		if err := s.ing.warm(ctx); err != nil {
			s.mu.Unlock()
			return r, err
		}
	}
	s.mu.Unlock()
	// Reclaiming pages can take seconds. Do it without the ingest lock, or
	// a large database makes one ingest wait for most of the pass.
	if _, err := s.w.ExecContext(ctx, `PRAGMA incremental_vacuum`); err != nil {
		return r, err
	}
	s.invalidateAnomalies()
	return r, nil
}

// RunRetention applies retention every interval until ctx ends.
func (s *Store) RunRetention(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		r, err := s.Retain(ctx)
		if err != nil && ctx.Err() == nil {
			s.log.Error("retention", "err", err)
		} else if r != (RetentionResult{}) {
			s.log.Info("retention", "flows", r.Flows, "dns", r.DNS, "observations", r.Observations, "facts", r.Facts, "rollups", r.Rollups, "entities", r.Entities)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
