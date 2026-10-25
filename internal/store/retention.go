package store

import (
	"context"
	"time"
)

// RetentionResult counts what one retention pass deleted.
type RetentionResult struct {
	Flows, DNS, Answers, Observations, Facts, Rollups, Entities int64
}

// Retain deletes data past its retention: raw tables after RawRetention,
// facts and hourly rollups after RollupRetention, and entities nothing
// refers to any more. Deletes run in chunks so ingest is never blocked for
// long, and freed pages are returned to the filesystem.
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
		{&r.Entities, `DELETE FROM entities WHERE rowid IN (SELECT id FROM entities e WHERE e.last_seen < ?
			AND NOT EXISTS (SELECT 1 FROM facts WHERE src = e.id OR dst = e.id) LIMIT 5000)`, roll},
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range steps {
		for {
			if err := ctx.Err(); err != nil {
				return r, err
			}
			res, err := s.w.ExecContext(ctx, st.sql, st.arg)
			if err != nil {
				return r, err
			}
			n, _ := res.RowsAffected()
			*st.n += n
			if n < 5000 {
				break
			}
		}
	}
	if r.Entities > 0 || r.Facts > 0 {
		// Cached IDs may point at deleted rows.
		s.ing = newIngester(s)
		if err := s.ing.warm(ctx); err != nil {
			return r, err
		}
	}
	if _, err := s.w.ExecContext(ctx, `PRAGMA incremental_vacuum`); err != nil {
		return r, err
	}
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
