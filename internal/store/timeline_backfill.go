package store

import (
	"context"
	"fmt"
	"time"
)

// BackfillTimeline rebuilds the Flight Recorder's event index from the raw
// tables. It is idempotent (the unique index ignores existing rows) and is
// meant for databases created before the index existed, or after dropping
// it. It is chunked by the caller's `since` value, not by row count, so a
// very old raw window can still take a while; run it once.
func (s *Store) BackfillTimeline(ctx context.Context, since time.Time) (int64, error) {
	if s.w == nil {
		return 0, fmt.Errorf("database is open read-only")
	}
	from := ms(since)
	var total int64
	steps := []string{
		`INSERT OR IGNORE INTO timeline_events
			(ts, kind, entity_id, entity_key, title, ref_table, ref_key, attrs)
		 SELECT first_seen, 'device_new', id, kind || ':' || key,
		        'new device ' || coalesce(nullif(label, ''), key),
		        'entities', cast(id AS TEXT), '{}'
		 FROM entities WHERE kind = 'device' AND first_seen >= ?`,
		`INSERT OR IGNORE INTO timeline_events
			(ts, kind, entity_id, entity_key, title, ref_table, ref_key, attrs)
		 SELECT o.ts, 'observation', o.device,
		        coalesce(e.kind || ':' || e.key, ''), o.type || ' ' || o.ip,
		        'observations', cast(o.id AS TEXT), json_object('type', o.type)
		 FROM observations o LEFT JOIN entities e ON e.id = o.device
		 WHERE o.ts >= ?`,
		`INSERT OR IGNORE INTO timeline_events
			(ts, kind, entity_id, entity_key, title, ref_table, ref_key, attrs)
		 SELECT d.ts, 'dns', d.client_device,
		        coalesce(e.kind || ':' || e.key, ''), d.qname,
		        'dns', cast(d.id AS TEXT), json_object('qtype', d.qtype, 'rcode', d.rcode)
		 FROM dns d LEFT JOIN entities e ON e.id = d.client_device
		 WHERE d.ts >= ?`,
		`INSERT OR IGNORE INTO timeline_events
			(ts, kind, entity_id, entity_key, title, ref_table, ref_key, attrs)
		 SELECT c.first_seen, 'flow_open', c.client_device,
		        coalesce(e.kind || ':' || e.key, ''),
		        'opened ' || coalesce(nullif(c.sni, ''), nullif(c.http_host, ''), nullif(c.qname, ''), c.remote_ip),
		        'connections', c.flow_key, json_object('direction', c.direction)
		 FROM connections c LEFT JOIN entities e ON e.id = c.client_device
		 WHERE c.first_seen >= ?`,
		`INSERT OR IGNORE INTO timeline_events
			(ts, kind, entity_id, entity_key, title, ref_table, ref_key, attrs)
		 SELECT c.last_seen, 'flow_close', c.client_device,
		        coalesce(e.kind || ':' || e.key, ''),
		        'closed ' || coalesce(nullif(c.sni, ''), nullif(c.http_host, ''), nullif(c.qname, ''), c.remote_ip),
		        'connections', c.flow_key || ':close',
		        json_object('direction', c.direction, 'reason', c.end_reason)
		 FROM connections c LEFT JOIN entities e ON e.id = c.client_device
		 WHERE c.final = 1 AND c.last_seen >= ?`,
	}
	for _, q := range steps {
		res, err := s.w.ExecContext(ctx, q, from)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}
