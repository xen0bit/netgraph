package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"iter"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/xen0bit/netgraph/internal/asn"
	"github.com/xen0bit/netgraph/internal/model"
)

// enrichChunk is how many rows one EnrichASN step looks up while holding
// the ingest lock.
const enrichChunk = 2000

// EnrichASN fills in the network of remote ends that were stored while no
// ASN table was loaded (remote_asn NULL), in connections and in the hourly
// rollups, and records the networks it finds as asn entities. It works in
// chunks that each hold the ingest lock only briefly. It returns how many
// rows it updated; without a table it does nothing.
func (s *Store) EnrichASN(ctx context.Context) (int64, error) {
	db := s.cfg.ASN()
	if db == nil || s.w == nil {
		return 0, nil
	}
	var total int64
	for _, t := range []struct {
		sel, upd string
		keys     int // leading columns that identify a row
	}{
		{`SELECT flow_key, remote_ip, last_seen FROM connections WHERE remote_asn IS NULL LIMIT ?`,
			`UPDATE connections SET remote_asn = ?, remote_cc = ? WHERE flow_key = ?`, 1},
		{`SELECT bucket, client_device, client_ip, remote_ip, remote_port, proto, name, direction, remote_ip, bucket + 3600000 FROM traffic_hourly WHERE remote_asn IS NULL LIMIT ?`,
			`UPDATE traffic_hourly SET remote_asn = ?, remote_cc = ? WHERE bucket = ? AND client_device = ? AND client_ip = ? AND remote_ip = ? AND remote_port = ? AND proto = ? AND name = ? AND direction = ?`, 8},
	} {
		for {
			n, err := s.enrichStep(ctx, db, t.sel, t.upd, t.keys)
			if err != nil {
				return total, err
			}
			total += int64(n)
			if n < enrichChunk {
				break
			}
		}
	}
	return total, nil
}

// enrichStep looks up one chunk of rows: sel returns each row's key
// columns, then its remote address and a time it was seen.
func (s *Store) enrichStep(ctx context.Context, db *asn.DB, sel, upd string, keys int) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.w.QueryContext(ctx, sel, enrichChunk)
	if err != nil {
		return 0, err
	}
	type row struct {
		key    []any
		remote string
		ts     int64
	}
	var todo []row
	for rows.Next() {
		r := row{key: make([]any, keys)}
		dest := make([]any, keys+2)
		for i := range r.key {
			dest[i] = &r.key[i]
		}
		dest[keys], dest[keys+1] = &r.remote, &r.ts
		if err := rows.Scan(dest...); err != nil {
			rows.Close()
			return 0, err
		}
		todo = append(todo, r)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if len(todo) == 0 {
		return 0, nil
	}
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var updated int64
	for _, r := range todo {
		var n int64
		var cc string
		if a, err := netip.ParseAddr(r.remote); err == nil {
			if info, ok := db.Lookup(a); ok {
				n, cc = int64(info.ASN), info.Country
				if err := upsertASN(ctx, tx, info, r.ts); err != nil {
					return 0, err
				}
			}
		}
		res, err := tx.ExecContext(ctx, upd, append([]any{n, cc}, r.key...)...)
		if err != nil {
			return 0, err
		}
		k, _ := res.RowsAffected()
		updated += k
	}
	if updated == 0 {
		// The same rows would come back forever.
		return 0, errors.New("enrich asn: no row updated")
	}
	return len(todo), tx.Commit()
}

// upsertASN records a network outside the ingester, as asnEntity does:
// the entity's ID never changes, so the ingester's cache stays valid.
func upsertASN(ctx context.Context, tx *sql.Tx, info asn.Info, ts int64) error {
	attrs := map[string]string{}
	if info.Country != "" {
		attrs["country"] = info.Country
	}
	b, _ := json.Marshal(attrs)
	_, err := tx.ExecContext(ctx, `INSERT INTO entities (kind, key, label, first_seen, last_seen, attrs) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (kind, key) DO UPDATE SET first_seen = min(first_seen, excluded.first_seen), last_seen = max(last_seen, excluded.last_seen)`,
		model.KindASN, strconv.FormatUint(uint64(info.ASN), 10), ASNLabel(info.ASN, info.Org), ts, ts, string(b))
	return err
}

// setASOrgs names the network of each flow that has one, from the asn
// entities ingest recorded: the database keeps the names, so they show
// without the table loaded.
func (s *Store) setASOrgs(ctx context.Context, flows []model.Flow) error {
	orgs, err := s.asOrgs(ctx, func(yield func(uint32) bool) {
		for _, fl := range flows {
			if fl.ASN != 0 && !yield(fl.ASN) {
				return
			}
		}
	})
	if err != nil {
		return err
	}
	for i := range flows {
		flows[i].ASOrg = orgs[flows[i].ASN]
	}
	return nil
}

// asOrgs maps AS numbers to their organisations.
func (s *Store) asOrgs(ctx context.Context, asns iter.Seq[uint32]) (map[uint32]string, error) {
	keys := map[string]bool{}
	for n := range asns {
		keys[strconv.FormatUint(uint64(n), 10)] = true
	}
	out := map[uint32]string{}
	if len(keys) == 0 {
		return out, nil
	}
	cond, arg := inList("key", slices.Sorted(maps.Keys(keys)))
	rows, err := s.r.QueryContext(ctx, `SELECT key, label FROM entities WHERE kind = 'asn' AND `+cond, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, label string
		if err := rows.Scan(&key, &label); err != nil {
			return nil, err
		}
		n, err := strconv.ParseUint(key, 10, 32)
		if err != nil {
			continue
		}
		org, _ := strings.CutPrefix(label, "AS"+key)
		out[uint32(n)] = strings.TrimSpace(org)
	}
	return out, rows.Err()
}
