package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

// ForgetOptions controls a device erasure.
type ForgetOptions struct {
	// DryRun performs every count and rolls the transaction back.
	DryRun bool
}

// ForgetResult counts what ForgetDevice removed.
type ForgetResult struct {
	Device       string `json:"device"`
	Flows        int64  `json:"flows"`
	Connections  int64  `json:"connections"`
	DNS          int64  `json:"dns"`
	Observations int64  `json:"observations"`
	Facts        int64  `json:"facts"`
	Rollups      int64  `json:"rollups"`
	Entities     int64  `json:"entities"`
	Handshakes   int64  `json:"handshakes"`
	Groups       int64  `json:"group_keys"`
	Mutes        int64  `json:"mutes"`
	DryRun       bool   `json:"dry_run,omitempty"`
}

// ForgetDevice removes one device and everything attributed to it: its
// connections and interval records, lookups, observations, facts, Wi-Fi
// sync records, rollups and private address entities, then the device
// entity. It is the privacy control for a phone that was sold or a guest
// that should not remain in the history.
func (s *Store) ForgetDevice(ctx context.Context, mac string) (ForgetResult, error) {
	return s.ForgetDeviceWithOptions(ctx, mac, ForgetOptions{})
}

func (s *Store) ForgetDeviceWithOptions(ctx context.Context, mac string, opts ForgetOptions) (ForgetResult, error) {
	res := ForgetResult{Device: mac, DryRun: opts.DryRun}
	m, ok := normMAC(mac)
	if !ok {
		return res, fmt.Errorf("%w: MAC %q", ErrInvalid, mac)
	}
	if s.w == nil {
		return res, errors.New("database is open read-only")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	var id int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM entities WHERE kind = ? AND key = ?`, model.KindDevice, m).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return res, fmt.Errorf("%w: device %s", ErrNotFound, m)
		}
		return res, err
	}
	// Remember the private entities attached to the device before the facts
	// that mention them go away. Only addresses are in Search's result set
	// (and therefore a privacy leak); hostnames and service strings are
	// dropped if no other fact keeps them alive too.
	var related []int64
	rows, err := tx.QueryContext(ctx, `SELECT dst FROM facts WHERE src = ? AND dst != ?
		UNION SELECT src FROM facts WHERE dst = ? AND src != ?`, id, id, id, id)
	if err != nil {
		return res, err
	}
	for rows.Next() {
		var rel int64
		if err := rows.Scan(&rel); err != nil {
			rows.Close()
			return res, err
		}
		related = append(related, rel)
	}
	if err := rows.Close(); err != nil {
		return res, err
	}
	count := func(q string, args ...any) int64 {
		r, err2 := tx.ExecContext(ctx, q, args...)
		if err2 != nil {
			err = err2
			return 0
		}
		n, _ := r.RowsAffected()
		return n
	}
	res.Flows = count(`DELETE FROM flows WHERE client_device = ? OR client_mac = ?`, id, m)
	res.Connections = count(`DELETE FROM connections WHERE client_device = ? OR client_mac = ?`, id, m)
	res.DNS = count(`DELETE FROM dns WHERE client_device = ?`, id)
	// dns_answers has no device column; remove answers whose lookup rows
	// were just deleted (or were already orphaned by an earlier purge).
	count(`DELETE FROM dns_answers WHERE dns_id NOT IN (SELECT id FROM dns)`)
	res.Observations = count(`DELETE FROM observations WHERE device = ?`, id)
	res.Facts = count(`DELETE FROM facts WHERE src = ? OR dst = ?`, id, id)
	res.Rollups = count(`DELETE FROM traffic_hourly WHERE client_device = ?`, id) +
		count(`DELETE FROM dns_hourly WHERE client_device = ?`, id)
	res.Handshakes = count(`DELETE FROM wifi_handshakes WHERE bssid = ? OR sta = ?`, m, m)
	res.Groups = count(`DELETE FROM wifi_group_keys WHERE bssid = ? OR sta = ?`, m, m)
	res.Mutes = count(`DELETE FROM anomaly_mutes WHERE device = ?`, model.EntityID(model.KindDevice, m))
	if err == nil {
		// Delete addresses that belonged only to this device. Shared
		// addresses (a DNS answer, another device's lease) stay because
		// facts still reference them.
		if len(related) > 0 {
			res.Entities = count(`DELETE FROM entities WHERE id IN (` + idList(related) + `)
				AND kind IN ('ip', 'hostname', 'service', 'fingerprint', 'useragent', 'upnp', 'lldp')
				AND NOT EXISTS (SELECT 1 FROM facts f WHERE f.src = entities.id OR f.dst = entities.id)`)
		}
		res.Entities += count(`DELETE FROM entities WHERE id = ?`, id)
	}
	if err != nil {
		return res, err
	}
	if opts.DryRun {
		return res, nil
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}
	// The cached entity/fact IDs may now point at deleted rows.
	s.ing = newIngester(s)
	if err := s.ing.warm(ctx); err != nil {
		s.log.Error("rewarm ingest caches after forget", "err", err)
	}
	_, _ = s.w.ExecContext(ctx, `PRAGMA incremental_vacuum`)
	s.invalidateAnomalies()
	return res, nil
}

// PurgeOptions controls an age-based purge.
type PurgeOptions struct {
	// DryRun performs every count and rolls the transaction back.
	DryRun bool
}

// PurgeResult counts what PurgeBefore removed.
type PurgeResult struct {
	Flows, Connections, DNS, Answers, Observations, Facts, Rollups, Entities, Handshakes, Mutes int64
	DryRun                                                                                      bool
}

// PurgeBefore deletes data older than before, regardless of the configured
// retention. It is an operator escape hatch for a disk that needs space now
// or a period that must not remain in the history.
func (s *Store) PurgeBefore(ctx context.Context, before time.Time) (PurgeResult, error) {
	return s.PurgeBeforeWithOptions(ctx, before, PurgeOptions{})
}

func (s *Store) PurgeBeforeWithOptions(ctx context.Context, before time.Time, opts PurgeOptions) (PurgeResult, error) {
	var r PurgeResult
	r.DryRun = opts.DryRun
	if s.w == nil {
		return r, errors.New("database is open read-only")
	}
	cut := ms(before)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	count := func(q string, args ...any) int64 {
		res, err2 := tx.ExecContext(ctx, q, args...)
		if err2 != nil {
			err = err2
			return 0
		}
		n, _ := res.RowsAffected()
		return n
	}
	r.Flows = count(`DELETE FROM flows WHERE t_end < ?`, cut)
	r.Connections = count(`DELETE FROM connections WHERE last_seen < ?`, cut)
	r.DNS = count(`DELETE FROM dns WHERE ts < ?`, cut)
	r.Answers = count(`DELETE FROM dns_answers WHERE expires < ? OR ts < ?`, cut, cut)
	r.Observations = count(`DELETE FROM observations WHERE ts < ?`, cut)
	r.Facts = count(`DELETE FROM facts WHERE last_seen < ?`, cut)
	r.Rollups = count(`DELETE FROM traffic_hourly WHERE bucket < ?`, cut) +
		count(`DELETE FROM dns_hourly WHERE bucket < ?`, cut)
	r.Handshakes = count(`DELETE FROM wifi_handshakes WHERE ts < ?`, cut) +
		count(`DELETE FROM wifi_group_keys WHERE ts < ?`, cut)
	r.Mutes = count(`DELETE FROM anomaly_mutes WHERE until < ?`, cut)
	if err == nil {
		// An entity may still be named by a raw row that survived the
		// cutoff (a long-running connection, for example). Keep it in
		// that case so queries never show a device ID without a label.
		r.Entities = count(`DELETE FROM entities WHERE id IN (SELECT e.id FROM entities e WHERE e.last_seen < ?
			AND NOT EXISTS (SELECT 1 FROM facts f WHERE f.src = e.id OR f.dst = e.id)
			AND NOT EXISTS (SELECT 1 FROM connections c WHERE c.client_device = e.id)
			AND NOT EXISTS (SELECT 1 FROM dns d WHERE d.client_device = e.id)
			AND NOT EXISTS (SELECT 1 FROM observations o WHERE o.device = e.id)
			AND NOT EXISTS (SELECT 1 FROM traffic_hourly t WHERE t.client_device = e.id)
			AND NOT EXISTS (SELECT 1 FROM dns_hourly h WHERE h.client_device = e.id))`, cut)
	}
	if err != nil {
		return r, err
	}
	if opts.DryRun {
		return r, nil
	}
	if err := tx.Commit(); err != nil {
		return r, err
	}
	s.ing = newIngester(s)
	if err := s.ing.warm(ctx); err != nil {
		s.log.Error("rewarm ingest caches after purge", "err", err)
	}
	_, _ = s.w.ExecContext(ctx, `PRAGMA incremental_vacuum`)
	s.invalidateAnomalies()
	return r, nil
}
