package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

// ForgetResult counts what ForgetDevice removed.
type ForgetResult struct {
	Device       string `json:"device"`
	Flows        int64  `json:"flows"`
	Connections  int64  `json:"connections"`
	DNS          int64  `json:"dns"`
	Observations int64  `json:"observations"`
	Facts        int64  `json:"facts"`
	Rollups      int64  `json:"rollups"`
	Handshakes   int64  `json:"handshakes"`
	Groups       int64  `json:"group_keys"`
}

// ForgetDevice removes one device and everything attributed to it: its
// connections and interval records, lookups, observations, facts, Wi-Fi
// sync records and rollups, then the device entity. It is the privacy
// control for a phone that was sold or a guest that should not remain in
// the history.
func (s *Store) ForgetDevice(ctx context.Context, mac string) (ForgetResult, error) {
	res := ForgetResult{Device: mac}
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
	// dns_answers has no device column; remove answers of the lookups the
	// device made before deleting those lookup rows.
	count(`DELETE FROM dns_answers WHERE dns_id NOT IN (SELECT id FROM dns)`)
	res.Observations = count(`DELETE FROM observations WHERE device = ?`, id)
	res.Facts = count(`DELETE FROM facts WHERE src = ? OR dst = ?`, id, id)
	res.Rollups = count(`DELETE FROM traffic_hourly WHERE client_device = ?`, id) +
		count(`DELETE FROM dns_hourly WHERE client_device = ?`, id)
	res.Handshakes = count(`DELETE FROM wifi_handshakes WHERE bssid = ? OR sta = ?`, m, m)
	res.Groups = count(`DELETE FROM wifi_group_keys WHERE bssid = ? OR sta = ?`, m, m)
	if err == nil {
		count(`DELETE FROM entities WHERE id = ?`, id)
	}
	if err != nil {
		return res, err
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}
	// The cached entity/fact IDs may now point at deleted rows.
	s.ing = newIngester(s)
	if err := s.ing.warm(ctx); err != nil {
		s.log.Error("rewarm ingest caches after forget", "err", err)
	}
	s.invalidateAnomalies()
	return res, nil
}

// PurgeResult counts what PurgeBefore removed.
type PurgeResult struct {
	Flows, Connections, DNS, Answers, Observations, Facts, Rollups, Entities, Handshakes int64
}

// PurgeBefore deletes data older than before, regardless of the configured
// retention. It is an operator escape hatch for a disk that needs space now
// or a period that must not remain in the history.
func (s *Store) PurgeBefore(ctx context.Context, before time.Time) (PurgeResult, error) {
	var r PurgeResult
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
	if err == nil {
		r.Entities = count(`DELETE FROM entities WHERE id IN (SELECT e.id FROM entities e WHERE e.last_seen < ?
			AND NOT EXISTS (SELECT 1 FROM facts f WHERE f.src = e.id OR f.dst = e.id))`, cut)
	}
	if err != nil {
		return r, err
	}
	if err := tx.Commit(); err != nil {
		return r, err
	}
	s.ing = newIngester(s)
	if err := s.ing.warm(ctx); err != nil {
		s.log.Error("rewarm ingest caches after purge", "err", err)
	}
	s.invalidateAnomalies()
	return r, nil
}
