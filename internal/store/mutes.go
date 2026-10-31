package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

const maxMuteNote = 200

// SetAnomalyMute creates or replaces a mute. An empty Until means one day
// from now. A mute with no kind and no device/entity would silence
// everything, so it is rejected.
func (s *Store) SetAnomalyMute(ctx context.Context, m model.AnomalyMute) error {
	if s.w == nil {
		return errors.New("database is open read-only")
	}
	if m.Kind == "" && m.Device == "" && m.Entity == "" {
		return fmt.Errorf("%w: a mute needs a kind, device or entity", ErrInvalid)
	}
	if len(m.Kind) > 64 || len(m.Device) > 128 || len(m.Entity) > 256 || len(m.Note) > maxMuteNote {
		return fmt.Errorf("%w: mute field too long", ErrInvalid)
	}
	now := s.cfg.Now()
	if m.Until <= 0 {
		m.Until = now.Add(24 * time.Hour).UnixMilli()
	}
	if m.Until <= now.UnixMilli() {
		return fmt.Errorf("%w: until must be in the future", ErrInvalid)
	}
	m.Note = strings.TrimSpace(m.Note)
	_, err := s.w.ExecContext(ctx, `INSERT INTO anomaly_mutes (kind, device, entity, until, note, created)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (kind, device, entity) DO UPDATE SET until = excluded.until, note = excluded.note, created = excluded.created`,
		m.Kind, m.Device, m.Entity, m.Until, m.Note, now.UnixMilli())
	if err == nil {
		s.invalidateAnomalies()
	}
	return err
}

// DeleteAnomalyMute removes the exact mute key.
func (s *Store) DeleteAnomalyMute(ctx context.Context, kind, device, entity string) error {
	if s.w == nil {
		return errors.New("database is open read-only")
	}
	_, err := s.w.ExecContext(ctx, `DELETE FROM anomaly_mutes WHERE kind = ? AND device = ? AND entity = ?`, kind, device, entity)
	if err == nil {
		s.invalidateAnomalies()
	}
	return err
}

// AnomalyMutes lists mutes. With active true, expired rows are omitted.
func (s *Store) AnomalyMutes(ctx context.Context, active bool) ([]model.AnomalyMute, error) {
	q := `SELECT kind, device, entity, until, note, created FROM anomaly_mutes`
	args := []any{}
	if active {
		q += ` WHERE until > ?`
		args = append(args, s.cfg.Now().UnixMilli())
	}
	q += ` ORDER BY until, kind, device, entity`
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AnomalyMute{}
	for rows.Next() {
		var m model.AnomalyMute
		if err := rows.Scan(&m.Kind, &m.Device, &m.Entity, &m.Until, &m.Note, &m.Created); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func muteMatches(m model.AnomalyMute, a model.Anomaly) bool {
	return (m.Kind == "" || m.Kind == a.Kind) &&
		(m.Device == "" || m.Device == a.Device) &&
		(m.Entity == "" || m.Entity == a.Entity)
}
