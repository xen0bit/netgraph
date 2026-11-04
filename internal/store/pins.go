package store

import (
	"context"
	"database/sql"
	"fmt"
	"math"

	"github.com/xen0bit/netgraph/internal/model"
)

// maxPins bounds what a client can store: far more than anyone drags by hand.
const maxPins = 5000

// MapPins lists the nodes a person has placed.
func (s *Store) MapPins(ctx context.Context) ([]model.MapPin, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, x, y, updated FROM map_pins ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.MapPin{}
	for rows.Next() {
		var p model.MapPin
		if err := rows.Scan(&p.ID, &p.X, &p.Y, &p.Updated); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetMapPins stores places for nodes, all or none. IDs are graph node IDs:
// entity IDs, which can be sites or networks as well as devices.
func (s *Store) SetMapPins(ctx context.Context, pins []model.MapPin) error {
	if len(pins) > maxPins {
		return fmt.Errorf("%w: at most %d pins at once", ErrInvalid, maxPins)
	}
	for _, p := range pins {
		if p.ID == "" || len(p.ID) > 512 {
			return fmt.Errorf("%w: pin id", ErrInvalid)
		}
		if _, _, ok := model.SplitEntityID(p.ID); !ok {
			return fmt.Errorf("%w: pin id %q", ErrInvalid, p.ID)
		}
		if math.IsNaN(p.X) || math.IsInf(p.X, 0) || math.IsNaN(p.Y) || math.IsInf(p.Y, 0) {
			return fmt.Errorf("%w: pin position", ErrInvalid)
		}
	}
	now := ms(s.cfg.Now())
	if err := s.inTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM map_pins`).Scan(&n); err != nil {
			return err
		}
		if n+len(pins) > maxPins {
			// Moving existing pins is always fine; only growth is capped.
			if _, err := tx.ExecContext(ctx, `DELETE FROM map_pins WHERE id IN (SELECT id FROM map_pins ORDER BY updated LIMIT ?)`, n+len(pins)-maxPins); err != nil {
				return err
			}
		}
		for _, p := range pins {
			if _, err := tx.ExecContext(ctx, `INSERT INTO map_pins (id, x, y, updated) VALUES (?, ?, ?, ?)
				ON CONFLICT (id) DO UPDATE SET x = excluded.x, y = excluded.y, updated = excluded.updated`, p.ID, p.X, p.Y, now); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// DeleteMapPins removes pins; an empty list removes them all.
func (s *Store) DeleteMapPins(ctx context.Context, ids []string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if len(ids) == 0 {
			_, err := tx.ExecContext(ctx, `DELETE FROM map_pins`)
			return err
		}
		for _, id := range ids {
			if _, err := tx.ExecContext(ctx, `DELETE FROM map_pins WHERE id = ?`, id); err != nil {
				return err
			}
		}
		return nil
	})
}
