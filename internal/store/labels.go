package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/xen0bit/netgraph/internal/model"
)

// ErrInvalid is returned for a request the store refuses, such as a
// malformed MAC or label.
var ErrInvalid = errors.New("invalid request")

// MaxLabel is the longest user label, in characters.
const MaxLabel = 64

// SetDeviceLabel names a device by hand. The name overrides every
// automatic source (DHCP, mDNS, ...) until it is cleared with an empty
// label, which restores the best automatic name. The automatic name keeps
// being tracked meanwhile, in the auto_label attribute.
func (s *Store) SetDeviceLabel(ctx context.Context, mac, label string) error {
	if s.w == nil {
		return errors.New("database is open read-only")
	}
	m, ok := normMAC(mac)
	if !ok {
		return fmt.Errorf("%w: MAC %q", ErrInvalid, mac)
	}
	label = strings.TrimSpace(label)
	if utf8.RuneCountInString(label) > MaxLabel || !utf8.ValidString(label) ||
		strings.IndexFunc(label, unicode.IsControl) >= 0 {
		return fmt.Errorf("%w: a label is at most %d printable characters", ErrInvalid, MaxLabel)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.ing
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	g.tx = tx
	defer func() { g.tx = nil }()
	err = g.userLabel(ctx, m, label)
	if err == nil {
		err = tx.Commit()
	} else {
		_ = tx.Rollback()
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		// The cached row may now describe a rolled-back write.
		s.ing = newIngester(s)
		if werr := s.ing.warm(ctx); werr != nil {
			s.log.Error("rewarm ingest caches", "err", werr)
		}
	}
	return err
}

func (g *ingester) userLabel(ctx context.Context, mac, label string) error {
	var seen int64
	err := g.tx.QueryRowContext(ctx, `SELECT last_seen FROM entities WHERE kind = ? AND key = ?`, model.KindDevice, mac).Scan(&seen)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: device %s", ErrNotFound, mac)
	}
	if err != nil {
		return err
	}
	// Loading through the cache at the row's own last_seen changes no
	// timestamps, and keeps the cache and the row in step.
	if _, err := g.entity(ctx, model.KindDevice, mac, seen, nil); err != nil {
		return err
	}
	e := g.row(model.KindDevice, mac)
	user := e.attrs["user_label"]
	switch {
	case label == "" && user == "":
		return nil
	case label == "":
		e.label = e.attrs["auto_label"]
		delete(e.attrs, "user_label")
		delete(e.attrs, "auto_label")
	default:
		if user == "" {
			e.attrs["auto_label"] = e.label
		}
		e.attrs["user_label"] = label
		e.label = label
	}
	b, _ := json.Marshal(e.attrs)
	if _, err := g.tx.ExecContext(ctx, `UPDATE entities SET label = ?, attrs = ? WHERE id = ?`, e.label, string(b), e.id); err != nil {
		return err
	}
	e.dirty = false
	return nil
}

// FirstSensorSeen is when the first sensor first reported: when the network
// started being learned. It is the zero time before any sensor has.
func (s *Store) FirstSensorSeen(ctx context.Context) (time.Time, error) {
	var first sql.NullInt64
	if err := s.r.QueryRowContext(ctx, `SELECT min(first_seen) FROM sensors`).Scan(&first); err != nil {
		return time.Time{}, err
	}
	if !first.Valid {
		return time.Time{}, nil
	}
	return time.UnixMilli(first.Int64).UTC(), nil
}
