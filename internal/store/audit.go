package store

import (
	"context"
	"errors"

	"github.com/xen0bit/netgraph/internal/model"
)

const (
	maxAuditField = 256
	maxAuditRows  = 1000
)

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// AddAudit records a change someone made. Everything in it is bounded, since a
// proxy's header and a path both come from outside.
func (s *Store) AddAudit(ctx context.Context, e model.AuditEntry) error {
	if s.w == nil {
		return errors.New("database is open read-only")
	}
	if e.TS == 0 {
		e.TS = ms(s.cfg.Now())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.w.ExecContext(ctx, `INSERT INTO audit_log (ts, actor, role, action, target, remote) VALUES (?, ?, ?, ?, ?, ?)`,
		e.TS, clip(e.Actor, maxAuditField), clip(e.Role, maxAuditField), clip(e.Action, maxAuditField), clip(e.Target, maxAuditField), clip(e.Remote, maxAuditField))
	return err
}

// Audit lists changes, newest first.
func (s *Store) Audit(ctx context.Context, limit int) ([]model.AuditEntry, error) {
	if limit <= 0 || limit > maxAuditRows {
		limit = 200
	}
	rows, err := s.r.QueryContext(ctx, `SELECT id, ts, actor, role, action, target, remote FROM audit_log ORDER BY ts DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AuditEntry{}
	for rows.Next() {
		var e model.AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.Role, &e.Action, &e.Target, &e.Remote); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
