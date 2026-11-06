package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/purpose"
)

// Purposes lists purpose metadata.
func (s *Store) Purposes(ctx context.Context) ([]model.Purpose, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, application, developer, website, host, purpose, deny_consequences, source, updated
		FROM app_purposes ORDER BY application, host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Purpose{}
	for rows.Next() {
		var p model.Purpose
		if err := rows.Scan(&p.ID, &p.Application, &p.Developer, &p.Website, &p.Host, &p.Purpose, &p.DenyConsequences, &p.Source, &p.Updated); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PurposeFor returns the metadata for a host, newest first.
func (s *Store) PurposeFor(ctx context.Context, host string) ([]model.Purpose, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	rows, err := s.r.QueryContext(ctx, `SELECT id, application, developer, website, host, purpose, deny_consequences, source, updated
		FROM app_purposes WHERE host = ? ORDER BY application`, host)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Purpose{}
	for rows.Next() {
		var p model.Purpose
		if err := rows.Scan(&p.ID, &p.Application, &p.Developer, &p.Website, &p.Host, &p.Purpose, &p.DenyConsequences, &p.Source, &p.Updated); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ImportPurpose replaces one application's purpose entries.
func (s *Store) ImportPurpose(ctx context.Context, m *purpose.Manifest) (int, error) {
	if m == nil {
		return 0, fmt.Errorf("%w: no manifest", ErrInvalid)
	}
	if err := m.Validate(); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	now := s.cfg.Now().UTC().UnixMilli()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM app_purposes WHERE application = ?`, m.Application); err != nil {
		return 0, err
	}
	for _, c := range m.Connections {
		if _, err := tx.ExecContext(ctx, `INSERT INTO app_purposes
			(application, developer, website, host, purpose, deny_consequences, source, updated)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			m.Application, m.Developer, m.Website, c.Host, c.Purpose, c.DenyConsequences, m.Source, now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(m.Connections), nil
}

// DeletePurpose removes one entry.
func (s *Store) DeletePurpose(ctx context.Context, id int64) error {
	res, err := s.w.ExecContext(ctx, `DELETE FROM app_purposes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: purpose %d", ErrNotFound, id)
	}
	return nil
}
