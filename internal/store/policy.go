package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/xen0bit/netgraph/internal/policy"
)

func newPolicyID(prefix string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

// Policies lists saved policies, newest first.
func (s *Store) Policies(ctx context.Context) ([]policy.Summary, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT auid, name, version, mode, active, notes, created, modified, body
		FROM policies ORDER BY modified DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []policy.Summary{}
	for rows.Next() {
		var p policy.Summary
		var active int
		var body string
		if err := rows.Scan(&p.ID, &p.Name, &p.Version, &p.Mode, &active, &p.Notes, &p.Created, &p.Modified, &body); err != nil {
			return nil, err
		}
		p.Active = active != 0
		if parsed, err := policy.Parse(strings.NewReader(body)); err == nil {
			if parsed.Version == 2 {
				p.Rules = len(parsed.RulesV2)
			} else {
				p.Rules = len(parsed.Rules)
			}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Policy loads one policy by ID.
func (s *Store) Policy(ctx context.Context, id string) (*policy.Policy, error) {
	var body string
	var active int
	var created, modified int64
	err := s.r.QueryRowContext(ctx, `SELECT body, active, created, modified FROM policies WHERE auid = ?`, id).
		Scan(&body, &active, &created, &modified)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: policy %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, err
	}
	p, err := policy.Parse(strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", id, err)
	}
	p.ID, p.Active, p.Created, p.Modified = id, active != 0, created, modified
	return p, nil
}

// ActivePolicy returns the active policy, or nil when none is active.
func (s *Store) ActivePolicy(ctx context.Context) (*policy.Policy, error) {
	var id string
	err := s.r.QueryRowContext(ctx, `SELECT auid FROM policies WHERE active = 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.Policy(ctx, id)
}

// SavePolicy inserts or replaces a policy and its normalized rule rows.
func (s *Store) SavePolicy(ctx context.Context, p *policy.Policy) (*policy.Policy, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: no policy", ErrInvalid)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if p.ID == "" {
		id, err := newPolicyID("pol_")
		if err != nil {
			return nil, err
		}
		p.ID = id
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		p.Name = "policy " + p.ID
	}
	if p.Mode == "" {
		if p.Version == 2 {
			p.Mode = "precedence"
		} else {
			p.Mode = "first-match"
		}
	}
	now := s.cfg.Now().UTC().UnixMilli()
	if p.Created == 0 {
		p.Created = now
	}
	p.Modified = now
	if p.Version == 2 {
		ids := map[string]bool{}
		for i := range p.RulesV2 {
			if id := p.RulesV2[i].ID; id != "" {
				if ids[id] {
					return nil, fmt.Errorf("%w: rule ID %q appears twice", ErrInvalid, id)
				}
				ids[id] = true
			}
		}
		for i := range p.RulesV2 {
			if p.RulesV2[i].ID == "" {
				id, err := newPolicyID("rule_")
				if err != nil {
					return nil, err
				}
				p.RulesV2[i].ID = id
			}
		}
	}
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var existing int64
	var policyID int64
	err = tx.QueryRowContext(ctx, `SELECT id, created FROM policies WHERE auid = ?`, p.ID).Scan(&policyID, &existing)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, ierr := tx.ExecContext(ctx, `INSERT INTO policies (auid, name, version, mode, active, notes, body, created, modified)
			VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)`, p.ID, p.Name, p.Version, p.Mode, p.Notes, string(body), p.Created, p.Modified)
		if ierr != nil {
			return nil, ierr
		}
		policyID, err = res.LastInsertId()
	case err != nil:
		return nil, err
	default:
		p.Created = existing
		_, err = tx.ExecContext(ctx, `UPDATE policies SET name = ?, version = ?, mode = ?, notes = ?, body = ?, modified = ? WHERE auid = ?`,
			p.Name, p.Version, p.Mode, p.Notes, string(body), p.Modified, p.ID)
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_rules WHERE policy_id = ?`, policyID); err != nil {
		return nil, err
	}
	if p.Version == 2 {
		for i := range p.RulesV2 {
			r := &p.RulesV2[i]
			if r.ID == "" {
				id, err := newPolicyID("rule_")
				if err != nil {
					return nil, err
				}
				r.ID = id
			}
			local, _ := json.Marshal(r.Local)
			remote, _ := json.Marshal(r.Remote.Values)
			ports, _ := json.Marshal(r.Ports)
			enabled := 0
			if r.EnabledValue() {
				enabled = 1
			}
			trusted := 0
			if r.RequiresTrusted {
				trusted = 1
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO policy_rules
				(auid, policy_id, name, notes, origin, action, direction, priority, enabled, protected, profile, group_name,
				 local_selector, remote_type, remote_values, ports, protocol, lifetime, expiry, code_requirement, requires_trusted,
				 created, modified, last_used, use_count)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)`,
				r.ID, policyID, r.Name, r.Notes, r.Origin, r.Action, r.Direction, r.Priority, enabled, boolInt(r.Protected),
				r.Profile, r.Group, string(local), r.Remote.Type, string(remote), string(ports), r.Protocol, r.Lifetime,
				r.Expiry, r.CodeRequirement, trusted, p.Created, p.Modified)
			if err != nil {
				if strings.Contains(err.Error(), "UNIQUE") {
					return nil, fmt.Errorf("%w: rule ID %q belongs to another policy", ErrInvalid, r.ID)
				}
				return nil, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	// Re-read so the caller sees the generated rule IDs and normalized fields.
	return s.Policy(ctx, p.ID)
}

// DeletePolicy removes a policy and its rules.
func (s *Store) DeletePolicy(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var policyID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM policies WHERE auid = ?`, id).Scan(&policyID); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: policy %s", ErrNotFound, id)
	} else if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_rules WHERE policy_id = ?`, policyID); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM policies WHERE auid = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%w: policy %s", ErrNotFound, id)
	}
	return tx.Commit()
}

// ActivatePolicy makes one policy active and the rest inactive.
func (s *Store) ActivatePolicy(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var one int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM policies WHERE auid = ?`, id).Scan(&one); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: policy %s", ErrNotFound, id)
	} else if err != nil {
		return err
	}
	now := s.cfg.Now().UTC().UnixMilli()
	if _, err := tx.ExecContext(ctx, `UPDATE policies SET active = 0, modified = ? WHERE active = 1`, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE policies SET active = 1, modified = ? WHERE auid = ?`, now, id); err != nil {
		return err
	}
	return tx.Commit()
}
