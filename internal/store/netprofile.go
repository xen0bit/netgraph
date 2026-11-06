package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/wire"
)

// Profiles lists profiles.
func (s *Store) Profiles(ctx context.Context) ([]model.Profile, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, auid, name, description, active, mode, dns_exceptions, is_default, created, modified
		FROM profiles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Profile{}
	for rows.Next() {
		var p model.Profile
		var active, def int
		var dns string
		if err := rows.Scan(&p.ID, &p.AUID, &p.Name, &p.Description, &active, &p.Mode, &dns, &def, &p.Created, &p.Modified); err != nil {
			return nil, err
		}
		p.Active, p.IsDefault = active != 0, def != 0
		_ = json.Unmarshal([]byte(dns), &p.DNSExceptions)
		out = append(out, p)
	}
	return out, rows.Err()
}

// Profile loads one profile.
func (s *Store) Profile(ctx context.Context, id int64) (*model.Profile, error) {
	list, err := s.Profiles(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("%w: profile %d", ErrNotFound, id)
}

// SaveProfile inserts or replaces a profile.
func (s *Store) SaveProfile(ctx context.Context, p *model.Profile) (*model.Profile, error) {
	if strings.TrimSpace(p.Name) == "" {
		return nil, fmt.Errorf("%w: a profile needs a name", ErrInvalid)
	}
	if p.AUID == "" && p.ID != 0 {
		if existing, err := s.Profile(ctx, p.ID); err == nil {
			p.AUID = existing.AUID
			if p.Created == 0 {
				p.Created = existing.Created
			}
		}
	}
	if p.AUID == "" {
		id, err := newPolicyID("prof_")
		if err != nil {
			return nil, err
		}
		p.AUID = id
	}
	if p.Mode == "" {
		p.Mode = "alert"
	}
	if p.Mode != "alert" && p.Mode != "silent-allow" && p.Mode != "silent-deny" {
		return nil, fmt.Errorf("%w: mode %q", ErrInvalid, p.Mode)
	}
	dns, _ := json.Marshal(p.DNSExceptions)
	now := s.cfg.Now().UTC().UnixMilli()
	if p.Created == 0 {
		p.Created = now
	}
	p.Modified = now
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.Active {
		if _, err := s.w.ExecContext(ctx, `UPDATE profiles SET active = 0, modified = ? WHERE active = 1`, now); err != nil {
			return nil, err
		}
	}
	if p.IsDefault {
		if _, err := s.w.ExecContext(ctx, `UPDATE profiles SET is_default = 0, modified = ? WHERE is_default = 1`, now); err != nil {
			return nil, err
		}
	}
	_, err := s.w.ExecContext(ctx, `INSERT INTO profiles
		(auid, name, description, active, mode, dns_exceptions, is_default, created, modified)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(auid) DO UPDATE SET name=excluded.name, description=excluded.description,
		active=excluded.active, mode=excluded.mode, dns_exceptions=excluded.dns_exceptions,
		is_default=excluded.is_default, modified=excluded.modified`,
		p.AUID, p.Name, p.Description, boolInt(p.Active), p.Mode, string(dns), boolInt(p.IsDefault), p.Created, p.Modified)
	if err != nil {
		return nil, err
	}
	var id int64
	if err := s.w.QueryRowContext(ctx, `SELECT id FROM profiles WHERE auid = ?`, p.AUID).Scan(&id); err != nil {
		return nil, err
	}
	return s.Profile(ctx, id)
}

// DeleteProfile removes a profile and its triggers.
func (s *Store) DeleteProfile(ctx context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM network_triggers WHERE profile_id = ?`, id); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM profiles WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: profile %d", ErrNotFound, id)
	}
	return tx.Commit()
}

// ActivateProfile makes one profile active.
func (s *Store) ActivateProfile(ctx context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activateProfileLocked(ctx, id)
}

func (s *Store) activateProfileLocked(ctx context.Context, id int64) error {
	now := s.cfg.Now().UTC().UnixMilli()
	if id == 0 {
		_, err := s.w.ExecContext(ctx, `UPDATE profiles SET active = 0, modified = ? WHERE active = 1`, now)
		return err
	}
	var one int
	if err := s.w.QueryRowContext(ctx, `SELECT 1 FROM profiles WHERE id = ?`, id).Scan(&one); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: profile %d", ErrNotFound, id)
	} else if err != nil {
		return err
	}
	if _, err := s.w.ExecContext(ctx, `UPDATE profiles SET active = 0, modified = ? WHERE active = 1`, now); err != nil {
		return err
	}
	_, err := s.w.ExecContext(ctx, `UPDATE profiles SET active = 1, modified = ? WHERE id = ?`, now, id)
	return err
}

// NetworkTriggers lists triggers.
func (s *Store) NetworkTriggers(ctx context.Context) ([]model.NetworkTrigger, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT t.id, t.auid, t.profile_id, p.name, t.signature, t.action, t.mode,
		t.enabled, t.last_triggered, t.created, t.modified
		FROM network_triggers t JOIN profiles p ON p.id = t.profile_id ORDER BY t.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.NetworkTrigger{}
	for rows.Next() {
		var t model.NetworkTrigger
		var enabled int
		if err := rows.Scan(&t.ID, &t.AUID, &t.ProfileID, &t.ProfileName, &t.Signature, &t.Action, &t.Mode,
			&enabled, &t.LastTriggered, &t.Created, &t.Modified); err != nil {
			return nil, err
		}
		t.Enabled = enabled != 0
		out = append(out, t)
	}
	return out, rows.Err()
}

// SaveNetworkTrigger inserts or replaces a trigger.
func (s *Store) SaveNetworkTrigger(ctx context.Context, t *model.NetworkTrigger) (*model.NetworkTrigger, error) {
	if t.Signature == "" {
		return nil, fmt.Errorf("%w: a trigger needs a signature", ErrInvalid)
	}
	if t.Action == "" {
		t.Action = "activate"
	}
	switch t.Action {
	case "activate", "deactivate", "ask", "none":
	default:
		return nil, fmt.Errorf("%w: trigger action %q", ErrInvalid, t.Action)
	}
	if t.AUID == "" {
		id, err := newPolicyID("trig_")
		if err != nil {
			return nil, err
		}
		t.AUID = id
	}
	now := s.cfg.Now().UTC().UnixMilli()
	if t.Created == 0 {
		t.Created = now
	}
	t.Modified = now
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.w.ExecContext(ctx, `INSERT INTO network_triggers
		(auid, profile_id, signature, action, mode, enabled, last_triggered, created, modified)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(auid) DO UPDATE SET profile_id=excluded.profile_id, signature=excluded.signature,
		action=excluded.action, mode=excluded.mode, enabled=excluded.enabled,
		last_triggered=excluded.last_triggered, modified=excluded.modified`,
		t.AUID, t.ProfileID, t.Signature, t.Action, t.Mode, boolInt(t.Enabled), t.LastTriggered, t.Created, t.Modified)
	if err != nil {
		return nil, err
	}
	var id int64
	if err := s.w.QueryRowContext(ctx, `SELECT id FROM network_triggers WHERE auid = ?`, t.AUID).Scan(&id); err != nil {
		return nil, err
	}
	t.ID = id
	return t, nil
}

// DeleteNetworkTrigger removes a trigger.
func (s *Store) DeleteNetworkTrigger(ctx context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.w.ExecContext(ctx, `DELETE FROM network_triggers WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: trigger %d", ErrNotFound, id)
	}
	return nil
}

// NetworkContext returns the network signature netgraph can see now.
func (s *Store) NetworkContext(ctx context.Context) (*model.NetworkContext, error) {
	return s.networkContext(ctx, false)
}

func (s *Store) networkContext(ctx context.Context, locked bool) (*model.NetworkContext, error) {
	q := s.r
	if locked {
		q = nil
	}
	get := func(query string, args ...any) (string, error) {
		var v string
		var err error
		if locked {
			err = s.w.QueryRowContext(ctx, query, args...).Scan(&v)
		} else {
			err = q.QueryRowContext(ctx, query, args...).Scan(&v)
		}
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return v, err
	}
	ssid, err := get(`SELECT key FROM entities WHERE kind = 'ssid' ORDER BY last_seen DESC LIMIT 1`)
	if err != nil {
		return nil, err
	}
	bssid, err := get(`SELECT e.key FROM facts f JOIN entities e ON e.id = f.src
		WHERE f.rel = 'broadcasts' ORDER BY f.last_seen DESC LIMIT 1`)
	if err != nil {
		return nil, err
	}
	var hello string
	if locked {
		err = s.w.QueryRowContext(ctx, `SELECT hello FROM sensors ORDER BY last_seen DESC LIMIT 1`).Scan(&hello)
	} else {
		err = s.r.QueryRowContext(ctx, `SELECT hello FROM sensors ORDER BY last_seen DESC LIMIT 1`).Scan(&hello)
	}
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	var h wire.Hello
	_ = json.Unmarshal([]byte(hello), &h)
	iface, router := "", ""
	if len(h.Interfaces) > 0 {
		iface = h.Interfaces[0].Name
		router = h.Interfaces[0].MAC
	}
	sig := signature(ssid, bssid, router, iface)
	return &model.NetworkContext{Signature: sig, SSID: ssid, BSSID: bssid, Router: router, Interface: iface}, nil
}

func signature(ssid, bssid, router, iface string) string {
	b, _ := json.Marshal(struct {
		SSID      string `json:"ssid,omitempty"`
		BSSID     string `json:"bssid,omitempty"`
		Router    string `json:"router,omitempty"`
		Interface string `json:"iface,omitempty"`
	}{ssid, bssid, router, iface})
	return string(b)
}

// EvaluateProfile applies the first matching network trigger and returns the
// active profile. It is safe to call from ingest while the write lock is held.
func (s *Store) EvaluateProfile(ctx context.Context) (*model.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evaluateProfileLocked(ctx)
}

func (s *Store) evaluateProfileLocked(ctx context.Context) (*model.Profile, error) {
	nc, err := s.networkContext(ctx, true)
	if err != nil {
		return nil, err
	}
	rows, err := s.w.QueryContext(ctx, `SELECT id, profile_id, signature, action, mode FROM network_triggers WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	type trigger struct {
		id, profileID int64
		pattern       string
		action, mode  string
	}
	var triggers []trigger
	for rows.Next() {
		var t trigger
		if err := rows.Scan(&t.id, &t.profileID, &t.pattern, &t.action, &t.mode); err != nil {
			rows.Close()
			return nil, err
		}
		triggers = append(triggers, t)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	now := s.cfg.Now().UTC().UnixMilli()
	for _, t := range triggers {
		if !matchSignature(t.pattern, nc.Signature) {
			continue
		}
		switch t.action {
		case "activate", "ask":
			if err := s.activateProfileLocked(ctx, t.profileID); err != nil {
				return nil, err
			}
		case "deactivate":
			if err := s.activateProfileLocked(ctx, 0); err != nil {
				return nil, err
			}
		case "none":
		}
		if t.mode != "" {
			if _, err := s.w.ExecContext(ctx, `UPDATE profiles SET mode = ?, modified = ? WHERE id = ?`, t.mode, now, t.profileID); err != nil {
				return nil, err
			}
		}
		if _, err := s.w.ExecContext(ctx, `UPDATE network_triggers SET last_triggered = ? WHERE id = ?`, now, t.id); err != nil {
			return nil, err
		}
		break
	}
	var auid string
	err = s.w.QueryRowContext(ctx, `SELECT auid FROM profiles WHERE active = 1`).Scan(&auid)
	if errors.Is(err, sql.ErrNoRows) {
		err = s.w.QueryRowContext(ctx, `SELECT auid FROM profiles WHERE is_default = 1`).Scan(&auid)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
	}
	if err != nil {
		return nil, err
	}
	var p model.Profile
	var active int
	if err := s.w.QueryRowContext(ctx, `SELECT id, name, mode, active FROM profiles WHERE auid = ?`, auid).Scan(&p.ID, &p.Name, &p.Mode, &active); err != nil {
		return nil, err
	}
	p.AUID = auid
	p.Active = active != 0
	return &p, nil
}

func matchSignature(pattern, sig string) bool {
	if pattern == "" {
		return false
	}
	if pattern == sig || pattern == "*" {
		return true
	}
	ok, err := path.Match(pattern, sig)
	return err == nil && ok
}

func profileRelevant(events []wire.Event) bool {
	for _, e := range events {
		switch e.Type {
		case wire.TypeHello, wire.TypeWiFi, wire.TypeLLDP, wire.TypeDHCP:
			return true
		}
	}
	return false
}

// ActiveProfile returns the active profile, or nil when none is active.
func (s *Store) ActiveProfile(ctx context.Context) (*model.Profile, error) {
	var id int64
	err := s.r.QueryRowContext(ctx, `SELECT id FROM profiles WHERE active = 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.Profile(ctx, id)
}
