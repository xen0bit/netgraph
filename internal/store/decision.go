package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy"
)

// Decision statuses.
const (
	DecisionOpen        = "open"
	DecisionAllowed     = "allowed"
	DecisionDenied      = "denied"
	DecisionRuleCreated = "rule-created"
	DecisionExpired     = "expired"
)

// ScanDecisions evaluates the active policy over a window and records the
// connections that would have asked. It is a passive record: netgraph did not
// block anything. Only a host agent can set Stalled.
func (s *Store) ScanDecisions(ctx context.Context, f model.Filter, limit int) (int, error) {
	if s.w == nil {
		return 0, errors.New("database is open read-only")
	}
	p, err := s.ActivePolicy(ctx)
	if err != nil || p == nil {
		return 0, err
	}
	active, err := s.ActiveProfile(ctx)
	if err != nil {
		return 0, err
	}
	profileName, mode := "", ""
	if active != nil {
		profileName, mode = active.Name, active.Mode
	}
	if limit <= 0 || limit > 5000 {
		limit = 2000
	}
	ff := f
	ff.Limit = limit
	flows, err := s.Flows(ctx, ff)
	if err != nil {
		return 0, err
	}
	devices, err := s.Devices(ctx, ff)
	if err != nil {
		return 0, err
	}
	type info struct{ label, role string }
	byID := map[string]info{}
	for _, d := range devices {
		byID[d.ID] = info{d.Label, d.Role}
	}
	now := s.cfg.Now().UTC().UnixMilli()
	created := 0
	for _, fl := range flows {
		if fl.Direction == model.DirExternal {
			continue
		}
		dev := byID[fl.Device]
		label := firstNonEmpty(fl.DeviceName, dev.label, fl.Device)
		zone := p.ZoneFor(fl.Device, label, dev.role)
		peerZone := ""
		if fl.PeerDevice != "" {
			peer := byID[fl.PeerDevice]
			peerZone = p.ZoneFor(fl.PeerDevice, firstNonEmpty(fl.PeerName, peer.label, fl.PeerDevice), peer.role)
		}
		dst := firstNonEmpty(fl.Name, fl.RemoteIP)
		conn := policy.Conn{
			Zone: zone, PeerZone: peerZone, Device: fl.Device, Label: label, Role: dev.role,
			Direction: fl.Direction, Profile: profileName, Name: dst, Host: fl.Name, QName: fl.QName,
			IP: fl.RemoteIP, Port: strconv.Itoa(servicePort(fl)), Proto: fl.Proto,
			ASN: fl.ASN, Country: fl.Country, Now: now,
		}
		d := p.Evaluate(conn)
		action := ""
		switch {
		case d.Action == policy.ActionAsk:
			action = "ask"
		case !d.Matched && mode == "silent-allow":
			action = "silent-allow"
		case !d.Matched && mode == "silent-deny":
			action = "silent-deny"
		}
		if action == "" {
			continue
		}
		var open int
		err := s.r.QueryRowContext(ctx, `SELECT count(*) FROM policy_decisions WHERE flow_key = ? AND status = 'open'`, fl.Key).Scan(&open)
		if err != nil {
			return created, err
		}
		if open > 0 {
			continue
		}
		_, err = s.w.ExecContext(ctx, `INSERT INTO policy_decisions
			(ts, device, device_name, flow_key, direction, remote, port, proto, action, status, rule_id, rule_name,
			 profile, mode, stalled, unconfirmed, created, modified)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, 0, 1, ?, ?)`,
			fl.FirstSeen, fl.Device, label, fl.Key, fl.Direction, dst, portString(fl), fl.Proto, action,
			d.RuleID, d.Rule, profileName, mode, now, now)
		if err != nil {
			return created, err
		}
		created++
	}
	return created, nil
}

// Decisions lists decisions, newest first. status empty lists all.
func (s *Store) Decisions(ctx context.Context, status string, limit int) ([]model.PolicyDecision, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT id, ts, device, device_name, flow_key, direction, remote, port, proto, action, status,
		rule_id, rule_name, profile, mode, stalled, unconfirmed, decided_at, decided_by, note, created, modified
		FROM policy_decisions`
	var args []any
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, status)
	}
	q += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.PolicyDecision{}
	for rows.Next() {
		var d model.PolicyDecision
		var stalled, unconfirmed int
		if err := rows.Scan(&d.ID, &d.TS, &d.Device, &d.DeviceName, &d.FlowKey, &d.Direction, &d.Remote, &d.Port,
			&d.Proto, &d.Action, &d.Status, &d.RuleID, &d.RuleName, &d.Profile, &d.Mode, &stalled, &unconfirmed,
			&d.DecidedAt, &d.DecidedBy, &d.Note, &d.Created, &d.Modified); err != nil {
			return nil, err
		}
		d.Stalled, d.Unconfirmed = stalled != 0, unconfirmed != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

// Decision loads one decision.
func (s *Store) Decision(ctx context.Context, id int64) (*model.PolicyDecision, error) {
	list, err := s.Decisions(ctx, "", 1000)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("%w: decision %d", ErrNotFound, id)
}

// DecideDecision records a person's answer. It never claims that a passive
// server enforced anything; only an agent can do that.
func (s *Store) DecideDecision(ctx context.Context, id int64, status, by, note string) error {
	switch status {
	case DecisionAllowed, DecisionDenied, DecisionRuleCreated, DecisionExpired:
	default:
		return fmt.Errorf("%w: decision status %q", ErrInvalid, status)
	}
	now := s.cfg.Now().UTC().UnixMilli()
	res, err := s.w.ExecContext(ctx, `UPDATE policy_decisions
		SET status = ?, decided_at = ?, decided_by = ?, note = ?, unconfirmed = 0, modified = ? WHERE id = ?`,
		status, now, clip(by, 128), clip(note, 500), now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: decision %d", ErrNotFound, id)
	}
	return nil
}

// ResetDecision puts a decision back in the open queue.
func (s *Store) ResetDecision(ctx context.Context, id int64) error {
	now := s.cfg.Now().UTC().UnixMilli()
	res, err := s.w.ExecContext(ctx, `UPDATE policy_decisions SET status = 'open', decided_at = 0, decided_by = '', unconfirmed = 1, modified = ? WHERE id = ?`, now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: decision %d", ErrNotFound, id)
	}
	return nil
}

// ExpireDecisions closes open decisions older than before.
func (s *Store) ExpireDecisions(ctx context.Context, before int64) (int64, error) {
	if before <= 0 {
		return 0, fmt.Errorf("%w: expiry time", ErrInvalid)
	}
	res, err := s.w.ExecContext(ctx, `UPDATE policy_decisions SET status = 'expired', decided_at = ?, unconfirmed = 0, modified = ?
		WHERE status = 'open' AND ts < ?`, s.cfg.Now().UTC().UnixMilli(), s.cfg.Now().UTC().UnixMilli(), before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DecisionRule builds a version 2 rule from a decision, for a prefilled
// create-rule action.
func DecisionRule(d model.PolicyDecision) *policy.RuleV2 {
	r := &policy.RuleV2{Name: "review " + d.Remote, Action: policy.ActionAsk, Local: policy.Selector{Type: "any"}, Remote: policy.Selector{Type: "domain", Values: []string{d.Remote}}}
	if d.Direction == "in" {
		r.Direction = "in"
	}
	if d.Port != "" {
		if p, _, ok := strings.Cut(d.Port, "/"); ok {
			r.Ports = []string{p}
		}
	}
	return r
}
