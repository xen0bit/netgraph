package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
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
		// One decision per connection, whatever became of it: an answered
		// one must not come back on the next scan.
		var seen int
		err := s.r.QueryRowContext(ctx, `SELECT count(*) FROM policy_decisions WHERE flow_key = ?`, fl.Key).Scan(&seen)
		if err != nil {
			return created, err
		}
		if seen > 0 {
			continue
		}
		s.mu.Lock()
		_, err = s.w.ExecContext(ctx, `INSERT INTO policy_decisions
			(ts, device, device_name, flow_key, direction, remote, port, proto, action, status, rule_id, rule_name,
			 profile, mode, stalled, unconfirmed, created, modified)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, 0, 1, ?, ?)`,
			fl.FirstSeen, fl.Device, clip(label, 256), fl.Key, fl.Direction, clip(dst, 256), portString(fl), fl.Proto, action,
			d.RuleID, clip(d.Rule, 256), profileName, mode, now, now)
		s.mu.Unlock()
		if err != nil {
			return created, err
		}
		created++
	}
	return created, nil
}

const decisionSelect = `SELECT id, ts, device, device_name, flow_key, direction, remote, port, proto, action, status,
		rule_id, rule_name, profile, mode, stalled, unconfirmed, decided_at, decided_by, note, created, modified
		FROM policy_decisions`

// Decisions lists decisions, newest first. status empty lists all.
func (s *Store) Decisions(ctx context.Context, status string, limit int) ([]model.PolicyDecision, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := decisionSelect
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
	return scanDecisions(rows)
}

func scanDecisions(rows *sql.Rows) ([]model.PolicyDecision, error) {
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
	rows, err := s.r.QueryContext(ctx, decisionSelect+` WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	list, err := scanDecisions(rows)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%w: decision %d", ErrNotFound, id)
	}
	return &list[0], nil
}

// AnswerDecision records a person's answer: allow or deny once, or rule,
// which adds a rule for this connection to the active policy (ruleAction is
// that rule's allow or deny). It never claims that a passive server enforced
// anything; only an agent can do that.
func (s *Store) AnswerDecision(ctx context.Context, id int64, answer, ruleAction, by, note string) (*model.PolicyDecision, error) {
	var status string
	switch answer {
	case "allow":
		status = DecisionAllowed
	case "deny":
		status = DecisionDenied
	case "rule":
		status = DecisionRuleCreated
	default:
		return nil, fmt.Errorf("%w: answer %q is not allow, deny or rule", ErrInvalid, answer)
	}
	d, err := s.Decision(ctx, id)
	if err != nil {
		return nil, err
	}
	if answer == "rule" {
		if ruleAction == "" {
			ruleAction = policy.ActionDeny
		}
		if ruleAction != policy.ActionAllow && ruleAction != policy.ActionDeny {
			return nil, fmt.Errorf("%w: a rule from a decision is allow or deny, not %q", ErrInvalid, ruleAction)
		}
		p, err := s.ActivePolicy(ctx)
		if err != nil {
			return nil, err
		}
		if p == nil || p.Version != 2 {
			return nil, fmt.Errorf("%w: a rule can only be added to an active version 2 policy", ErrInvalid)
		}
		r := DecisionRule(*d)
		r.Action = ruleAction
		p.RulesV2 = append(p.RulesV2, *r)
		saved, err := s.SavePolicy(ctx, p)
		if err != nil {
			return nil, err
		}
		added := saved.RulesV2[len(saved.RulesV2)-1]
		d.RuleID, d.RuleName = added.ID, added.Name
	}
	now := s.cfg.Now().UTC().UnixMilli()
	s.mu.Lock()
	res, err := s.w.ExecContext(ctx, `UPDATE policy_decisions
		SET status = ?, decided_at = ?, decided_by = ?, note = ?, unconfirmed = 0, modified = ?,
		rule_id = ?, rule_name = ? WHERE id = ?`,
		status, now, clip(by, 128), clip(note, 500), now, d.RuleID, d.RuleName, id)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, fmt.Errorf("%w: decision %d", ErrNotFound, id)
	}
	return s.Decision(ctx, id)
}

// ResetDecision puts a decision back in the open queue.
func (s *Store) ResetDecision(ctx context.Context, id int64) error {
	now := s.cfg.Now().UTC().UnixMilli()
	s.mu.Lock()
	defer s.mu.Unlock()
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
	now := s.cfg.Now().UTC().UnixMilli()
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.w.ExecContext(ctx, `UPDATE policy_decisions SET status = 'expired', decided_at = ?, unconfirmed = 0, modified = ?
		WHERE status = 'open' AND ts < ?`, now, now, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DecisionRule builds the version 2 rule a decision would become: this
// device, this exact destination (an address, or the host name it used),
// this port. The caller sets the action.
func DecisionRule(d model.PolicyDecision) *policy.RuleV2 {
	r := &policy.RuleV2{
		Name: "decision " + strconv.FormatInt(d.ID, 10) + ": " + d.Remote, Origin: "decision",
		Action: policy.ActionAsk, Local: policy.Selector{Type: "any"},
	}
	if d.Device != "" {
		r.Local = policy.Selector{Type: "device", Values: []string{d.Device}}
	}
	if _, err := netip.ParseAddr(d.Remote); err == nil {
		r.Remote = policy.Selector{Type: "ip", Values: []string{d.Remote}}
	} else {
		r.Remote = policy.Selector{Type: "host", Values: []string{d.Remote}}
	}
	switch d.Direction {
	case "in", "out", "local":
		r.Direction = d.Direction
	}
	if port, proto, ok := strings.Cut(d.Port, "/"); ok && port != "0" {
		r.Ports = []string{port + "/" + proto}
	}
	return r
}
