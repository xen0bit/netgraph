package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xen0bit/netgraph/internal/agent"
	"github.com/xen0bit/netgraph/internal/model"
)

// RegisterAgent records an agent hello.
func (s *Store) RegisterAgent(ctx context.Context, h *agent.Hello, boot string) error {
	if h == nil || strings.TrimSpace(h.Name) == "" {
		return fmt.Errorf("%w: agent needs a name", ErrInvalid)
	}
	caps, _ := json.Marshal(h.Capabilities)
	now := s.cfg.Now().UTC().UnixMilli()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.w.ExecContext(ctx, `INSERT INTO agents (name, host, os, arch, version, capabilities, boot, seq, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
		ON CONFLICT(name) DO UPDATE SET host=excluded.host, os=excluded.os, arch=excluded.arch,
		version=excluded.version, capabilities=excluded.capabilities, boot=excluded.boot, last_seen=excluded.last_seen`,
		h.Name, h.Host, h.OS, h.Arch, h.Version, string(caps), boot, now, now)
	return err
}

// IngestAgentBatch stores process and connection observations from one agent.
func (s *Store) IngestAgentBatch(ctx context.Context, b *agent.Batch) (map[string]int, error) {
	if b == nil || b.Version != agent.Version {
		return nil, fmt.Errorf("%w: agent protocol version", ErrInvalid)
	}
	if strings.TrimSpace(b.Agent) == "" {
		return nil, fmt.Errorf("%w: agent name is empty", ErrInvalid)
	}
	if b.Hello != nil {
		if err := s.RegisterAgent(ctx, b.Hello, b.Boot); err != nil {
			return nil, err
		}
	}
	now := s.cfg.Now().UTC().UnixMilli()
	counts := map[string]int{}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, p := range b.Processes {
		if p.PID <= 0 {
			continue
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO agent_processes
			(agent, pid, ppid, uid, path, cmdline, code_id, sha256, signer, package, start, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(agent, pid) DO UPDATE SET ppid=excluded.ppid, uid=excluded.uid, path=excluded.path,
			cmdline=excluded.cmdline, code_id=excluded.code_id, sha256=excluded.sha256, signer=excluded.signer,
			package=excluded.package, start=excluded.start, last_seen=excluded.last_seen`,
			b.Agent, p.PID, p.PPID, p.UID, clip(p.Path, 1024), clip(p.Cmdline, 2048), clip(p.CodeID, 128), clip(p.SHA256, 128),
			clip(p.Signer, 256), clip(p.Package, 256), p.Start, now, now)
		if err != nil {
			return nil, err
		}
		counts["processes"]++
	}
	for _, c := range b.Connections {
		if c.Key == "" {
			continue
		}
		first := c.FirstSeen
		if first == 0 {
			first = now
		}
		last := c.LastSeen
		if last == 0 {
			last = now
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO agent_connections
			(agent, key, proto, local_ip, local_port, remote_ip, remote_port, direction, state, pid, uid,
			 app, path, code_id, sha256, bytes_out, bytes_in, first_seen, last_seen, sni, http_host,
			 predicted, actual, rule, reason, stalled)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(agent, key) DO UPDATE SET state=excluded.state, pid=excluded.pid, uid=excluded.uid,
			app=excluded.app, path=excluded.path, code_id=excluded.code_id, sha256=excluded.sha256,
			bytes_out=max(bytes_out, excluded.bytes_out), bytes_in=max(bytes_in, excluded.bytes_in),
			last_seen=max(last_seen, excluded.last_seen), sni=excluded.sni, http_host=excluded.http_host,
			predicted=excluded.predicted, actual=excluded.actual, rule=excluded.rule, reason=excluded.reason,
			stalled=excluded.stalled`,
			b.Agent, clip(c.Key, 256), c.Proto, c.LocalIP, c.LocalPort, c.RemoteIP, c.RemotePort, c.Direction, c.State,
			c.PID, c.UID, clip(c.App, 256), clip(c.Path, 1024), clip(c.CodeID, 128), clip(c.SHA256, 128),
			c.BytesOut, c.BytesIn, first, last, clip(c.SNI, 255), clip(c.HTTPHost, 255),
			c.Predicted, c.Actual, clip(c.Rule, 256), clip(c.Reason, 512), boolInt(c.Stalled))
		if err != nil {
			return nil, err
		}
		counts["connections"]++
	}
	for _, a := range b.Actuals {
		if a.Key == "" {
			continue
		}
		action := a.Action
		if action == "" {
			action = "none"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agent_connections SET actual=?, rule=?, reason=?, stalled=?, last_seen=?
			WHERE agent=? AND key=?`, action, clip(a.Rule, 256), clip(a.Reason, 512), boolInt(a.Stalled), now, b.Agent, a.Key); err != nil {
			return nil, err
		}
		counts["actuals"]++
	}
	if _, err := tx.ExecContext(ctx, `UPDATE agents SET seq=max(seq, ?), last_seen=? WHERE name=?`, b.Seq, now, b.Agent); err != nil {
		return nil, err
	}
	return counts, tx.Commit()
}

// Agents lists host agents with current counts.
func (s *Store) Agents(ctx context.Context) ([]model.Agent, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT a.name, a.host, a.os, a.arch, a.version, a.capabilities, a.boot, a.seq, a.first_seen, a.last_seen,
		(SELECT count(*) FROM agent_processes p WHERE p.agent=a.name), (SELECT count(*) FROM agent_connections c WHERE c.agent=a.name)
		FROM agents a ORDER BY a.last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Agent{}
	for rows.Next() {
		var a model.Agent
		var caps string
		if err := rows.Scan(&a.Name, &a.Host, &a.OS, &a.Arch, &a.Version, &caps, &a.Boot, &a.Seq, &a.FirstSeen, &a.LastSeen, &a.Processes, &a.Connections); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(caps), &a.Capabilities)
		out = append(out, a)
	}
	return out, rows.Err()
}

// AgentProcesses lists one agent's processes, newest first.
func (s *Store) AgentProcesses(ctx context.Context, agentName string, limit int) ([]model.AgentProcess, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := s.r.QueryContext(ctx, `SELECT agent, pid, ppid, uid, path, cmdline, code_id, sha256, signer, package, start, first_seen, last_seen
		FROM agent_processes WHERE agent=? ORDER BY last_seen DESC LIMIT ?`, agentName, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AgentProcess{}
	for rows.Next() {
		var p model.AgentProcess
		if err := rows.Scan(&p.Agent, &p.PID, &p.PPID, &p.UID, &p.Path, &p.Cmdline, &p.CodeID, &p.SHA256, &p.Signer, &p.Package, &p.Start, &p.FirstSeen, &p.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// AgentConnections lists one agent's attributed connections.
func (s *Store) AgentConnections(ctx context.Context, agentName string, limit int) ([]model.AgentConnection, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	rows, err := s.r.QueryContext(ctx, `SELECT agent, key, proto, local_ip, local_port, remote_ip, remote_port, direction, state,
		pid, uid, app, path, code_id, sha256, bytes_out, bytes_in, first_seen, last_seen, sni, http_host,
		predicted, actual, rule, reason, stalled
		FROM agent_connections WHERE agent=? ORDER BY last_seen DESC LIMIT ?`, agentName, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AgentConnection{}
	for rows.Next() {
		var c model.AgentConnection
		var stalled int
		if err := rows.Scan(&c.Agent, &c.Key, &c.Proto, &c.LocalIP, &c.LocalPort, &c.RemoteIP, &c.RemotePort, &c.Direction, &c.State,
			&c.PID, &c.UID, &c.App, &c.Path, &c.CodeID, &c.SHA256, &c.BytesOut, &c.BytesIn, &c.FirstSeen, &c.LastSeen,
			&c.SNI, &c.HTTPHost, &c.Predicted, &c.Actual, &c.Rule, &c.Reason, &stalled); err != nil {
			return nil, err
		}
		c.Stalled = stalled != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

// AgentPolicy returns the active policy and profile mode for an agent.
func (s *Store) AgentPolicy(ctx context.Context) (*agent.PolicyResponse, error) {
	p, err := s.ActivePolicy(ctx)
	if err != nil {
		return nil, err
	}
	out := &agent.PolicyResponse{Policy: p}
	if p != nil {
		out.Hash = p.Hash()
	}
	pr, err := s.ActiveProfile(ctx)
	if err != nil {
		return nil, err
	}
	if pr != nil {
		out.Profile, out.Mode = pr.Name, pr.Mode
	}
	return out, nil
}
