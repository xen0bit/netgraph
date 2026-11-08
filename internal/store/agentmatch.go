package store

import (
	"context"
	"maps"
	"slices"
	"strconv"

	"github.com/xen0bit/netgraph/internal/agent"
	"github.com/xen0bit/netgraph/internal/model"
)

// agentSlack is how far apart in time an agent's socket and the sensor's
// connection may be and still be the same one. The agent sees a socket at
// its next scan and re-sends an open one each refresh (a minute by
// default), so its first and last sightings trail the packets.
const agentSlack = 2 * 60 * 1000

// agentSocket is one row of agent_connections, as matching needs it.
type agentSocket struct {
	agent, app  string
	pid         int
	first, last int64
}

// tupleKey is a connection's protocol and both ends, as the host at
// local:lport sees it.
func tupleKey(proto, local string, lport int, remote string, rport int) string {
	return proto + "|" + local + "|" + strconv.Itoa(lport) + "|" + remote + "|" + strconv.Itoa(rport)
}

// setProcesses names the program behind each flow from what host agents
// reported: a socket with the same protocol and both ends, seen while the
// connection was open. A LAN connection can be matched at both ends.
//
// A socket that names no program (one whose owner the agent couldn't read,
// or that no program held any more, as agents up to 0.1.9 sent TIME_WAIT
// sockets) is skipped: it would shadow an earlier sighting that did.
//
// The sensor and the agent must see the same addresses: a host behind NAT
// from the sensor (a VM, a container network) keeps its own, and matches
// nothing.
func (s *Store) setProcesses(ctx context.Context, flows []model.Flow, from, to int64) error {
	if len(flows) == 0 {
		return nil
	}
	var n int
	if err := s.r.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT 1 FROM agent_connections LIMIT 1)`).Scan(&n); err != nil || n == 0 {
		return err
	}
	// Look sockets up by their remote end: a flow's remote end for the
	// device's own agent, its device end for the peer's.
	ips := map[string]bool{}
	for _, fl := range flows {
		if fl.ClientPort == 0 && fl.ServerPort == 0 {
			continue
		}
		ips[fl.RemoteIP] = true
		if fl.Direction == model.DirLocal {
			ips[fl.LocalIP()] = true
		}
	}
	socks := map[string][]agentSocket{}
	for chunk := range slices.Chunk(slices.Sorted(maps.Keys(ips)), 500) {
		cond, arg := inList("remote_ip", chunk)
		rows, err := s.r.QueryContext(ctx, `SELECT proto, local_ip, local_port, remote_ip, remote_port, agent, app, pid, first_seen, last_seen
			FROM agent_connections WHERE `+cond+` AND app != '' AND last_seen >= ? AND first_seen < ?`, arg, from-agentSlack, to+agentSlack)
		if err != nil {
			return err
		}
		for rows.Next() {
			var proto, local, remote string
			var lport, rport int
			var a agentSocket
			if err := rows.Scan(&proto, &local, &lport, &remote, &rport, &a.agent, &a.app, &a.pid, &a.first, &a.last); err != nil {
				rows.Close()
				return err
			}
			k := tupleKey(protoBase(proto), local, lport, remote, rport)
			socks[k] = append(socks[k], a)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
	}
	if len(socks) == 0 {
		return nil
	}
	match := func(k string, fl model.Flow) (agentSocket, bool) {
		var best agentSocket
		ok := false
		for _, a := range socks[k] {
			if a.first-agentSlack > fl.LastSeen || a.last+agentSlack < fl.FirstSeen {
				continue
			}
			if !ok || a.last > best.last {
				best, ok = a, true
			}
		}
		return best, ok
	}
	for i := range flows {
		fl := &flows[i]
		local, lport := fl.LocalIP(), fl.ClientPort
		if fl.Inbound() {
			lport = fl.ServerPort
		}
		if a, ok := match(tupleKey(fl.Proto, local, lport, fl.RemoteIP, fl.RemotePort), *fl); ok {
			fl.Process, fl.PID, fl.Agent = a.app, a.pid, a.agent
		}
		if fl.Direction == model.DirLocal {
			if a, ok := match(tupleKey(fl.Proto, fl.RemoteIP, fl.RemotePort, local, lport), *fl); ok {
				fl.PeerProcess = a.app
			}
		}
	}
	return nil
}

// protoBase is tcp or udp, as the sensor names them, for an agent's tcp6.
func protoBase(p string) string { return agent.BaseProto(p) }
