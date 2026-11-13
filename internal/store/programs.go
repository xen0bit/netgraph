package store

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/model"
)

// maxProgramSockets bounds the agent sockets one Programs answer reads.
const maxProgramSockets = 200000

// Programs lists the programs host agents reported in the window, busiest
// first: what each connected to and accepted, from the agents' own sockets,
// and the bytes of the sensor's connections matched to it. With a device
// filter, only programs matched on that device.
func (s *Store) Programs(ctx context.Context, f model.Filter) ([]model.Program, error) {
	from, to := s.window(f)
	type key struct{ agent, name string }
	type acc struct {
		p        model.Program
		pids     map[int]int64 // last seen
		peers    map[string]int
		serves   map[string]int
		devices  map[string]int
		devNames map[string]string
		pathAt   int64
	}
	by := map[key]*acc{}
	get := func(k key) *acc {
		a := by[k]
		if a == nil {
			a = &acc{p: model.Program{Agent: k.agent, Name: k.name}, pids: map[int]int64{}, peers: map[string]int{},
				serves: map[string]int{}, devices: map[string]int{}, devNames: map[string]string{}}
			by[k] = a
		}
		return a
	}
	rows, err := s.r.QueryContext(ctx, `SELECT agent, app, path, code_id, pid, proto, direction, local_port, remote_ip, remote_port, first_seen, last_seen
		FROM agent_connections WHERE app != '' AND last_seen >= ? AND first_seen < ? ORDER BY last_seen DESC LIMIT ?`, from, to, maxProgramSockets)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k key
		var path, code, proto, dir, rip string
		var pid, lport, rport int
		var first, last int64
		if err := rows.Scan(&k.agent, &k.name, &path, &code, &pid, &proto, &dir, &lport, &rip, &rport, &first, &last); err != nil {
			rows.Close()
			return nil, err
		}
		a := get(k)
		a.p.Connections++
		switch dir {
		case "in":
			a.p.In++
			a.serves[strconv.Itoa(lport)+"/"+protoBase(proto)]++
		case "local":
			// Both ends are this host. The end on a fixed port, its peer on
			// an ephemeral one (Linux's 32768-60999), is the server's.
			a.p.Local++
			if lport < 32768 && rport >= 32768 {
				a.serves[strconv.Itoa(lport)+"/"+protoBase(proto)]++
			} else {
				a.peers[hostPort(rip, rport)]++
			}
		default:
			a.p.Out++
			a.peers[hostPort(rip, rport)]++
		}
		if pid > 0 && last > a.pids[pid] {
			a.pids[pid] = last
		}
		if path != "" && last > a.pathAt {
			a.p.Path, a.p.CodeID, a.pathAt = path, code, last
		}
		if a.p.FirstSeen == 0 || first < a.p.FirstSeen {
			a.p.FirstSeen = first
		}
		a.p.LastSeen = max(a.p.LastSeen, last)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(by) == 0 {
		return []model.Program{}, nil
	}
	// The sensor's side: the connections matched to each program.
	flows, err := s.Flows(ctx, model.Filter{From: time.UnixMilli(from), To: time.UnixMilli(to), Limit: 100000, Multicast: true})
	if err != nil {
		return nil, err
	}
	for _, fl := range flows {
		if fl.Process == "" {
			continue
		}
		a := by[key{fl.Agent, fl.Process}]
		if a == nil {
			continue
		}
		a.p.Flows += max(fl.Connections, 1)
		a.p.BytesOut += fl.BytesOut
		a.p.BytesIn += fl.BytesIn
		if fl.Device != "" {
			a.devices[fl.Device]++
			a.devNames[fl.Device] = fl.DeviceName
		}
	}
	out := make([]model.Program, 0, len(by))
	for _, a := range by {
		p := a.p
		if len(a.devices) > 0 {
			p.Device = topKeys(a.devices, 1)[0]
			p.DeviceName = a.devNames[p.Device]
			p.ID = graph.ProcessID(p.Device, p.Name)
		}
		if f.Device != "" && (p.Device == "" || !deviceIs(p.Device, f.Device)) {
			continue
		}
		pids := slices.SortedFunc(maps.Keys(a.pids), func(x, y int) int { return cmp.Compare(a.pids[y], a.pids[x]) })
		p.PIDs = pids[:min(len(pids), 20)]
		p.Peers = peersFirst(a.peers, 5)
		p.Serves = counted(a.serves, 5)
		p.Cmdlines, p.StartedBy = s.lineage(ctx, p.Agent, p.PIDs)
		out = append(out, p)
	}
	slices.SortFunc(out, func(x, y model.Program) int {
		return cmp.Or(cmp.Compare(y.Connections, x.Connections), cmp.Compare(y.BytesOut+y.BytesIn, x.BytesOut+x.BytesIn),
			cmp.Compare(x.Agent, y.Agent), cmp.Compare(x.Name, y.Name))
	})
	return out, nil
}

// deviceIs reports whether a device entity is the one a filter names (by MAC).
func deviceIs(id, want string) bool {
	_, mac, _ := model.SplitEntityID(id)
	return mac == want || id == want
}

func hostPort(ip string, port int) string {
	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}
	if port == 0 {
		return ip
	}
	return ip + ":" + strconv.Itoa(port)
}

// topKeys returns the n keys with the highest counts, ties by key.
func topKeys(m map[string]int, n int) []string {
	ks := slices.SortedFunc(maps.Keys(m), func(x, y string) int { return cmp.Or(cmp.Compare(m[y], m[x]), cmp.Compare(x, y)) })
	return ks[:min(len(ks), n)]
}

// peersFirst is counted, but the peers off this host before those on it: a
// proxy's health checks to its backends, thousands a day, would otherwise
// hide everything it talks to on the network.
func peersFirst(m map[string]int, n int) []string {
	off, on := map[string]int{}, map[string]int{}
	for k, v := range m {
		host := k
		if h, _, err := net.SplitHostPort(k); err == nil {
			host = h
		}
		if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && a.IsLoopback() {
			on[k] = v
		} else {
			off[k] = v
		}
	}
	out := counted(off, n)
	return append(out, counted(on, n-len(out))...)
}

// counted is topKeys with each count: "203.0.113.9:443 ×12".
func counted(m map[string]int, n int) []string {
	var out []string
	for _, k := range topKeys(m, n) {
		if m[k] > 1 {
			k = fmt.Sprintf("%s ×%d", k, m[k])
		}
		out = append(out, k)
	}
	return out
}
