//go:build linux

package linux

import (
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/xen0bit/netgraph/internal/agent"
	"github.com/xen0bit/netgraph/internal/agent/linux/bpf"
)

// EventSource delivers connection events as they happen: package bpf's
// Reader, or a fake in tests.
type EventSource interface {
	Read() (bpf.Event, error)
	Close() error
}

// maxPending bounds the events held between two scans.
const maxPending = 20000

// pendingConn is a connection an event reported, with what it said about
// the process, waiting for the next scan.
type pendingConn struct {
	c     agent.Connection
	procs []agent.Process // the owner first, then its parents
	tuple string          // to find the socket in /proc when the event had no inode
	ino   uint64
	ticks int64
	// verified: /proc/<pid> was the process the kernel named (same start
	// time) when the event arrived. Else the process is only the kernel's
	// command name: it had exited, or the agent sees another PID namespace.
	verified bool
}

type eventState struct {
	mu      sync.Mutex
	pending []pendingConn
	dropped int
	procs   map[int]procEntry // identities read for events
	routes  map[netip.Addr]routeEntry
	on      bool
}

type routeEntry struct {
	src netip.Addr
	at  time.Time
}

// Listen reads events from src until it fails or is closed. Each one's
// process is read from /proc the moment it arrives, before a short-lived
// program can exit, and is held for the next scan.
func (s *Scanner) Listen(src EventSource) {
	s.ev.mu.Lock()
	s.ev.on = true
	s.ev.mu.Unlock()
	go func() {
		for {
			e, err := src.Read()
			if err != nil {
				return
			}
			s.onEvent(e)
		}
	}()
}

func tupleOf(proto, local string, lport int, remote string, rport int) string {
	return agent.BaseProto(proto) + "|" + agent.Unmap(local) + "|" + strconv.Itoa(lport) + "|" + agent.Unmap(remote) + "|" + strconv.Itoa(rport)
}

func (s *Scanner) onEvent(e bpf.Event) {
	root := s.root()
	now := time.Now().UnixMilli()
	ticks := int64(e.Start / 1e7) // ns to the clock ticks /proc counts in
	s.ev.mu.Lock()
	defer s.ev.mu.Unlock()
	if len(s.ev.pending) >= maxPending {
		s.ev.dropped++
		return
	}
	if s.ev.procs == nil || len(s.ev.procs) > 4096 {
		s.ev.procs = map[int]procEntry{}
	}
	var procs []agent.Process
	owner, verified := s.eventProcess(root, e.PID, ticks)
	if verified {
		procs = append(procs, owner.p)
		pp := owner.p.PPID
		for range maxAncestors {
			if pp <= 1 {
				break
			}
			ppid, t, ok := readStat(root, pp)
			if !ok {
				break
			}
			a, ok := s.eventProcess(root, pp, t)
			if !ok {
				break
			}
			procs = append(procs, a.p)
			pp = ppid
		}
	} else {
		owner.p = agent.Process{PID: e.PID, PPID: e.PPID, UID: e.UID, Cmdline: e.Comm}
		if b := s.bootTime(root); b > 0 {
			owner.p.Start = b*1000 + ticks*10
		}
		procs = append(procs, owner.p)
	}
	var proto string
	switch e.Proto {
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	case 1:
		proto = "icmp"
	case 58:
		proto = "icmpv6"
	default:
		return
	}
	src := e.Src
	if src.IsUnspecified() {
		// An unbound socket: its datagram leaves from the address the route
		// gives, which is what the sensor sees.
		src = s.routeSource(e.Dst)
	}
	sock := agent.Socket{Proto: proto, LocalIP: src.String(), LocalPort: int(e.SPort), RemoteIP: e.Dst.String(),
		RemotePort: int(e.DPort), PID: e.PID, UID: e.UID}
	if e.Ino != 0 {
		sock.ID = strconv.FormatUint(e.Ino, 10)
	}
	switch e.Kind {
	case bpf.KindConnect:
		sock.State = "SYN_SENT"
	case bpf.KindAccept:
		sock.State = "ESTABLISHED"
	}
	c := agent.NewConnection(sock, nil, owner.p, now)
	if e.Kind == bpf.KindAccept && c.Direction != "local" {
		c.Direction = "in"
	}
	s.ev.pending = append(s.ev.pending, pendingConn{c: c, procs: procs, ino: e.Ino, ticks: ticks, verified: verified,
		tuple: tupleOf(proto, sock.LocalIP, sock.LocalPort, sock.RemoteIP, sock.RemotePort)})
}

// eventProcess reads a process's identity if /proc/<pid> is still the
// process with that start time. ev.mu is held.
func (s *Scanner) eventProcess(root string, pid int, ticks int64) (procEntry, bool) {
	if e, ok := s.ev.procs[pid]; ok && e.ticks == ticks {
		return e, true
	}
	ppid, t, ok := readStat(root, pid)
	if !ok || t != ticks {
		return procEntry{}, false
	}
	p, ok := readProcess(root, pid, ppid, t, s.bootTime(root))
	if !ok {
		return procEntry{}, false
	}
	p.Cmdline = agent.ClipCmdline(p.Cmdline, s.Cmdlines)
	p.SHA256, p.CodeID = s.hash.Hash(p.Path, root+"/"+strconv.Itoa(pid)+"/exe")
	e := procEntry{p: p, ticks: t}
	s.ev.procs[pid] = e
	return e, true
}

// routeSource is the address this host sends to dst from, as the routing
// table chooses it: a UDP socket's connect picks it and sends nothing.
// Cached for half a minute. ev.mu is held.
func (s *Scanner) routeSource(dst netip.Addr) netip.Addr {
	if r, ok := s.ev.routes[dst]; ok && time.Since(r.at) < 30*time.Second {
		return r.src
	}
	if s.ev.routes == nil || len(s.ev.routes) > 1024 {
		s.ev.routes = map[netip.Addr]routeEntry{}
	}
	src := netip.IPv4Unspecified()
	if dst.Is6() {
		src = netip.IPv6Unspecified()
	}
	if c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 9))); err == nil {
		src = c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap()
		c.Close()
	}
	s.ev.routes[dst] = routeEntry{src, time.Now()}
	return src
}

// takePending hands over the events since the last scan.
func (s *Scanner) takePending() ([]pendingConn, int, bool) {
	s.ev.mu.Lock()
	defer s.ev.mu.Unlock()
	p, d := s.ev.pending, s.ev.dropped
	s.ev.pending, s.ev.dropped = nil, 0
	return p, d, s.ev.on
}
