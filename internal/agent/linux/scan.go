//go:build linux

// Package linux implements the Linux host-agent scanner. It reads the
// kernel's /proc socket tables and maps socket inodes to processes; it does
// not capture packet payloads.
package linux

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xen0bit/netgraph/internal/agent"
)

const (
	maxPIDs      = 20000
	maxFDsPerPID = 1 << 16
)

// Scanner reads /proc. Reuse one across scans: it remembers which process
// holds each socket, so a scan walks /proc/<pid>/fd only for sockets it hasn't
// placed yet, and it caches process identities and executable hashes.
type Scanner struct {
	Root string // /proc by default; tests set a fixture root
	// Cmdlines sends each process's full command line. Off, only the
	// program's name is sent: arguments can hold passwords and tokens.
	Cmdlines bool
	hash     agent.Hasher
	bootOnce sync.Once
	boot     int64

	mu sync.Mutex
	// owners is the process each connected socket was found in, by inode.
	owners map[uint64]int
	// procs are the identities read so far, by PID; ticks (the start time
	// in clock ticks) tells a reused PID from the process that had it.
	procs map[int]procEntry
	// listed is every PID of the last /proc listing: one not in it is new.
	listed map[int]bool
	// missed is when a full walk last failed to place an inode: one whose
	// owner can't be read (another user's, a process AppArmor hides) isn't
	// looked for in every process again at every scan.
	missed map[uint64]time.Time
}

type procEntry struct {
	p     agent.Process
	ticks int64
}

// How often an inode no walk could place is looked for again everywhere.
const missRetry = 30 * time.Second

// maxAncestors bounds how far up the parent chain a socket's owner is
// described: enough for "sshd -> sshd -> bash -> python3".
const maxAncestors = 8

// maxFDsPerScan bounds the descriptors one scan reads links of.
const maxFDsPerScan = 1 << 18

type socket struct {
	proto      string
	localIP    string
	localPort  int
	remoteIP   string
	remotePort int
	state      string
	uid        int
	inode      uint64
}

// Capabilities says what this scanner reports.
func (s *Scanner) Capabilities() []string {
	return []string{"process-identity", "process-ancestry", "proc-sockets"}
}

// Scan returns the current connections, the processes holding them and
// their parents.
func (s *Scanner) Scan(ctx context.Context) ([]agent.Process, []agent.Connection, error) {
	root := s.Root
	if root == "" {
		root = "/proc"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owners == nil {
		s.owners, s.procs, s.missed = map[uint64]int{}, map[int]procEntry{}, map[uint64]time.Time{}
	}
	sockets, err := readSockets(root)
	if err != nil {
		return nil, nil, err
	}
	// A connection to a port this host listens on was accepted, not made.
	listeners := map[agent.Listener]bool{}
	// Inode 0 is a socket no program holds any more (TIME_WAIT, an
	// orphaned FIN_WAIT2): the kernel finishes it alone. It names no
	// program, and would shadow the sighting that did.
	want := map[uint64]bool{}
	for _, so := range sockets {
		if so.state == "LISTEN" {
			listeners[agent.Listener{Proto: strings.TrimSuffix(so.proto, "6"), Port: so.localPort}] = true
		}
		if so.inode != 0 && (agent.Socket{RemoteIP: so.remoteIP, RemotePort: so.remotePort}).Connected() {
			want[so.inode] = true
		}
	}
	s.place(ctx, root, want)
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	now := time.Now().UnixMilli()
	used := map[int]bool{}
	var out []agent.Connection
	for _, so := range sockets {
		if !want[so.inode] {
			continue
		}
		pid := s.owners[so.inode]
		as := agent.Socket{Proto: so.proto, LocalIP: so.localIP, LocalPort: so.localPort, RemoteIP: so.remoteIP,
			RemotePort: so.remotePort, State: so.state, UID: so.uid, PID: pid, ID: strconv.FormatUint(so.inode, 10)}
		var p agent.Process
		if e, ok := s.procs[pid]; ok && pid > 0 {
			p = e.p
			used[pid] = true
		}
		out = append(out, agent.NewConnection(as, listeners, p, now))
		if len(out) >= agent.MaxConnections {
			break
		}
	}
	// The parents of each socket's owner, as far as they can be read: who
	// started the program that connected.
	for _, pid := range slices.Sorted(maps.Keys(used)) {
		pp := s.procs[pid].p.PPID
		for range maxAncestors {
			if pp <= 1 || used[pp] {
				break
			}
			e, ok := s.process(root, pp)
			if !ok {
				break
			}
			used[pp] = true
			pp = e.p.PPID
		}
	}
	procs := make([]agent.Process, 0, len(used))
	for _, pid := range slices.Sorted(maps.Keys(used)) {
		procs = append(procs, s.procs[pid].p)
		if len(procs) >= agent.MaxProcesses {
			break
		}
	}
	// Forget what this scan didn't need: sockets that closed, processes
	// that hold none of them.
	for ino := range s.owners {
		if !want[ino] {
			delete(s.owners, ino)
		}
	}
	for ino := range s.missed {
		if !want[ino] {
			delete(s.missed, ino)
		}
	}
	for pid := range s.procs {
		if !used[pid] {
			delete(s.procs, pid)
		}
	}
	return procs, out, nil
}

// place finds the process holding each wanted socket. A socket placed by an
// earlier scan keeps its owner while that process lives. The rest are looked
// for first among the processes already holding sockets (a server accepting
// one more), then in processes started since the last listing (a client
// that just ran), and only then everywhere, at most every missRetry for an
// inode that a walk already failed to place.
func (s *Scanner) place(ctx context.Context, root string, want map[uint64]bool) {
	alive := map[int]bool{}
	live := func(pid int) bool {
		if v, ok := alive[pid]; ok {
			return v
		}
		e, ok := s.procs[pid]
		v := ok
		if ok {
			_, ticks, ok := readStat(root, pid)
			v = ok && ticks == e.ticks
		}
		alive[pid] = v
		return v
	}
	unknown := map[uint64]bool{}
	for ino := range want {
		if pid, ok := s.owners[ino]; !ok || !live(pid) {
			delete(s.owners, ino)
			unknown[ino] = true
		}
	}
	if len(unknown) == 0 {
		return
	}
	now := time.Now()
	retry := false
	for ino := range unknown {
		if at, ok := s.missed[ino]; !ok || now.Sub(at) >= missRetry {
			retry = true
			break
		}
	}
	pids := listPIDs(root)
	var known, fresh, rest []int
	for _, pid := range pids {
		_, held := s.procs[pid]
		switch {
		case held:
			known = append(known, pid)
		case s.listed != nil && !s.listed[pid]:
			fresh = append(fresh, pid)
		default:
			rest = append(rest, pid)
		}
	}
	s.listed = make(map[int]bool, len(pids))
	for _, pid := range pids {
		s.listed[pid] = true
	}
	order := append(known, fresh...)
	if retry {
		order = append(order, rest...)
	}
	budget := maxFDsPerScan
	for _, pid := range order {
		if len(unknown) == 0 || budget <= 0 || ctx.Err() != nil {
			break
		}
		for _, ino := range socketFDs(root, pid, &budget) {
			if !unknown[ino] {
				continue
			}
			// Read who it is now: a short-lived program may be gone by the
			// end of the scan.
			if _, ok := s.process(root, pid); !ok {
				break
			}
			s.owners[ino] = pid
			delete(unknown, ino)
		}
	}
	for ino := range unknown {
		if retry {
			s.missed[ino] = now
		}
	}
}

// process returns a process's identity, reading it unless it is cached for
// the same process (same start time).
func (s *Scanner) process(root string, pid int) (procEntry, bool) {
	ppid, ticks, ok := readStat(root, pid)
	if !ok {
		return procEntry{}, false
	}
	if e, ok := s.procs[pid]; ok && e.ticks == ticks {
		e.p.PPID = ppid // a parent's exit reparents it
		s.procs[pid] = e
		return e, true
	}
	p, ok := readProcess(root, pid, ppid, ticks, s.bootTime(root))
	if !ok {
		return procEntry{}, false
	}
	p.Cmdline = agent.ClipCmdline(p.Cmdline, s.Cmdlines)
	// Through /proc/<pid>/exe: from a container, the path names a file in
	// the host's mount namespace, not this one.
	p.SHA256, p.CodeID = s.hash.Hash(p.Path, filepath.Join(root, strconv.Itoa(pid), "exe"))
	e := procEntry{p: p, ticks: ticks}
	s.procs[pid] = e
	return e, true
}

func readSockets(root string) ([]socket, error) {
	var out []socket
	for _, f := range []struct{ name, proto string }{
		{"net/tcp", "tcp"}, {"net/tcp6", "tcp6"}, {"net/udp", "udp"}, {"net/udp6", "udp6"},
	} {
		file, err := os.Open(filepath.Join(root, f.name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(file)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue
			}
			so, ok := parseSocket(sc.Text(), f.proto)
			if ok {
				out = append(out, so)
			}
		}
		file.Close()
	}
	return out, nil
}

func parseSocket(line, proto string) (socket, bool) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return socket{}, false
	}
	l, err1 := parseHexAddr(fields[1])
	r, err2 := parseHexAddr(fields[2])
	if err1 != nil || err2 != nil {
		return socket{}, false
	}
	inode, _ := strconv.ParseUint(fields[9], 10, 64)
	uid, _ := strconv.Atoi(fields[7])
	return socket{
		proto: proto, localIP: l.Addr, localPort: l.Port, remoteIP: r.Addr, remotePort: r.Port,
		state: stateName(fields[3]), uid: uid, inode: inode,
	}, true
}

type hexAddr struct {
	Addr string
	Port int
}

func parseHexAddr(s string) (hexAddr, error) {
	ip, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return hexAddr{}, fmt.Errorf("bad address %q", s)
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return hexAddr{}, err
	}
	if len(ip) == 8 {
		v, err := strconv.ParseUint(ip, 16, 32)
		if err != nil {
			return hexAddr{}, err
		}
		b := []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
		return hexAddr{Addr: netip.AddrFrom4([4]byte(b)).String(), Port: int(port)}, nil
	}
	if len(ip) == 32 {
		var b [16]byte
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(ip[i*8:(i+1)*8], 16, 32)
			if err != nil {
				return hexAddr{}, err
			}
			b[i*4], b[i*4+1], b[i*4+2], b[i*4+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
		}
		return hexAddr{Addr: netip.AddrFrom16(b).String(), Port: int(port)}, nil
	}
	return hexAddr{}, fmt.Errorf("bad address %q", s)
}

func stateName(s string) string {
	switch s {
	case "01":
		return "ESTABLISHED"
	case "02":
		return "SYN_SENT"
	case "03":
		return "SYN_RECV"
	case "04":
		return "FIN_WAIT1"
	case "05":
		return "FIN_WAIT2"
	case "06":
		return "TIME_WAIT"
	case "07":
		return "CLOSE"
	case "08":
		return "CLOSE_WAIT"
	case "09":
		return "LAST_ACK"
	case "0A":
		return "LISTEN"
	case "0B":
		return "CLOSING"
	}
	return s
}

// listPIDs lists the processes in /proc, at most maxPIDs.
func listPIDs(root string) []int {
	f, err := os.Open(root)
	if err != nil {
		return nil
	}
	defer f.Close()
	names, _ := f.Readdirnames(-1)
	out := make([]int, 0, len(names))
	for _, n := range names {
		if pid, err := strconv.Atoi(n); err == nil && pid > 0 {
			out = append(out, pid)
			if len(out) >= maxPIDs {
				break
			}
		}
	}
	slices.Sort(out)
	return out
}

// socketFDs returns the inodes of the sockets a process holds, reading at
// most *budget descriptors (and maxFDsPerPID of one process).
func socketFDs(root string, pid int, budget *int) []uint64 {
	fdDir := filepath.Join(root, strconv.Itoa(pid), "fd")
	f, err := os.Open(fdDir)
	if err != nil {
		return nil
	}
	names, _ := f.Readdirnames(min(maxFDsPerPID, *budget))
	f.Close()
	var out []uint64
	for _, fd := range names {
		*budget--
		link, err := os.Readlink(filepath.Join(fdDir, fd))
		if err != nil || !strings.HasPrefix(link, "socket:[") {
			continue
		}
		if inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64); err == nil {
			out = append(out, inode)
		}
	}
	return out
}

// readStat reads a process's parent and start time (clock ticks after boot)
// from /proc/<pid>/stat.
func readStat(root string, pid int) (ppid int, ticks int64, ok bool) {
	b, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, 0, false
	}
	// The command, in parentheses, may hold spaces and parentheses: count
	// fields from after its last ")".
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return 0, 0, false
	}
	rest := strings.Fields(string(b[i+1:]))
	if len(rest) <= 19 {
		return 0, 0, false
	}
	ppid, _ = strconv.Atoi(rest[1])
	ticks, err = strconv.ParseInt(rest[19], 10, 64)
	return ppid, ticks, err == nil
}

// readProcess reads the rest of a process's identity. It fails when the
// process is gone or its executable can't be read, as a process AppArmor
// hides: a PID alone names nothing.
func readProcess(root string, pid, ppid int, ticks, boot int64) (agent.Process, bool) {
	base := filepath.Join(root, strconv.Itoa(pid))
	p := agent.Process{PID: pid, PPID: ppid}
	// Clock ticks after boot, as Unix ms. USER_HZ is 100 on every
	// architecture Linux exposes to userspace.
	if boot > 0 {
		p.Start = boot*1000 + ticks*10
	}
	if b, err := os.ReadFile(filepath.Join(base, "status")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				if fs := strings.Fields(line); len(fs) >= 2 {
					p.UID, _ = strconv.Atoi(fs[1])
				}
			}
		}
	}
	if link, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		p.Path = strings.TrimSuffix(link, " (deleted)")
	}
	if b, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
		p.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
		if len(p.Cmdline) > agent.MaxCmdline {
			p.Cmdline = p.Cmdline[:agent.MaxCmdline]
		}
	}
	// A kernel thread has neither; neither does a process that just exited.
	if p.Path == "" && p.Cmdline == "" {
		return p, false
	}
	return p, true
}

// bootTime is the btime line of /proc/stat: when the system booted, in Unix
// seconds.
func (s *Scanner) bootTime(root string) int64 {
	s.bootOnce.Do(func() {
		b, err := os.ReadFile(filepath.Join(root, "stat"))
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "btime "); ok {
				s.boot, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			}
		}
	})
	return s.boot
}
