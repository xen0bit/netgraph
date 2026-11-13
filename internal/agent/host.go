package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// What every platform's scanner bounds a snapshot to.
const (
	MaxConnections = 5000
	MaxProcesses   = 2000
	MaxCmdline     = 2048
	maxHashBytes   = 64 << 20
)

// Socket is one socket as a platform reports it, before it becomes a
// Connection. Addresses may be IPv4-mapped IPv6 (a dual-stack socket's view
// of an IPv4 peer); NewConnection unmaps them, as the sensor records them.
type Socket struct {
	Proto      string // tcp or udp; a trailing 6 is dropped
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
	State      string
	UID        int
	PID        int
	// ID tells two sockets with the same addresses apart over time, such as
	// an inode; it is part of the key, so a reused port is a new connection.
	ID string
}

// Connected reports whether the socket has a peer: a listener or an unbound
// UDP socket has none, and is not a connection.
func (s Socket) Connected() bool {
	a, err := netip.ParseAddr(s.RemoteIP)
	return err == nil && !a.IsUnspecified() && s.RemotePort != 0
}

// Unmap writes an address the way the sensor and the policy do: an
// IPv4-mapped IPv6 address as plain IPv4. Anything unparsable is returned
// as it is.
func Unmap(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	return a.Unmap().WithZone("").String()
}

// Listener is a protocol and local port something listens on.
type Listener struct {
	Proto string
	Port  int
}

// NewConnection turns a socket into a connection: unmapped addresses, the
// direction (in when a local listener has its port, local when the peer is
// this host or link-local), and a key unique to the socket.
func NewConnection(s Socket, listening map[Listener]bool, p Process, now int64) Connection {
	proto := BaseProto(s.Proto)
	local, remote := Unmap(s.LocalIP), Unmap(s.RemoteIP)
	dir := "out"
	if listening[Listener{proto, s.LocalPort}] {
		dir = "in"
	}
	if r, err := netip.ParseAddr(remote); err == nil && (r.IsLoopback() || r.IsLinkLocalUnicast() || remote == local) {
		dir = "local"
	}
	key := proto + "|" + local + ":" + strconv.Itoa(s.LocalPort) + "|" + remote + ":" + strconv.Itoa(s.RemotePort)
	if s.ID != "" {
		key += "|" + s.ID
	}
	app := AppName(p.Path, p.Cmdline)
	if k, ok := LoopbackKey(proto, local, s.LocalPort, remote, s.RemotePort, app, s.PID); ok {
		key = k
	}
	uid := s.UID
	if uid == 0 {
		uid = p.UID
	}
	return Connection{
		Key: key, Proto: proto, LocalIP: local, LocalPort: s.LocalPort, RemoteIP: remote, RemotePort: s.RemotePort,
		Direction: dir, State: s.State, PID: s.PID, UID: uid, App: app, Path: p.Path,
		CodeID: p.CodeID, SHA256: p.SHA256, FirstSeen: now, LastSeen: now,
	}
}

// LoopbackKey is the key of a connection this host makes to itself, over
// loopback or to its own address: one per program and fixed end, whatever its
// ephemeral port. No sensor can see such a connection, so nothing is lost,
// and a health check every second would otherwise add a row a second (a
// proxy's checks once made up 7 million of 7.7 million rows). The end on the
// lower port is taken as the fixed one, the server's. It names the program,
// not the process: a health check is often a new process every time.
func LoopbackKey(proto, local string, lport int, remote string, rport int, app string, pid int) (string, bool) {
	l, err1 := netip.ParseAddr(local)
	r, err2 := netip.ParseAddr(remote)
	if err1 != nil || err2 != nil || !(l.IsLoopback() && r.IsLoopback() || l == r) {
		return "", false
	}
	end, side := netip.AddrPortFrom(r, uint16(rport)).String(), "client"
	if lport < rport {
		end, side = netip.AddrPortFrom(l, uint16(lport)).String(), "server"
	}
	who := app
	if who == "" {
		who = "pid " + strconv.Itoa(pid)
	}
	return proto + "|self|" + side + "|" + end + "|" + who, true
}

// MergeKeys folds connections sharing a key into one: the earliest first
// sighting, the latest last one, the newest state.
func MergeKeys(conns []Connection) []Connection {
	at := make(map[string]int, len(conns))
	out := conns[:0]
	for _, c := range conns {
		i, ok := at[c.Key]
		if !ok {
			at[c.Key] = len(out)
			out = append(out, c)
			continue
		}
		m := &out[i]
		first := min(m.FirstSeen, c.FirstSeen)
		if c.LastSeen >= m.LastSeen {
			*m = c
		}
		m.FirstSeen = first
	}
	return out
}

// BaseProto names a protocol as the sensor does: tcp6 and udp6 are tcp and
// udp; icmp and icmpv6 stay apart, as the sensor keeps them.
func BaseProto(p string) string {
	p = strings.ToLower(p)
	switch p {
	case "tcp6":
		return "tcp"
	case "udp6":
		return "udp"
	}
	return p
}

// Argv0 is the program part of a command line, without its arguments.
func Argv0(cmdline string) string {
	if i := strings.IndexByte(cmdline, ' '); i >= 0 {
		return cmdline[:i]
	}
	return cmdline
}

// AppName is the name a policy's process selector matches: the executable's
// base name, else the command's.
func AppName(path, cmdline string) string {
	base := func(p string) string {
		// Windows paths use backslashes, whatever the agent runs on.
		if i := strings.LastIndexAny(p, `/\`); i >= 0 {
			return p[i+1:]
		}
		return p
	}
	if path != "" {
		return base(path)
	}
	return base(Argv0(cmdline))
}

// ClipCmdline bounds a command line, and keeps only the program unless full
// command lines were asked for: arguments can hold passwords and tokens.
func ClipCmdline(cmdline string, full bool) string {
	if !full {
		cmdline = Argv0(cmdline)
	}
	if len(cmdline) > MaxCmdline {
		cmdline = cmdline[:MaxCmdline]
	}
	return cmdline
}

// Hasher hashes executables, at most 64 MiB of each, and caches the result
// until the file's size or modification time changes.
type Hasher struct {
	mu    sync.Mutex
	cache map[string]hashEntry
}

type hashEntry struct {
	size  int64
	mtime int64
	sha   string
}

// Hash returns the SHA-256 of the file at open, and its code ID. key names
// the executable for the cache (its path); open is what is read, which may
// differ: on Linux /proc/<pid>/exe reaches the running binary even from
// another mount namespace, or after it was replaced on disk.
func (h *Hasher) Hash(key, open string) (sha, codeID string) {
	if open == "" {
		return "", ""
	}
	if key == "" {
		key = open
	}
	st, err := os.Stat(open)
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxHashBytes {
		return "", ""
	}
	h.mu.Lock()
	if h.cache == nil {
		h.cache = map[string]hashEntry{}
	}
	e, ok := h.cache[key]
	h.mu.Unlock()
	if ok && e.size == st.Size() && e.mtime == st.ModTime().UnixMilli() {
		return e.sha, "sha256:" + e.sha
	}
	f, err := os.Open(filepath.Clean(open))
	if err != nil {
		return "", ""
	}
	defer f.Close()
	d := sha256.New()
	if _, err := io.Copy(d, io.LimitReader(f, maxHashBytes)); err != nil {
		return "", ""
	}
	sum := hex.EncodeToString(d.Sum(nil))
	h.mu.Lock()
	if len(h.cache) > 4*MaxProcesses {
		h.cache = map[string]hashEntry{} // binaries come and go; don't keep every one forever
	}
	h.cache[key] = hashEntry{size: st.Size(), mtime: st.ModTime().UnixMilli(), sha: sum}
	h.mu.Unlock()
	return sum, "sha256:" + sum
}
