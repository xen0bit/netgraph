//go:build linux

// Package linux implements the Linux host-agent scanner. It reads the
// kernel's /proc socket tables and maps socket inodes to processes; it does
// not capture packet payloads.
package linux

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xen0bit/netgraph/internal/agent"
)

const (
	maxPIDs        = 20000
	maxFDsPerPID   = 512
	maxConnections = 5000
	maxProcesses   = 2000
	maxHashBytes   = 64 << 20
)

// Scanner reads /proc. It is safe to reuse across scans; the executable hash
// cache avoids re-reading unchanged binaries.
type Scanner struct {
	Root string // /proc by default; tests set a fixture root
	// Cmdlines sends each process's full command line. Off, only the
	// program's name is sent: arguments can hold passwords and tokens.
	Cmdlines bool
	mu       sync.Mutex
	hash     map[string]hashEntry
}

type hashEntry struct {
	size  int64
	mtime int64
	sha   string
}

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

// Scan returns the current process and connection snapshot.
func (s *Scanner) Scan(ctx context.Context) ([]agent.Process, []agent.Connection, error) {
	root := s.Root
	if root == "" {
		root = "/proc"
	}
	sockets, err := readSockets(root)
	if err != nil {
		return nil, nil, err
	}
	inodes := socketInodes(root)
	// A connection to a port this host listens on was accepted, not made.
	type listen struct {
		proto string
		port  int
	}
	listeners := map[listen]bool{}
	for _, so := range sockets {
		if so.state == "LISTEN" {
			listeners[listen{so.proto, so.localPort}] = true
		}
	}
	now := time.Now().UnixMilli()
	procCache := map[int]agent.Process{}
	seenProc := map[int]bool{}
	var out []agent.Connection
	for _, so := range sockets {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		if so.remoteIP == "" || (so.remoteIP == "0.0.0.0" || so.remoteIP == "::") {
			continue
		}
		pid := 0
		if p, ok := inodes[so.inode]; ok {
			pid = p
		}
		p, ok := procCache[pid]
		if !ok && pid > 0 {
			p = readProcess(root, pid)
			if !s.Cmdlines {
				p.Cmdline = argv0(p.Cmdline)
			}
			p.SHA256, p.CodeID = s.hashExe(p.Path)
			procCache[pid] = p
		}
		if pid > 0 {
			seenProc[pid] = true
		}
		dir := "out"
		if listeners[listen{so.proto, so.localPort}] {
			dir = "in"
		}
		if isLocal(so.remoteIP) || so.remoteIP == so.localIP {
			dir = "local"
		}
		c := agent.Connection{
			Key:   so.proto + "|" + so.localIP + ":" + strconv.Itoa(so.localPort) + "|" + so.remoteIP + ":" + strconv.Itoa(so.remotePort),
			Proto: so.proto, LocalIP: so.localIP, LocalPort: so.localPort,
			RemoteIP: so.remoteIP, RemotePort: so.remotePort, Direction: dir, State: so.state,
			PID: pid, UID: so.uid, App: appName(p.Path, p.Cmdline), Path: p.Path,
			CodeID: p.CodeID, SHA256: p.SHA256, FirstSeen: now, LastSeen: now,
		}
		out = append(out, c)
		if len(out) >= maxConnections {
			break
		}
	}
	var procs []agent.Process
	for pid := range seenProc {
		p := procCache[pid]
		if p.PID == 0 {
			continue
		}
		if p.SHA256 == "" {
			p.SHA256, p.CodeID = s.hashExe(p.Path)
		}
		procs = append(procs, p)
		if len(procs) >= maxProcesses {
			break
		}
	}
	return procs, out, nil
}

// argv0 is the program part of a command line, without its arguments.
func argv0(cmdline string) string {
	if i := strings.IndexByte(cmdline, ' '); i >= 0 {
		return cmdline[:i]
	}
	return cmdline
}

func isLocal(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return a.IsLoopback() || a.IsLinkLocalUnicast()
}

func appName(path, cmdline string) string {
	if path != "" {
		return filepath.Base(path)
	}
	if i := strings.IndexByte(cmdline, ' '); i > 0 {
		return filepath.Base(cmdline[:i])
	}
	return cmdline
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

func socketInodes(root string) map[uint64]int {
	out := map[uint64]int{}
	entries, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join(root, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for i, fd := range fds {
			if i >= maxFDsPerPID {
				break
			}
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 64)
			if err == nil {
				out[inode] = pid
			}
		}
		n++
		if n >= maxPIDs {
			break
		}
	}
	return out
}

func readProcess(root string, pid int) agent.Process {
	base := filepath.Join(root, strconv.Itoa(pid))
	p := agent.Process{PID: pid}
	if b, err := os.ReadFile(filepath.Join(base, "stat")); err == nil {
		fields := strings.Fields(string(b))
		if len(fields) > 21 {
			p.PPID, _ = strconv.Atoi(fields[3])
			p.Start, _ = strconv.ParseInt(fields[21], 10, 64)
		}
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
		if len(p.Cmdline) > 2048 {
			p.Cmdline = p.Cmdline[:2048]
		}
	}
	return p
}

func (s *Scanner) hashExe(path string) (sha, codeID string) {
	if path == "" {
		return "", ""
	}
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || st.Size() > maxHashBytes {
		return "", ""
	}
	key := path
	s.mu.Lock()
	if s.hash == nil {
		s.hash = map[string]hashEntry{}
	}
	if e, ok := s.hash[key]; ok && e.size == st.Size() && e.mtime == st.ModTime().UnixMilli() {
		s.mu.Unlock()
		return e.sha, "sha256:" + e.sha
	}
	s.mu.Unlock()
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxHashBytes)); err != nil {
		return "", ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	s.mu.Lock()
	s.hash[key] = hashEntry{size: st.Size(), mtime: st.ModTime().UnixMilli(), sha: sum}
	s.mu.Unlock()
	return sum, "sha256:" + sum
}
