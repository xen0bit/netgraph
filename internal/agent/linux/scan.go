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
	maxFDsPerPID = 512
)

// Scanner reads /proc. It is safe to reuse across scans; the executable hash
// cache avoids re-reading unchanged binaries.
type Scanner struct {
	Root string // /proc by default; tests set a fixture root
	// Cmdlines sends each process's full command line. Off, only the
	// program's name is sent: arguments can hold passwords and tokens.
	Cmdlines bool
	hash     agent.Hasher
	bootOnce sync.Once
	boot     int64
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

// Capabilities says what this scanner reports.
func (s *Scanner) Capabilities() []string { return []string{"process-identity", "proc-sockets"} }

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
	listeners := map[agent.Listener]bool{}
	for _, so := range sockets {
		if so.state == "LISTEN" {
			listeners[agent.Listener{Proto: strings.TrimSuffix(so.proto, "6"), Port: so.localPort}] = true
		}
	}
	now := time.Now().UnixMilli()
	procCache := map[int]agent.Process{}
	var out []agent.Connection
	for _, so := range sockets {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		as := agent.Socket{Proto: so.proto, LocalIP: so.localIP, LocalPort: so.localPort, RemoteIP: so.remoteIP,
			RemotePort: so.remotePort, State: so.state, UID: so.uid, PID: inodes[so.inode], ID: strconv.FormatUint(so.inode, 10)}
		if !as.Connected() {
			continue
		}
		p, ok := procCache[as.PID]
		if !ok && as.PID > 0 {
			p = readProcess(root, as.PID, s.bootTime(root))
			p.Cmdline = agent.ClipCmdline(p.Cmdline, s.Cmdlines)
			// Through /proc/<pid>/exe: from a container, the path names a
			// file in the host's mount namespace, not this one.
			p.SHA256, p.CodeID = s.hash.Hash(p.Path, filepath.Join(root, strconv.Itoa(as.PID), "exe"))
			procCache[as.PID] = p
		}
		out = append(out, agent.NewConnection(as, listeners, p, now))
		if len(out) >= agent.MaxConnections {
			break
		}
	}
	procs := make([]agent.Process, 0, len(procCache))
	for _, pid := range slices.Sorted(maps.Keys(procCache)) {
		if p := procCache[pid]; p.PID != 0 {
			procs = append(procs, p)
		}
		if len(procs) >= agent.MaxProcesses {
			break
		}
	}
	return procs, out, nil
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

func readProcess(root string, pid int, boot int64) agent.Process {
	base := filepath.Join(root, strconv.Itoa(pid))
	p := agent.Process{PID: pid}
	if b, err := os.ReadFile(filepath.Join(base, "stat")); err == nil {
		// The command, in parentheses, may hold spaces and parentheses:
		// count fields from after its last ")".
		if i := bytes.LastIndexByte(b, ')'); i >= 0 {
			rest := strings.Fields(string(b[i+1:]))
			if len(rest) > 19 {
				p.PPID, _ = strconv.Atoi(rest[1])
				// Clock ticks after boot, as Unix ms. USER_HZ is 100 on
				// every architecture Linux exposes to userspace.
				if ticks, err := strconv.ParseInt(rest[19], 10, 64); err == nil && boot > 0 {
					p.Start = boot*1000 + ticks*10
				}
			}
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
