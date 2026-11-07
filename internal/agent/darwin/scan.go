// Package darwin implements the macOS host-agent scanner. It needs no cgo:
// sockets and their processes come from the system's lsof, and executables
// from ps, both run by absolute path with fixed arguments. It has no build
// tag, so its parsers are tested everywhere; only macOS has the commands.
package darwin

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/agent"
)

const maxOutput = 32 << 20

// Scanner runs lsof and ps. Running as root, it sees every user's sockets.
type Scanner struct {
	// Cmdlines sends each process's full command line. Off, only the
	// program: arguments can hold passwords and tokens.
	Cmdlines bool
	// Run runs a command and returns its output; tests replace it.
	Run  func(ctx context.Context, name string, args ...string) ([]byte, error)
	hash agent.Hasher
}

// Capabilities says what this scanner reports.
func (s *Scanner) Capabilities() []string { return []string{"process-identity", "lsof"} }

func (s *Scanner) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if s.Run != nil {
		return s.Run(ctx, name, args...)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &limited{w: &out, n: maxOutput}
	err := cmd.Run()
	// lsof exits 1 when some of what it was asked for matched nothing.
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 && out.Len() > 0 {
		err = nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return out.Bytes(), nil
}

// Scan returns the current process and connection snapshot.
func (s *Scanner) Scan(ctx context.Context) ([]agent.Process, []agent.Connection, error) {
	raw, err := s.run(ctx, "/usr/sbin/lsof", "-nP", "-iTCP", "-iUDP", "-FpcuftPnT")
	if err != nil {
		return nil, nil, err
	}
	sockets := ParseLsof(raw)
	psOut, err := s.run(ctx, "/bin/ps", "-axww", "-o", "pid=,ppid=,uid=,comm=")
	if err != nil {
		return nil, nil, err
	}
	all := ParsePs(psOut)
	if s.Cmdlines {
		if args, err := s.run(ctx, "/bin/ps", "-axww", "-o", "pid=,args="); err == nil {
			for pid, line := range parseArgs(args) {
				if p, ok := all[pid]; ok {
					p.Cmdline = line
					all[pid] = p
				}
			}
		}
	}
	procs := map[int]agent.Process{}
	var list []agent.Process
	for _, so := range sockets {
		if _, done := procs[so.PID]; done || !so.Connected() || so.PID <= 0 {
			continue
		}
		p, ok := all[so.PID]
		if !ok {
			p = agent.Process{PID: so.PID}
		}
		p.Cmdline = agent.ClipCmdline(p.Cmdline, s.Cmdlines)
		p.SHA256, p.CodeID = s.hash.Hash(p.Path, p.Path)
		procs[so.PID] = p
		if len(list) < agent.MaxProcesses {
			list = append(list, p)
		}
	}
	listening := map[agent.Listener]bool{}
	for _, so := range sockets {
		if so.State == "LISTEN" {
			listening[agent.Listener{Proto: so.Proto, Port: so.LocalPort}] = true
		}
	}
	now := time.Now().UnixMilli()
	var conns []agent.Connection
	for _, so := range sockets {
		if !so.Connected() || so.State == "LISTEN" {
			continue
		}
		conns = append(conns, agent.NewConnection(so, listening, procs[so.PID], now))
		if len(conns) >= agent.MaxConnections {
			break
		}
	}
	return list, conns, nil
}

// ParseLsof reads lsof -F output: a "p" line starts a process ("c" its
// command, "u" its uid), an "f" line a file within it, followed by its "P"
// protocol, "n" name (local->remote) and "TST=" state.
func ParseLsof(b []byte) []agent.Socket {
	var out []agent.Socket
	var pid, uid int
	var cur *agent.Socket
	flush := func() {
		if cur != nil && cur.LocalIP != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		v := line[1:]
		switch line[0] {
		case 'p':
			flush()
			pid, _ = strconv.Atoi(v)
			uid = 0
		case 'u':
			uid, _ = strconv.Atoi(v)
		case 'f':
			flush()
			cur = &agent.Socket{PID: pid, UID: uid, ID: strconv.Itoa(pid) + "/" + v}
		case 'P':
			if cur != nil {
				cur.Proto = strings.ToLower(v)
			}
		case 'n':
			if cur != nil {
				local, remote, _ := strings.Cut(v, "->")
				cur.LocalIP, cur.LocalPort = hostPort(local)
				cur.RemoteIP, cur.RemotePort = hostPort(remote)
			}
		case 'T':
			if cur != nil && strings.HasPrefix(v, "ST=") {
				cur.State = strings.TrimPrefix(v, "ST=")
				if cur.State == "LISTEN" {
					cur.RemoteIP, cur.RemotePort = "", 0
				}
			}
		}
		if len(out) >= agent.MaxConnections*4 {
			break
		}
	}
	flush()
	return out
}

// hostPort splits lsof's "10.0.0.5:443", "[fe80::1%en0]:443" or "*:22".
func hostPort(s string) (string, int) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0
	}
	host, port := s[:i], s[i+1:]
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if j := strings.IndexByte(host, '%'); j >= 0 {
		host = host[:j]
	}
	if host == "*" {
		host = "0.0.0.0"
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return "", 0
	}
	return host, p
}

// ParsePs reads "pid ppid uid comm" lines; on macOS comm is the
// executable's full path.
func ParsePs(b []byte) map[int]agent.Process {
	out := map[int]agent.Process{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil || pid <= 0 {
			continue
		}
		ppid, _ := strconv.Atoi(f[1])
		uid, _ := strconv.Atoi(f[2])
		path := strings.Join(f[3:], " ")
		p := agent.Process{PID: pid, PPID: ppid, UID: uid, Cmdline: path}
		if strings.HasPrefix(path, "/") {
			p.Path = path
		}
		out[pid] = p
		if len(out) >= 100000 {
			break
		}
	}
	return out
}

// parseArgs reads "pid args..." lines.
func parseArgs(b []byte) map[int]string {
	out := map[int]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		pidS, rest, _ := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if pid, err := strconv.Atoi(pidS); err == nil {
			out[pid] = strings.TrimSpace(rest)
		}
	}
	return out
}

// limited writes at most n bytes, discarding the rest.
type limited struct {
	w io.Writer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	q := p
	if len(q) > l.n {
		q = q[:l.n]
	}
	l.n -= len(q)
	if _, err := l.w.Write(q); err != nil {
		return 0, err
	}
	return len(p), nil
}
