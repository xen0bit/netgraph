//go:build linux

package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/xen0bit/netgraph/internal/agent"
)

func TestScannerFixture(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0900A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 999 1 0 0 0 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 100 1 0 0 0 0
   2: 0100007F:1F91 0900A8C0:01BB 06 00000000:00000000 03:00000F9F 00000000     0        0 0 3 0000000000000000
`
	if err := os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	// An IPv4 peer of a dual-stack listener on :22, as tcp6 shows it:
	// ::ffff:192.168.0.5 port 22 <- ::ffff:192.168.0.9 port 40000.
	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000500A8C0:0016 0000000000000000FFFF00000900A8C0:9C40 01 00000000:00000000 00:00000000 00000000     0        0 1000 1 0 0 0 0
`
	if err := os.WriteFile(filepath.Join(root, "net", "tcp6"), []byte(tcp6), 0o644); err != nil {
		t.Fatal(err)
	}
	pidDir := filepath.Join(root, "1234")
	if err := os.MkdirAll(filepath.Join(pidDir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(t.TempDir(), "curl")
	if err := os.WriteFile(exe, []byte("not really curl"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(pidDir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[999]", filepath.Join(pidDir, "fd", "3")); err != nil {
		t.Fatal(err)
	}
	// A command with a space and a parenthesis must not shift the fields.
	stat := "1234 (cu rl) x) S 1 1234 1234 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0\n"
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte("cpu 1 2 3\nbtime 1700000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte("Name:\tcurl\nUid:\t1000\t1000\t1000\t1000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("curl\x00https://example.com\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	sc := &Scanner{Root: root}
	procs, conns, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Not the TIME_WAIT socket (inode 0): no program holds it.
	if len(conns) != 2 {
		t.Fatalf("connections = %+v", conns)
	}
	c := conns[0]
	if c.PID != 1234 || c.LocalPort != 8080 || c.RemoteIP != "192.168.0.9" || c.RemotePort != 443 || c.Direction != "out" ||
		c.Key != "tcp|127.0.0.1:8080|192.168.0.9:443|999" || c.App != "curl" {
		t.Fatalf("connection = %+v", c)
	}
	in := conns[1]
	if in.Proto != "tcp" || in.LocalIP != "192.168.0.5" || in.RemoteIP != "192.168.0.9" || in.RemotePort != 40000 || in.Direction != "in" {
		t.Fatalf("dual-stack connection = %+v", in)
	}
	if len(procs) != 1 || procs[0].PID != 1234 || procs[0].PPID != 1 || procs[0].UID != 1000 || procs[0].Path != exe || procs[0].SHA256 == "" ||
		procs[0].Start != 1700000000*1000+12345*10 {
		t.Fatalf("process = %+v", procs)
	}
	// Arguments stay home unless asked for.
	if procs[0].Cmdline != "curl" {
		t.Fatalf("cmdline = %q", procs[0].Cmdline)
	}
}

// procFixture is a /proc with a socket table and processes in it.
type procFixture struct {
	t    *testing.T
	root string
}

func newProcFixture(t *testing.T) *procFixture {
	f := &procFixture{t, t.TempDir()}
	f.write("stat", "cpu 1 2 3\nbtime 1700000000\n")
	return f
}

func (f *procFixture) write(name, body string) {
	f.t.Helper()
	p := filepath.Join(f.root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// sockets writes net/tcp: one established connection per inode, from
// 10.0.0.2 port 40000+i to 192.0.2.1:443.
func (f *procFixture) sockets(inodes ...int) {
	s := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	for i, ino := range inodes {
		s += fmt.Sprintf("   %d: 0200000A:%04X 010200C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 %d 1 0 0 0 0\n", i, 40000+i, ino)
	}
	f.write("net/tcp", s)
}

// proc writes a process: its parent, start ticks, program and sockets.
func (f *procFixture) proc(pid, ppid int, ticks int64, cmdline string, inodes ...int) {
	f.t.Helper()
	dir := filepath.Join(f.root, strconv.Itoa(pid))
	_ = os.RemoveAll(dir)
	f.write(filepath.Join(strconv.Itoa(pid), "stat"),
		fmt.Sprintf("%d (x) S %d 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0\n", pid, ppid, ticks))
	f.write(filepath.Join(strconv.Itoa(pid), "cmdline"), strings.ReplaceAll(cmdline, " ", "\x00")+"\x00")
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
		f.t.Fatal(err)
	}
	for i, ino := range inodes {
		if err := os.Symlink(fmt.Sprintf("socket:[%d]", ino), filepath.Join(dir, "fd", strconv.Itoa(3+i))); err != nil {
			f.t.Fatal(err)
		}
	}
}

func owners(conns []agent.Connection) map[string]int {
	out := map[string]int{}
	for _, c := range conns {
		out[c.Key[strings.LastIndexByte(c.Key, '|')+1:]] = c.PID
	}
	return out
}

// A socket keeps the owner it was found in while that process lives, without
// walking /proc again; a reused PID is a new process, looked up afresh; a
// process that has gone is never sent as a bare PID.
func TestScannerRemembersOwners(t *testing.T) {
	f := newProcFixture(t)
	f.sockets(11, 12)
	f.proc(100, 1, 500, "haproxy -f cfg", 11)
	f.proc(200, 1, 600, "curl https://example.com", 12)
	sc := &Scanner{Root: f.root}
	_, conns, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := owners(conns); got["11"] != 100 || got["12"] != 200 {
		t.Fatalf("owners = %v", got)
	}
	// The descriptor goes from /proc (as if unreadable now): the owner
	// found before still holds the socket while it lives.
	if err := os.Remove(filepath.Join(f.root, "100", "fd", "3")); err != nil {
		t.Fatal(err)
	}
	_, conns, _ = sc.Scan(context.Background())
	if got := owners(conns); got["11"] != 100 {
		t.Fatalf("remembered owner = %v", got)
	}
	// PID 100 is reused by another program: socket 11 has no known owner
	// any more, and a new socket in a new process is found.
	f.proc(100, 1, 900, "sleep 1")
	f.proc(300, 200, 700, "wget http://example.com", 13)
	f.sockets(11, 12, 13)
	procs, conns, _ := sc.Scan(context.Background())
	if got := owners(conns); got["11"] != 0 || got["12"] != 200 || got["13"] != 300 {
		t.Fatalf("owners after reuse = %v", got)
	}
	// wget's parent (curl, 200) is described as well, once.
	var pids []int
	for _, p := range procs {
		pids = append(pids, p.PID)
		if p.Path == "" && p.Cmdline == "" {
			t.Fatalf("bare PID sent: %+v", p)
		}
	}
	if !slices.Equal(pids, []int{200, 300}) {
		t.Fatalf("processes = %v", pids)
	}
	// curl exits before its identity is read: its socket has no program,
	// and no process is sent for it.
	sc2 := &Scanner{Root: f.root}
	if err := os.Remove(filepath.Join(f.root, "200", "stat")); err != nil {
		t.Fatal(err)
	}
	procs, conns, _ = sc2.Scan(context.Background())
	if got := owners(conns); got["12"] != 0 || got["13"] != 300 {
		t.Fatalf("owners with curl gone = %v", got)
	}
	for _, p := range procs {
		if p.PID == 200 {
			t.Fatalf("gone process sent: %+v", p)
		}
	}
}

// The parents of a socket's owner are sent, so the server can say who
// started it.
func TestScannerAncestors(t *testing.T) {
	f := newProcFixture(t)
	f.sockets(21)
	f.proc(10, 1, 100, "sshd")
	f.proc(20, 10, 200, "bash")
	f.proc(30, 20, 300, "python3 job.py --token=secret", 21)
	procs, _, err := (&Scanner{Root: f.root}).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]agent.Process{}
	for _, p := range procs {
		got[p.PID] = p
	}
	if len(got) != 3 || got[30].PPID != 20 || got[20].PPID != 10 || got[10].Cmdline != "sshd" {
		t.Fatalf("processes = %+v", procs)
	}
	if got[30].Cmdline != "python3" {
		t.Fatalf("arguments sent without -cmdlines: %q", got[30].Cmdline)
	}
	procs, _, _ = (&Scanner{Root: f.root, Cmdlines: true}).Scan(context.Background())
	for _, p := range procs {
		if p.PID == 30 && p.Cmdline != "python3 job.py --token=secret" {
			t.Fatalf("cmdline = %q", p.Cmdline)
		}
	}
}
