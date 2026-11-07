//go:build linux

package linux

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
