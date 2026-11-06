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
`
	if err := os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(tcp), 0o644); err != nil {
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
	stat := "1234 (curl) S 1 1234 1234 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0\n"
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
	if len(conns) != 1 {
		t.Fatalf("connections = %+v", conns)
	}
	c := conns[0]
	if c.PID != 1234 || c.LocalPort != 8080 || c.RemoteIP != "192.168.0.9" || c.RemotePort != 443 || c.Direction != "out" {
		t.Fatalf("connection = %+v", c)
	}
	if len(procs) != 1 || procs[0].PID != 1234 || procs[0].UID != 1000 || procs[0].Path != exe || procs[0].SHA256 == "" {
		t.Fatalf("process = %+v", procs)
	}
}
