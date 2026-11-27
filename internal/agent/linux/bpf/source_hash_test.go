//go:build linux

package bpf

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestBPFSourceHash pins the C source the checked-in objects were built from.
// Editing src/conn.c without rebuilding (make bpf) would leave an object whose
// code no longer matches its source. Byte-identical rebuilds are not portable
// across clang and kernel-header versions, so the source is what is compared,
// not the object: make bpf records the hash after a successful build.
func TestBPFSourceHash(t *testing.T) {
	src, err := os.ReadFile("src/conn.c")
	if err != nil {
		t.Fatal(err)
	}
	sum, err := os.ReadFile("src/conn.c.sha256")
	if err != nil {
		t.Fatalf("%v: run make bpf to record the source hash", err)
	}
	fields := strings.Fields(string(sum))
	if len(fields) == 0 {
		t.Fatal("src/conn.c.sha256 is empty: run make bpf")
	}
	got := fmt.Sprintf("%x", sha256.Sum256(src))
	if !strings.EqualFold(fields[0], got) {
		t.Fatalf("src/conn.c changed since the BPF objects were built: run make bpf\n  built from %s\n  now        %s", fields[0], got)
	}
}
