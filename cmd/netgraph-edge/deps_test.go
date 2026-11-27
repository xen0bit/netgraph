package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The edge runs on the box at the network's edge, next to the VPN listeners:
// it ships events, as a sensor does, and stores nothing. SQLite, d2 and the
// TUI libraries belong to the server, and pulling one in through a shared
// package would make the edge a server-sized binary for no reason.
func TestEdgeDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	forbidden := []string{
		"modernc.org/sqlite", "oss.terrastruct.com/d2", "github.com/charmbracelet/",
		"github.com/gopacket/gopacket/layers", "github.com/gopacket/gopacket/pcapgo",
		// TOY is insecure by design and must never carry traffic.
		"github.com/xen0bit/netgraph/vpn/toy",
	}
	for dep := range strings.FieldsSeq(string(out)) {
		for _, f := range forbidden {
			if dep == f || strings.HasPrefix(dep, f) && (strings.HasSuffix(f, "/") || strings.HasPrefix(dep[len(f):], "/")) {
				t.Errorf("netgraph-edge depends on %s (forbidden: %s)", dep, f)
			}
		}
	}
}
