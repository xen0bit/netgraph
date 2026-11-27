package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The sensor ships to mips routers with a few MB to spare. SQLite (modernc)
// does not build for mips at all and d2 adds tens of MB, so neither may ever
// become a dependency of this binary, directly or through a shared package.
func TestSensorDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	// gopacket/layers and pcapgo are what internal/capture deliberately
	// avoids (the hand-rolled pcap reader exists for this): layers alone
	// more than doubles the binary. afpacket is the one gopacket package the
	// sensor may use.
	forbidden := []string{
		"modernc.org/sqlite", "oss.terrastruct.com/d2", "github.com/charmbracelet/",
		"github.com/gopacket/gopacket/layers", "github.com/gopacket/gopacket/pcapgo",
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, f := range forbidden {
			if strings.HasPrefix(dep, f) {
				t.Errorf("netgraph-sensor depends on %s (forbidden prefix %s)", dep, f)
			}
		}
	}
}
