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
	forbidden := []string{"modernc.org/sqlite", "oss.terrastruct.com/d2", "github.com/charmbracelet/"}
	for _, dep := range strings.Fields(string(out)) {
		for _, f := range forbidden {
			if strings.HasPrefix(dep, f) {
				t.Errorf("netgraph-sensor depends on %s (forbidden prefix %s)", dep, f)
			}
		}
	}
}
