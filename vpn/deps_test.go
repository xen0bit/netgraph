package veepin

// veepin's thesis is "from scratch": its dependencies are the standard library
// and golang.org/x/{crypto,net,sys}, and nothing else (AGENTS.md). In its own
// module that was enforced by go.mod, which named nothing more. Under vpn/ it
// shares netgraph's go.mod, which also names SQLite, d2 and the TUI libraries,
// so an import of any of them would now build without complaint. This test is
// the go.mod that vpn/ no longer has.

import (
	"os/exec"
	"strings"
	"testing"
)

func TestVPNImportsOnlyTheStandardLibraryAndXModules(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps",
		"-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", "./...").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	allowed := []string{
		"github.com/xen0bit/netgraph/vpn/",
		"golang.org/x/crypto/", "golang.org/x/net/", "golang.org/x/sys/",
	}
	for dep := range strings.FieldsSeq(string(out)) {
		ok := false
		for _, a := range allowed {
			if dep+"/" == a || strings.HasPrefix(dep, a) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("vpn/ depends on %s: only the standard library and golang.org/x/{crypto,net,sys} are allowed", dep)
		}
	}
}
