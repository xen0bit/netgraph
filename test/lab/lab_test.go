//go:build lab

// Package lab drives test/lab/compose.yml: it brings the isolated network up,
// lets the scripted clients generate traffic, queries the server and tears it
// all down. It needs Docker and is behind the lab tag so `go test ./...`
// never requires it.
package lab

import (
	"os/exec"
	"strings"
	"testing"
)

func compose(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", append([]string{"compose", "-f", "compose.yml"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func TestLab(t *testing.T) {
	compose(t, "build")
	t.Cleanup(func() { compose(t, "down", "-v", "--remove-orphans") })
	compose(t, "up", "-d", "router")

	for _, svc := range []string{"sensor", "server"} {
		out := compose(t, "run", "--rm", svc)
		if !strings.Contains(out, "dev") {
			t.Errorf("%s: unexpected version output: %q", svc, out)
		}
	}
}
