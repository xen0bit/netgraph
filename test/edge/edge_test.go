//go:build edgelab

// Package edge drives test/edge/compose.yml: a real WireGuard client
// (wireguard-go) connects to netgraph-edge and moves TCP through the tunnel to
// a server behind it, and netgraph is asked who did what.
//
//	make edge.lab
package edge

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	api        = "http://127.0.0.1:18444"
	readToken  = "edge-read-token"
	clientKey  = "gjMMAROzi5lHFapIKeaAdJ2RhGe0lW24XysGzBd1OSM=" // compose.yml's CLIENT_PUBLIC
	clientAddr = "10.10.10.2/32"
)

func compose(t *testing.T, args ...string) string {
	t.Helper()
	out, err := composeErr(args...)
	if err != nil {
		t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func composeErr(args ...string) (string, error) {
	out, err := exec.Command("docker", append([]string{"compose", "-f", "compose.yml"}, args...)...).CombinedOutput()
	return string(out), err
}

func waitFor(t *testing.T, what string, timeout time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(time.Second)
	}
}

type session struct {
	Sensor   string     `json:"sensor"`
	Listener string     `json:"listener"`
	Protocol string     `json:"protocol"`
	User     string     `json:"user"`
	Prefixes []string   `json:"prefixes"`
	Outer    string     `json:"outer"`
	End      *time.Time `json:"end"`
	Reason   string     `json:"reason"`
	Flows    int64      `json:"flows"`
	BytesOut int64      `json:"bytes_out"`
	BytesIn  int64      `json:"bytes_in"`
}

func sessions() ([]session, error) {
	req, _ := http.NewRequest("GET", api+"/api/v1/vpn/sessions?from=-1h", nil)
	req.Header.Set("Authorization", "Bearer "+readToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var out []session
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// The whole claim of netgraph-edge, against a client it shares no code with:
// the session is the key the handshake proved, at the address the listener
// gave it, from where it dialled; the TCP it moved through the tunnel is
// attributed to it; and stopping the edge closes it.
func TestEdgeLab(t *testing.T) {
	compose(t, "down", "-v", "--remove-orphans")
	compose(t, "build")
	t.Cleanup(func() {
		if t.Failed() {
			for _, svc := range []string{"edge", "wg-client", "server"} {
				out, _ := composeErr("logs", "--tail", "40", svc)
				t.Logf("--- %s\n%s", svc, out)
			}
		}
		compose(t, "down", "-v", "--remove-orphans")
	})
	compose(t, "up", "-d")

	waitFor(t, "the client to finish its transfer", 2*time.Minute, func() bool {
		_, err := composeErr("exec", "-T", "wg-client", "test", "-f", "/tmp/done")
		return err == nil
	})
	var s session
	waitFor(t, "the session and its traffic at the server", time.Minute, func() bool {
		all, err := sessions()
		if err != nil || len(all) != 1 {
			return false
		}
		s = all[0]
		return s.Flows > 0 && s.BytesOut >= 1<<20
	})
	if s.Sensor != "edge-lab" || s.Listener != "office" || s.Protocol != "wireguard" {
		t.Errorf("session's origin = %s/%s/%s", s.Sensor, s.Listener, s.Protocol)
	}
	if s.User != clientKey {
		t.Errorf("session user %q, want the client's public key", s.User)
	}
	if len(s.Prefixes) != 1 || s.Prefixes[0] != clientAddr {
		t.Errorf("session prefixes %v, want [%s]", s.Prefixes, clientAddr)
	}
	if !strings.HasPrefix(s.Outer, "198.18.1.50:") {
		t.Errorf("session outer %q, want the client's address on the public network", s.Outer)
	}

	compose(t, "stop", "-t", "20", "edge")
	waitFor(t, "the session to close when the edge stops", 30*time.Second, func() bool {
		all, err := sessions()
		if err != nil || len(all) != 1 {
			return false
		}
		s = all[0]
		return s.End != nil
	})
	if s.Reason != "shutdown" {
		t.Errorf("closed with reason %q, want shutdown", s.Reason)
	}
}
