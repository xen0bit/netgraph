//go:build edgelab

// Package edge drives test/edge/compose.yml: real clients of five protocols
// -- wireguard-go; strongSwan with EAP-MSCHAPv2; openconnect as AnyConnect,
// GlobalProtect and Fortinet -- connect to netgraph-edge and move TCP through
// their tunnels to a server behind it, and netgraph is asked who did what.
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
	Auth     string     `json:"auth"`
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

// The whole claim of netgraph-edge, against clients it shares no code with:
// each session is the identity its handshake proved (a WireGuard key; an EAP
// username, not the IKE identity), at the address the listener gave it, from
// where it dialled; the TCP it moved through the tunnel is attributed to it;
// and stopping the edge closes it.
func TestEdgeLab(t *testing.T) {
	compose(t, "down", "-v", "--remove-orphans")
	compose(t, "build")
	t.Cleanup(func() {
		if t.Failed() {
			for _, svc := range []string{"edge", "wg-client", "ikev2-client", "anyconnect-client", "gp-client", "fortinet-client", "server"} {
				out, _ := composeErr("logs", "--tail", "40", svc)
				t.Logf("--- %s\n%s", svc, out)
			}
		}
		compose(t, "down", "-v", "--remove-orphans")
	})
	compose(t, "up", "-d")

	// One real client per protocol, each with its own user and pool.
	want := []struct {
		svc, listener, protocol, user, auth, pool, outer string
	}{
		{"wg-client", "office", "wireguard", clientKey, "public-key", "10.10.10.2/32", "198.18.1.50:"},
		{"ikev2-client", "remote", "ikev2", "alice", "eap-mschapv2", "10.11.11.", "198.18.1.51:"},
		{"anyconnect-client", "ssl", "anyconnect", "carol", "password", "10.12.12.", "198.18.1.52:"},
		{"gp-client", "gp", "gp", "dave", "password", "10.13.13.", "198.18.1.53:"},
		{"fortinet-client", "forti", "fortinet", "erin", "password", "10.14.14.", "198.18.1.54:"},
	}
	for _, w := range want {
		waitFor(t, w.svc+" to finish its transfer", 2*time.Minute, func() bool {
			_, err := composeErr("exec", "-T", w.svc, "test", "-f", "/tmp/done")
			return err == nil
		})
	}
	byListener := map[string]session{}
	waitFor(t, "every session and its traffic at the server", time.Minute, func() bool {
		all, err := sessions()
		if err != nil || len(all) != len(want) {
			return false
		}
		for _, s := range all {
			byListener[s.Listener] = s
		}
		for _, s := range byListener {
			if s.Flows == 0 || s.BytesOut < 1<<20 {
				return false
			}
		}
		return true
	})
	for _, w := range want {
		s := byListener[w.listener]
		if s.Sensor != "edge-lab" || s.Protocol != w.protocol || s.User != w.user || s.Auth != w.auth {
			t.Errorf("%s session = %+v, want %s by %s", w.protocol, s, w.user, w.auth)
		}
		if len(s.Prefixes) != 1 || !strings.HasPrefix(s.Prefixes[0], w.pool) || !strings.HasPrefix(s.Outer, w.outer) {
			t.Errorf("%s session holds %v from %s, want %s* from %s*", w.protocol, s.Prefixes, s.Outer, w.pool, w.outer)
		}
	}

	compose(t, "stop", "-t", "20", "edge")
	waitFor(t, "the sessions to close when the edge stops", 30*time.Second, func() bool {
		all, err := sessions()
		if err != nil {
			return false
		}
		for _, s := range all {
			if s.End == nil {
				return false
			}
			byListener[s.Listener] = s
		}
		return len(all) == len(want)
	})
	for name, s := range byListener {
		if s.Reason != "shutdown" {
			t.Errorf("%s closed with reason %q, want shutdown", name, s.Reason)
		}
	}
}
