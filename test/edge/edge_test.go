//go:build edgelab

// Package edge drives test/edge/compose.yml: real clients -- wireguard-go,
// and strongSwan with EAP-MSCHAPv2 -- connect to netgraph-edge and move TCP
// through their tunnels to a server behind it, and netgraph is asked who did
// what.
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
			for _, svc := range []string{"edge", "wg-client", "ikev2-client", "server"} {
				out, _ := composeErr("logs", "--tail", "40", svc)
				t.Logf("--- %s\n%s", svc, out)
			}
		}
		compose(t, "down", "-v", "--remove-orphans")
	})
	compose(t, "up", "-d")

	for _, svc := range []string{"wg-client", "ikev2-client"} {
		waitFor(t, svc+" to finish its transfer", 2*time.Minute, func() bool {
			_, err := composeErr("exec", "-T", svc, "test", "-f", "/tmp/done")
			return err == nil
		})
	}
	byListener := map[string]session{}
	waitFor(t, "both sessions and their traffic at the server", time.Minute, func() bool {
		all, err := sessions()
		if err != nil || len(all) != 2 {
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
	wg := byListener["office"]
	if wg.Sensor != "edge-lab" || wg.Protocol != "wireguard" || wg.User != clientKey || wg.Auth != "public-key" {
		t.Errorf("WireGuard session = %+v, want the client's public key", wg)
	}
	if len(wg.Prefixes) != 1 || wg.Prefixes[0] != clientAddr || !strings.HasPrefix(wg.Outer, "198.18.1.50:") {
		t.Errorf("WireGuard session holds %v from %s, want [%s] from 198.18.1.50", wg.Prefixes, wg.Outer, clientAddr)
	}
	ike := byListener["remote"]
	if ike.Protocol != "ikev2" || ike.User != "alice" || ike.Auth != "eap-mschapv2" {
		t.Errorf("IKEv2 session = %+v, want alice by eap-mschapv2", ike)
	}
	if len(ike.Prefixes) != 1 || !strings.HasPrefix(ike.Prefixes[0], "10.11.11.") || !strings.HasPrefix(ike.Outer, "198.18.1.51:") {
		t.Errorf("IKEv2 session holds %v from %s, want a pool address from 198.18.1.51", ike.Prefixes, ike.Outer)
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
		return len(all) == 2
	})
	for name, s := range byListener {
		if s.Reason != "shutdown" {
			t.Errorf("%s closed with reason %q, want shutdown", name, s.Reason)
		}
	}
}
