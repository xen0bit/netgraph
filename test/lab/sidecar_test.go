//go:build lab

package lab

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/apiclient"
	"github.com/xen0bit/netgraph/internal/model"
)

// TestSidecarExample runs deploy/compose/sidecar.yml exactly as a user
// would, with the images the lab built, and checks the sidecar sensor
// reports traffic to the app it is attached to.
func TestSidecarExample(t *testing.T) {
	env := append(os.Environ(),
		"NETGRAPH_TOKEN=sidecar-token", "NETGRAPH_READ_TOKEN=sidecar-read",
		"NETGRAPH_SENSOR_IMAGE=netgraph-sensor:lab", "NETGRAPH_IMAGE=netgraph:lab",
		"APP_PORT=18080", "NETGRAPH_PORT=18444")
	dc := func(args ...string) (string, error) {
		cmd := exec.Command("docker", append([]string{"compose", "-p", "netgraph-sidecar-test", "-f", "../../deploy/compose/sidecar.yml"}, args...)...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	// The lab images are built by TestLab's compose; build them here too
	// when this test runs alone.
	if out, err := exec.Command("docker", "compose", "-f", "compose.yml", "build", "sensor", "server").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	if out, err := dc("up", "-d"); err != nil {
		t.Fatalf("up: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := dc("logs", "--tail", "30")
			t.Logf("%s", out)
		}
		_, _ = dc("down", "-v")
	})
	waitFor(t, "the sidecar's server", 2*time.Minute, func() bool {
		resp, err := http.Get("http://127.0.0.1:18444/healthz")
		if err == nil {
			resp.Body.Close()
		}
		return err == nil && resp.StatusCode == 200
	})
	c := apiclient.NewClient("http://127.0.0.1:18444", "sidecar-read")
	ctx := context.Background()
	waitFor(t, "the sensor to report", time.Minute, func() bool {
		s, err := c.Sensors(ctx)
		return err == nil && len(s) == 1 && s[0].Name == "app-sidecar"
	})
	// Traffic to the app, from the host.
	for range 3 {
		resp, err := http.Get("http://127.0.0.1:18080/?from=netgraph-lab")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	waitFor(t, "the app's HTTP connections", 90*time.Second, func() bool {
		fl, err := c.Flows(ctx, model.Filter{From: time.Now().Add(-10 * time.Minute), To: time.Now().Add(time.Minute), Port: 80})
		if err != nil {
			return false
		}
		// The Host header (127.0.0.1:18080) is an address, which names
		// nothing: decoding shows in the app and the user agent.
		for _, f := range fl {
			if f.App == "http" && f.ServerPort == 80 && f.HTTPHost == "" && strings.HasPrefix(f.UserAgent, "Go-http-client") {
				return true
			}
		}
		return false
	})
}
