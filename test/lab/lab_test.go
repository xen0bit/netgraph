//go:build lab

// Package lab drives test/lab/compose.yml: a home network in containers
// (real dnsmasq, avahi, nmbd, lldpd, curl and quic-go), with the sensor
// beside the router and the server behind it. The test waits for the
// scripted user to finish, then checks what netgraph learned through the
// same API the UIs use, against Wireshark, against a replay of the lab's
// own capture, and in a headless browser.
//
//	make lab                       # build, run, assert, tear down
//	NETGRAPH_LAB_KEEP=1 make lab   # leave it running afterwards
//	NETGRAPH_SHOTS=dir make lab    # keep the browser screenshots
package lab

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/apiclient"
	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/sensor"
	"github.com/xen0bit/netgraph/internal/store"
	"github.com/xen0bit/netgraph/internal/wire"
)

const (
	api       = "http://127.0.0.1:18443"
	readToken = "lab-read-token"
	devtools  = "ws://127.0.0.1:19222"
	laptopMAC = "3c:22:fb:00:00:64"
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
	cmd := exec.Command("docker", append([]string{"compose", "-f", "compose.yml"}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// waitFor polls check every second until it returns true or the timeout.
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

func TestLab(t *testing.T) {
	compose(t, "down", "-v", "--remove-orphans")
	compose(t, "build")
	t.Cleanup(func() {
		if t.Failed() {
			for _, svc := range []string{"sensor", "server", "router", "laptop"} {
				out, _ := composeErr("logs", "--tail", "40", svc)
				t.Logf("--- %s logs ---\n%s", svc, out)
			}
		}
		if os.Getenv("NETGRAPH_LAB_KEEP") == "" {
			compose(t, "down", "-v", "--remove-orphans")
		}
	})
	compose(t, "up", "-d")

	waitFor(t, "the server", 2*time.Minute, func() bool {
		resp, err := http.Get(api + "/healthz")
		if err == nil {
			resp.Body.Close()
		}
		return err == nil && resp.StatusCode == 200
	})
	waitFor(t, "the scripted user to finish", 5*time.Minute, func() bool {
		_, err := composeErr("exec", "-T", "laptop", "test", "-f", "/shared/done")
		return err == nil
	})
	steps := readSteps(t)
	for _, s := range []string{"dhcp", "dns-www", "https-www", "hold-start", "h3-quic", "http-plain", "dns-nx", "https-alias", "hold-end"} {
		if steps[s] == 0 {
			t.Fatalf("the scripted user did not complete %q: %v", s, steps)
		}
	}
	c := apiclient.NewClient(api, readToken)
	ctx := context.Background()
	whole := model.Filter{From: time.UnixMilli(steps["start"]).Add(-time.Minute), To: time.Now().Add(time.Minute)}
	// The sensor exports every 5s and ships every 1s: wait until the held
	// connection's final record has arrived.
	waitFor(t, "the held connection's final record", time.Minute, func() bool {
		fl, err := c.Flows(ctx, model.Filter{From: whole.From, To: whole.To, Domain: "hold.lab.test"})
		return err == nil && len(fl) == 1 && fl[0].Closed
	})

	t.Run("devices", func(t *testing.T) { checkDevices(t, c, whole) })
	t.Run("dns", func(t *testing.T) { checkDNS(t, c, whole) })
	t.Run("flows", func(t *testing.T) { checkFlows(t, c, whole) })
	t.Run("windows", func(t *testing.T) { checkWindows(t, c, steps) })
	t.Run("graph", func(t *testing.T) { checkGraph(t, c, whole) })
	pcap := filepath.Join(t.TempDir(), "lab.pcap")
	compose(t, "cp", "tap:/shared/lab.pcap", pcap)
	t.Run("wireshark", func(t *testing.T) { checkWireshark(t, c, whole) })
	t.Run("replay", func(t *testing.T) { checkReplay(t, c, whole, pcap) })
	t.Run("browser", func(t *testing.T) {
		shots := os.Getenv("NETGRAPH_SHOTS")
		if shots != "" {
			_ = os.MkdirAll(shots, 0o755)
		}
		checkWebUI(t, devtools, "http://server:8443", readToken, shots, []string{"lab-laptop", "hold.lab.test"})
	})
}

// readSteps reads the laptop's "<unix ms> <step>" log.
func readSteps(t *testing.T) map[string]int64 {
	out := compose(t, "exec", "-T", "laptop", "cat", "/shared/events.log")
	steps := map[string]int64{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		ms, step, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			continue
		}
		v, _ := strconv.ParseInt(ms, 10, 64)
		steps[step] = v
	}
	return steps
}

func checkDevices(t *testing.T, c *apiclient.Client, f model.Filter) {
	devs, err := c.Devices(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]model.Device{}
	for _, d := range devs {
		by[d.MAC] = d
	}
	laptop := by[laptopMAC]
	if laptop.Label != "lab-laptop" || laptop.VendorShort != "Apple" || !slices.Contains(laptop.IPs, "10.77.0.100") {
		t.Errorf("laptop = %+v", laptop)
	}
	if !slices.ContainsFunc(laptop.Fingerprints, func(s string) bool { return strings.HasSuffix(s, "|lab-vendor-class") }) {
		t.Errorf("laptop lacks its DHCP fingerprint: %v", laptop.Fingerprints)
	}
	if !slices.ContainsFunc(laptop.Fingerprints, func(s string) bool { return strings.HasPrefix(s, "ja4:q") }) {
		t.Errorf("laptop lacks its QUIC JA4: %v", laptop.Fingerprints)
	}
	if !slices.Contains(laptop.UserAgents, "lab-agent/1.0") {
		t.Errorf("laptop lacks its user agent: %v", laptop.UserAgents)
	}
	if p := by["00:1b:a9:00:00:65"]; p.Label != "lab-printer" || p.VendorShort != "Brother" || !slices.Contains(p.Services, "Lab Printer") {
		t.Errorf("printer = %+v", p)
	}
	if n := by["00:15:5d:00:00:66"]; n.Label != "lab-nas" || slices.Contains(n.Hostnames, "lab") {
		t.Errorf("nas = %+v", n)
	}
	var router *model.Device
	for i := range devs {
		if devs[i].Role == "router" {
			router = &devs[i]
		}
	}
	if router == nil || router.Label != "lab-router" || !slices.Contains(router.IPs, "10.77.0.10") {
		t.Errorf("router = %+v", router)
	}
	facts, err := c.Facts(context.Background(), model.Filter{From: f.From, To: f.To, Limit: 10000})
	if err != nil {
		t.Fatal(err)
	}
	var upnp, lldp bool
	for _, ft := range facts {
		switch {
		case ft.Rel == model.RelUPnP && ft.Src == "device:f4:f5:d8:00:00:67" && strings.Contains(ft.DstLabel, "LabTV/2.0"):
			upnp = true
		case ft.Rel == model.RelNeighbor && router != nil && ft.Src == router.ID && strings.Contains(ft.DstLabel, "lab-router"):
			lldp = true
		}
	}
	if !upnp || !lldp {
		t.Errorf("upnp=%v lldp=%v", upnp, lldp)
	}
}

func checkDNS(t *testing.T, c *apiclient.Client, f model.Filter) {
	qs, err := c.DNS(context.Background(), model.Filter{From: f.From, To: f.To, Device: laptopMAC, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	var www, nx, alias bool
	for _, q := range qs {
		switch {
		case q.QName == "www.lab.test" && q.QType == "A" && q.RCode == "NOERROR":
			www = len(q.Answers) == 1 && q.Answers[0].Data == "198.18.0.30" && q.Answers[0].TTL == 300 && q.DeviceName == "lab-laptop"
		case q.QName == "nx.lab.test":
			nx = q.RCode == "NXDOMAIN"
		case q.QName == "alias.lab.test" && q.QType == "A":
			alias = len(q.Answers) == 2 && q.Answers[0].Type == "CNAME" && q.Answers[0].Data == "www.lab.test"
		}
	}
	if !www || !nx || !alias {
		t.Errorf("www=%v nx=%v alias=%v in %+v", www, nx, alias, qs)
	}
}

func checkFlows(t *testing.T, c *apiclient.Client, f model.Filter) {
	fl, err := c.Flows(context.Background(), model.Filter{From: f.From, To: f.To, Device: laptopMAC, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]model.Flow{}
	for _, x := range fl {
		// An ICMP error to the same server (a port unreachable for a QUIC
		// packet that arrives after curl closed its socket) carries the
		// same name; it must not stand in for the connection itself.
		if _, seen := by[x.Name]; x.Name != "" && (!seen || x.Proto != "icmp") {
			by[x.Name] = x
		}
	}
	if h := by["hold.lab.test"]; h.App != "tls" || h.SNI != "hold.lab.test" || h.QName != "hold.lab.test" || !strings.HasPrefix(h.JA4, "t13d") ||
		h.ALPN != "h2" || h.BytesIn < 90_000 || h.Direction != "out" {
		t.Errorf("hold = %+v", h)
	}
	if q := by["quic.lab.test"]; q.App != "quic" || q.SNI != "quic.lab.test" || q.ALPN != "h3" || !strings.HasPrefix(q.JA4, "q13d") || q.RemotePort != 443 {
		t.Errorf("quic = %+v", q)
	}
	if h := by["plain.lab.test"]; h.App != "http" || h.HTTPHost != "plain.lab.test" || h.UserAgent != "lab-agent/1.0" {
		t.Errorf("http = %+v", h)
	}
	// alias.lab.test was looked up by its CNAME; the TLS SNI is the name
	// curl asked for.
	if a := by["alias.lab.test"]; a.SNI != "alias.lab.test" {
		t.Errorf("alias = %+v", a)
	}
}

// The held connection streams 1000 bytes a second for 90 seconds.
func checkWindows(t *testing.T, c *apiclient.Client, steps map[string]int64) {
	ctx := context.Background()
	start := time.UnixMilli(steps["hold-start"])
	hold := func(a, b time.Duration) model.Flow {
		t.Helper()
		fl, err := c.Flows(ctx, model.Filter{From: start.Add(a), To: start.Add(b), Domain: "hold.lab.test"})
		if err != nil || len(fl) != 1 {
			t.Fatalf("window %s..%s: %v %+v", a, b, err, fl)
		}
		return fl[0]
	}
	first := hold(-5*time.Second, 10*time.Second)
	if first.State != model.StateOpened || first.Closed {
		t.Errorf("opening window: %+v", first)
	}
	mid := hold(30*time.Second, 60*time.Second)
	if mid.State != model.StateCarried || mid.Closed {
		t.Errorf("middle window: %+v", mid)
	}
	// 30 s at 1000 B/s of payload, give or take the export intervals.
	if mid.BytesIn < 22_000 || mid.BytesIn > 42_000 {
		t.Errorf("middle window carried %d bytes in, want about 32000", mid.BytesIn)
	}
	end := time.UnixMilli(steps["hold-end"])
	last := hold(end.Sub(start)-10*time.Second, end.Sub(start)+10*time.Second)
	if last.State != model.StateCarried || !last.Closed {
		t.Errorf("closing window: %+v", last)
	}
	sum, err := c.Summary(ctx, model.Filter{From: start.Add(30 * time.Second), To: start.Add(60 * time.Second)})
	if err != nil || sum.PeakConns < 1 {
		t.Errorf("summary: %v %+v", err, sum)
	}
}

func checkGraph(t *testing.T, c *apiclient.Client, f model.Filter) {
	ctx := context.Background()
	g, err := c.Graph(ctx, f, model.DefaultGraphOptions)
	if err != nil {
		t.Fatal(err)
	}
	var connects, queried bool
	for _, e := range g.Edges {
		if e.From == "device:"+laptopMAC && e.To == "domain:hold.lab.test" {
			connects = connects || e.Rel == model.RelConnects
			queried = queried || e.Rel == model.RelQueried
		}
	}
	if !connects || !queried {
		t.Errorf("graph lacks laptop -> hold.lab.test edges: %+v", g.Edges)
	}
	txt, err := c.GraphFormat(ctx, f, model.DefaultGraphOptions, "txt", "")
	if err != nil || !bytes.Contains(txt, []byte("lab-laptop")) {
		t.Errorf("text graph: %v\n%s", err, txt)
	}
}

// checkWireshark compares the JA4 of every TLS and QUIC ClientHello in the
// lab's capture, as Wireshark computes it, with netgraph's.
func checkWireshark(t *testing.T, c *apiclient.Client, f model.Filter) {
	out := compose(t, "exec", "-T", "tap", "tshark", "-r", "/shared/lab.pcap", "-Y", "tls.handshake.type == 1",
		"-T", "fields", "-e", "tls.handshake.extensions_server_name", "-e", "tls.handshake.ja4")
	want := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		sni, ja4, ok := strings.Cut(line, "\t")
		if ok && sni != "" && ja4 != "" {
			want[sni] = ja4
		}
	}
	if len(want) < 4 {
		t.Fatalf("tshark found only %v", want)
	}
	fl, err := c.Flows(context.Background(), model.Filter{From: f.From, To: f.To, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range fl {
		if w, ok := want[x.SNI]; ok && x.JA4 != w {
			t.Errorf("%s (%s): netgraph JA4 %s, Wireshark %s", x.SNI, x.App, x.JA4, w)
		}
	}
}

type sink struct{ events []wire.Event }

func (s *sink) Emit(ev wire.Event) {
	ev.Seq = uint64(len(s.events) + 1)
	s.events = append(s.events, ev)
}

// checkReplay imports the lab's own capture into a fresh database: a
// replay must learn the same names the live sensor did.
func checkReplay(t *testing.T, c *apiclient.Client, f model.Filter, pcap string) {
	src, err := capture.OpenFile(pcap)
	if err != nil {
		t.Fatal(err)
	}
	var out sink
	r := &sensor.Runner{Processor: sensor.NewProcessor(sensor.Config{}, &out), Out: &out}
	if err := r.RunFile(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "replay.db"), store.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Ingest(context.Background(), "replay", "1", out.events); err != nil {
		t.Fatal(err)
	}
	replayed, err := st.Flows(context.Background(), model.Filter{From: f.From, To: f.To, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	live, err := c.Flows(context.Background(), model.Filter{From: f.From, To: f.To, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	names := func(fl []model.Flow) map[string]bool {
		m := map[string]bool{}
		for _, x := range fl {
			if x.SNI != "" || x.HTTPHost != "" {
				m[x.Name] = true
			}
		}
		return m
	}
	l, r2 := names(live), names(replayed)
	for n := range l {
		if !r2[n] {
			t.Errorf("replay missed %s (live saw it)", n)
		}
	}
}
