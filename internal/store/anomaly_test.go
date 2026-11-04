package store

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/asn"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

// anomalyNet plays a synthetic network into a store: a week of history
// before a one-hour window, with one device per anomaly check.
type anomalyNet struct {
	t      *testing.T
	evs    []wire.Event
	flowID uint64
	asn    *asn.DB // the server's ASN table, if any
}

func (n *anomalyNet) add(at time.Time, e wire.Event) {
	e.TS = at
	n.evs = append(n.evs, e)
}

type host struct {
	mac string
	ip  netip.Addr
}

var (
	plug     = host{"b8:27:eb:00:00:10", netip.MustParseAddr("192.168.1.10")}
	laptop   = host{"3c:22:fb:00:00:20", netip.MustParseAddr("192.168.1.20")}
	infected = host{"00:1a:2b:00:00:30", netip.MustParseAddr("192.168.1.30")}
)

func (n *anomalyNet) flow(h host, at time.Time, name, dst string, port uint16, up uint64) {
	n.flowID++
	n.add(at.Add(time.Second), wire.Event{Type: wire.TypeFlow, Flow: &wire.Flow{
		ID: n.flowID, Proto: 6, Src: h.ip, SrcPort: uint16(40000 + n.flowID%20000), Dst: netip.MustParseAddr(dst), DstPort: port, SrcMAC: h.mac,
		FirstSeen: at, Start: at, End: at.Add(time.Second), BytesOut: up, BytesIn: 5000, PktsOut: 10, PktsIn: 10,
		App: map[bool]string{true: "tls"}[name != ""], SNI: name, Final: true, EndReason: "fin"}})
}

func (n *anomalyNet) lookup(h host, at time.Time, name, rcode string) {
	n.add(at, wire.Event{Type: wire.TypeDNS, DNS: &wire.DNS{Client: h.ip, ClientMAC: h.mac, Server: netip.MustParseAddr("192.168.1.1"),
		Proto: "udp", QName: name, QType: "A", RCode: rcode}})
}

func (n *anomalyNet) join(mac string, ip netip.Addr, name string, at time.Time) {
	n.add(at, wire.Event{Type: wire.TypeDHCP, DHCP: &wire.DHCP{Version: 4, MsgType: "ACK", MAC: mac, YourIP: ip, Hostname: name}})
}

func (n *anomalyNet) beacon(bssid, ssid, sec string, at time.Time) {
	n.add(at, wire.Event{Type: wire.TypeWiFi, WiFi: &wire.WiFi{Kind: "beacon", BSSID: bssid, SSID: ssid, Channel: 6, Security: sec}})
}

func (n *anomalyNet) store(started time.Time) *Store {
	n.t.Helper()
	// The server's clock follows the events as they arrive: it dates when a
	// sensor first reported.
	now := started
	st, err := Open(filepath.Join(n.t.TempDir(), "ng.db"), Config{Now: func() time.Time { return now }, ASN: func() *asn.DB { return n.asn }})
	if err != nil {
		n.t.Fatal(err)
	}
	n.t.Cleanup(func() { st.Close() })
	hello := wire.Event{Type: wire.TypeHello, TS: started, Hello: &wire.Hello{Name: "router", Version: "test",
		Interfaces: []wire.Interface{{Name: "br-lan", MAC: "02:00:5e:00:00:01", Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.1/24")}}}}}
	// Nothing is heard before the sensor starts.
	evs := []wire.Event{hello}
	for _, e := range n.evs {
		if !e.TS.Before(started) {
			evs = append(evs, e)
		}
	}
	slices.SortStableFunc(evs, func(a, b wire.Event) int { return a.TS.Compare(b.TS) })
	for i := range evs {
		evs[i].Seq = uint64(i + 1)
	}
	// Small batches, as a sensor ships them, each received as it starts.
	for chunk := range slices.Chunk(evs, 50) {
		now = chunk[0].TS
		if _, err := st.Ingest(context.Background(), "router", "b1", chunk); err != nil {
			n.t.Fatal(err)
		}
	}
	now = window.To.Add(time.Hour)
	return st
}

// window is the hour the checks look at, a week after the network started.
var window = model.Filter{From: testutil.Base.Add(7 * 24 * time.Hour), To: testutil.Base.Add(7*24*time.Hour + time.Hour)}

func homeWeek(t *testing.T) *anomalyNet {
	n := &anomalyNet{t: t}
	day0 := testutil.Base.Add(time.Minute)
	w := window.From
	n.join(plug.mac, plug.ip, "plug", day0)
	n.join(laptop.mac, laptop.ip, "laptop", day0)
	n.join(infected.mac, infected.ip, "pc", day0)
	for h := range 7 * 24 {
		at := day0.Add(time.Duration(h) * time.Hour)
		// The plug only ever talks to its cloud, a little each hour.
		n.flow(plug, at, "cloud.plug.example.com", "93.184.216.10", 443, 10_000)
		// The laptop browses forty different sites over the week.
		n.flow(laptop, at.Add(10*time.Minute), fmt.Sprintf("www.site%d-shop.com", h%40), "93.184.216.20", 443, 50_000)
		if h%24 == 0 {
			n.flow(infected, at, "update.pc-vendor.com", "93.184.216.30", 443, 1000)
		}
	}
	// The home network: one access point, which the plug joins.
	n.beacon("aa:bb:cc:00:00:01", "Home-Net", "wpa2", day0)
	n.add(day0.Add(time.Second), wire.Event{Type: wire.TypeWiFi, WiFi: &wire.WiFi{Kind: "association_request", BSSID: "aa:bb:cc:00:00:01", Client: plug.mac, SSID: "Home-Net"}})
	n.beacon("aa:bb:cc:00:00:01", "Home-Net", "wpa2", w.Add(time.Minute))

	// The window.
	n.flow(plug, w.Add(time.Minute), "cloud.plug.example.com", "93.184.216.10", 443, 10_000)
	n.flow(plug, w.Add(20*time.Minute), "drop.exfil.example.net", "198.51.100.99", 443, 30<<20)
	n.flow(laptop, w.Add(2*time.Minute), "www.site3-shop.com", "93.184.216.20", 443, 50_000)
	n.flow(laptop, w.Add(3*time.Minute), "www.new-small.com", "93.184.216.21", 443, 100_000)
	n.flow(laptop, w.Add(4*time.Minute), "www.new-big.com", "93.184.216.22", 443, 2<<20)
	for i := range 60 {
		n.flow(laptop, w.Add(time.Duration(i)*time.Minute+5*time.Second), "", "203.0.113.50", 8443, 300)
	}
	for i := range 30 {
		n.lookup(infected, w.Add(time.Duration(i)*time.Second), fmt.Sprintf("q%07x.com", i*7919), "NXDOMAIN")
	}
	for i := range 10 {
		n.lookup(infected, w.Add(time.Duration(i)*time.Second), fmt.Sprintf("www.ok%d.com", i), "NOERROR")
		n.lookup(infected, w.Add(time.Duration(i)*time.Second), "wpad", "NXDOMAIN") // local: not evidence
	}
	for i := range 60 {
		n.lookup(infected, w.Add(5*time.Minute+time.Duration(i)*time.Second), fmt.Sprintf("%024x.t.tunnel-example.net", i*104729+1), "NOERROR")
	}
	n.join("00:1b:2c:00:00:40", netip.MustParseAddr("192.168.1.40"), "newcomer", w.Add(30*time.Minute))
	n.join("da:00:00:00:00:50", netip.MustParseAddr("192.168.1.50"), "", w.Add(31*time.Minute))
	n.beacon("aa:bb:cc:00:00:02", "Home-Net", "open", w.Add(40*time.Minute)) // an open twin
	n.beacon("aa:bb:cc:00:00:03", "Home-Net", "wpa2", w.Add(41*time.Minute)) // a new access point
	n.beacon("dd:ee:ff:00:00:04", "Neighbor", "wpa2", w.Add(42*time.Minute)) // not our network
	return n
}

type found struct{ kind, severity, device, entity string }

func anomalySet(as []model.Anomaly) map[found]bool {
	out := map[found]bool{}
	for _, a := range as {
		out[found{a.Kind, a.Severity, a.Device, a.Entity}] = true
	}
	return out
}

func TestAnomalies(t *testing.T) {
	st := homeWeek(t).store(testutil.Base)
	rep, err := st.Anomalies(context.Background(), window)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Learning {
		t.Error("a week of history, still learning")
	}
	dev := func(mac string) string { return "device:" + mac }
	want := []found{
		{model.AnomalyNewDestination, model.SeverityHigh, dev(plug.mac), "site:example.net"},
		{model.AnomalyUploadSpike, model.SeverityMedium, dev(plug.mac), ""},
		{model.AnomalyNewDestination, model.SeverityLow, dev(laptop.mac), "site:new-big.com"},
		{model.AnomalyBeacon, model.SeverityMedium, dev(laptop.mac), "ip:203.0.113.50"},
		{model.AnomalyDNSFailures, model.SeverityMedium, dev(infected.mac), ""},
		{model.AnomalyDNSTunnel, model.SeverityMedium, dev(infected.mac), "site:tunnel-example.net"},
		{model.AnomalyNewDevice, model.SeverityMedium, dev("00:1b:2c:00:00:40"), ""},
		{model.AnomalyNewDevice, model.SeverityLow, dev("da:00:00:00:00:50"), ""},
		{model.AnomalyRogueAP, model.SeverityHigh, "", "ssid:home-net"},
		{model.AnomalyRogueAP, model.SeverityMedium, dev("aa:bb:cc:00:00:03"), "ssid:home-net"},
	}
	got := anomalySet(rep.Anomalies)
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing %+v", w)
		}
	}
	for _, a := range rep.Anomalies {
		switch {
		case a.Entity == "site:new-small.com":
			t.Errorf("a busy device's small new site reported: %+v", a)
		case a.Entity == "site:example.com", a.Entity == "site:site3-shop.com":
			t.Errorf("a known destination reported: %+v", a)
		case a.Device == dev(plug.mac) || a.Device == dev(laptop.mac) || a.Device == dev(infected.mac):
			if a.Kind == model.AnomalyNewDevice {
				t.Errorf("a device from the first day reported as new: %+v", a)
			}
		case a.Entity == "ssid:neighbor":
			t.Errorf("a neighbour's access point reported: %+v", a)
		}
		if a.Summary == "" || a.TS < window.From.UnixMilli() || a.TS >= window.To.UnixMilli() {
			t.Errorf("summary/time: %+v", a)
		}
		// The open twin appeared 40 minutes in.
		if a.Kind == model.AnomalyRogueAP && a.Severity == model.SeverityHigh && a.TS != window.From.Add(40*time.Minute).UnixMilli() {
			t.Errorf("evil twin dated %v", time.UnixMilli(a.TS).Sub(window.From))
		}
	}
	for i := 1; i < len(rep.Anomalies); i++ {
		if model.SeverityRank(rep.Anomalies[i].Severity) > model.SeverityRank(rep.Anomalies[i-1].Severity) {
			t.Fatalf("not most severe first: %+v", rep.Anomalies)
		}
	}

	// A device filter keeps that device's.
	f := window
	f.Device = plug.mac
	rep, err = st.Anomalies(context.Background(), f)
	if err != nil || len(rep.Anomalies) != 2 {
		t.Fatalf("plug only: %v %+v", err, rep)
	}

	// The graph marks what medium and high anomalies are about.
	g, err := st.Graph(context.Background(), window, model.DefaultGraphOptions)
	if err != nil {
		t.Fatal(err)
	}
	marked := map[string]string{}
	for _, n := range g.Nodes {
		marked[n.ID] = n.Attrs["anomaly"]
	}
	if marked[dev(plug.mac)] != model.SeverityHigh || marked["site:example.net"] != model.SeverityHigh {
		t.Errorf("plug and its new site not marked: %+v", marked)
	}
	if marked["site:new-big.com"] != "" {
		t.Error("a low anomaly drawn")
	}
	var edge bool
	for _, e := range g.Edges {
		edge = edge || (e.From == dev(plug.mac) && e.To == "site:example.net" && e.Attrs["anomaly"] == model.SeverityHigh)
	}
	if !edge {
		t.Error("the plug's edge to its new site not marked")
	}
}

// Before a day of history only the checks that need none run.
func TestAnomaliesLearning(t *testing.T) {
	st := homeWeek(t).store(window.From.Add(-2 * time.Hour))
	rep, err := st.Anomalies(context.Background(), window)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Learning {
		t.Error("two hours of history, not learning")
	}
	kinds := map[string]bool{}
	for _, a := range rep.Anomalies {
		kinds[a.Kind] = true
	}
	for _, k := range []string{model.AnomalyNewDestination, model.AnomalyUploadSpike, model.AnomalyNewDevice} {
		if kinds[k] {
			t.Errorf("%s reported while learning", k)
		}
	}
	for _, k := range []string{model.AnomalyBeacon, model.AnomalyDNSFailures, model.AnomalyDNSTunnel, model.AnomalyRogueAP} {
		if !kinds[k] {
			t.Errorf("%s needs no history but was not reported", k)
		}
	}
}

// A live view asks for a window ending now on every refresh. It must not run
// every check each time, and requests that arrive together share one run.
func TestAnomaliesLiveWindowUsesCache(t *testing.T) {
	now := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	live := func() model.Filter { return model.Filter{From: now.Add(-time.Hour), To: now} }

	first, err := st.Anomalies(ctx, live())
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	moved, err := st.Anomalies(ctx, live())
	if err != nil {
		t.Fatal(err)
	}
	if n := st.anomRuns.Load(); n != 1 {
		t.Errorf("a window two seconds on ran the checks %d times, want 1", n)
	}
	if moved.ToMS != now.UnixMilli() || moved.FromMS != now.Add(-time.Hour).UnixMilli() {
		t.Errorf("the report names window [%d, %d), not the one asked for", moved.FromMS, moved.ToMS)
	}
	if first.ToMS == moved.ToMS {
		t.Error("the shared report was changed for the later request")
	}
	// It expires, since sensor_silent depends on the clock.
	now = now.Add(anomalyLiveTTL)
	if _, err := st.Anomalies(ctx, live()); err != nil {
		t.Fatal(err)
	}
	if n := st.anomRuns.Load(); n != 2 {
		t.Errorf("after the live TTL the checks ran %d times, want 2", n)
	}
	// A different span is a different report.
	if _, err := st.Anomalies(ctx, model.Filter{From: now.Add(-2 * time.Hour), To: now}); err != nil {
		t.Fatal(err)
	}
	if n := st.anomRuns.Load(); n != 3 {
		t.Errorf("another span ran the checks %d times, want 3", n)
	}
	// A historical window keeps its exact key.
	old := model.Filter{From: now.Add(-3 * time.Hour), To: now.Add(-2 * time.Hour)}
	for range 2 {
		if _, err := st.Anomalies(ctx, old); err != nil {
			t.Fatal(err)
		}
	}
	if n := st.anomRuns.Load(); n != 4 {
		t.Errorf("a repeated historical window ran the checks %d times, want 4", n)
	}
	other := model.Filter{From: old.From.Add(time.Second), To: old.To.Add(time.Second)}
	if _, err := st.Anomalies(ctx, other); err != nil {
		t.Fatal(err)
	}
	if n := st.anomRuns.Load(); n != 5 {
		t.Errorf("a shifted historical window ran the checks %d times, want 5", n)
	}
}

// A waiter survives the run it waited on failing: its client going away must
// not fail another client's request.
func TestAnomaliesWaiterOutlivesCancelledRun(t *testing.T) {
	now := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	f := model.Filter{From: now.Add(-time.Hour), To: now}
	run := &anomalyRun{done: make(chan struct{}), err: context.Canceled}
	st.anomMu.Lock()
	st.anomFlight = map[string]*anomalyRun{fmt.Sprintf("live|%d|", time.Hour.Milliseconds()): run}
	st.anomMu.Unlock()
	got := make(chan error, 1)
	go func() {
		_, err := st.Anomalies(context.Background(), f)
		got <- err
	}()
	time.Sleep(50 * time.Millisecond) // let it reach the wait
	st.anomMu.Lock()
	clear(st.anomFlight)
	st.anomMu.Unlock()
	close(run.done)
	if err := <-got; err != nil {
		t.Errorf("waiter failed with the other request's error: %v", err)
	}
}

func TestDataRange(t *testing.T) {
	now := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	empty, err := st.DataRange(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if empty.FirstMS != 0 || empty.LastMS != 0 || empty.NowMS != now.UnixMilli() {
		t.Errorf("empty store: %+v", empty)
	}
	if empty.RawFromMS >= empty.NowMS || empty.RollupFromMS > empty.RawFromMS {
		t.Errorf("retention bounds: %+v", empty)
	}
}

// Ingest arrives more often than slow checks finish. If it stopped a running
// report being cached, a busy network would never have a cached report at all.
func TestAnomalyReportSurvivesIngestWhileRunning(t *testing.T) {
	now := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	gen := st.anomGen
	st.invalidateAnomaliesThrottled() // nothing cached, as during a first run
	if st.anomGen != gen {
		t.Error("ingest marked the running report out of date")
	}
	// It does drop a report past its allowance.
	st.anomRep, st.anomKey, st.anomAt = &model.AnomalyReport{}, "k", now.Add(-time.Minute)
	st.invalidateAnomaliesThrottled()
	if st.anomRep != nil {
		t.Error("ingest kept a report older than its allowance")
	}
	// A change a person made still applies at once.
	gen = st.anomGen
	st.invalidateAnomalies()
	if st.anomGen == gen {
		t.Error("an explicit invalidation did not mark running reports out of date")
	}
}
