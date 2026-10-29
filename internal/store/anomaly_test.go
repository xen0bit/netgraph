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
