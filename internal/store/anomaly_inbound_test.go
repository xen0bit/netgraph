package store

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

// Servers here, as a router forwarding ports sees them.
var (
	web  = host{"02:42:ac:00:00:80", netip.MustParseAddr("192.168.1.80")}
	shop = host{"02:42:ac:00:00:85", netip.MustParseAddr("192.168.1.85")}
	nas  = host{"02:42:ac:00:00:90", netip.MustParseAddr("192.168.1.90")}
)

const routerMAC = "02:00:5e:00:00:01"

// visit is a connection from outside (or from the router, for a hairpin)
// to a server here: the client sent ask packets, the server reply.
func (n *anomalyNet) visit(h host, client string, sport, port uint16, at time.Time, dur time.Duration, ask, reply uint64) {
	n.flowID++
	n.add(at.Add(dur), wire.Event{Type: wire.TypeFlow, Flow: &wire.Flow{
		ID: n.flowID, Proto: 6, Src: netip.MustParseAddr(client), SrcPort: sport, SrcMAC: routerMAC, Dst: h.ip, DstPort: port, DstMAC: h.mac,
		FirstSeen: at, Start: at, End: at.Add(dur), BytesOut: 60 * ask, BytesIn: 200 * reply, PktsOut: ask, PktsIn: reply,
		Final: true, EndReason: "fin"}})
}

// session is a real exchange; probe one that never became one.
func (n *anomalyNet) session(h host, client string, port uint16, at time.Time) {
	n.visit(h, client, uint16(30000+n.flowID%30000), port, at, 2*time.Second, 10, 12)
}

func (n *anomalyNet) probe(h host, client string, port uint16, at time.Time) {
	n.visit(h, client, 61000, port, at, 0, 1, 1)
}

func serverWeek(t *testing.T) *anomalyNet {
	n := &anomalyNet{t: t}
	day0 := testutil.Base.Add(time.Minute)
	w := window.From
	n.join(web.mac, web.ip, "web", day0)
	n.join(shop.mac, shop.ip, "shop", day0)
	n.join(nas.mac, nas.ip, "nas", day0)
	// History: the web server serves HTTPS and its admin's SSH; the shop
	// has a steady 20 visitors an hour for the last two days.
	for h := range 7 * 24 {
		at := day0.Add(time.Duration(h) * time.Hour)
		if h%6 == 0 {
			n.session(web, fmt.Sprintf("198.51.100.%d", h%50+1), 443, at)
		}
		if h%24 == 0 {
			n.session(web, "198.51.100.200", 22, at.Add(time.Minute))
		}
		if h >= 5*24 {
			for i := range 20 {
				n.session(shop, fmt.Sprintf("192.0.2.%d", i+1), 443, at.Add(time.Duration(i)*time.Minute))
			}
		}
	}

	// The window. Ordinary visitors, and one busy client: none of it is
	// news.
	for i := range 30 {
		n.session(web, fmt.Sprintf("198.51.100.%d", i+1), 443, w.Add(time.Duration(i)*time.Minute))
	}
	for i := range 100 {
		n.session(web, "198.51.100.150", 443, w.Add(time.Duration(i)*10*time.Second))
	}
	// A scanner tries 25 ports on the web server.
	for p := range 25 {
		n.probe(web, "203.0.113.9", uint16(20+p), w.Add(time.Minute+time.Duration(p)*time.Second))
	}
	// Twelve scanners try 10 ports each on the NAS: one summary.
	for s := range 12 {
		for p := range 10 {
			n.probe(nas, fmt.Sprintf("203.0.113.%d", 100+s), uint16(8000+p), w.Add(2*time.Minute+time.Duration(s*10+p)*time.Second))
		}
	}
	// A sweep: telnet on twelve addresses here.
	for i := range 12 {
		n.probe(host{"", netip.AddrFrom4([4]byte{192, 168, 1, byte(100 + i)})}, "203.0.113.200", 23, w.Add(3*time.Minute))
	}
	// One address guesses SSH passwords; 25 more do, a little each.
	for i := range 60 {
		n.session(web, "203.0.113.66", 22, w.Add(5*time.Minute+time.Duration(i)*5*time.Second))
	}
	for a := range 25 {
		for i := range 21 {
			n.session(web, fmt.Sprintf("203.0.113.%d", 150+a), 22, w.Add(10*time.Minute+time.Duration(a*21+i)*time.Second))
		}
	}
	// The router's hairpin (docker-proxy, NAT loopback) to SSH is local,
	// never an attack.
	for i := range 600 {
		n.visit(web, "192.168.1.1", uint16(30000+i), 22, w.Add(20*time.Minute+time.Duration(i)*time.Second), time.Second, 10, 12)
	}
	// The web server starts serving 8080 to five clients; and a
	// peer-to-peer app a dynamic port, which is not a service.
	for i := range 5 {
		n.session(web, fmt.Sprintf("198.51.100.%d", 60+i), 8080, w.Add(30*time.Minute+time.Duration(i)*time.Second))
		n.session(web, fmt.Sprintf("198.51.100.%d", 70+i), 51413, w.Add(31*time.Minute+time.Duration(i)*time.Second))
	}
	// The shop is suddenly very popular.
	for i := range 1200 {
		n.session(shop, fmt.Sprintf("192.0.2.%d", i%200+1), 443, w.Add(40*time.Minute+time.Duration(i)*time.Second))
	}
	return n
}

func TestInboundAnomalies(t *testing.T) {
	n := serverWeek(t)
	n.asn = testASN(t)
	st := n.store(testutil.Base)
	rep, err := st.Anomalies(context.Background(), window)
	if err != nil {
		t.Fatal(err)
	}
	dev := func(h host) string { return "device:" + h.mac }
	want := []found{
		{model.AnomalyScan, model.SeverityLow, dev(web), "ip:203.0.113.9"},
		{model.AnomalyScan, model.SeverityLow, dev(nas), ""},
		{model.AnomalyScan, model.SeverityLow, "", "ip:203.0.113.200"},
		{model.AnomalyBruteForce, model.SeverityMedium, dev(web), "ip:203.0.113.66"},
		{model.AnomalyBruteForce, model.SeverityLow, dev(web), ""},
		{model.AnomalyNewService, model.SeverityMedium, dev(web), ""},
		{model.AnomalyInboundSurge, model.SeverityMedium, dev(shop), ""},
	}
	got := anomalySet(rep.Anomalies)
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing %+v", w)
		}
	}
	counts := map[string]int{}
	for _, a := range rep.Anomalies {
		counts[a.Kind]++
		t.Logf("%s %s: %s %v", a.Severity, a.Kind, a.Summary, a.Evidence)
		switch {
		case a.Entity == "ip:198.51.100.150":
			t.Errorf("a busy web client reported: %+v", a)
		case a.Entity == "ip:192.168.1.1", strings.Contains(a.Summary, "192.168.1.1 "):
			t.Errorf("the router's hairpin reported: %+v", a)
		case a.Kind == model.AnomalyNewService && a.Evidence["port"] != "8080/tcp":
			t.Errorf("a served or dynamic port reported as new: %+v", a)
		case a.Kind == model.AnomalyInboundSurge && a.Device != dev(shop):
			t.Errorf("a surge on a steady server: %+v", a)
		}
	}
	if counts[model.AnomalyScan] != 3 || counts[model.AnomalyBruteForce] != 2 || counts[model.AnomalyNewService] != 1 || counts[model.AnomalyInboundSurge] != 1 {
		t.Errorf("counts = %v", counts)
	}
	for _, a := range rep.Anomalies {
		if a.Kind == model.AnomalyScan && a.Device == dev(nas) && (a.Evidence["scanners"] != "12" || a.Evidence["ports"] != "10" ||
			!strings.HasSuffix(a.Summary, "most from AS64501 SCANNET ×12")) {
			t.Errorf("scan summary = %+v", a)
		}
		// Sources are named by their network.
		if a.Entity == "ip:203.0.113.66" && (a.Evidence["network"] != "AS64501 SCANNET" || a.Evidence["country"] != "NL" ||
			!strings.HasPrefix(a.Summary, "203.0.113.66 (AS64501 SCANNET, NL) opened 60")) {
			t.Errorf("brute force source = %+v", a)
		}
		if a.Kind == model.AnomalyBruteForce && a.Severity == model.SeverityLow && (a.Evidence["addresses"] != "25" || a.Evidence["sessions"] != "525") {
			t.Errorf("spread brute force = %+v", a)
		}
	}

	// The graph outlines a guesser and its edge into the server: its
	// network's node, or with Networks off its own.
	for _, c := range []struct {
		networks bool
		id       string
	}{{true, "asn:64501"}, {false, "ip:203.0.113.66"}} {
		o := model.DefaultGraphOptions
		o.Networks = c.networks
		g, err := st.Graph(context.Background(), window, o)
		if err != nil {
			t.Fatal(err)
		}
		var node, edge bool
		for _, n := range g.Nodes {
			node = node || n.ID == c.id && n.Attrs["anomaly"] == model.SeverityMedium
		}
		for _, e := range g.Edges {
			edge = edge || e.From == c.id && e.To == dev(web) && e.Attrs["anomaly"] == model.SeverityMedium
		}
		if !node || !edge {
			t.Errorf("%s marked: node %v, edge %v", c.id, node, edge)
		}
	}

	// Without a day of history, scans and guessing are still reported; new
	// services and surges need the week.
	st = serverWeek(t).store(window.From.Add(-2 * time.Hour))
	if rep, err = st.Anomalies(context.Background(), window); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, a := range rep.Anomalies {
		kinds[a.Kind] = true
	}
	if !kinds[model.AnomalyScan] || !kinds[model.AnomalyBruteForce] || kinds[model.AnomalyNewService] || kinds[model.AnomalyInboundSurge] {
		t.Errorf("while learning: %v", kinds)
	}
}
