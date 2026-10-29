package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/flow"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/sensor"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

type sink struct{ events []wire.Event }

func (s *sink) Emit(ev wire.Event) {
	ev.Seq = uint64(len(s.events) + 1)
	s.events = append(s.events, ev)
}

// homeStore replays the home scenario through the sensor pipeline into a
// fresh database whose clock reads ten minutes after the scenario began.
func homeStore(t *testing.T) (*Store, *testutil.Capture, []wire.Event) {
	t.Helper()
	capt := testutil.Home(t)
	src, err := capture.OpenFile(capt.WriteFile())
	if err != nil {
		t.Fatal(err)
	}
	var out sink
	r := &sensor.Runner{Processor: sensor.NewProcessor(sensor.Config{Flow: flow.Config{ActiveTimeout: 30 * time.Second}}, &out), Out: &out, Hello: wire.Hello{Name: "router"}}
	if err := r.RunFile(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return testutil.Base.Add(10 * time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	// Ingest in several batches, as a sensor would send them.
	for i := 0; i < len(out.events); i += 25 {
		if _, err := st.Ingest(context.Background(), "router", "boot1", out.events[i:min(i+25, len(out.events))]); err != nil {
			t.Fatal(err)
		}
	}
	return st, capt, out.events
}

func win(a, b time.Duration) model.Filter {
	return model.Filter{From: testutil.Base.Add(a), To: testutil.Base.Add(b)}
}

func TestIngestDedupesRetries(t *testing.T) {
	st, _, events := homeStore(t)
	ctx := context.Background()
	before, _ := st.Flows(ctx, win(0, time.Hour))
	res, err := st.Ingest(ctx, "router", "boot1", events[:50])
	if err != nil {
		t.Fatal(err)
	}
	if res.Accepted != 0 || res.Duplicates != 50 {
		t.Fatalf("retry: %+v", res)
	}
	after, _ := st.Flows(ctx, win(0, time.Hour))
	if len(before) != len(after) {
		t.Fatalf("flows %d -> %d after a retried batch", len(before), len(after))
	}
}

func TestDevices(t *testing.T) {
	st, _, _ := homeStore(t)
	devs, err := st.Devices(context.Background(), win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	byMAC := map[string]model.Device{}
	for _, d := range devs {
		byMAC[d.MAC] = d
	}
	phone := byMAC[testutil.Phone.MAC.String()]
	if phone.Label != "alice-iphone" || phone.Vendor != "Apple, Inc." || !slices.Contains(phone.IPs, "192.168.1.23") || phone.DNSQueries != 4 || phone.Flows < 3 {
		t.Errorf("phone = %+v", phone)
	}
	if !slices.ContainsFunc(phone.Fingerprints, func(s string) bool { return strings.HasPrefix(s, "dhcp:1,3,6,15,119,252|apple-ios") }) ||
		!slices.ContainsFunc(phone.Fingerprints, func(s string) bool { return strings.HasPrefix(s, "ja4:t13d") }) {
		t.Errorf("phone fingerprints = %v", phone.Fingerprints)
	}
	if p := byMAC[testutil.Printer.MAC.String()]; p.Label != "BRN001BA9" || !slices.Contains(p.Services, "Office Printer") || p.Vendor != "Brother industries, LTD." {
		t.Errorf("printer = %+v", p)
	}
	if tv := byMAC[testutil.TV.MAC.String()]; tv.Label != "Google aa:bb:cc" || !slices.Contains(tv.IPs, "fd00::50") || !slices.Contains(tv.UserAgents, "CrKey/1.56") {
		t.Errorf("tv = %+v", tv)
	}
	if d := byMAC[testutil.Desktop.MAC.String()]; d.Label != "desktop-1" {
		t.Errorf("desktop = %+v", d)
	}
	if sw := byMAC[testutil.Switch.MAC.String()]; sw.Label != "core-switch" || sw.Role != "switch" {
		t.Errorf("switch = %+v", sw)
	}
}

func TestFlowCorrelation(t *testing.T) {
	st, _, _ := homeStore(t)
	flows, err := st.Flows(context.Background(), win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]model.Flow{}
	for _, f := range flows {
		by[f.RemoteIP] = f
	}
	tls := by[testutil.ExampleIP.String()]
	if tls.Name != "www.example.com" || tls.QName != "www.example.com" || tls.SNI != "www.example.com" || tls.DeviceName != "alice-iphone" || tls.Direction != "out" || !tls.Closed || tls.EndReason != "fin" {
		t.Errorf("tls = %+v", tls)
	}
	if q := by[testutil.QUICIP.String()]; q.QName != "quic.example.org" || q.App != "quic" || q.SNI != "quic.example.org" {
		t.Errorf("quic = %+v", q)
	}
	if h := by[testutil.PlainIP.String()]; h.QName != "plain.example.net" || h.HTTPHost != "plain.example.net" || h.DeviceName != "Google aa:bb:cc" {
		t.Errorf("http = %+v", h)
	}
	for _, f := range flows {
		if f.RemoteIP == "224.0.0.251" || f.RemoteIP == "255.255.255.255" {
			t.Errorf("multicast flow without Multicast: %+v", f)
		}
	}
}

// The heart of netgraph: a window sees connections that were already open
// when it started, with only the bytes that moved inside it.
func TestWindowSemantics(t *testing.T) {
	st, capt, _ := homeStore(t)
	ctx := context.Background()
	tlsFlow := func(f model.Filter) model.Flow {
		t.Helper()
		f.IP = testutil.ExampleIP.String()
		fl, err := st.Flows(ctx, f)
		if err != nil || len(fl) != 1 {
			t.Fatalf("flows(%v): %v %+v", f, err, fl)
		}
		return fl[0]
	}

	open := tlsFlow(win(0, 10*time.Second))
	if open.State != model.StateOpened || open.Closed {
		t.Errorf("first window: %+v", open)
	}
	mid := tlsFlow(win(60*time.Second, 90*time.Second))
	if mid.State != model.StateCarried || mid.Closed {
		t.Errorf("middle window: %+v", mid)
	}
	// Server segments at 7s + 3s*i: those at 61..88s fall inside.
	want := 0.0
	for i := range 40 {
		if at := 7 + 3*i; at >= 60 && at < 90 {
			want += 1400
		}
	}
	if got := float64(mid.BytesIn); math.Abs(got-want)/want > 0.12 {
		t.Errorf("middle window bytes in = %v, want ≈%v", got, want)
	}
	end := tlsFlow(win(120*time.Second, 130*time.Second))
	if end.State != model.StateCarried || !end.Closed {
		t.Errorf("last window: %+v", end)
	}
	if fl, _ := st.Flows(ctx, model.Filter{From: testutil.Base.Add(200 * time.Second), To: testutil.Base.Add(300 * time.Second), IP: testutil.ExampleIP.String()}); len(fl) != 0 {
		t.Errorf("after close: %+v", fl)
	}
	// The whole window counts every byte exactly.
	all := tlsFlow(win(0, time.Hour))
	bo, bi := capt.FlowBytes(netip.AddrPortFrom(testutil.Phone.IP, 50000), netip.AddrPortFrom(testutil.ExampleIP, 443))
	if all.BytesOut != bo || all.BytesIn != bi {
		t.Errorf("whole window bytes %d/%d, want %d/%d", all.BytesOut, all.BytesIn, bo, bi)
	}
	// Splitting the hour into slices loses nothing.
	var sumIn uint64
	for a := time.Duration(0); a < 3*time.Minute; a += 7 * time.Second {
		f := win(a, a+7*time.Second)
		f.IP = testutil.ExampleIP.String()
		fl, _ := st.Flows(ctx, f)
		for _, x := range fl {
			sumIn += x.BytesIn
		}
	}
	if d := int64(sumIn) - int64(bi); d < -40 || d > 40 {
		t.Errorf("slices sum to %d bytes in, whole is %d", sumIn, bi)
	}
}

func TestDNSAndFacts(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	qs, err := st.DNS(ctx, model.Filter{From: testutil.Base, To: testutil.Base.Add(time.Hour), Domain: "www.example.com"})
	if err != nil || len(qs) != 1 {
		t.Fatalf("dns: %v %+v", err, qs)
	}
	q := qs[0]
	if q.DeviceName != "alice-iphone" || q.LatencyMS != 12 || len(q.Answers) != 2 || q.Answers[1].Expires != q.TS+300_000 {
		t.Errorf("query = %+v", q)
	}
	facts, err := st.Facts(ctx, model.Filter{From: testutil.Base, To: testutil.Base.Add(time.Hour), Domain: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	var resolves, cname, serves bool
	for _, f := range facts {
		switch {
		case f.Rel == model.RelResolvesTo && f.Dst == "ip:93.184.216.34" && f.Attrs["ttl"] == "300" && f.Attrs["via"] == "edge.example.net":
			resolves = f.LastSeen-f.FirstSeen == 300_000
		case f.Rel == model.RelCNAME && f.Dst == "domain:edge.example.net":
			cname = true
		case f.Rel == model.RelServes && f.Src == "ip:93.184.216.34":
			serves = true
		}
	}
	if !resolves || !cname || !serves {
		t.Errorf("resolves=%v cname=%v serves=%v in %+v", resolves, cname, serves, facts)
	}
	// An answer's validity is its TTL: a window after it expired does not
	// see the mapping.
	late, _ := st.Facts(ctx, model.Filter{From: testutil.Base.Add(6 * time.Minute), To: testutil.Base.Add(7 * time.Minute), Domain: "www.example.com"})
	for _, f := range late {
		if f.Rel == model.RelResolvesTo {
			t.Errorf("expired answer still valid: %+v", f)
		}
	}
}

func TestGraph(t *testing.T) {
	st, _, _ := homeStore(t)
	g, err := st.Graph(context.Background(), win(0, 15*time.Second), model.DefaultGraphOptions)
	if err != nil {
		t.Fatal(err)
	}
	nodes := map[string]model.Node{}
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}
	phone := "device:" + testutil.Phone.MAC.String()
	if nodes[phone].Label != "alice-iphone" {
		t.Fatalf("no phone node in %+v", g.Nodes)
	}
	// Sites (the default) draws example.com once, with the names under it.
	site := nodes["site:example.com"]
	if site.Attrs["addresses"] != "93.184.216.34" || site.Attrs["names"] != "www.example.com" {
		t.Errorf("site = %+v", site)
	}
	// One edge per relationship: the lookup is counted on the connection.
	var connects, queried bool
	for _, e := range g.Edges {
		if e.From == phone && e.To == "site:example.com" {
			switch e.Rel {
			case model.RelConnects:
				connects = e.Opened == 1 && e.Peak == 1 && slices.Equal(e.Ports, []string{"443/tcp"}) && e.Attrs["lookups"] == "1"
			case model.RelQueried:
				queried = true
			}
		}
	}
	if !connects || queried {
		t.Errorf("connects=%v queried=%v edges=%+v", connects, queried, g.Edges)
	}
	if n, ok := nodes["site:example.org"]; !ok || n.Attrs["names"] != "quic.example.org" {
		t.Errorf("quic site missing: %+v", n)
	}

	// Without Sites, names are their own nodes.
	o := model.DefaultGraphOptions
	o.Sites = false
	g1, err := st.Graph(context.Background(), win(0, 15*time.Second), o)
	if err != nil {
		t.Fatal(err)
	}
	var www bool
	for _, n := range g1.Nodes {
		www = www || (n.ID == "domain:www.example.com" && n.Attrs["addresses"] == "93.184.216.34")
	}
	if !www {
		t.Errorf("no www.example.com node: %+v", g1.Nodes)
	}

	// Identity and uncollapsed.
	g2, err := st.Graph(context.Background(), win(0, time.Hour), model.GraphOptions{Identity: true, DNS: true, TopN: -1})
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, n := range g2.Nodes {
		kinds[n.Kind] = true
	}
	for _, k := range []string{model.KindDevice, model.KindIP, model.KindDomain, model.KindService} {
		if !kinds[k] {
			t.Errorf("identity graph lacks %s nodes", k)
		}
	}
	// Each device's own hostname, fingerprint and vendor are on its node;
	// none is shared here, so none is drawn.
	for _, k := range []string{model.KindHostname, model.KindFingerprint, model.KindVendor} {
		if kinds[k] {
			t.Errorf("identity graph draws unshared %s nodes", k)
		}
	}
}

func TestSiteEntity(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	d, err := st.Entity(ctx, "site:example.com", win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if d.Label != "example.com" || d.Attrs["names"] != "lost.example.com,www.example.com" || len(d.Flows) != 1 || len(d.DNS) != 2 || len(d.Timeline) == 0 {
		t.Fatalf("site = %+v", d)
	}
	for _, fl := range d.Flows {
		if fl.Name != "www.example.com" {
			t.Errorf("flow of another site: %+v", fl)
		}
	}
	if _, err := st.Entity(ctx, "site:nothing.example", win(0, time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown site: %v", err)
	}
}

func TestEntityAndTimeseries(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	d, err := st.Entity(ctx, "device:"+testutil.Phone.MAC.String(), win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if d.Device == nil || d.Label != "alice-iphone" || len(d.Flows) == 0 || len(d.DNS) != 4 || len(d.Timeline) == 0 || d.Attrs["vendor"] != "Apple, Inc." {
		t.Fatalf("entity = %+v", d)
	}
	var types []string
	for _, ev := range d.Timeline {
		types = append(types, ev.Type)
	}
	for _, want := range []string{"dhcp", "binding", "dns", "flow-open", "flow-close"} {
		if !slices.Contains(types, want) {
			t.Errorf("timeline lacks %s: %v", want, types)
		}
	}
	if _, err := st.Entity(ctx, "device:00:00:00:00:00:99", win(0, time.Hour)); err != ErrNotFound {
		t.Errorf("missing entity: %v", err)
	}
	ts, err := st.Timeseries(ctx, win(0, 3*time.Minute), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var in uint64
	var dns, flows int
	for _, b := range ts.Buckets {
		in += b.BytesIn
		dns += b.DNSQueries
		flows += b.FlowsNew
	}
	all, _ := st.Flows(ctx, win(0, 3*time.Minute))
	var want uint64
	for _, f := range all {
		want += f.BytesIn
	}
	if len(ts.Buckets) != 3 || dns != 5 || flows != len(all) || absDiff(in, want) > 10 {
		t.Errorf("timeseries: %d buckets, dns=%d flows=%d/%d bytes=%d/%d", len(ts.Buckets), dns, flows, len(all), in, want)
	}
}

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// Past raw retention, the same questions are answered from hourly rollups.
func TestRetentionAndRollups(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	exact, _ := st.Devices(ctx, win(0, time.Hour))
	st.cfg.Now = func() time.Time { return testutil.Base.Add(30 * 24 * time.Hour) }
	r, err := st.Retain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.Flows == 0 || r.DNS == 0 || r.Facts != 0 {
		t.Fatalf("retention = %+v", r)
	}
	sum, err := st.Summary(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Precision != model.PrecisionHour || sum.DNSQueries != 5 || sum.Devices == 0 {
		t.Errorf("summary = %+v", sum)
	}
	hourly, _ := st.Devices(ctx, win(0, time.Hour))
	for _, d := range exact {
		if d.Label != "alice-iphone" {
			continue
		}
		for _, h := range hourly {
			if h.MAC == d.MAC && (h.BytesIn != d.BytesIn || h.BytesOut != d.BytesOut) {
				t.Errorf("rollup bytes %d/%d, raw %d/%d", h.BytesOut, h.BytesIn, d.BytesOut, d.BytesIn)
			}
		}
	}
	g, err := st.Graph(ctx, win(0, time.Hour), model.DefaultGraphOptions)
	if err != nil || g.Precision != model.PrecisionHour || len(g.Nodes) == 0 {
		t.Errorf("hourly graph: %v %+v", err, g)
	}
}

// TestInListUnbounded: inList binds one parameter however many values it
// holds; one placeholder each fails past SQLite's 32766 variables.
func TestInListUnbounded(t *testing.T) {
	st, _, _ := homeStore(t)
	keys := []string{"192.168.1.23", "www.example.com"}
	for i := range 40000 {
		keys = append(keys, fmt.Sprintf("absent-%d", i))
	}
	cond, arg := inList("key", keys)
	var n int
	if err := st.r.QueryRow(`SELECT count(*) FROM entities WHERE `+cond, arg).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("matched %d entities, want 2", n)
	}
	cond, arg = inList("key", nil)
	if err := st.r.QueryRow(`SELECT count(*) FROM entities WHERE `+cond, arg).Scan(&n); err != nil || n != 0 {
		t.Errorf("empty list: %d, %v", n, err)
	}
}

// TestSummaryFilter: the summary's counts follow the filter, as the tables
// they head do, at both precisions.
func TestSummaryFilter(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	check := func(precision string) {
		t.Helper()
		all, err := st.Summary(ctx, win(0, time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		narrowed := false
		for _, f := range []model.Filter{
			{Device: "alice-iphone"},
			{Device: "Google*"},
			{Domain: "www.example.com"},
		} {
			f.From, f.To = testutil.Base, testutil.Base.Add(time.Hour)
			sum, err := st.Summary(ctx, f)
			if err != nil {
				t.Fatal(err)
			}
			// The DNS table reads raw lookups only; past raw retention
			// the rollup is what is left of them.
			dns, err := st.DNS(ctx, f)
			if precision == model.PrecisionHour {
				dns, err = st.dnsHourly(ctx, f, ms(f.From), ms(f.To))
			}
			if err != nil {
				t.Fatal(err)
			}
			if sum.Precision != precision || sum.DNSQueries != len(dns) {
				t.Errorf("%s %+v: summary says %d lookups (%s), DNS lists %d", precision, f, sum.DNSQueries, sum.Precision, len(dns))
			}
			if precision == model.PrecisionExact {
				flows, err := st.Flows(ctx, f)
				if err != nil {
					t.Fatal(err)
				}
				if sum.Flows != len(flows) {
					t.Errorf("%+v: summary says %d connections, Flows lists %d", f, sum.Flows, len(flows))
				}
			}
			if sum.DNSQueries < all.DNSQueries || sum.Flows < all.Flows {
				narrowed = true
			}
		}
		if !narrowed {
			t.Errorf("%s: no filter narrowed the summary (%+v)", precision, all)
		}
	}
	check(model.PrecisionExact)
	st.cfg.Now = func() time.Time { return testutil.Base.Add(30 * 24 * time.Hour) }
	if _, err := st.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	check(model.PrecisionHour)
}

func TestReadOnly(t *testing.T) {
	st, _, _ := homeStore(t)
	ro, err := OpenReadOnly(st.Path(), Config{Now: st.cfg.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	devs, err := ro.Devices(context.Background(), win(0, time.Hour))
	if err != nil || len(devs) < 5 {
		t.Fatalf("read-only devices: %v %d", err, len(devs))
	}
	if _, err := ro.Ingest(context.Background(), "x", "y", nil); err == nil {
		t.Fatal("read-only store accepted ingest")
	}
}

// An mDNS reflector (here: the router) re-announces the printer's records.
// They belong to the printer, found by address, not to the reflector.
func TestMDNSReflectorAttribution(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	at := testutil.Base.Add(5 * time.Minute)
	ev := wire.Event{Seq: 1, Type: wire.TypeMDNS, TS: at, MDNS: &wire.MDNS{
		MAC: testutil.Router.MAC.String(), IP: testutil.Router.IP, Response: true,
		Hosts:    []wire.MDNSHost{{Name: "Office-Printer.local", Addrs: []netip.Addr{testutil.Printer.IP}}},
		Services: []wire.Service{{Instance: "Reflected._ipp._tcp.local", Type: "_ipp._tcp", Target: "Office-Printer.local", Port: 631}},
	}}
	if _, err := st.Ingest(ctx, "router", "reflector", []wire.Event{ev}); err != nil {
		t.Fatal(err)
	}
	devs, err := st.Devices(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devs {
		switch d.MAC {
		case testutil.Printer.MAC.String():
			if !slices.Contains(d.Hostnames, "Office-Printer.local") || !slices.Contains(d.Services, "Reflected") {
				t.Errorf("printer did not get its reflected records: %+v", d)
			}
		case testutil.Router.MAC.String():
			if len(d.Hostnames) > 0 || len(d.Services) > 0 {
				t.Errorf("reflector was credited: %+v", d)
			}
		}
	}
}

// Two names on one address, looked up back to back: each connection gets
// the name its own SNI asks for, not merely the newest lookup.
func TestCorrelationPrefersSNI(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return testutil.Base.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	client := netip.MustParseAddr("192.168.1.9")
	cdn := netip.MustParseAddr("198.18.0.30")
	at := testutil.Base
	ans := func(seq uint64, d time.Duration, name string) wire.Event {
		return wire.Event{Seq: seq, Type: wire.TypeDNS, TS: at.Add(d), DNS: &wire.DNS{Client: client, Server: netip.MustParseAddr("192.168.1.1"), QName: name, QType: "A", RCode: "NOERROR",
			Answers: []wire.Answer{{Name: name, Type: "A", TTL: 300, Data: cdn.String()}}}}
	}
	flow := func(seq, id uint64, d time.Duration, sni string) wire.Event {
		return wire.Event{Seq: seq, Type: wire.TypeFlow, TS: at.Add(d + time.Second), Flow: &wire.Flow{ID: id, Proto: 6, Src: client, SrcPort: uint16(40000 + id), Dst: cdn, DstPort: 443,
			FirstSeen: at.Add(d), Start: at.Add(d), End: at.Add(d + time.Second), BytesOut: 100, SNI: sni, App: "tls", Final: true}}
	}
	evs := []wire.Event{ans(1, 0, "www.lab.test"), ans(2, 10*time.Millisecond, "hold.lab.test"),
		flow(3, 1, 20*time.Millisecond, "www.lab.test"), flow(4, 2, 30*time.Millisecond, "hold.lab.test"), flow(5, 3, 40*time.Millisecond, "")}
	if _, err := st.Ingest(context.Background(), "s", "b", evs); err != nil {
		t.Fatal(err)
	}
	fl, _ := st.Flows(context.Background(), model.Filter{From: at.Add(-time.Minute), To: at.Add(time.Minute)})
	got := map[int]string{}
	for _, f := range fl {
		got[f.ClientPort-40000] = f.QName
	}
	if got[1] != "www.lab.test" || got[2] != "hold.lab.test" || got[3] != "hold.lab.test" {
		t.Fatalf("qnames by flow: %v", got)
	}
}

// An LLDP neighbour renamed after its first advertisement takes the new name.
func TestLLDPRename(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	mac := testutil.Switch.MAC.String()
	evs := []wire.Event{
		{Seq: 1, Type: wire.TypeLLDP, TS: testutil.Base.Add(80 * time.Second), LLDP: &wire.LLDP{MAC: mac, ChassisID: "00:1b:21:aa:00:01", PortID: "port-7", SystemName: "renamed-switch"}},
	}
	if _, err := st.Ingest(ctx, "router", "rename", evs); err != nil {
		t.Fatal(err)
	}
	facts, _ := st.Facts(ctx, model.Filter{From: testutil.Base, To: testutil.Base.Add(time.Hour), Device: mac})
	var found bool
	for _, f := range facts {
		if f.Rel == model.RelNeighbor {
			found = f.DstLabel == "renamed-switch port-7"
		}
	}
	devs, _ := st.Devices(ctx, model.Filter{From: testutil.Base, To: testutil.Base.Add(time.Hour), Device: mac})
	if !found || len(devs) != 1 || devs[0].Label != "renamed-switch" {
		t.Fatalf("neighbor renamed=%v devices=%+v", found, devs)
	}
}

// TestRetentionLetsIngestIn: a large retention pass gives ingest the lock
// between its chunks instead of holding it to the end.
func TestRetentionLetsIngestIn(t *testing.T) {
	st, _, events := homeStore(t)
	ctx := context.Background()
	// A backlog well past raw retention: many chunks of flows and
	// connections.
	const backlog = 12000
	old := testutil.Base.Add(-60 * 24 * time.Hour).UnixMilli()
	for _, q := range []string{
		`INSERT INTO flows (sensor_id, flow_key, proto, src_ip, src_port, dst_ip, dst_port, first_seen, t_start, t_end,
			bytes_out, bytes_in, pkts_out, pkts_in, client_ip, client_port, remote_ip, remote_port, direction)
		WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?)
		SELECT 1, 'old:' || i, 6, '192.168.1.9', i, '93.184.216.34', 443, ?, ?, ?, 1, 1, 1, 1, '192.168.1.9', i, '93.184.216.34', 443, 'out' FROM n`,
		`INSERT INTO connections (flow_key, sensor_id, proto, client_ip, client_port, remote_ip, remote_port, direction, first_seen, last_seen)
		WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?)
		SELECT 'old:' || i, 1, 6, '192.168.1.9', i, '93.184.216.34', 443, 'out', ?, ? FROM n`,
	} {
		args := []any{backlog, old, old, old}
		if strings.Contains(q, "connections") {
			args = args[:3]
		}
		if _, err := st.w.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	before, err := st.Flows(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan RetentionResult)
	start := time.Now()
	go func() {
		r, err := st.Retain(ctx)
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	// Re-sending ingested events is cheap (they are duplicates) but still
	// takes the ingest lock. Holding it for the whole pass would make one
	// of them wait for nearly all of it.
	var longest time.Duration
	var r RetentionResult
loop:
	for {
		select {
		case r = <-done:
			break loop
		default:
		}
		t0 := time.Now()
		if _, err := st.Ingest(ctx, "router", "boot1", events[:1]); err != nil {
			t.Fatal(err)
		}
		longest = max(longest, time.Since(t0))
	}
	pass := time.Since(start)
	if r.Flows < 2*backlog {
		t.Fatalf("retention deleted %d flow rows, want %d", r.Flows, 2*backlog)
	}
	if longest > pass/2 {
		t.Errorf("an ingest waited %s of a %s retention pass: it held the ingest lock", longest, pass)
	}
	after, err := st.Flows(ctx, win(0, time.Hour))
	if err != nil || len(after) != len(before) {
		t.Errorf("recent flows %d -> %d (%v)", len(before), len(after), err)
	}
}

func TestSearch(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	ids := func(q string) []string {
		t.Helper()
		rs, err := st.Search(ctx, q, 0)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rs {
			out = append(out, r.ID)
		}
		return out
	}
	iphone := "device:3c:22:fb:01:02:03"
	for _, c := range []struct {
		q     string
		first string // the best match
	}{
		{"alice", iphone},                   // a hostname
		{"ALICE-iPhone", iphone},            // in any case
		{"3c:22:fb", iphone},                // a MAC prefix
		{"192.168.1.23", "ip:192.168.1.23"}, // an address: exact first
		{"www.example.com", "domain:www.example.com"},
		{"device:3c:22", iphone}, // one kind
	} {
		got := ids(c.q)
		if len(got) == 0 || got[0] != c.first {
			t.Errorf("Search(%q) = %v, want %s first", c.q, got, c.first)
		}
	}
	for _, q := range []string{"", "a", "%", "_x", "no-such-thing"} {
		if got := ids(q); len(got) != 0 {
			t.Errorf("Search(%q) = %v, want nothing", q, got)
		}
	}
	if got := ids("ip:alice"); len(got) != 0 {
		t.Errorf("a kind's search found other kinds: %v", got)
	}
	// A device found by its own name is labelled with it.
	if err := st.SetDeviceLabel(ctx, "3c:22:fb:01:02:03", "Living room"); err != nil {
		t.Fatal(err)
	}
	rs, err := st.Search(ctx, "living", 5)
	if err != nil || len(rs) != 1 || rs[0].Label != "Living room" || rs[0].Kind != model.KindDevice {
		t.Errorf("by label: %+v %v", rs, err)
	}
	if got := ids("alice"); len(got) == 0 || got[0] != iphone {
		t.Errorf("by automatic name after a label: %v", got)
	}
}
