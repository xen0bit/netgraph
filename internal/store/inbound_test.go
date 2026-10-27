package store

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

// A web server here, as a sensor beside a reverse proxy sees it: clients
// from the internet connect in, and the server connects out on its own.
const (
	webMAC = "02:42:ac:12:00:03"
	gwMAC  = "02:42:ac:12:00:01" // the bridge: inbound packets arrive from it
)

var (
	webIP    = netip.MustParseAddr("172.18.0.3")
	visitor  = netip.MustParseAddr("198.51.100.7")
	scanner  = netip.MustParseAddr("203.0.113.9")
	upstream = netip.MustParseAddr("93.184.215.14")
)

func inboundEvents(at time.Time) []wire.Event {
	flow := func(id uint64, src netip.Addr, sport uint16, smac string, dst netip.Addr, dport uint16, dmac string, f wire.Flow) wire.Event {
		ts := at.Add(time.Duration(id) * time.Second)
		f.ID, f.Proto, f.Src, f.SrcPort, f.SrcMAC, f.Dst, f.DstPort, f.DstMAC = id, 6, src, sport, smac, dst, dport, dmac
		f.FirstSeen, f.Start, f.End, f.Final, f.EndReason = ts, ts, ts.Add(2*time.Second), true, "fin"
		return wire.Event{Seq: id + 10, Type: wire.TypeFlow, TS: f.End, Flow: &f}
	}
	return []wire.Event{
		{Seq: 1, Type: wire.TypeHello, TS: at, Hello: &wire.Hello{Name: "web", Version: "test",
			Interfaces: []wire.Interface{{Name: "eth0", MAC: webMAC, Prefixes: []netip.Prefix{netip.MustParsePrefix("172.18.0.3/16")}}}}},
		{Seq: 2, Type: wire.TypeBinding, TS: at, Binding: &wire.Binding{MAC: gwMAC, IP: netip.MustParseAddr("172.18.0.1"), Source: "arp"}},
		// A browser fetches a page: a small request, a large response.
		flow(1, visitor, 51234, gwMAC, webIP, 443, webMAC, wire.Flow{BytesOut: 1000, BytesIn: 50000, PktsOut: 10, PktsIn: 40,
			App: "tls", SNI: "Web.Example.com", JA4: "t13d_visitor", ALPN: "h2"}),
		// A scanner asks for the address itself.
		flow(2, scanner, 40000, gwMAC, webIP, 80, webMAC, wire.Flow{BytesOut: 200, BytesIn: 300, PktsOut: 2, PktsIn: 2,
			App: "http", HTTPHost: "172.18.0.3:80", UserAgent: "zgrab/0.x"}),
		// The server calls an API of its own.
		flow(3, webIP, 40001, webMAC, upstream, 443, gwMAC, wire.Flow{BytesOut: 300, BytesIn: 4000, PktsOut: 3, PktsIn: 5,
			App: "tls", SNI: "api.example.com", JA4: "t13d_server"}),
	}
}

func inboundStore(t *testing.T, cfg Config) (*Store, time.Time) {
	t.Helper()
	at := testutil.Base
	cfg.Now = func() time.Time { return at.Add(time.Hour) }
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.Ingest(context.Background(), "web", "boot", inboundEvents(at)); err != nil {
		t.Fatal(err)
	}
	return st, at
}

// A connection from outside belongs to the device that accepted it, counted
// from that device's side: its client is the remote end, its port is the
// device's own, and what the client revealed (fingerprint, user agent, the
// name it asked for) describes the client, not the device.
func TestInboundConnections(t *testing.T) {
	ctx := context.Background()
	st, at := inboundStore(t, Config{})
	win := model.Filter{From: at, To: at.Add(time.Hour)}

	flows, err := st.Flows(ctx, win)
	if err != nil {
		t.Fatal(err)
	}
	byClient := map[string]model.Flow{}
	for _, f := range flows {
		byClient[f.ClientIP] = f
	}
	in := byClient[visitor.String()]
	if in.Direction != model.DirIn || in.ClientPort != 51234 || in.ServerIP != webIP.String() || in.ServerPort != 443 ||
		in.RemoteIP != visitor.String() || in.Device != "device:"+webMAC {
		t.Errorf("inbound flow ends = %+v", in)
	}
	if in.BytesOut != 50000 || in.BytesIn != 1000 || in.PktsOut != 40 || in.PktsIn != 10 {
		t.Errorf("inbound flow counted from the client's side: out %d in %d", in.BytesOut, in.BytesIn)
	}
	if in.Name != "web.example.com" {
		t.Errorf("name = %q, want the SNI as the server matches it", in.Name)
	}
	if c, s := in.Ends(); c != "198.51.100.7:51234" || s != "web:443/tcp" {
		t.Errorf("Ends() = %q, %q", c, s)
	}
	if f := byClient[scanner.String()]; f.Name != "" || f.ServerPort != 80 {
		t.Errorf("a Host naming an address is no name: %+v", f)
	}
	out := byClient[webIP.String()]
	if out.Direction != model.DirOut || out.ServerIP != upstream.String() || out.ServerPort != 443 || out.BytesOut != 300 {
		t.Errorf("outbound flow = %+v", out)
	}

	devs, err := st.Devices(ctx, win)
	if err != nil {
		t.Fatal(err)
	}
	var web model.Device
	for _, d := range devs {
		if d.MAC == webMAC {
			web = d
		}
	}
	if web.Flows != 3 || web.Inbound != 2 || !slices.Equal(web.Serves, []string{"443/tcp", "80/tcp"}) {
		t.Errorf("device: %d flows, %d inbound, serves %v", web.Flows, web.Inbound, web.Serves)
	}
	if web.BytesOut != 50000+300+300 || web.BytesIn != 1000+200+4000 {
		t.Errorf("device sent %d, received %d", web.BytesOut, web.BytesIn)
	}
	if !slices.Equal(web.Fingerprints, []string{"ja4:t13d_server"}) || len(web.UserAgents) != 0 {
		t.Errorf("device took its clients' fingerprints: %v %v", web.Fingerprints, web.UserAgents)
	}

	sum, err := st.Summary(ctx, win)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Flows != 3 || sum.Inbound != 2 || sum.BytesOut != web.BytesOut {
		t.Errorf("summary = %+v", sum)
	}

	// port: is the service; dir: the side.
	for _, c := range []struct {
		f    model.Filter
		want int
	}{
		{model.Filter{Port: 443}, 2},
		{model.Filter{Port: 51234}, 0},
		{model.Filter{Dir: model.DirIn}, 2},
		{model.Filter{Dir: model.DirIn, Port: 80}, 1},
		{model.Filter{Dir: model.DirOut}, 1},
	} {
		c.f.From, c.f.To = win.From, win.To
		got, err := st.Flows(ctx, c.f)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != c.want {
			t.Errorf("Flows(port %d, dir %q) = %d, want %d", c.f.Port, c.f.Dir, len(got), c.want)
		}
	}

	// The visitor's fingerprint is the visitor's; it serves nothing.
	ent, err := st.Entity(ctx, "ip:"+visitor.String(), win)
	if err != nil {
		t.Fatal(err)
	}
	var rels []string
	for _, f := range ent.Facts {
		rels = append(rels, f.Rel+" "+f.Dst)
	}
	if !slices.Contains(rels, "fingerprint fingerprint:ja4:t13d_visitor") || slices.ContainsFunc(rels, func(r string) bool { return strings.HasPrefix(r, "serves") }) {
		t.Errorf("visitor's facts = %v", rels)
	}
	ent, err = st.Entity(ctx, "ip:"+webIP.String(), win)
	if err != nil {
		t.Fatal(err)
	}
	rels = rels[:0]
	for _, f := range ent.Facts {
		rels = append(rels, f.Rel+" "+f.Dst)
	}
	if !slices.Contains(rels, "serves domain:web.example.com") {
		t.Errorf("the server's own address does not serve its name: %v", rels)
	}
}

// The graph points every connection from client to server: clients from
// outside into the device, and the name they asked for stays on the edge
// rather than becoming a destination.
func TestInboundGraph(t *testing.T) {
	ctx := context.Background()
	st, at := inboundStore(t, Config{})
	g, err := st.Graph(ctx, model.Filter{From: at, To: at.Add(time.Hour)}, model.GraphOptions{Collapse: true, Sites: true, DNS: true, TopN: 15})
	if err != nil {
		t.Fatal(err)
	}
	dev := "device:" + webMAC
	var in, out *model.Edge
	for i, e := range g.Edges {
		switch {
		case e.From == "ip:"+visitor.String() && e.To == dev:
			in = &g.Edges[i]
		case e.From == dev && e.To == "site:example.com":
			out = &g.Edges[i]
		case e.From == dev && strings.HasPrefix(e.To, "ip:") && e.Rel == model.RelConnects:
			t.Errorf("device drawn connecting to its client: %+v", e)
		}
	}
	if in == nil || !slices.Equal(in.Ports, []string{"443/tcp"}) || in.BytesOut != 1000 || in.BytesIn != 50000 || in.Attrs["names"] != "web.example.com" {
		t.Fatalf("inbound edge = %+v", in)
	}
	if out == nil || out.BytesOut != 300 {
		t.Fatalf("outbound edge = %+v", out)
	}
	for _, n := range g.Nodes {
		switch n.ID {
		case "site:example.com":
			if n.Attrs["names"] != "api.example.com" {
				t.Errorf("site names = %q: an inbound connection's name is not a destination", n.Attrs["names"])
			}
		case dev:
			if n.Attrs["serves"] != "80/tcp,443/tcp" || n.Attrs["served_names"] != "web.example.com" {
				t.Errorf("device serves %q (%q)", n.Attrs["serves"], n.Attrs["served_names"])
			}
			if n.BytesOut != 50000+300+300 {
				t.Errorf("device node sent %d", n.BytesOut)
			}
		}
	}

	// Top N keeps clients and destinations apart.
	g, err = st.Graph(ctx, model.Filter{From: at, To: at.Add(time.Hour)}, model.GraphOptions{Collapse: true, Sites: true, TopN: 1})
	if err != nil {
		t.Fatal(err)
	}
	rest, ok := nodeByID(g, "other:clients:"+dev)
	if !ok || rest.Label != "1 more clients" {
		t.Fatalf("clients rest node = %+v (%v)", rest, ok)
	}
	if _, ok := nodeByID(g, "other:"+dev); ok {
		t.Error("the one destination was cut by the clients' Top N")
	}
	for _, e := range g.Edges {
		if e.From == rest.ID && (e.To != dev || e.BytesOut != 200) {
			t.Errorf("rest edge = %+v, want into the device with what the client sent", e)
		}
	}
}

// Hourly rollups key an inbound connection by the device's port and keep
// its direction.
func TestInboundRollups(t *testing.T) {
	ctx := context.Background()
	st, at := inboundStore(t, Config{ExactMax: time.Minute})
	f := model.Filter{From: at, To: at.Add(time.Hour)}
	flows, err := st.Flows(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	var in []model.Flow
	for _, fl := range flows {
		if fl.Direction == model.DirIn {
			in = append(in, fl)
		}
	}
	if len(in) != 2 || in[0].ClientIP != visitor.String() || in[0].ServerPort != 443 || in[0].ClientPort != 0 || in[0].BytesOut != 50000 {
		t.Fatalf("hourly inbound flows = %+v", in)
	}
	f.Port = 443
	if flows, err = st.Flows(ctx, f); err != nil || len(flows) != 2 {
		t.Errorf("hourly port filter = %d flows (%v), want 2", len(flows), err)
	}
}

func nodeByID(g *model.Graph, id string) (model.Node, bool) {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return model.Node{}, false
}

func TestHostName(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM":        "example.com",
		"example.com:8080":   "example.com",
		"example.com.":       "example.com",
		"203.0.113.9":        "",
		"203.0.113.9:80":     "",
		"[2001:db8::1]:443":  "",
		"2001:db8::1":        "",
		"":                   "",
		"host.lan":           "host.lan",
		"WWW.Example.com.:1": "www.example.com",
	} {
		if got := hostName(in); got != want {
			t.Errorf("hostName(%q) = %q, want %q", in, got, want)
		}
	}
}
