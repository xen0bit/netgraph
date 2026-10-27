package graph

import (
	"fmt"
	"slices"
	"testing"

	"github.com/xen0bit/netgraph/internal/model"
)

func TestSite(t *testing.T) {
	for name, want := range map[string]string{
		"auth.time.com":                 "time.com",
		"www.bbc.co.uk":                 "bbc.co.uk",
		"time.com":                      "time.com",
		"WWW.Example.COM.":              "example.com",
		"d3ff2o2v4hyh3b.cloudfront.net": "cloudfront.net", // private suffix: grouped under the CDN
		"tls13.taboola.map.fastly.net":  "fastly.net",
		"s3.us-east-1.amazonaws.com":    "amazonaws.com",
		"printer.local":                 "printer.local", // no ICANN suffix: its own site
		"localhost":                     "localhost",
	} {
		if got := Site(name); got != want {
			t.Errorf("Site(%q) = %q, want %q", name, got, want)
		}
	}
}

const laptop = "device:aa:bb:cc:00:00:01"

func flow(dev, name, ip string, bytes uint64) model.Flow {
	return model.Flow{Device: dev, Name: name, RemoteIP: ip, RemotePort: 443, Proto: "tcp", Direction: "out", BytesIn: bytes, FirstSeen: 1000, LastSeen: 2000}
}

func edgesOf(g *model.Graph, from, to string) map[string]model.Edge {
	out := map[string]model.Edge{}
	for _, e := range g.Edges {
		if e.From == from && e.To == to {
			out[e.Rel] = e
		}
	}
	return out
}

func nodeOf(g *model.Graph, id string) (model.Node, bool) {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return model.Node{}, false
}

func TestBuildFoldsLookupsIntoConnections(t *testing.T) {
	in := Input{
		Devices: []model.Device{{ID: laptop, MAC: "aa:bb:cc:00:00:01", Label: "laptop"}},
		Flows:   []model.Flow{flow(laptop, "www.example.com", "93.184.216.34", 100)},
		DNS: []model.DNSQuery{
			{Device: laptop, QName: "www.example.com", RCode: "NOERROR", TS: 900},
			{Device: laptop, QName: "www.example.com", RCode: "NOERROR", TS: 950},
			{Device: laptop, QName: "nope.example.net", RCode: "NXDOMAIN", TS: 960},
		},
	}
	g := Build(in, model.GraphOptions{Collapse: true, DNS: true, TopN: -1})
	es := edgesOf(g, laptop, "domain:www.example.com")
	if _, ok := es[model.RelQueried]; ok || es[model.RelConnects].Attrs["lookups"] != "2" {
		t.Errorf("lookups not folded into the connection: %+v", es)
	}
	// A lookup that led to no connection keeps its own edge.
	if q, ok := edgesOf(g, laptop, "domain:nope.example.net")[model.RelQueried]; !ok || q.Attrs["rcode"] != "NXDOMAIN" {
		t.Errorf("failed lookup lost: %+v", g.Edges)
	}
}

func TestBuildSites(t *testing.T) {
	in := Input{
		Devices: []model.Device{{ID: laptop, MAC: "aa:bb:cc:00:00:01", Label: "laptop"}},
		Flows: []model.Flow{
			flow(laptop, "www.time.com", "151.101.1.1", 100),
			flow(laptop, "auth.time.com", "151.101.1.2", 50),
			flow(laptop, "www.bbc.co.uk", "151.101.2.1", 10),
		},
		DNS: []model.DNSQuery{{Device: laptop, QName: "auth.time.com", RCode: "NOERROR", TS: 900}},
		Facts: []model.Fact{
			{Rel: model.RelResolvesTo, Src: "domain:www.time.com", Dst: "ip:151.101.1.9", Count: 1},
			// Not a name the graph draws: its answer must not land on the site.
			{Rel: model.RelResolvesTo, Src: "domain:other.time.com", Dst: "ip:10.9.9.9", Count: 1},
		},
	}
	g := Build(in, model.GraphOptions{Collapse: true, DNS: true, Sites: true, TopN: -1})
	site, ok := nodeOf(g, "site:time.com")
	if !ok {
		t.Fatalf("no site node: %+v", g.Nodes)
	}
	if site.Kind != model.KindSite || site.Label != "time.com" || site.Sub != "2 names" || site.Attrs["names"] != "auth.time.com,www.time.com" {
		t.Errorf("site = %+v", site)
	}
	if site.Attrs["addresses"] != "151.101.1.1,151.101.1.2,151.101.1.9" || site.BytesIn != 150 {
		t.Errorf("site addresses/bytes = %+v", site)
	}
	if e := edgesOf(g, laptop, "site:time.com")[model.RelConnects]; e.Count != 2 || e.Attrs["lookups"] != "1" {
		t.Errorf("one edge per site: %+v", g.Edges)
	}
	// A site of one name reads as that name.
	if bbc, _ := nodeOf(g, "site:bbc.co.uk"); bbc.Label != "www.bbc.co.uk" || bbc.Sub != "" {
		t.Errorf("bbc = %+v", bbc)
	}
}

func TestBuildFoldsCNAMEs(t *testing.T) {
	in := Input{
		Devices: []model.Device{{ID: laptop, MAC: "aa:bb:cc:00:00:01", Label: "laptop"}},
		Flows: []model.Flow{
			flow(laptop, "www.example.com", "151.101.1.1", 100),
			flow(laptop, "cdn.example.org", "151.101.1.2", 100),
		},
		DNS: []model.DNSQuery{{Device: laptop, QName: "www.example.com", RCode: "NOERROR", TS: 900}},
		Facts: []model.Fact{
			{Rel: model.RelCNAME, Src: "domain:www.example.com", Dst: "domain:www.example.com.edge.net", Count: 1},
			{Rel: model.RelCNAME, Src: "domain:www.example.com.edge.net", Dst: "domain:x1.map.fastly.net", Count: 1},
			{Rel: model.RelCNAME, Src: "domain:cdn.example.org", Dst: "domain:www.example.com", Count: 1},
		},
	}
	g := Build(in, model.GraphOptions{Collapse: true, DNS: true, TopN: -1})
	www, _ := nodeOf(g, "domain:www.example.com")
	if www.Attrs["via"] != "edge.net,fastly.net" {
		t.Errorf("via = %+v", www)
	}
	for _, n := range g.Nodes {
		if n.Label == "www.example.com.edge.net" || n.Label == "x1.map.fastly.net" {
			t.Errorf("CNAME target drawn as a node: %+v", n)
		}
	}
	// A target the graph draws anyway keeps its edge.
	if _, ok := edgesOf(g, "domain:cdn.example.org", "domain:www.example.com")[model.RelCNAME]; !ok {
		t.Errorf("CNAME between drawn names lost: %+v", g.Edges)
	}
	// Uncollapsed, the chain is drawn as it is.
	g = Build(in, model.GraphOptions{DNS: true, TopN: -1})
	if _, ok := edgesOf(g, "domain:www.example.com", "domain:www.example.com.edge.net")[model.RelCNAME]; !ok {
		t.Errorf("uncollapsed graph lost the chain: %+v", g.Edges)
	}
}

func TestBuildSummarisesTheRest(t *testing.T) {
	in := Input{
		Devices: []model.Device{{ID: laptop, MAC: "aa:bb:cc:00:00:01", Label: "laptop"}},
		Flows: []model.Flow{
			flow(laptop, "big.example.com", "1.1.1.1", 1000),
			flow(laptop, "mid.example.net", "1.1.1.2", 100),
			flow(laptop, "small.example.org", "1.1.1.3", 10),
		},
		// What the store's own Top N already left out.
		Rest: map[string]Rest{laptop: {Destinations: 4, Connections: 6, BytesIn: 5}},
	}
	g := Build(in, model.GraphOptions{Collapse: true, TopN: 1})
	if !g.Truncated {
		t.Error("not marked truncated")
	}
	other, ok := nodeOf(g, "other:"+laptop)
	if !ok || other.Label != "6 more destinations" || other.BytesIn != 115 || other.Attrs["device"] != laptop {
		t.Fatalf("rest node = %+v (%v)", other, ok)
	}
	if e := edgesOf(g, laptop, other.ID)[model.RelConnects]; e.Count != 8 || e.BytesIn != 115 {
		t.Errorf("rest edge = %+v", e)
	}
	if _, ok := nodeOf(g, "domain:big.example.com"); !ok {
		t.Error("top destination missing")
	}
}

func TestBuildIdentityDrawsSharedLeaves(t *testing.T) {
	phone := "device:aa:bb:cc:00:00:02"
	in := Input{
		Devices: []model.Device{
			{ID: laptop, MAC: "aa:bb:cc:00:00:01", Label: "laptop", Vendor: "Dell"},
			{ID: phone, MAC: "aa:bb:cc:00:00:02", Label: "phone", Vendor: "Apple"},
		},
		Flows: []model.Flow{flow(laptop, "a.example.com", "1.1.1.1", 1), flow(phone, "a.example.com", "1.1.1.1", 1)},
		Facts: []model.Fact{
			{Rel: model.RelFingerprint, Src: laptop, Dst: "fingerprint:JA4 shared", DstLabel: "JA4 shared", Count: 1},
			{Rel: model.RelFingerprint, Src: phone, Dst: "fingerprint:JA4 shared", DstLabel: "JA4 shared", Count: 1},
			{Rel: model.RelFingerprint, Src: phone, Dst: "fingerprint:JA4 own", DstLabel: "JA4 own", Count: 1},
			{Rel: model.RelHostname, Src: phone, Dst: "hostname:phone", DstLabel: "phone", Count: 1},
			{Rel: model.RelAnnounces, Src: phone, Dst: "service:_airplay._tcp", DstLabel: "_airplay._tcp", Count: 1},
		},
	}
	g := Build(in, model.GraphOptions{Collapse: true, Identity: true, TopN: -1})
	for id, want := range map[string]bool{
		"fingerprint:JA4 shared": true,  // ties the two devices together
		"fingerprint:JA4 own":    false, // one device's: on its node already
		"hostname:phone":         false,
		"vendor:Apple":           false,
		"service:_airplay._tcp":  true, // says what the device is
	} {
		if _, ok := nodeOf(g, id); ok != want {
			t.Errorf("%s drawn = %v, want %v", id, ok, want)
		}
	}
}

// The layout places nodes in the order the graph lists them, so the same
// input must always give the same order (it once followed map iteration).
func TestBuildIsDeterministic(t *testing.T) {
	var in Input
	for i := range 8 {
		dev := fmt.Sprintf("device:aa:bb:cc:00:00:%02d", i)
		in.Devices = append(in.Devices, model.Device{ID: dev, Label: dev})
		in.Flows = append(in.Flows, flow(dev, fmt.Sprintf("host%d.example.com", i), fmt.Sprintf("1.1.1.%d", i), 100))
	}
	order := func() []string {
		var ids []string
		for _, n := range Build(in, model.DefaultGraphOptions).Nodes {
			ids = append(ids, n.ID)
		}
		return ids
	}
	first := order()
	for range 20 {
		if got := order(); !slices.Equal(got, first) {
			t.Fatalf("node order changed:\n%v\n%v", first, got)
		}
	}
}
