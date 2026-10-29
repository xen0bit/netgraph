package store

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/asn"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/wire"
)

// testASN covers the inbound scenario's remote ends.
func testASN(t *testing.T) *asn.DB {
	t.Helper()
	db, err := asn.Parse(strings.NewReader(
		"93.184.215.0\t93.184.215.255\t15133\tUS\tEDGECAST\n" +
			"198.51.100.0\t198.51.100.255\t64500\tDE\tVISITNET Example GmbH\n" +
			"203.0.113.0\t203.0.113.255\t64501\tNL\tSCANNET\n"))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// networks returns each table's remote_asn by remote address, "NULL" when
// it was not looked up.
func networks(t *testing.T, st *Store, table string) map[string]string {
	t.Helper()
	rows, err := st.r.Query(`SELECT DISTINCT remote_ip, coalesce(CAST(remote_asn AS TEXT), 'NULL') || ' ' || remote_cc FROM ` + table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var ip, v string
		if err := rows.Scan(&ip, &v); err != nil {
			t.Fatal(err)
		}
		out[ip] = strings.TrimSpace(v)
	}
	return out
}

var wantNetworks = map[string]string{
	visitor.String():  "64500 DE",
	scanner.String():  "64501 NL",
	upstream.String(): "15133 US",
}

func checkNetworks(t *testing.T, st *Store, win model.Filter) {
	t.Helper()
	for _, table := range []string{"connections", "traffic_hourly"} {
		got := networks(t, st, table)
		for ip, want := range wantNetworks {
			if got[ip] != want {
				t.Errorf("%s: %s has network %q, want %q", table, ip, got[ip], want)
			}
		}
	}
	ctx := context.Background()
	d, err := st.Entity(ctx, "asn:64500", win)
	if err != nil {
		t.Fatal(err)
	}
	if d.Label != "AS64500 VISITNET Example GmbH" || d.Attrs["country"] != "DE" {
		t.Errorf("asn entity: %q %v", d.Label, d.Attrs)
	}
}

// Ingest records the network of each remote end when a table is loaded.
func TestASNAtIngest(t *testing.T) {
	db := testASN(t)
	st, at := inboundStore(t, Config{ASN: func() *asn.DB { return db }})
	win := model.Filter{From: at, To: at.Add(time.Hour)}
	checkNetworks(t, st, win)
	if n, err := st.EnrichASN(context.Background()); err != nil || n != 0 {
		t.Errorf("EnrichASN after ingest with a table: %d, %v", n, err)
	}
}

// Without a table, remote ends wait (NULL) and EnrichASN fills them in once
// one is loaded; local ends are never looked up.
func TestEnrichASN(t *testing.T) {
	var db *asn.DB
	st, at := inboundStore(t, Config{ASN: func() *asn.DB { return db }})
	win := model.Filter{From: at, To: at.Add(time.Hour)}
	got := networks(t, st, "connections")
	for ip := range wantNetworks {
		if got[ip] != "NULL" {
			t.Errorf("without a table %s has network %q", ip, got[ip])
		}
	}
	ctx := context.Background()
	if n, err := st.EnrichASN(ctx); err != nil || n != 0 {
		t.Errorf("EnrichASN without a table: %d, %v", n, err)
	}
	db = testASN(t)
	n, err := st.EnrichASN(ctx)
	if err != nil || n == 0 {
		t.Fatalf("EnrichASN: %d, %v", n, err)
	}
	checkNetworks(t, st, win)
	if n, err := st.EnrichASN(ctx); err != nil || n != 0 {
		t.Errorf("second EnrichASN: %d, %v", n, err)
	}
	// Ingest after enrichment keeps the networks found.
	if _, err := st.Ingest(ctx, "web", "boot2", inboundEvents(at)); err != nil {
		t.Fatal(err)
	}
	checkNetworks(t, st, win)
}

// The asn and cc filters select connections by their remote end's network,
// in every query that takes a filter and at both precisions.
func TestASNFilter(t *testing.T) {
	db := testASN(t)
	st, at := inboundStore(t, Config{ASN: func() *asn.DB { return db }})
	ctx := context.Background()
	check := func(precision string) {
		t.Helper()
		for _, c := range []struct {
			f    model.Filter
			want string // the remote end of the one connection selected
		}{
			{model.Filter{ASN: 64500}, visitor.String()},
			{model.Filter{Country: "NL"}, scanner.String()},
			{model.Filter{ASN: 15133, Country: "US"}, upstream.String()},
			{model.Filter{ASN: 15133, Country: "DE"}, ""},
		} {
			f := c.f
			f.From, f.To = at, at.Add(time.Hour)
			flows, err := st.Flows(ctx, f)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, fl := range flows {
				got = append(got, fl.RemoteIP)
				if fl.ASN != f.ASN && f.ASN != 0 {
					t.Errorf("%s %+v: flow in AS%d", precision, c.f, fl.ASN)
				}
			}
			if want := []string{c.want}; c.want == "" && len(got) != 0 || c.want != "" && !slices.Equal(got, want) {
				t.Errorf("%s %+v: flows to %v, want %q", precision, c.f, got, c.want)
			}
			sum, err := st.Summary(ctx, f)
			if err != nil {
				t.Fatal(err)
			}
			ts, err := st.Timeseries(ctx, f, 5*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			var tsBytes uint64
			for _, b := range ts.Buckets {
				tsBytes += b.BytesOut + b.BytesIn
			}
			var flowBytes uint64
			for _, fl := range flows {
				flowBytes += fl.BytesOut + fl.BytesIn
			}
			if sum.Flows != len(flows) && precision == model.PrecisionExact || sum.BytesOut+sum.BytesIn != flowBytes || tsBytes != flowBytes {
				t.Errorf("%s %+v: summary %d conns %d bytes, timeseries %d bytes; flows %d, %d bytes",
					precision, c.f, sum.Flows, sum.BytesOut+sum.BytesIn, tsBytes, len(flows), flowBytes)
			}
		}
		flows, _ := st.Flows(ctx, model.Filter{From: at, To: at.Add(time.Hour), ASN: 64500})
		if len(flows) == 1 && (flows[0].ASOrg != "VISITNET Example GmbH" || flows[0].Country != "DE") {
			t.Errorf("%s: flow network %d %q %q", precision, flows[0].ASN, flows[0].ASOrg, flows[0].Country)
		}
	}
	check(model.PrecisionExact)
	st.cfg.Now = func() time.Time { return at.Add(30 * 24 * time.Hour) }
	if _, err := st.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	check(model.PrecisionHour)
}

// With Networks, Top N ranks a server's clients by network: five small
// visitors from one network outrank one larger visitor from another.
func TestGraphNetworksTopN(t *testing.T) {
	db := testASN(t)
	st, at := inboundStore(t, Config{ASN: func() *asn.DB { return db }})
	ctx := context.Background()
	var evs []wire.Event
	for i := range 6 {
		src, bytes := netip.AddrFrom4([4]byte{198, 51, 100, byte(10 + i)}), uint64(20000) // VISITNET
		if i == 5 {
			src, bytes = netip.MustParseAddr("203.0.113.50"), 90000 // SCANNET
		}
		ts := at.Add(time.Duration(10+i) * time.Second)
		evs = append(evs, wire.Event{Seq: uint64(100 + i), Type: wire.TypeFlow, TS: ts.Add(time.Second), Flow: &wire.Flow{
			ID: uint64(100 + i), Proto: 6, Src: src, SrcPort: 50000, SrcMAC: gwMAC, Dst: webIP, DstPort: 443, DstMAC: webMAC,
			FirstSeen: ts, Start: ts, End: ts.Add(time.Second), Final: true, EndReason: "fin", BytesOut: bytes, BytesIn: 100}})
	}
	if _, err := st.Ingest(ctx, "web", "boot", evs); err != nil {
		t.Fatal(err)
	}
	win := model.Filter{From: at, To: at.Add(time.Hour)}
	o := model.DefaultGraphOptions
	o.TopN = 1
	g, err := st.Graph(ctx, win, o)
	if err != nil {
		t.Fatal(err)
	}
	var clients []string
	for _, e := range g.Edges {
		if e.Rel == model.RelConnects && e.To == model.EntityID(model.KindDevice, webMAC) {
			clients = append(clients, e.From)
		}
	}
	if !slices.Contains(clients, "asn:64500") || slices.Contains(clients, "asn:64501") {
		t.Errorf("clients drawn = %v, want asn:64500 kept and asn:64501 in the rest", clients)
	}
	o.Networks = false
	if g, err = st.Graph(ctx, win, o); err != nil {
		t.Fatal(err)
	}
	for _, n := range g.Nodes {
		if n.Kind == model.KindASN {
			t.Errorf("network node %s without Networks", n.ID)
		}
	}
}
