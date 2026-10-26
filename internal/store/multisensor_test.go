package store

import (
	"context"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

// Several sensors ship to one server. Their sequence numbers, boots and flow
// IDs are independent; the server attributes each record to the sensor that
// sent it, learns each sensor's local prefixes, and keeps both copies of a
// connection that both saw.
func TestMultipleSensors(t *testing.T) {
	ctx := context.Background()
	at := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return at.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	type sensor struct {
		name string
		mac  string
		ip   netip.Addr
		lan  netip.Prefix
	}
	sensors := []sensor{
		{name: "upstairs", mac: "02:00:5e:00:00:11", ip: netip.MustParseAddr("2001:db8:1::1"), lan: netip.MustParsePrefix("2001:db8:1::/64")},
		{name: "downstairs", mac: "02:00:5e:00:00:12", ip: netip.MustParseAddr("2001:db8:2::1"), lan: netip.MustParsePrefix("2001:db8:2::/64")},
	}
	clientMACs := []string{"3c:22:fb:01:02:11", "3c:22:fb:01:02:12"}
	remote := netip.MustParseAddr("93.184.216.34")

	for i, s := range sensors {
		// A host address inside the sensor's prefix, not the prefix
		// address itself.
		b := s.lan.Addr().As16()
		b[15] = byte(20 + i)
		client := netip.AddrFrom16(b)
		events := []wire.Event{
			{Seq: 1, Type: wire.TypeHello, TS: at, Hello: &wire.Hello{
				Name: s.name, Version: "test",
				Interfaces: []wire.Interface{{Name: "mon0", MAC: s.mac, Prefixes: []netip.Prefix{s.lan}}},
			}},
			{Seq: 2, Type: wire.TypeDHCP, TS: at.Add(time.Second), DHCP: &wire.DHCP{
				Version: 6, MsgType: "REPLY", MAC: clientMACs[i], Addresses: []netip.Addr{client}, Hostname: "host-" + s.name,
			}},
			{Seq: 3, Type: wire.TypeFlow, TS: at.Add(2 * time.Second), Flow: &wire.Flow{
				ID: 7, Proto: 6, Src: client, SrcPort: 40000, Dst: remote, DstPort: 443,
				SrcMAC: clientMACs[i], FirstSeen: at.Add(2 * time.Second), Start: at.Add(2 * time.Second),
				End: at.Add(32 * time.Second), BytesOut: 1000, BytesIn: 2000, PktsOut: 10, PktsIn: 20, Final: true,
			}},
		}
		res, err := st.Ingest(ctx, s.name, "boot-"+s.name, events)
		if err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if res.Accepted != 3 {
			t.Errorf("%s: accepted %+v", s.name, res)
		}
	}

	// A retry is deduplicated per sensor boot, not globally.
	if res, err := st.Ingest(ctx, "upstairs", "boot-upstairs", []wire.Event{{Seq: 1, Type: wire.TypeStats, TS: at}}); err != nil || res.Duplicates != 1 {
		t.Errorf("retry: %v %+v", err, res)
	}

	ss, err := st.Sensors(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ss) != 2 || ss[0].Name != "downstairs" || ss[1].Name != "upstairs" || ss[1].Version != "test" {
		t.Fatalf("sensors = %+v", ss)
	}
	if !slices.Contains(ss[1].Interfaces, "mon0") {
		t.Errorf("sensor interfaces = %v", ss[1].Interfaces)
	}

	flows, err := st.Flows(ctx, model.Filter{From: at, To: at.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 {
		t.Fatalf("flows = %+v", flows)
	}
	for i, fl := range flows {
		// Both sensors have a flow ID 7; the flow keys must not collide.
		if fl.Key == flows[1-i].Key {
			t.Errorf("flow keys collide: %+v", flows)
		}
		if fl.Direction != "out" || fl.RemoteIP != remote.String() || fl.BytesOut != 1000 || fl.BytesIn != 2000 {
			t.Errorf("flow %d = %+v", i, fl)
		}
	}

	// Each sensor's public IPv6 prefix defines its own LAN.
	devs, err := st.Devices(ctx, model.Filter{From: at, To: at.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{}
	for _, d := range devs {
		labels[d.MAC] = d.Label
	}
	if labels[clientMACs[0]] != "host-upstairs" || labels[clientMACs[1]] != "host-downstairs" {
		t.Errorf("device labels = %v", labels)
	}
}
