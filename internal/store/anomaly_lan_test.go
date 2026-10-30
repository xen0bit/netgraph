package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

func TestARPConflictAndRogueDHCP(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.168.1.99")
	one := "02:00:00:00:00:11"
	two := "02:00:00:00:00:22"
	var evs []wire.Event
	seq := uint64(900000)
	for _, mac := range []string{one, two} {
		for _, d := range []time.Duration{time.Minute, 7 * time.Minute} {
			seq++
			evs = append(evs, wire.Event{Seq: seq, Type: wire.TypeBinding, TS: testutil.Base.Add(d),
				Binding: &wire.Binding{MAC: mac, IP: ip, Source: "arp"}})
		}
	}
	// A second DHCP server, on an address no device here holds.
	seq++
	evs = append(evs, wire.Event{Seq: seq, Type: wire.TypeDHCP, TS: testutil.Base.Add(2 * time.Minute),
		DHCP: &wire.DHCP{Version: 4, MsgType: "OFFER", MAC: "02:00:00:00:00:33",
			ServerID: netip.MustParseAddr("192.168.1.222"), YourIP: ip}})
	if _, err := st.Ingest(ctx, "router", "extra", evs); err != nil {
		t.Fatal(err)
	}
	rep, err := st.Anomalies(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var arp, rogue bool
	for _, a := range rep.Anomalies {
		switch a.Kind {
		case model.AnomalyARPConflict:
			arp = true
			if a.Entity != model.EntityID(model.KindIP, ip.String()) {
				t.Errorf("arp conflict entity = %q", a.Entity)
			}
		case model.AnomalyRogueDHCP:
			if a.Entity == model.EntityID(model.KindIP, "192.168.1.222") {
				rogue = true
			}
		}
	}
	if !arp {
		t.Error("no ARP conflict")
	}
	if !rogue {
		t.Error("no rogue DHCP finding")
	}
}
