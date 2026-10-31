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

// Separate periods for the same address are not an overlap. A min/max across
// all periods used to report this as a conflict.
func TestARPConflictSeparatePeriods(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.168.1.98")
	var evs []wire.Event
	seq := uint64(910000)
	for _, mac := range []string{"02:00:00:00:00:44", "02:00:00:00:00:55"} {
		start := time.Minute
		if mac[len(mac)-1] == '5' {
			start = 10 * time.Minute
		}
		for _, d := range []time.Duration{start, start + time.Minute} {
			seq++
			evs = append(evs, wire.Event{Seq: seq, Type: wire.TypeBinding, TS: testutil.Base.Add(d),
				Binding: &wire.Binding{MAC: mac, IP: ip, Source: "arp"}})
		}
	}
	if _, err := st.Ingest(ctx, "router", "separate", evs); err != nil {
		t.Fatal(err)
	}
	rep, err := st.Anomalies(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range rep.Anomalies {
		if a.Kind == model.AnomalyARPConflict && a.Entity == model.EntityID(model.KindIP, ip.String()) {
			t.Fatalf("separate periods reported as a conflict: %+v", a)
		}
	}
}

func TestAnomalyCacheInvalidatedByLabel(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	if _, err := st.Anomalies(ctx, win(0, time.Hour)); err != nil {
		t.Fatal(err)
	}
	if st.anomRep == nil {
		t.Fatal("anomaly report was not cached")
	}
	if err := st.SetDeviceLabel(ctx, testutil.Phone.MAC.String(), "phone renamed"); err != nil {
		t.Fatal(err)
	}
	if st.anomRep != nil {
		t.Fatal("label change left the anomaly cache in place")
	}
}

func TestAnomalyMute(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("192.168.1.97")
	var evs []wire.Event
	seq := uint64(920000)
	for _, mac := range []string{"02:00:00:00:00:66", "02:00:00:00:00:77"} {
		for _, d := range []time.Duration{time.Minute, 7 * time.Minute} {
			seq++
			evs = append(evs, wire.Event{Seq: seq, Type: wire.TypeBinding, TS: testutil.Base.Add(d),
				Binding: &wire.Binding{MAC: mac, IP: ip, Source: "arp"}})
		}
	}
	if _, err := st.Ingest(ctx, "router", "mute", evs); err != nil {
		t.Fatal(err)
	}
	rep, err := st.Anomalies(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var found *model.Anomaly
	for i := range rep.Anomalies {
		if rep.Anomalies[i].Kind == model.AnomalyARPConflict && rep.Anomalies[i].Entity == model.EntityID(model.KindIP, ip.String()) {
			found = &rep.Anomalies[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no ARP conflict to mute")
	}
	m := model.AnomalyMute{Kind: found.Kind, Device: found.Device, Entity: found.Entity, Until: testutil.Base.Add(time.Hour).UnixMilli()}
	if err := st.SetAnomalyMute(ctx, m); err != nil {
		t.Fatal(err)
	}
	rep, err = st.Anomalies(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range rep.Anomalies {
		if a.Kind == found.Kind && a.Device == found.Device && a.Entity == found.Entity {
			t.Fatalf("muted finding returned: %+v", a)
		}
	}
	if err := st.DeleteAnomalyMute(ctx, m.Kind, m.Device, m.Entity); err != nil {
		t.Fatal(err)
	}
	rep, err = st.Anomalies(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	back := false
	for _, a := range rep.Anomalies {
		if a.Kind == found.Kind && a.Device == found.Device && a.Entity == found.Entity {
			back = true
		}
	}
	if !back {
		t.Fatal("finding did not return after unmute")
	}
}
