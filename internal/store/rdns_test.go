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

// A reverse DNS name is recorded at the time the host was observed and labels
// a device that has no better identity, but never overrides DHCP or mDNS.
func TestReverseDNSName(t *testing.T) {
	ctx := context.Background()
	at := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return at.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	mac := testutil.Phone.MAC.String()
	observed := at.Add(5 * time.Second)
	events := []wire.Event{
		{Seq: 1, Type: wire.TypeBinding, TS: observed, Binding: &wire.Binding{MAC: mac, IP: testutil.Phone.IP, Source: "arp"}},
		{Seq: 2, Type: wire.TypeName, TS: observed, Name: &wire.Name{
			MAC: mac, IP: testutil.Phone.IP, Name: "alice-iphone.lan.", Proto: "rdns",
		}},
	}
	if _, err := st.Ingest(ctx, "router", "boot", events); err != nil {
		t.Fatal(err)
	}

	devs, err := st.Devices(ctx, model.Filter{From: at, To: at.Add(time.Hour), Device: mac})
	if err != nil || len(devs) != 1 {
		t.Fatalf("devices: %v %+v", err, devs)
	}
	if devs[0].Label != "alice-iphone.lan" || !slices.Contains(devs[0].Hostnames, "alice-iphone.lan") {
		t.Errorf("device = %+v", devs[0])
	}
	facts, _ := st.Facts(ctx, model.Filter{From: at, To: at.Add(time.Hour), Device: mac})
	var rdns *model.Fact
	for i := range facts {
		if facts[i].Rel == model.RelHostname && facts[i].Source == "rdns" {
			rdns = &facts[i]
		}
	}
	if rdns == nil || rdns.FirstSeen != observed.UnixMilli() || rdns.Dst != "hostname:alice-iphone.lan" {
		t.Errorf("rDNS fact = %+v (all %+v)", rdns, facts)
	}

	// A better source wins afterwards, and keeps winning.
	if _, err := st.Ingest(ctx, "router", "boot2", []wire.Event{
		{Seq: 1, Type: wire.TypeDHCP, TS: observed.Add(time.Second), DHCP: &wire.DHCP{
			Version: 4, MsgType: "ACK", MAC: mac, YourIP: testutil.Phone.IP, Hostname: "alice-iphone",
		}},
		{Seq: 2, Type: wire.TypeName, TS: observed.Add(2 * time.Second), Name: &wire.Name{
			MAC: mac, IP: testutil.Phone.IP, Name: "stale.lan", Proto: "rdns",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	devs, _ = st.Devices(ctx, model.Filter{From: at, To: at.Add(time.Hour), Device: mac})
	if len(devs) != 1 || devs[0].Label != "alice-iphone" {
		t.Errorf("after DHCP: %+v", devs)
	}
}

// Reverse DNS must not rename the router: the sensor's own name for the
// interface that sent the hello is stronger. (The lab caught this when
// Docker's resolver returned the router container's hostname.)
func TestReverseDNSDoesNotRenameRouter(t *testing.T) {
	ctx := context.Background()
	at := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return at.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	mac := "02:42:0a:4d:00:0a"
	ip := testutil.Router.IP
	events := []wire.Event{
		{Seq: 1, Type: wire.TypeHello, TS: at, Hello: &wire.Hello{
			Name: "lab-router",
			Interfaces: []wire.Interface{{
				Name: "eth0", MAC: mac,
				Prefixes: []netip.Prefix{netip.MustParsePrefix("10.77.0.0/24")},
			}},
		}},
		{Seq: 2, Type: wire.TypeName, TS: at.Add(time.Second), Name: &wire.Name{
			MAC: mac, IP: ip, Name: "35cfe281ff9c", Proto: "rdns",
		}},
	}
	if _, err := st.Ingest(ctx, "lab-router", "boot", events); err != nil {
		t.Fatal(err)
	}
	devs, err := st.Devices(ctx, model.Filter{From: at, To: at.Add(time.Hour), Device: mac})
	if err != nil || len(devs) != 1 {
		t.Fatalf("devices: %v %+v", err, devs)
	}
	if devs[0].Label != "lab-router" || devs[0].Role != "router" {
		t.Errorf("router = %+v", devs[0])
	}
}
