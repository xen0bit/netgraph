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

// A host on a routed subnet (an IoT VLAN) reaches the captured LAN under the
// router's MAC. That MAC must not make the host the router: the router keeps
// only its own addresses, and the host's traffic goes to the device its own
// binding names.
func TestRoutedSubnetNotAttributedToRouter(t *testing.T) {
	ctx := context.Background()
	at := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return at.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const router, plug, laptop = "02:00:5e:00:00:01", "3c:22:fb:00:00:20", "3c:22:fb:00:00:10"
	routerIP := netip.MustParseAddr("192.168.1.1")
	plugIP := netip.MustParseAddr("192.168.20.5") // the IoT VLAN, not captured here
	laptopIP := netip.MustParseAddr("192.168.1.10")
	flow := func(id uint64, src netip.Addr, srcMAC string, dst netip.Addr, dstMAC string, ts time.Time) wire.Event {
		return wire.Event{Seq: id + 10, Type: wire.TypeFlow, TS: ts.Add(time.Second), Flow: &wire.Flow{
			ID: id, Proto: 6, Src: src, SrcPort: 40000, Dst: dst, DstPort: 8080, SrcMAC: srcMAC, DstMAC: dstMAC,
			FirstSeen: ts, Start: ts, End: ts.Add(time.Second), BytesOut: 100, BytesIn: 200, PktsOut: 1, PktsIn: 1, Final: true,
		}}
	}
	events := []wire.Event{
		{Seq: 1, Type: wire.TypeHello, TS: at, Hello: &wire.Hello{Name: "router", Version: "test",
			Interfaces: []wire.Interface{{Name: "br-lan", MAC: router, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.1/24")}}}}},
		// The plug's address was seen bound to its own MAC (another
		// sensor, or DHCP relayed to this LAN).
		{Seq: 2, Type: wire.TypeBinding, TS: at, Binding: &wire.Binding{MAC: plug, IP: plugIP, Source: "arp"}},
		// The plug talks to the laptop through the router: on br-lan the
		// packets carry the router's MAC.
		flow(1, plugIP, router, laptopIP, laptop, at.Add(5*time.Second)),
		// The laptop talks to the router itself, which is the router's own
		// address and is evidence.
		flow(2, laptopIP, laptop, routerIP, router, at.Add(6*time.Second)),
	}
	if _, err := st.Ingest(ctx, "router", "boot", events); err != nil {
		t.Fatal(err)
	}
	win := model.Filter{From: at, To: at.Add(time.Hour)}
	devs, err := st.Devices(ctx, win)
	if err != nil {
		t.Fatal(err)
	}
	ips := map[string][]string{}
	for _, d := range devs {
		ips[d.MAC] = d.IPs
	}
	if slices.Contains(ips[router], plugIP.String()) {
		t.Errorf("router took the routed host's address: %v", ips[router])
	}
	if !slices.Contains(ips[router], routerIP.String()) {
		t.Errorf("router lost its own address: %v", ips[router])
	}
	if !slices.Contains(ips[plug], plugIP.String()) {
		t.Errorf("plug = %v, want %v", ips[plug], plugIP)
	}
	flows, err := st.Flows(ctx, model.Filter{From: at, To: at.Add(time.Hour), Device: plug})
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 {
		t.Errorf("plug's flows = %+v, want the forwarded connection", flows)
	}
}
