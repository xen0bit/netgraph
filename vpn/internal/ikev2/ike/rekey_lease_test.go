package ike

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/vpn/internal/vlog"
)

// leaseServer is mobikeServer with a dual-stack lease and a record of every
// release, so a test can see the pool get an address back.
func leaseServer(t *testing.T) (p500, p4500 int, srv *Server, dp *capturingDataPath, released func() []Assignment) {
	t.Helper()
	p500, p4500 = freeUDPPort(t), freeUDPPort(t)
	dp = newCapturingDataPath()
	var mu sync.Mutex
	var rel []Assignment
	cfg := Config{
		ListenIP: "127.0.0.1", Port500: p500, Port4500: p4500,
		PSK:      []byte("mobike-psk"),
		LocalID:  FQDNIdentity("vpn.example"),
		PublicIP: net.ParseIP("127.0.0.1"),
		Logger:   vlog.Discard(),
		AssignAddr: func(req AddressRequest) (Assignment, error) {
			a := Assignment{IP4: net.IPv4(10, 9, 9, 9), Netmask: net.IPv4(255, 255, 255, 0)}
			if req.IP6 {
				a.IP6, a.Prefix6 = net.ParseIP("fd00:9::9"), 64
			}
			return a, nil
		},
		ReleaseAddr: func(a Assignment) {
			mu.Lock()
			defer mu.Unlock()
			rel = append(rel, a)
		},
		DataPath: dp,
	}
	var err error
	srv, err = NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(50 * time.Millisecond)
	return p500, p4500, srv, dp, func() []Assignment {
		mu.Lock()
		defer mu.Unlock()
		return append([]Assignment(nil), rel...)
	}
}

// An IKE SA rekey hands the client's lease to the new SA, and the old SA is
// deleted moments later. Deleting it must not give the lease back: the client
// still holds those addresses through the new SA, and a pool that has them
// back hands them to the next client, so two peers share an address -- and
// everything that attributes traffic by address attributes it to the wrong
// one. A dual-stack lease is the case that matters, because both families
// have to be detached from the old SA, not only IPv4.
func TestAnIKERekeyDoesNotReleaseTheLeaseItHandedOn(t *testing.T) {
	p500, p4500, srv, dp, released := leaseServer(t)
	defer srv.Close()

	client := NewClient(ClientConfig{
		ServerHost: "127.0.0.1", ServerPort: p500, NATTPort: p4500,
		PSK:     []byte("mobike-psk"),
		LocalID: FQDNIdentity("client.example"),
		Logger:  vlog.Discard(),
	})
	if _, err := client.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()
	client.Attach()
	go pumpInbox(client)
	select {
	case <-dp.added:
	case <-time.After(2 * time.Second):
		t.Fatal("no initial Child SA")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.RekeyIKE(ctx); err != nil {
		t.Fatalf("rekey IKE: %v", err)
	}
	// The old SA's deletion follows the rekey; give it time to land.
	time.Sleep(300 * time.Millisecond)
	if rel := released(); len(rel) != 0 {
		t.Fatalf("the IKE rekey released %+v while the client still holds it", rel)
	}

	// And the lease is the new SA's now, both families, so that SA's own
	// deletion is what gives it back.
	sa := srv.lookupByRSPI(client.spiR)
	if sa == nil {
		t.Fatal("the server has no SA under the rekeyed responder SPI")
	}
	sa.mu.Lock()
	ip4, ip6 := sa.assigned.IP4, sa.assigned.IP6
	sa.mu.Unlock()
	if ip4 == nil || ip6 == nil {
		t.Fatalf("the new SA holds lease %v / %v, want both families", ip4, ip6)
	}
}
