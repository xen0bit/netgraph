package ike

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/vpn/client"
	"github.com/xen0bit/netgraph/vpn/internal/ikev2/payload"
	"github.com/xen0bit/netgraph/vpn/internal/vlog"
)

// An IKEv2 session is one authenticated identity holding one lease: it opens
// in IKE_AUTH with the identity the AUTH payload proved, how it was proved,
// and both addresses of a dual-stack lease, and it closes when the peer's
// Delete ends the IKE SA and the lease goes back to the pool. If this fails,
// the edge cannot say whose an address was, or says it for longer than it was.
func TestAnIKEv2SessionIsOneIdentityHoldingOneLease(t *testing.T) {
	psk := []byte("session psk")
	p500, p4500 := freeUDPPort(t), freeUDPPort(t)
	var hub client.SessionHub
	var mu sync.Mutex
	var evs []client.SessionEvent
	var released int
	hub.SetSessionHook(func(ev client.SessionEvent) {
		mu.Lock()
		defer mu.Unlock()
		evs = append(evs, ev)
	})
	srv, err := NewServer(Config{
		ListenIP: "127.0.0.1", Port500: p500, Port4500: p4500,
		PSK: psk, LocalID: FQDNIdentity("responder.test"), Logger: vlog.Discard(),
		AssignAddr: func(AddressRequest) (Assignment, error) {
			return Assignment{IP4: net.IPv4(10, 20, 30, 2), Netmask: net.IPv4(255, 255, 255, 0),
				IP6: net.ParseIP("fd00:20:30::2"), Prefix6: 64}, nil
		},
		ReleaseAddr: func(Assignment) { mu.Lock(); released++; mu.Unlock() },
		Sessions:    &hub,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ListenAndServe() }()
	defer srv.Close()
	time.Sleep(50 * time.Millisecond)

	cli, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: p500})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	it := &initiator{tb: t, conn: cli, psk: psk, id: FQDNIdentity("alice.example")}
	it.doSAInit()
	it.doAuth()

	mu.Lock()
	if len(evs) != 1 || !evs[0].Open {
		mu.Unlock()
		t.Fatalf("after IKE_AUTH: %+v, want one open", evs)
	}
	open := evs[0]
	mu.Unlock()
	if open.User != "alice.example" || open.Auth != "psk" {
		t.Errorf("session %q by %q, want alice.example by psk", open.User, open.Auth)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.20.30.2/32"), netip.MustParsePrefix("fd00:20:30::2/128")}
	if len(open.Addrs) != 2 || open.Addrs[0] != want[0] || open.Addrs[1] != want[1] {
		t.Errorf("session addrs %v, want %v", open.Addrs, want)
	}
	if open.Outer != cli.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Errorf("session outer %v, want %v", open.Outer, cli.LocalAddr())
	}

	// The client leaves: INFORMATIONAL{D(IKE)}.
	b := payload.NewBuilder()
	b.Add(payload.TypeDelete, false, payload.MarshalDelete(payload.DeletePayload{Protocol: payload.ProtoIKE}))
	it.send(it.buildEnc(payload.INFORMATIONAL, 2, b.FirstType(), b.Bytes()))
	_ = it.recv()
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n, r := len(evs), released
		mu.Unlock()
		if n >= 2 && r >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(evs) != 2 || evs[1].Open || evs[1].ID != open.ID || evs[1].Reason != "disconnected" {
		t.Fatalf("after the peer's delete: %+v, want the session closed as disconnected", evs)
	}
	if released != 1 {
		t.Errorf("lease released %d times, want once with the session's close", released)
	}
}
