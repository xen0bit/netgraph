package anyconnect

import (
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/vpn/client"
	"github.com/xen0bit/netgraph/vpn/dataplane"
)

// An AnyConnect session is one user, proved by password, holding one address
// for the life of its tunnel: it opens once CONNECT assigns the address and
// closes when the connection goes and the address returns to the pool. A
// wrong password opens nothing. If this fails, the edge attributes traffic to
// a user who never authenticated, or for longer than they were there.
func TestAnAnyConnectSessionIsOneUserHoldingOneAddress(t *testing.T) {
	pool, gateway, err := dataplane.NewAddrPool("10.11.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	var hub client.SessionHub
	var mu sync.Mutex
	var seen []client.SessionEvent
	hub.SetSessionHook(func(ev client.SessionEvent) { mu.Lock(); seen = append(seen, ev); mu.Unlock() })
	events := func() []client.SessionEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]client.SessionEvent(nil), seen...)
	}

	srv := NewServer(newFakeTUN(), ServerConfig{
		Sessions: &hub, Users: map[string]string{"alice": "password"}, Pool: pool, Gateway: gateway,
	})
	srv.Start()
	defer srv.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.ServeConn(conn)
		}
	}()
	dial := func(password string) (*Client, net.Addr, error) {
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // test cert
		if err != nil {
			t.Fatal(err)
		}
		c := NewClient(conn, newFakeTUN(), ClientConfig{Host: ln.Addr().String(), Username: "alice", Password: password})
		_, err = c.Handshake()
		return c, conn.LocalAddr(), err
	}

	bad, _, err := dial("wrong")
	if err == nil {
		t.Fatal("a wrong password was accepted")
	}
	bad.Close()
	if evs := events(); len(evs) != 0 {
		t.Fatalf("a refused login opened a session: %+v", evs)
	}

	c, local, err := dial("password")
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	evs := events()
	if len(evs) != 1 || !evs[0].Open || evs[0].User != "alice" || evs[0].Auth != "password" {
		t.Fatalf("after CONNECT: %+v, want alice's session by password", evs)
	}
	if len(evs[0].Addrs) != 1 || evs[0].Addrs[0].Bits() != 32 || !pool.Network().Contains(evs[0].Addrs[0].Addr().AsSlice()) {
		t.Errorf("session addrs %v, want one /32 from the pool", evs[0].Addrs)
	}
	if evs[0].Outer != client.OuterOf(local) {
		t.Errorf("session outer %v, want the client's %v", evs[0].Outer, local)
	}

	go func() { _ = c.Run(0) }()
	c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for len(events()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	evs = events()
	if len(evs) != 2 || evs[1].Open || evs[1].ID != evs[0].ID || evs[1].Reason != "disconnected" {
		t.Fatalf("after the client left: %+v, want its session closed as disconnected", evs)
	}
}
