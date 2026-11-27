package gp

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/vpn/client"
)

// A GlobalProtect session is one user, proved by password at login, holding
// the address the login assigned until the gateway takes it back: when the
// user's tunnel ends, or when a login that never brought a tunnel up expires.
// A wrong password opens nothing. If this fails, an address is attributed to
// someone who is gone, or to someone who never proved who they were.
func TestAGlobalProtectSessionLastsAsLongAsTheLease(t *testing.T) {
	var hub client.SessionHub
	var mu sync.Mutex
	var seen []client.SessionEvent
	hub.SetSessionHook(func(ev client.SessionEvent) { mu.Lock(); seen = append(seen, ev); mu.Unlock() })
	events := func() []client.SessionEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]client.SessionEvent(nil), seen...)
	}
	h := newHarness(t, ServerConfig{Sessions: &hub}, false)

	if _, _, err := Login(h.hc, h.url, "alice", "wrong", "testhost"); err == nil {
		t.Fatal("a wrong password logged in")
	}
	if evs := events(); len(evs) != 0 {
		t.Fatalf("a refused login opened a session: %+v", evs)
	}

	info, cfg := mustLogin(t, h)
	evs := events()
	if len(evs) != 1 || !evs[0].Open || evs[0].User != "alice" || evs[0].Auth != "password" {
		t.Fatalf("after login: %+v, want alice's session by password", evs)
	}
	ip, _ := netip.AddrFromSlice(cfg.AssignedIP.To4())
	if len(evs[0].Addrs) != 1 || evs[0].Addrs[0] != netip.PrefixFrom(ip, 32) {
		t.Errorf("session addrs %v, want the assigned %s/32", evs[0].Addrs, ip)
	}
	if !evs[0].Outer.Addr().IsLoopback() || evs[0].Outer.Port() == 0 {
		t.Errorf("session outer %v, want the client's loopback address and port", evs[0].Outer)
	}

	c := h.dialSSL(t, info, cfg, newFakeTUN())
	_ = c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for len(events()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	evs = events()
	if len(evs) != 2 || evs[1].Open || evs[1].ID != evs[0].ID || evs[1].Reason != "disconnected" {
		t.Fatalf("after the tunnel ended: %+v, want the session closed as disconnected", evs)
	}
}
