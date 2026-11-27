package client

import (
	"net/netip"
	"testing"
	"time"
)

type recorder struct{ evs []SessionEvent }

func (r *recorder) hook(ev SessionEvent) { r.evs = append(r.evs, ev) }

// A close must name the session its open did, carry the same identity and
// addresses, and say why: the edge pairs them by ID to bound the interval in
// which an address belonged to a user.
func TestSessionCloseCarriesItsOpensIdentity(t *testing.T) {
	var h SessionHub
	var r recorder
	h.SetSessionHook(r.hook)
	addrs := []netip.Prefix{netip.MustParsePrefix("10.8.0.2/32")}
	id := h.OpenSession(SessionEvent{User: "alice", Addrs: addrs, Outer: netip.MustParseAddrPort("198.51.100.7:51820")})
	addrs[0] = netip.MustParsePrefix("10.8.0.99/32") // the caller reuses its slice
	h.CloseSession(id, "disconnected", time.Time{})

	if len(r.evs) != 2 {
		t.Fatalf("got %d events, want 2", len(r.evs))
	}
	open, closed := r.evs[0], r.evs[1]
	if !open.Open || closed.Open || open.ID != id || closed.ID != id {
		t.Fatalf("open/close mismatch: %+v / %+v", open, closed)
	}
	if closed.User != "alice" || closed.Addrs[0].String() != "10.8.0.2/32" || closed.Reason != "disconnected" {
		t.Errorf("close lost its identity: %+v", closed)
	}
	if closed.Time.Before(open.Time) {
		t.Errorf("closed at %v, before it opened at %v", closed.Time, open.Time)
	}
}

// Teardown paths race each other (a disconnect and a shutdown, say); the
// second close must say nothing rather than report a session ending twice.
func TestClosingASessionTwiceReportsOnce(t *testing.T) {
	var h SessionHub
	var r recorder
	h.SetSessionHook(r.hook)
	id := h.OpenSession(SessionEvent{User: "bob"})
	h.CloseSession(id, "disconnected", time.Time{})
	h.CloseSession(id, "shutdown", time.Time{})
	h.CloseAllSessions("shutdown")
	if len(r.evs) != 2 {
		t.Fatalf("got %d events, want 2: %+v", len(r.evs), r.evs)
	}
}

// A hook installed after clients connected still learns who is connected,
// or their traffic would go unattributed until they next reconnect.
func TestALateHookIsToldWhoIsAlreadyConnected(t *testing.T) {
	var h SessionHub
	h.OpenSession(SessionEvent{User: "carol"})
	h.OpenSession(SessionEvent{User: "dave"})
	var r recorder
	h.SetSessionHook(r.hook)
	if len(r.evs) != 2 || r.evs[0].User != "carol" || r.evs[1].User != "dave" || !r.evs[0].Open {
		t.Fatalf("replay = %+v", r.evs)
	}
}

// A close timed before its open (a clock stepped back, or a sweep's
// last-seen predating the open) is clamped: a session that ends before it
// starts falls out of every half-open window downstream.
func TestASessionNeverEndsBeforeItBegan(t *testing.T) {
	var h SessionHub
	var r recorder
	h.SetSessionHook(r.hook)
	id := h.OpenSession(SessionEvent{User: "erin"})
	h.CloseSession(id, "expired", time.Unix(0, 0))
	if got := r.evs[1].Time; !got.Equal(r.evs[0].Time) {
		t.Errorf("close time %v, want the open time %v", got, r.evs[0].Time)
	}
}

// Shutdown closes everything still open, oldest first, and leaves nothing.
func TestCloseAllEndsEverySessionInOrder(t *testing.T) {
	var h SessionHub
	var r recorder
	h.SetSessionHook(r.hook)
	a := h.OpenSession(SessionEvent{User: "a"})
	b := h.OpenSession(SessionEvent{User: "b"})
	h.CloseAllSessions("shutdown")
	if len(r.evs) != 4 || r.evs[2].ID != a || r.evs[3].ID != b || r.evs[3].Reason != "shutdown" {
		t.Fatalf("events = %+v", r.evs)
	}
	if n := len(h.OpenSessions()); n != 0 {
		t.Errorf("%d sessions still open", n)
	}
}

// Without a hook a server still calls Open and Close; they must work.
func TestAnUnhookedHubStillCounts(t *testing.T) {
	var h SessionHub
	id := h.OpenSession(SessionEvent{User: "x"})
	if n := len(h.OpenSessions()); n != 1 {
		t.Fatalf("%d open, want 1", n)
	}
	h.CloseSession(id, "disconnected", time.Time{})
	if n := len(h.OpenSessions()); n != 0 {
		t.Fatalf("%d open, want 0", n)
	}
}
