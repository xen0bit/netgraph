package client

// Sessions: who held which tunnel address, and when.
//
// A VPN server is the one place that knows, from evidence rather than
// inference, which authenticated identity is behind an inner address: it
// assigned the address, or checked the peer's packets against it, after the
// handshake proved who the peer was. netgraph-edge turns that into the
// attribution of every flow the tunnel carries, so a server that reports its
// sessions makes its traffic say whose it is.
//
//	handshake ──► OpenSession(user, addrs, outer) ──► SessionEvent{Open: true}
//	expiry / disconnect / Close ──► CloseSession(id) ──► SessionEvent{Open: false}
//
// It is an optional capability, discovered by type assertion like
// PeerDescriber: a protocol that does not report sessions still serves, and the
// edge says once that its traffic will not be attributed.

import (
	"cmp"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// SessionEvent is one authenticated session opening or closing on a server.
type SessionEvent struct {
	// ID names the session within one server instance; the close carries the
	// open's ID. Zero is never used.
	ID uint64
	// Open is true for the event that starts the session and false for the one
	// that ends it.
	Open bool
	// Time is when it opened or closed. A close found by a sweep (an expired
	// key) carries the last moment the session was alive, not the sweep's.
	Time time.Time
	// User is the identity the handshake proved: a username, a certificate's
	// subject, or a public key. It is what the peer authenticated as, never a
	// name it merely claimed.
	User string
	// Auth says how User was proved, which is how far to trust it:
	// "public-key" (a key only that peer holds), "certificate" (a chain to a
	// configured CA, matching User), "eap-mschapv2" or "password" (a per-user
	// secret), or "psk" (a key shared by everyone who has it, so User is the
	// name a key-holder chose).
	Auth string
	// Name is an optional label the operator configured for the peer.
	Name string
	// Addrs are the inner prefixes the session carries: an assigned /32 or
	// /128, or a WireGuard peer's AllowedIPs.
	Addrs []netip.Prefix
	// Outer is the peer's address on the underlying network when it opened.
	Outer netip.AddrPort
	// Reason says why a session closed: "expired", "disconnected", "kicked" or
	// "shutdown". Empty on an open.
	Reason string
}

// SessionReporter is a Server that reports its sessions. SetSessionHook is
// called before ListenAndServe; the hook must not block or call back into the
// server, since it runs on the server's own goroutines.
type SessionReporter interface {
	SetSessionHook(func(SessionEvent))
}

// SessionHub is the bookkeeping a server embeds to be a SessionReporter. Its
// zero value is ready, and every method is safe on a hub nobody hooked: a
// server calls OpenSession and CloseSession unconditionally.
type SessionHub struct {
	mu   sync.Mutex
	hook func(SessionEvent)
	next uint64
	open map[uint64]SessionEvent
}

// SetSessionHook installs f. Sessions already open are replayed to it as opens,
// so a hook set late still learns who is connected.
func (h *SessionHub) SetSessionHook(f func(SessionEvent)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hook = f
	if f == nil {
		return
	}
	ids := make([]uint64, 0, len(h.open))
	for id := range h.open {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		f(h.open[id])
	}
}

// OpenSession records a session and returns its ID. ev's ID and Open are set here, and
// Time when it is zero. Addrs is copied, so the caller may reuse its slice.
func (h *SessionHub) OpenSession(ev SessionEvent) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	ev.ID, ev.Open, ev.Reason = h.next, true, ""
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	ev.Addrs = slices.Clone(ev.Addrs)
	// A dual-stack socket reports an IPv4 peer as ::ffff:a.b.c.d. It is the
	// IPv4 address, and anything matching on it downstream expects that form.
	if ev.Outer.IsValid() {
		ev.Outer = netip.AddrPortFrom(ev.Outer.Addr().Unmap(), ev.Outer.Port())
	}
	if h.open == nil {
		h.open = map[uint64]SessionEvent{}
	}
	h.open[ev.ID] = ev
	if h.hook != nil {
		h.hook(ev)
	}
	return ev.ID
}

// CloseSession ends session id at time at (now, when zero). Closing an unknown or
// already-closed ID does nothing, so teardown paths need not coordinate.
func (h *SessionHub) CloseSession(id uint64, reason string, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closeLocked(id, reason, at)
}

func (h *SessionHub) closeLocked(id uint64, reason string, at time.Time) {
	ev, ok := h.open[id]
	if !ok {
		return
	}
	delete(h.open, id)
	if at.IsZero() {
		at = time.Now()
	}
	// A clock that stepped back must not produce a session that ends before
	// it began: windows downstream are half-open and would lose it.
	if at.Before(ev.Time) {
		at = ev.Time
	}
	ev.Open, ev.Time, ev.Reason = false, at, reason
	if h.hook != nil {
		h.hook(ev)
	}
}

// CloseAllSessions ends every open session, in the order they opened. A server calls it
// from Close with reason "shutdown".
func (h *SessionHub) CloseAllSessions(reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ids := make([]uint64, 0, len(h.open))
	for id := range h.open {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	now := time.Now()
	for _, id := range ids {
		h.closeLocked(id, reason, now)
	}
}

// OpenSessions returns the sessions open now, oldest first.
func (h *SessionHub) OpenSessions() []SessionEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]SessionEvent, 0, len(h.open))
	for _, ev := range h.open {
		out = append(out, ev)
	}
	slices.SortFunc(out, func(a, b SessionEvent) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

// HostPrefixes turns assigned inner addresses into the host prefixes a
// SessionEvent carries (/32, /128), skipping nil and invalid ones.
func HostPrefixes(ips ...net.IP) []netip.Prefix {
	var out []netip.Prefix
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// OuterOf is a peer's address on the underlying network, as a SessionEvent's
// Outer, from whatever net.Addr its connection reports (zero if neither TCP
// nor UDP).
func OuterOf(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.AddrPort()
	case *net.UDPAddr:
		return v.AddrPort()
	}
	return netip.AddrPort{}
}
