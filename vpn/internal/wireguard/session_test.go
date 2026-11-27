package wireguard

import (
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/vpn/client"
	"github.com/xen0bit/netgraph/vpn/internal/wireguard/noise"
)

// handshakeFrom runs one initiation from cfg at conn's address through the
// server, and requires a response.
func handshakeFrom(t *testing.T, s *Server, cfg noise.Config, conn *net.UDPConn) {
	t.Helper()
	i, err := noise.NewInitiator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	init, err := i.Initiation()
	if err != nil {
		t.Fatal(err)
	}
	s.handleInitiation(init, conn.LocalAddr().(*net.UDPAddr))
	if _, err := i.Consume(readOne(t, conn)); err != nil {
		t.Fatalf("no handshake response: %v", err)
	}
}

// A WireGuard session is a stretch of time a peer held live keys. The first
// handshake opens it under the peer's public key -- the identity the handshake
// proved -- with its AllowedIPs; a rekey inside it says nothing; keys that
// expire with no rekey close it; and the next handshake opens a new one. If
// this fails, the edge either attributes a gone peer's address to it forever
// or splits one connected peer into a session per rekey.
func TestAWireGuardSessionSpansRekeysAndEndsWhenKeysExpire(t *testing.T) {
	s, cfg := socketServer(t, DefaultCookieThreshold)
	var evs []client.SessionEvent
	s.SetSessionHook(func(ev client.SessionEvent) { evs = append(evs, ev) })
	conn, err := net.DialUDP("udp", nil, s.conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	handshakeFrom(t, s, cfg, conn)
	if len(evs) != 1 || !evs[0].Open {
		t.Fatalf("after the first handshake: %+v, want one open", evs)
	}
	pub := mustPub(t, cfg.LocalStatic)
	if want := base64.StdEncoding.EncodeToString(pub[:]); evs[0].User != want {
		t.Errorf("session user %q, want the peer's public key %q", evs[0].User, want)
	}
	if len(evs[0].Addrs) != 1 || evs[0].Addrs[0].String() != "10.0.0.2/32" {
		t.Errorf("session addrs %v, want the peer's AllowedIPs", evs[0].Addrs)
	}
	if evs[0].Outer != conn.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Errorf("session outer %v, want %v", evs[0].Outer, conn.LocalAddr())
	}

	time.Sleep(2 * time.Millisecond) // the next initiation's timestamp must advance
	handshakeFrom(t, s, cfg, conn)
	if len(evs) != 1 {
		t.Fatalf("a rekey reported a session event: %+v", evs[1:])
	}

	s.closeExpiredSessions(time.Now().Add(rejectAfterTime - time.Second))
	if len(evs) != 1 {
		t.Fatalf("a session closed before its keys expired: %+v", evs[1:])
	}
	s.closeExpiredSessions(time.Now().Add(rejectAfterTime + time.Second))
	if len(evs) != 2 || evs[1].Open || evs[1].ID != evs[0].ID || evs[1].Reason != "expired" {
		t.Fatalf("after expiry: %+v, want the session closed as expired", evs)
	}

	time.Sleep(2 * time.Millisecond)
	handshakeFrom(t, s, cfg, conn)
	if len(evs) != 3 || !evs[2].Open || evs[2].ID == evs[0].ID {
		t.Fatalf("a handshake after expiry did not open a new session: %+v", evs)
	}
}
