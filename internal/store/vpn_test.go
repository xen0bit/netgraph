package store

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

func vpnStore(t *testing.T) (*Store, time.Time) {
	t.Helper()
	at := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return at.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st, at
}

func vpnSessionEv(at time.Time, id uint64, open bool, user, prefix, reason string) wire.Event {
	return wire.Event{Type: wire.TypeVPNSession, TS: at, VPNSession: &wire.VPNSession{
		Listener: "office", Protocol: "wireguard", ID: id, Open: open, User: user,
		Addrs:  []netip.Prefix{netip.MustParsePrefix(prefix)},
		Outer:  netip.MustParseAddrPort("198.51.100.7:51820"),
		Reason: reason,
	}}
}

func tunnelFlow(at time.Time, id uint64, src string, dport uint16) wire.Event {
	return wire.Event{Type: wire.TypeFlow, TS: at.Add(10 * time.Second), Flow: &wire.Flow{
		ID: id, Proto: 6, Src: netip.MustParseAddr(src), SrcPort: 40000 + uint16(id), Dst: netip.MustParseAddr("93.184.216.34"), DstPort: dport,
		FirstSeen: at, Start: at, End: at.Add(10 * time.Second), BytesOut: 1000, BytesIn: 5000, PktsOut: 10, PktsIn: 10, Final: true, EndReason: "fin",
	}}
}

// numbered gives a batch's events increasing sequence numbers from first, as a
// sensor's shipper does: ingest applies each number once per boot.
func numbered(first uint64, evs ...wire.Event) []wire.Event {
	for i := range evs {
		evs[i].Seq = first + uint64(i)
	}
	return evs
}

func flowSessions(t *testing.T, st *Store) map[uint16]int64 {
	t.Helper()
	rows, err := st.r.Query(`SELECT remote_port, vpn_session FROM connections`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[uint16]int64{}
	for rows.Next() {
		var port uint16
		var sess int64
		if err := rows.Scan(&port, &sess); err != nil {
			t.Fatal(err)
		}
		out[port] = sess
	}
	return out
}

// A flow from a tunnel address belongs to the user whose session held that
// address when the flow began, on the edge that reported the session -- and to
// nobody else: not before the session opened, not after it closed, not on
// another sensor that happens to see the same private address, and not to the
// next user given that address. If this fails, traffic is pinned on the wrong
// person, which is worse than pinning it on nobody.
func TestEdgeFlowsBelongToTheSessionThatHeldTheirAddress(t *testing.T) {
	ctx := context.Background()
	st, at := vpnStore(t)
	edge := numbered(1,
		tunnelFlow(at.Add(-time.Minute), 1, "10.8.0.2", 1001), // before alice connected
		vpnSessionEv(at, 7, true, "alice", "10.8.0.2/32", ""), // alice opens
		vpnSessionEv(at, 7, true, "alice", "10.8.0.2/32", ""), // a replayed open
		tunnelFlow(at.Add(time.Minute), 2, "10.8.0.2", 1002),  // alice's
		tunnelFlow(at.Add(time.Minute), 3, "10.8.0.3", 1003),  // nobody's address
		vpnSessionEv(at.Add(10*time.Minute), 7, false, "alice", "10.8.0.2/32", "disconnected"),
		vpnSessionEv(at.Add(11*time.Minute), 8, true, "bob", "10.8.0.2/32", ""), // the address, reassigned
		tunnelFlow(at.Add(12*time.Minute), 4, "10.8.0.2", 1004),                 // bob's
	)
	if _, err := st.Ingest(ctx, "edge-1", "boot-a", edge); err != nil {
		t.Fatal(err)
	}
	// Another sensor sees the same private address on its own LAN.
	if _, err := st.Ingest(ctx, "router", "boot-r", []wire.Event{tunnelFlow(at.Add(time.Minute), 5, "10.8.0.2", 1005)}); err != nil {
		t.Fatal(err)
	}

	var alice, bob int64
	if err := st.r.QueryRow(`SELECT id FROM vpn_sessions WHERE user = 'alice'`).Scan(&alice); err != nil {
		t.Fatalf("alice's session was not stored: %v", err)
	}
	if err := st.r.QueryRow(`SELECT id FROM vpn_sessions WHERE user = 'bob'`).Scan(&bob); err != nil {
		t.Fatalf("bob's session was not stored: %v", err)
	}
	var n int
	_ = st.r.QueryRow(`SELECT count(*) FROM vpn_sessions`).Scan(&n)
	if n != 2 {
		t.Errorf("%d session rows, want 2: a replayed open made another", n)
	}

	got := flowSessions(t, st)
	want := map[uint16]int64{1001: 0, 1002: alice, 1003: 0, 1004: bob, 1005: 0}
	for port, w := range want {
		if got[port] != w {
			t.Errorf("flow to port %d attributed to session %d, want %d (alice=%d, bob=%d)", port, got[port], w, alice, bob)
		}
	}

	sessions, err := st.VPNSessions(ctx, at.Add(-time.Hour), at.Add(time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("VPNSessions = %+v", sessions)
	}
	a := sessions[1] // newest first
	if a.User != "alice" || a.End == nil || a.Reason != "disconnected" || a.Flows != 1 || a.BytesIn != 5000 || a.Sensor != "edge-1" {
		t.Errorf("alice's session = %+v", a)
	}
	if b := sessions[0]; b.User != "bob" || b.End != nil {
		t.Errorf("bob's session = %+v, want still open", b)
	}
}

// The ingester's session cache is rebuilt from the database after a restart
// (or a failed batch): a session opened in one process's lifetime must still
// claim flows that arrive in the next.
func TestASessionOpenedBeforeARestartStillClaimsFlows(t *testing.T) {
	ctx := context.Background()
	st, at := vpnStore(t)
	if _, err := st.Ingest(ctx, "edge-1", "boot-a", numbered(1, vpnSessionEv(at, 1, true, "carol", "10.8.0.9/32", ""))); err != nil {
		t.Fatal(err)
	}
	st.ing = newIngester(st) // what a restart or a failed batch leaves
	if _, err := st.Ingest(ctx, "edge-1", "boot-a", numbered(2, tunnelFlow(at.Add(time.Minute), 1, "10.8.0.9", 2001))); err != nil {
		t.Fatal(err)
	}
	if got := flowSessions(t, st)[2001]; got == 0 {
		t.Error("a flow after the cache was rebuilt was not attributed to the open session")
	}
}

// A close whose open was never seen has no start, so nothing can be
// attributed to it; it must not invent a session.
func TestACloseWithoutItsOpenRecordsNothing(t *testing.T) {
	ctx := context.Background()
	st, at := vpnStore(t)
	if _, err := st.Ingest(ctx, "edge-1", "boot-a", []wire.Event{vpnSessionEv(at, 3, false, "dave", "10.8.0.4/32", "expired")}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = st.r.QueryRow(`SELECT count(*) FROM vpn_sessions`).Scan(&n)
	if n != 0 {
		t.Errorf("%d sessions from a lone close", n)
	}
}
