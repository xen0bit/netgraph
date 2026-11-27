package edge

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/flow"
	"github.com/xen0bit/netgraph/internal/wire"
	"github.com/xen0bit/netgraph/vpn/client"
	"github.com/xen0bit/netgraph/vpn/supervisor"
)

// fakeServer is a listener's server that serves nothing but reports
// sessions, as a real one does after a handshake.
type fakeServer struct {
	client.SessionHub
	tun    string
	closed chan struct{}
	once   sync.Once
}

func (s *fakeServer) ListenAndServe() error { <-s.closed; return nil }
func (s *fakeServer) Close() error {
	s.once.Do(func() { close(s.closed); s.CloseAllSessions("shutdown") })
	return nil
}
func (s *fakeServer) TUNName() string { return s.tun }
func (s *fakeServer) Gateway() net.IP { return net.IPv4(10, 8, 0, 1) }
func (s *fakeServer) Network() *net.IPNet {
	_, n, _ := net.ParseCIDR("10.8.0.0/24")
	return n
}

// fakeTUN yields the packets sent to it as raw IP, then timeouts.
type fakeTUN struct {
	name string
	pkts chan []byte
	done chan struct{}
}

func (f *fakeTUN) Name() string  { return f.name }
func (f *fakeTUN) LinkType() int { return capture.LinkRaw }
func (f *fakeTUN) ReadPacket() ([]byte, time.Time, error) {
	select {
	case p := <-f.pkts:
		return p, time.Now(), nil
	case <-f.done:
		return nil, time.Time{}, errors.New("closed")
	case <-time.After(20 * time.Millisecond):
		return nil, time.Time{}, capture.ErrTimeout
	}
}
func (f *fakeTUN) Stats() (uint64, uint64) { return 0, 0 }
func (f *fakeTUN) Close() error            { return nil }

// recorder is a wire.Emitter that keeps everything.
type recorder struct {
	mu  sync.Mutex
	evs []wire.Event
}

func (r *recorder) Emit(ev wire.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
}

func (r *recorder) of(t wire.Type) []wire.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []wire.Event
	for _, ev := range r.evs {
		if ev.Type == t {
			out = append(out, ev)
		}
	}
	return out
}

// udp4 is a minimal IPv4/UDP packet, as a TUN yields it.
func udp4(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(p[10:], ^uint16(sum))
	binary.BigEndian.PutUint16(p[20:], sport)
	binary.BigEndian.PutUint16(p[22:], dport)
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// One listener, end to end without privileges: the edge hooks the server's
// sessions before it serves, captures its TUN through the sensor's
// processor, and reports both -- the session under an ID of the edge's own,
// with the listener's name and protocol, and the traffic from the session's
// address as flows. Stopping the edge closes the session as "shutdown" and
// flushes the flow. If this fails, the server has nothing to attribute: a
// session without its flows, or flows without their session.
func TestAnEdgeReportsItsListenersSessionsAndTheirTraffic(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := json.Marshal(map[string]any{"name": "office", "protocol": "wireguard", "options": map[string]string{}})
	if err := os.WriteFile(filepath.Join(dir, "office.json"), cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	srv := &fakeServer{tun: "wg-office", closed: make(chan struct{})}
	tun := &fakeTUN{name: "wg-office", pkts: make(chan []byte, 8), done: make(chan struct{})}
	var out recorder
	e := New(Config{
		Name: "edge-1", ListenerDir: dir, Out: &out, NoHostnet: true,
		Flow:        flow.Config{ActiveTimeout: time.Minute, TCPIdle: time.Minute, UDPIdle: time.Minute, MaxFlows: 64},
		Constructor: func(string, map[string]string) (client.Server, error) { return srv, nil },
		OpenCapture: func(iface string) (capture.Source, error) {
			if iface != "wg-office" {
				t.Errorf("captured %q, want the listener's TUN", iface)
			}
			return tun, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- e.Run(ctx) }()

	waitFor(t, "the listener to start", func() bool {
		ls := e.Listeners()
		return len(ls) == 1 && ls[0].State == "running"
	})
	srv.OpenSession(client.SessionEvent{User: "alice", Addrs: []netip.Prefix{netip.MustParsePrefix("10.8.0.2/32")},
		Outer: netip.MustParseAddrPort("198.51.100.7:51820")})
	tun.pkts <- udp4(netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("93.184.216.34"), 50000, 443, []byte("hello"))
	waitFor(t, "the session event", func() bool { return len(out.of(wire.TypeVPNSession)) == 1 })

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("Run: %v", err)
	}
	close(tun.done)

	sessions := out.of(wire.TypeVPNSession)
	if len(sessions) != 2 {
		t.Fatalf("session events = %d, want an open and a close", len(sessions))
	}
	open, closed := sessions[0].VPNSession, sessions[1].VPNSession
	if !open.Open || open.Listener != "office" || open.Protocol != "wireguard" || open.User != "alice" || open.ID == 0 {
		t.Errorf("open = %+v", open)
	}
	if closed.Open || closed.ID != open.ID || closed.Reason != "shutdown" {
		t.Errorf("close = %+v, want the open's ID closed as shutdown", closed)
	}
	var found bool
	for _, ev := range out.of(wire.TypeFlow) {
		if ev.Flow.Src == netip.MustParseAddr("10.8.0.2") && ev.Flow.DstPort == 443 {
			found = true
		}
	}
	if !found {
		t.Errorf("no flow from the session's address among %d flow events", len(out.of(wire.TypeFlow)))
	}
	if len(out.of(wire.TypeHello)) == 0 || len(out.of(wire.TypeStats)) == 0 {
		t.Error("no hello or stats: the server would not know the edge")
	}
}

func listenerCfg(name string) supervisor.ListenerConfig {
	return supervisor.ListenerConfig{Name: name, Protocol: "wireguard", Enabled: true}
}

// Session IDs are the edge's, not each server's: a rebuilt listener's hub
// counts from one again, and the server keys sessions by (boot, listener,
// ID), so reusing an ID would merge two people's sessions into one.
func TestSessionIDsAreUniqueAcrossRebuilds(t *testing.T) {
	var out recorder
	e := &Edge{cfg: Config{Out: &out}}
	first := e.sessionHook(listenerCfg("office"))
	second := e.sessionHook(listenerCfg("office")) // the same listener, rebuilt
	first(client.SessionEvent{ID: 1, Open: true, User: "alice"})
	second(client.SessionEvent{ID: 1, Open: true, User: "bob"})
	evs := out.of(wire.TypeVPNSession)
	if evs[0].VPNSession.ID == evs[1].VPNSession.ID {
		t.Fatalf("two sessions share edge ID %d", evs[0].VPNSession.ID)
	}
}
