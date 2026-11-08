//go:build linux

package linux

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/agent/linux/bpf"
)

type fakeEvents chan bpf.Event

func (f fakeEvents) Read() (bpf.Event, error) {
	e, ok := <-f
	if !ok {
		return bpf.Event{}, os.ErrClosed
	}
	return e, nil
}

func (f fakeEvents) Close() error { close(f); return nil }

// Events name what polling can't: a connection that closed before the scan,
// by a program that has exited, and an accepted connection /proc still
// shows becomes one row, not two.
func TestScannerEvents(t *testing.T) {
	f := newProcFixture(t)
	// curl (500) made a connection that closed before the scan; haproxy
	// (100) accepted one that is still open, socket 11; a one-shot program
	// (900) pinged and exited before its event was read.
	f.proc(100, 1, 500, "haproxy -f cfg", 11)
	f.proc(500, 100, 700, "curl https://example.com")
	f.sockets(11)
	ev := make(fakeEvents, 8)
	sc := &Scanner{Root: f.root}
	sc.Listen(ev)
	ns := func(ticks int64) uint64 { return uint64(ticks) * 1e7 }
	local, remote := netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("192.0.2.1")
	ev <- bpf.Event{Kind: bpf.KindConnect, Proto: 6, Family: 2, PID: 500, PPID: 100, Start: ns(700), Ino: 77,
		Src: local, SPort: 50000, Dst: netip.MustParseAddr("93.184.216.34"), DPort: 443, Comm: "curl"}
	ev <- bpf.Event{Kind: bpf.KindAccept, Proto: 6, Family: 2, PID: 100, PPID: 1, Start: ns(500),
		Src: local, SPort: 40000, Dst: remote, DPort: 443, Comm: "haproxy"}
	ev <- bpf.Event{Kind: bpf.KindSend, Proto: 1, Family: 2, PID: 900, PPID: 1, Start: ns(1234), Ino: 99,
		Src: local, SPort: 6354, Dst: netip.MustParseAddr("9.9.9.9"), Comm: "ping"}
	deadline := time.Now().Add(2 * time.Second)
	for {
		sc.ev.mu.Lock()
		n := len(sc.ev.pending)
		sc.ev.mu.Unlock()
		if n == 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The accepted socket's owner comes from the event: /proc can't show
	// it (as if another user's).
	if err := os.Remove(f.root + "/100/fd/3"); err != nil {
		t.Fatal(err)
	}
	procs, conns, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]int{}
	for _, c := range conns {
		byKey[c.Key] = c.PID
		switch c.Proto {
		case "icmp":
			if c.App != "ping" || c.LocalPort != 6354 || c.RemoteIP != "9.9.9.9" || c.RemotePort != 0 {
				t.Errorf("ping = %+v", c)
			}
		case "tcp":
			if c.RemotePort == 443 && c.RemoteIP == "93.184.216.34" && (c.App != "curl" || c.PID != 500 || c.Direction != "out") {
				t.Errorf("curl = %+v", c)
			}
		}
	}
	if len(conns) != 3 || byKey["tcp|10.0.0.2:50000|93.184.216.34:443|77"] != 500 || byKey["tcp|10.0.0.2:40000|192.0.2.1:443|11"] != 100 {
		t.Fatalf("connections = %v", byKey)
	}
	got := map[int]string{}
	for _, p := range procs {
		got[p.PID] = p.Cmdline
	}
	// curl and its parent haproxy from /proc; ping only by the kernel's name.
	if got[500] != "curl" || got[100] != "haproxy" || got[900] != "ping" {
		t.Fatalf("processes = %v", got)
	}
	// Events are a scan's, not every scan's.
	if _, conns, _ = sc.Scan(context.Background()); len(conns) != 1 {
		t.Fatalf("second scan = %+v", conns)
	}
	if caps := sc.Capabilities(); caps[len(caps)-1] != "bpf-events" {
		t.Fatalf("capabilities = %v", caps)
	}
}
