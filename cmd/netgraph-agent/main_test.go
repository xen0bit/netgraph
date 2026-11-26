package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/agent/enforce"
)

// The other binaries answer `version`; so does this one, before it needs a
// token or a server.
func TestVersion(t *testing.T) {
	for _, arg := range []string{"version", "-version", "--version"} {
		if err := run(context.Background(), []string{arg}); err != nil {
			t.Errorf("%s: %v", arg, err)
		}
	}
}

func TestResolveServer(t *testing.T) {
	ctx := context.Background()
	// A literal address is not looked up, and comes back unmapped and
	// unzoned, as the scanner reports peers.
	for _, c := range []struct{ server, want string }{
		{"http://192.0.2.10:8443", "192.0.2.10"},
		{"https://[2001:db8::1]:8443", "2001:db8::1"},
		{"https://[::ffff:192.0.2.10]:8443", "192.0.2.10"},
		{"http://[fe80::1%25eth0]:8443", "fe80::1"},
	} {
		looked := false
		got, err := resolveServer(ctx, c.server, func(context.Context, string) ([]netip.Addr, error) {
			looked = true
			return nil, nil
		})
		if err != nil || len(got) != 1 || got[0].String() != c.want || looked {
			t.Errorf("%s = %v, %v (looked %v); want %s", c.server, got, err, looked, c.want)
		}
	}

	var host string
	got, err := resolveServer(ctx, "https://netgraph.lan:8443", func(_ context.Context, h string) ([]netip.Addr, error) {
		host = h
		return []netip.Addr{
			netip.MustParseAddr("2001:db8::10"),
			netip.MustParseAddr("::ffff:192.0.2.10"),
			netip.MustParseAddr("2001:db8::10"), // a duplicate
			{},                                  // invalid
		}, nil
	})
	if err != nil || host != "netgraph.lan" || len(got) != 2 ||
		got[0].String() != "2001:db8::10" || got[1].String() != "192.0.2.10" {
		t.Fatalf("hostname = %v, %v, host %q", got, err, host)
	}

	if _, err := resolveServer(ctx, "http://", lookupServer); err == nil {
		t.Error("a server URL with no host was accepted")
	}
	if _, err := resolveServer(ctx, "https://netgraph.lan", func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("no such host")
	}); err == nil || !strings.Contains(err.Error(), "enforcement must not drop") {
		t.Errorf("lookup failure = %v", err)
	}
	if _, err := resolveServer(ctx, "https://netgraph.lan", func(context.Context, string) ([]netip.Addr, error) {
		return nil, nil
	}); err == nil {
		t.Error("a name with no addresses was accepted")
	}
}

// A lookup can't make the protected set unbounded.
func TestResolveServerBound(t *testing.T) {
	var many []netip.Addr
	for i := range maxServerAddrs + 10 {
		many = append(many, netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", i/256, i%256)))
	}
	got, err := resolveServer(context.Background(), "https://netgraph.lan", func(context.Context, string) ([]netip.Addr, error) {
		return many, nil
	})
	if err != nil || len(got) != maxServerAddrs {
		t.Fatalf("%d addresses, %v", len(got), err)
	}
}

func TestServerGuardRefresh(t *testing.T) {
	old, next := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")
	set := enforce.NewProtect([]netip.Addr{old})
	fail := false
	lookup := func(context.Context, string) ([]netip.Addr, error) {
		if fail {
			return nil, errors.New("temporary failure in name resolution")
		}
		return []netip.Addr{next}, nil
	}
	var logs []string
	g := &serverGuard{server: "https://netgraph.lan:8443", protect: set, lookup: lookup,
		logf: func(format string, a ...any) { logs = append(logs, fmt.Sprintf(format, a...)) }}
	if !g.refresh(context.Background()) || set.Contains(old) || !set.Contains(next) {
		t.Fatalf("refresh: protected = %v %v", set.Contains(old), set.Contains(next))
	}
	// A failed lookup keeps the addresses already known: a blip must not
	// make the server droppable.
	fail = true
	if g.refresh(context.Background()) || !set.Contains(next) {
		t.Fatalf("failed refresh changed the set")
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "keeping 1 addresses protected") {
		t.Fatalf("logs = %q", logs)
	}
}

func TestServerGuardAfterErrorIsThrottled(t *testing.T) {
	lookups := 0
	g := &serverGuard{server: "https://netgraph.lan", protect: enforce.NewProtect(nil),
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			lookups++
			return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
		}}
	g.refreshAfterError(context.Background())
	if lookups != 1 {
		t.Fatalf("lookups = %d", lookups)
	}
	// The first resolution just happened: a second failed request doesn't
	// resolve again.
	g.refreshAfterError(context.Background())
	if lookups != 1 {
		t.Fatalf("lookups after a recent resolution = %d", lookups)
	}
	// Once the minute has passed, it does.
	g.mu.Lock()
	g.last = time.Now().Add(-serverResolveMin - time.Second)
	g.mu.Unlock()
	g.refreshAfterError(context.Background())
	if lookups != 2 {
		t.Fatalf("lookups after the throttle = %d", lookups)
	}
}

// run re-resolves on its ticker until the context ends.
func TestServerGuardRun(t *testing.T) {
	looked := make(chan struct{}, 1)
	g := &serverGuard{server: "https://netgraph.lan", protect: enforce.NewProtect(nil), every: time.Millisecond,
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			select {
			case looked <- struct{}{}:
			default:
			}
			return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
		}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.run(ctx); close(done) }()
	select {
	case <-looked:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("run never resolved the server")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop with the context")
	}
	if !g.protect.Contains(netip.MustParseAddr("192.0.2.10")) {
		t.Fatal("run did not set the protected addresses")
	}
}
