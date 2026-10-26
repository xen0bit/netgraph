package rdns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeResolver struct {
	names map[string][]string
	err   error

	mu      sync.Mutex
	calls   map[string]int
	current int
	max     int
	block   chan struct{}
}

func (f *fakeResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	f.mu.Lock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[addr]++
	f.current++
	if f.current > f.max {
		f.max = f.current
	}
	f.mu.Unlock()
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
		}
	}
	f.mu.Lock()
	f.current--
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.names[addr], nil
}

func (f *fakeResolver) count(addr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[addr]
}

type clock struct{ atomic.Int64 }

func newClock(t time.Time) *clock {
	c := &clock{}
	c.Store(t.UnixNano())
	return c
}

func (c *clock) Now() time.Time { return time.Unix(0, c.Load()) }
func (c *clock) Add(d time.Duration) {
	c.Store(c.Load() + int64(d))
}

func TestLookupUsesObservationTime(t *testing.T) {
	f := &fakeResolver{names: map[string][]string{"192.168.1.23": {"Alice-IPhone.lan."}}}
	clk := newClock(time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC))
	got := make(chan Name, 1)
	l := New(Config{
		Resolver: f, Now: clk.Now, Workers: 1,
		Emit: func(n Name) { got <- n },
	})
	defer l.Close()

	observed := clk.Now().Add(-30 * time.Second)
	l.Observe(netip.MustParseAddr("192.168.1.23"), "3c:22:fb:01:02:03", observed)

	select {
	case n := <-got:
		if n.IP.String() != "192.168.1.23" || n.Name != "Alice-IPhone.lan" || n.MAC != "3c:22:fb:01:02:03" {
			t.Fatalf("name = %+v", n)
		}
		if !n.TS.Equal(observed) {
			t.Errorf("ts = %v, want observation time %v", n.TS, observed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lookup did not emit")
	}

	// A cached answer is not looked up again, and does not re-announce
	// until half its TTL has passed.
	l.Observe(netip.MustParseAddr("192.168.1.23"), "", clk.Now())
	if n := f.count("192.168.1.23"); n != 1 {
		t.Errorf("lookups = %d, want 1", n)
	}
	select {
	case n := <-got:
		t.Errorf("unexpected re-announcement: %+v", n)
	case <-time.After(50 * time.Millisecond):
	}
	clk.Add(31 * time.Minute)
	l.Observe(netip.MustParseAddr("192.168.1.23"), "", clk.Now())
	select {
	case n := <-got:
		if n.Name != "Alice-IPhone.lan" {
			t.Errorf("re-announcement = %+v", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no re-announcement after half TTL")
	}
	if n := f.count("192.168.1.23"); n != 1 {
		t.Errorf("lookups after cache hit = %d, want 1", n)
	}
}

func TestLookupNegativeCacheAndRetry(t *testing.T) {
	f := &fakeResolver{err: errors.New("no such host")}
	clk := newClock(time.Now())
	l := New(Config{Resolver: f, Now: clk.Now, Workers: 1, NegativeTTL: time.Minute})
	defer l.Close()

	ip := netip.MustParseAddr("192.168.1.99")
	l.Observe(ip, "", clk.Now())
	waitFor(t, func() bool { return f.count(ip.String()) == 1 })
	l.Observe(ip, "", clk.Now())
	if n := f.count(ip.String()); n != 1 {
		t.Fatalf("negative cache did not hold: %d lookups", n)
	}
	clk.Add(2 * time.Minute)
	l.Observe(ip, "", clk.Now())
	waitFor(t, func() bool { return f.count(ip.String()) == 2 })
}

func TestLookupBoundsConcurrency(t *testing.T) {
	f := &fakeResolver{block: make(chan struct{}), names: map[string][]string{}}
	l := New(Config{Resolver: f, Workers: 2})
	defer l.Close()
	for i := 1; i <= 8; i++ {
		l.Observe(netip.MustParseAddr(fmt.Sprintf("192.168.1.%d", i)), "", time.Now())
	}
	time.Sleep(50 * time.Millisecond)
	f.mu.Lock()
	max := f.max
	f.mu.Unlock()
	if max > 2 {
		t.Errorf("max concurrent lookups = %d, want <= 2", max)
	}
	close(f.block)
}

func TestObserveSkipsUnusableAddresses(t *testing.T) {
	f := &fakeResolver{}
	l := New(Config{Resolver: f, Workers: 1})
	defer l.Close()
	now := time.Now()
	for _, s := range []string{"", "0.0.0.0", "224.0.0.251", "127.0.0.1", "ff02::1"} {
		if s == "" {
			l.Observe(netip.Addr{}, "", now)
			continue
		}
		l.Observe(netip.MustParseAddr(s), "", now)
	}
	if len(f.calls) != 0 {
		t.Errorf("queried unusable addresses: %v", f.calls)
	}
}

func TestFirstName(t *testing.T) {
	if got := firstName([]string{"", " z.lan. ", "a.lan."}); got != "a.lan" {
		t.Errorf("firstName = %q", got)
	}
	if got := firstName(nil); got != "" {
		t.Errorf("empty firstName = %q", got)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}
