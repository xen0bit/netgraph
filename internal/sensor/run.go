package sensor

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/wire"
)

// Runner drives sources into a processor.
type Runner struct {
	Processor *Processor
	Out       wire.Emitter
	Hello     wire.Hello
	// HelloFunc, when set, rebuilds Hello for a periodic or post-reopen event.
	HelloFunc func() wire.Hello
	// ShipperStats, when set, is folded into stats events.
	ShipperStats func() wire.ShipperStats

	StatsEvery time.Duration // default 60s
	HelloEvery time.Duration // default 10m

	started time.Time
	sources []capture.Source
}

// RunLive captures from live sources until ctx is cancelled, then flushes
// every open flow.
func (r *Runner) RunLive(ctx context.Context, sources []capture.Source) error {
	r.started = time.Now()
	r.sources = sources
	if r.StatsEvery <= 0 {
		r.StatsEvery = time.Minute
	}
	if r.HelloEvery <= 0 {
		r.HelloEvery = 10 * time.Minute
	}
	r.emitHello(time.Now())

	// Readers get their own context so one failing source stops the rest,
	// and so they have all returned before any ring is unmapped: closing an
	// AF_PACKET source under a reader that is still polling it faults.
	capCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, len(sources))
	var wg sync.WaitGroup
	for _, s := range sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errc <- r.capture(capCtx, s)
		}()
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	lastStats, lastHello := time.Now(), time.Now()
	var err error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case err = <-errc:
			if err != nil {
				break loop
			}
		case now := <-tick.C:
			r.Processor.Tick(now)
			if now.Sub(lastStats) >= r.StatsEvery {
				r.emitStats(now)
				lastStats = now
			}
			if now.Sub(lastHello) >= r.HelloEvery {
				r.emitHello(now)
				lastHello = now
			}
		}
	}
	// A reconnecting source may be waiting to reopen; wake it before
	// cancelling the readers so shutdown is prompt.
	for _, s := range sources {
		if i, ok := s.(interface{ Interrupt() }); ok {
			i.Interrupt()
		}
	}
	cancel()
	wg.Wait()
	for _, s := range sources {
		s.Close()
	}
	now := time.Now()
	r.Processor.Flush(now, "shutdown")
	r.emitStats(now)
	return err
}

func (r *Runner) capture(ctx context.Context, s capture.Source) error {
	for ctx.Err() == nil {
		data, ts, err := s.ReadPacket()
		switch {
		case err == nil:
			r.Processor.Handle(ts, data, s.LinkType())
		case errors.Is(err, capture.ErrTimeout):
		case ctx.Err() != nil:
			return nil
		default:
			return err
		}
	}
	return nil
}

// RunFile replays a capture file on packet time: flows expire and DNS
// queries time out as they would have live, so a replay produces the same
// events the sensor would have sent at the time. At EOF every flow is
// finished with reason "shutdown".
func (r *Runner) RunFile(ctx context.Context, s capture.Source) error {
	r.sources = []capture.Source{s}
	defer s.Close()
	var clock, lastTick time.Time
	for ctx.Err() == nil {
		data, ts, err := s.ReadPacket()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if r.started.IsZero() {
			r.started = ts
			r.emitHello(ts)
		}
		if ts.After(clock) {
			clock = ts
		}
		r.Processor.Handle(ts, data, s.LinkType())
		if clock.Sub(lastTick) >= time.Second {
			r.Processor.Tick(clock)
			lastTick = clock
		}
	}
	if !clock.IsZero() {
		r.Processor.Flush(clock, "shutdown")
		r.emitStats(clock)
	}
	return ctx.Err()
}

func (r *Runner) emitHello(ts time.Time) {
	h := r.Hello
	if r.HelloFunc != nil {
		h = r.HelloFunc()
	}
	r.Out.Emit(wire.Event{Type: wire.TypeHello, TS: ts, Hello: &h})
}

// RefreshHello emits a new hello immediately, after a capture source was
// reopened and its addresses may have changed.
func (r *Runner) RefreshHello() {
	r.emitHello(time.Now())
}

func (r *Runner) emitStats(ts time.Time) {
	pk, by, de, fl, ev := r.Processor.Counters()
	st := &wire.Stats{
		Uptime: ts.Sub(r.started), Packets: pk, Bytes: by, DecodeErrors: de, FlowsActive: fl, FlowsEvicted: ev,
	}
	for _, s := range r.sources {
		_, dropped := s.Stats()
		st.KernelDrops += dropped
	}
	if r.ShipperStats != nil {
		ss := r.ShipperStats()
		st.EventsQueued, st.EventsDropped, st.BatchesSent, st.SendErrors = ss.Queued, ss.EventsDropped, ss.BatchesSent, ss.SendErrors
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	st.HeapBytes = ms.HeapAlloc
	r.Out.Emit(wire.Event{Type: wire.TypeStats, TS: ts, Stats: st})
}

// InterfaceInfo describes the named interfaces for a hello event.
func InterfaceInfo(names []string) []wire.Interface {
	var out []wire.Interface
	for _, n := range names {
		ifc, err := net.InterfaceByName(n)
		if err != nil {
			out = append(out, wire.Interface{Name: n})
			continue
		}
		wi := wire.Interface{Name: n}
		if len(ifc.HardwareAddr) > 0 {
			wi.MAC = ifc.HardwareAddr.String()
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				wi.Prefixes = append(wi.Prefixes, p)
			}
		}
		out = append(out, wi)
	}
	return out
}
