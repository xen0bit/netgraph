// Package edge is netgraph-edge: VPN listeners whose traffic reports itself.
//
// It runs vpn/'s servers through the supervisor (a directory of listener
// files, host networking included) and, for each one, does two things a
// sensor on a router cannot:
//
//   - it hooks the server's sessions (client.SessionReporter), so each one's
//     authenticated identity and inner prefixes go to the netgraph server as
//     vpn_session events; and
//   - it captures the server's TUN, the inside of the tunnel, through the
//     sensor's own processor, so every flow, DNS lookup, SNI and fingerprint
//     a VPN user's traffic carries is recorded as a sensor would record it.
//
// The server attributes those flows to the sessions by address and time (see
// internal/store/vpn.go). Both halves come from the same process, so the
// evidence that an address was a user's is the handshake that proved it.
//
//	listener files ──► supervisor ──► client.Server ──┬─ SessionHook ──► vpn_session ──┐
//	                                                  └─ TUN ──► capture ──► Processor ─┴─► wire.Emitter
package edge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/netgraph/internal/buildinfo"
	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/flow"
	"github.com/xen0bit/netgraph/internal/sensor"
	"github.com/xen0bit/netgraph/internal/wire"
	"github.com/xen0bit/netgraph/vpn/client"
	"github.com/xen0bit/netgraph/vpn/supervisor"
)

// Config configures an Edge.
type Config struct {
	Name        string       // reported as the sensor name
	ListenerDir string       // the supervisor's directory of listener files
	Out         wire.Emitter // where events go: a wire.Shipper in production
	Logger      *slog.Logger
	Flow        flow.Config
	RingBytes   int // AF_PACKET ring per TUN

	// Constructor builds a listener's server; nil means client.NewServer.
	// OpenCapture opens a capture on a TUN; nil means AF_PACKET. Tests set
	// both, so an edge runs without privileges.
	Constructor supervisor.Constructor
	OpenCapture func(iface string) (capture.Source, error)
	// NoHostnet skips the supervisor's host networking, for tests.
	NoHostnet bool

	StatsEvery time.Duration // default 60s
	HelloEvery time.Duration // default 10m
}

// Edge is a running edge. Make one with New, then Run it.
type Edge struct {
	cfg  Config
	log  *slog.Logger
	mgr  *supervisor.Manager
	proc *sensor.Processor

	// local is what the processor asks to decide a flow's direction: the
	// private ranges plus every TUN's prefixes, swapped whole as listeners
	// come and go.
	local atomic.Pointer[func(netip.Addr) bool]

	// nextSession numbers sessions across every listener and rebuild, so the
	// server's (boot, listener, ID) key never sees a hub's restarted count.
	nextSession atomic.Uint64

	mu       sync.Mutex
	captures map[string]*tunCapture // listener name -> its TUN's capture
	warned   map[string]bool        // protocols already said not to report sessions
	changed  chan struct{}          // a listener started or stopped: say hello again
	started  time.Time
}

type tunCapture struct {
	iface  string
	src    capture.Source
	cancel context.CancelFunc
	done   chan struct{}
}

// New builds an Edge. It starts nothing until Run.
func New(cfg Config) *Edge {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.StatsEvery <= 0 {
		cfg.StatsEvery = time.Minute
	}
	if cfg.HelloEvery <= 0 {
		cfg.HelloEvery = 10 * time.Minute
	}
	if cfg.OpenCapture == nil {
		ring := cfg.RingBytes
		cfg.OpenCapture = func(iface string) (capture.Source, error) {
			return capture.OpenLive(capture.LiveConfig{Interface: iface, RingBytes: ring})
		}
	}
	e := &Edge{cfg: cfg, log: cfg.Logger, captures: map[string]*tunCapture{}, warned: map[string]bool{},
		changed: make(chan struct{}, 1)}
	isLocal := sensor.LocalAddr
	e.local.Store(&isLocal)
	e.proc = sensor.NewProcessor(sensor.Config{
		Flow: cfg.Flow, Logger: cfg.Logger,
		IsLocal: func(a netip.Addr) bool { return (*e.local.Load())(a) },
	}, cfg.Out)
	e.mgr = supervisor.NewManager(cfg.ListenerDir, cfg.Logger, cfg.Constructor)
	if cfg.NoHostnet {
		e.mgr.SetCommander(func(string, ...string) ([]byte, error) { return nil, nil })
	}
	e.mgr.SetHooks(e.listenerStarted, e.listenerStopped)
	return e
}

// Reload reconciles the listeners to the directory again: the SIGHUP path.
func (e *Edge) Reload() error { return e.mgr.Apply() }

// Listeners reports each listener's state.
func (e *Edge) Listeners() []supervisor.Status { return e.mgr.All() }

// Run starts the listeners and reports until ctx is cancelled, then stops
// them, which closes every open session as "shutdown", and flushes the flows.
func (e *Edge) Run(ctx context.Context) error {
	e.started = time.Now()
	e.emitHello(e.started)
	if err := e.mgr.Apply(); err != nil {
		// One bad listener does not stop the others; the supervisor has
		// already said which, and Status keeps saying it.
		e.log.Warn("edge: some listeners did not start", "err", err)
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	lastStats, lastHello := time.Now(), time.Now()
	for {
		select {
		case <-ctx.Done():
			err := e.mgr.Close()
			now := time.Now()
			e.proc.Flush(now, "shutdown")
			e.emitStats(now)
			return err
		case <-e.changed:
			now := time.Now()
			e.emitHello(now)
			lastHello = now
		case now := <-tick.C:
			e.proc.Tick(now)
			if now.Sub(lastStats) >= e.cfg.StatsEvery {
				e.emitStats(now)
				lastStats = now
			}
			if now.Sub(lastHello) >= e.cfg.HelloEvery {
				e.emitHello(now)
				lastHello = now
			}
		}
	}
}

// listenerStarted is the supervisor's start hook: before the server serves,
// hook its sessions and capture its TUN.
func (e *Edge) listenerStarted(cfg supervisor.ListenerConfig, srv client.Server) {
	if sr, ok := srv.(client.SessionReporter); ok {
		sr.SetSessionHook(e.sessionHook(cfg))
	} else {
		e.mu.Lock()
		first := !e.warned[cfg.Protocol]
		e.warned[cfg.Protocol] = true
		e.mu.Unlock()
		if first {
			e.log.Warn("edge: this protocol does not report sessions yet, so its traffic is captured but not attributed to users",
				"protocol", cfg.Protocol, "listener", cfg.Name)
		}
	}
	iface := srv.TUNName()
	if iface == "" {
		return
	}
	src, err := e.cfg.OpenCapture(iface)
	if err != nil {
		e.log.Error("edge: cannot capture the listener's TUN; its traffic will not be recorded",
			"listener", cfg.Name, "iface", iface, "err", err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &tunCapture{iface: iface, src: src, cancel: cancel, done: make(chan struct{})}
	e.mu.Lock()
	old := e.captures[cfg.Name]
	e.captures[cfg.Name] = c
	e.mu.Unlock()
	if old != nil {
		old.stop()
	}
	go e.read(ctx, c)
	e.refreshLocal()
	e.signalChange()
}

// listenerStopped is the supervisor's stop hook. The server has closed, and
// with it its sessions; the capture goes too.
func (e *Edge) listenerStopped(cfg supervisor.ListenerConfig, srv client.Server) {
	e.mu.Lock()
	c := e.captures[cfg.Name]
	if c != nil && c.iface == srv.TUNName() {
		delete(e.captures, cfg.Name)
	} else {
		c = nil // a capture a newer generation of the listener owns
	}
	e.mu.Unlock()
	if c != nil {
		c.stop()
	}
	e.refreshLocal()
	e.signalChange()
}

// sessionHook turns one listener's session events into vpn_session events.
// The hub calls it serially, so its ID map needs no lock of its own.
func (e *Edge) sessionHook(cfg supervisor.ListenerConfig) func(client.SessionEvent) {
	ids := map[uint64]uint64{}
	return func(ev client.SessionEvent) {
		id, ok := ids[ev.ID]
		if !ok {
			if !ev.Open {
				return // the open was before this hook; nothing downstream knows it
			}
			id = e.nextSession.Add(1)
			ids[ev.ID] = id
		}
		if !ev.Open {
			delete(ids, ev.ID)
		}
		e.cfg.Out.Emit(wire.Event{Type: wire.TypeVPNSession, TS: ev.Time, VPNSession: &wire.VPNSession{
			Listener: cfg.Name, Protocol: cfg.Protocol, ID: id, Open: ev.Open,
			User: ev.User, Name: ev.Name, Addrs: slices.Clone(ev.Addrs), Outer: ev.Outer, Reason: ev.Reason,
		}})
	}
}

func (e *Edge) read(ctx context.Context, c *tunCapture) {
	defer close(c.done)
	for ctx.Err() == nil {
		data, ts, err := c.src.ReadPacket()
		switch {
		case err == nil:
			e.proc.Handle(ts, data, c.src.LinkType())
		case errors.Is(err, capture.ErrTimeout):
		default:
			if ctx.Err() == nil {
				e.log.Warn("edge: capture ended", "iface", c.iface, "err", err)
			}
			return
		}
	}
}

// stop ends the reader before closing the source: closing an AF_PACKET ring
// under a reader still polling it faults.
func (c *tunCapture) stop() {
	c.cancel()
	if i, ok := c.src.(interface{ Interrupt() }); ok {
		i.Interrupt()
	}
	<-c.done
	c.src.Close()
}

func (e *Edge) ifaces() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.captures))
	for _, c := range e.captures {
		out = append(out, c.iface)
	}
	slices.Sort(out)
	return out
}

func (e *Edge) refreshLocal() {
	f := sensor.LocalChecker(sensor.InterfaceInfo(e.ifaces()))
	e.local.Store(&f)
}

func (e *Edge) signalChange() {
	select {
	case e.changed <- struct{}{}:
	default:
	}
}

func (e *Edge) emitHello(ts time.Time) {
	h := wire.Hello{
		Name: e.cfg.Name, Version: buildinfo.Version, OS: runtime.GOOS, Arch: runtime.GOARCH,
		Interfaces: sensor.InterfaceInfo(e.ifaces()), ActiveTimeout: e.cfg.Flow.ActiveTimeout,
	}
	e.cfg.Out.Emit(wire.Event{Type: wire.TypeHello, TS: ts, Hello: &h})
}

func (e *Edge) emitStats(ts time.Time) {
	pk, by, de, fl, ev := e.proc.Counters()
	st := &wire.Stats{Uptime: ts.Sub(e.started), Packets: pk, Bytes: by, DecodeErrors: de, FlowsActive: fl, FlowsEvicted: ev}
	e.mu.Lock()
	for _, c := range e.captures {
		_, dropped := c.src.Stats()
		st.KernelDrops += dropped
	}
	e.mu.Unlock()
	if s, ok := e.cfg.Out.(interface{ Stats() wire.ShipperStats }); ok {
		ss := s.Stats()
		st.EventsQueued, st.EventsDropped, st.BatchesSent, st.SendErrors = ss.Queued, ss.EventsDropped, ss.BatchesSent, ss.SendErrors
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	st.HeapBytes = ms.HeapAlloc
	e.cfg.Out.Emit(wire.Event{Type: wire.TypeStats, TS: ts, Stats: st})
}

// String names the edge for logs.
func (e *Edge) String() string { return fmt.Sprintf("edge %q (%s)", e.cfg.Name, e.cfg.ListenerDir) }
