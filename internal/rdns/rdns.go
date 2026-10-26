// Package rdns resolves reverse DNS (PTR) names for local hosts as they are
// observed.
//
// Lookups are active, so they are kept out of the packet path: Observe only
// records that an address was seen and hands the work to a small, bounded
// worker pool. Results are emitted with the timestamp of the observation
// that asked for them, not the time the resolver answered, so a window shows
// the name the host had when it was on the network. Positive and negative
// answers are cached, and a host is never looked up concurrently with
// itself.
package rdns

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Resolver is the part of *net.Resolver this package needs. Tests provide a
// fake; production uses the system resolver.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Config tunes a Lookup.
type Config struct {
	// Resolver answers PTR queries. The zero value uses net.DefaultResolver.
	Resolver Resolver
	// Timeout bounds one lookup (default 2s).
	Timeout time.Duration
	// TTL is how long a successful answer is reused (default 1h).
	TTL time.Duration
	// NegativeTTL is how long a missing name is remembered (default 10m).
	NegativeTTL time.Duration
	// Workers bounds concurrent lookups (default 4).
	Workers int
	// Queue bounds observations waiting for a worker (default 256).
	Queue int
	// Now is the clock; tests set it.
	Now func() time.Time
	// Logger receives lookup failures. Optional.
	Logger *slog.Logger
	// Emit receives a name when a lookup succeeds. It may be called from
	// several workers at once.
	Emit func(Name)
}

// Name is one resolved reverse name.
type Name struct {
	IP   netip.Addr
	Name string
	MAC  string
	TS   time.Time // when the address was observed
}

type entry struct {
	name     string
	expires  time.Time
	lastEmit time.Time
}

type job struct {
	ip  netip.Addr
	mac string
	ts  time.Time
}

// Lookup resolves host names in the background. It is safe for concurrent
// use.
type Lookup struct {
	cfg Config
	log *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	jobs   chan job
	wg     sync.WaitGroup

	mu       sync.Mutex
	cache    map[netip.Addr]entry
	inflight map[netip.Addr]bool
}

// New starts a Lookup. Call Close to stop it.
func New(cfg Config) *Lookup {
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.TTL <= 0 {
		cfg.TTL = time.Hour
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = 10 * time.Minute
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.Queue <= 0 {
		cfg.Queue = 256
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &Lookup{
		cfg: cfg, log: cfg.Logger, ctx: ctx, cancel: cancel,
		jobs:     make(chan job, cfg.Queue),
		cache:    map[netip.Addr]entry{},
		inflight: map[netip.Addr]bool{},
	}
	for range cfg.Workers {
		l.wg.Add(1)
		go l.work()
	}
	return l
}

// Observe records that ip was seen at ts. It only enqueues work; it never
// blocks on the network.
func (l *Lookup) Observe(ip netip.Addr, mac string, ts time.Time) {
	if !ip.IsValid() || l.ctx.Err() != nil {
		return
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return
	}
	now := l.cfg.Now()
	l.mu.Lock()
	if len(l.cache) > 100_000 {
		for k, e := range l.cache {
			if now.After(e.expires) {
				delete(l.cache, k)
			}
		}
		if len(l.cache) > 100_000 {
			clear(l.cache)
		}
	}
	if e, ok := l.cache[ip]; ok && now.Before(e.expires) {
		// Re-announce a cached name occasionally so the server's hostname
		// fact keeps its period open, but never once per packet.
		if e.name != "" && now.Sub(e.lastEmit) >= l.cfg.TTL/2 {
			l.cache[ip] = entry{name: e.name, expires: e.expires, lastEmit: now}
			l.mu.Unlock()
			l.emit(Name{IP: ip, Name: e.name, MAC: mac, TS: ts})
			return
		}
		l.mu.Unlock()
		return
	}
	if l.inflight[ip] {
		l.mu.Unlock()
		return
	}
	l.inflight[ip] = true
	l.mu.Unlock()
	select {
	case l.jobs <- job{ip: ip, mac: mac, ts: ts}:
	case <-l.ctx.Done():
		l.clearInflight(ip)
	default:
		// The queue is full: forget this one and try on a later
		// observation instead of growing without bound.
		l.clearInflight(ip)
	}
}

func (l *Lookup) work() {
	defer l.wg.Done()
	for {
		select {
		case <-l.ctx.Done():
			return
		case j := <-l.jobs:
			l.resolve(j)
		}
	}
}

func (l *Lookup) resolve(j job) {
	ctx, cancel := context.WithTimeout(l.ctx, l.cfg.Timeout)
	names, err := l.cfg.Resolver.LookupAddr(ctx, j.ip.String())
	cancel()
	name := firstName(names)
	now := l.cfg.Now()
	l.mu.Lock()
	if err != nil || name == "" {
		if err != nil && l.ctx.Err() == nil {
			l.log.Debug("reverse lookup", "ip", j.ip, "err", err)
		}
		l.cache[j.ip] = entry{expires: now.Add(l.cfg.NegativeTTL)}
		delete(l.inflight, j.ip)
		l.mu.Unlock()
		return
	}
	l.cache[j.ip] = entry{name: name, expires: now.Add(l.cfg.TTL), lastEmit: now}
	delete(l.inflight, j.ip)
	l.mu.Unlock()
	l.emit(Name{IP: j.ip, Name: name, MAC: j.mac, TS: j.ts})
}

func (l *Lookup) emit(n Name) {
	if l.cfg.Emit != nil {
		l.cfg.Emit(n)
	}
}

func (l *Lookup) clearInflight(ip netip.Addr) {
	l.mu.Lock()
	delete(l.inflight, ip)
	l.mu.Unlock()
}

// Close stops the workers. A lookup already in flight is bounded by Timeout,
// so Close waits at most that long for it.
func (l *Lookup) Close() {
	l.cancel()
	l.wg.Wait()
}

// firstName picks the most useful name from a PTR answer: the first
// non-empty one, without its trailing dot. Multiple names are sorted so a
// resolver that answers in a different order does not flip the label.
func firstName(names []string) string {
	clean := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSuffix(strings.TrimSpace(n), ".")
		if n != "" {
			clean = append(clean, n)
		}
	}
	if len(clean) == 0 {
		return ""
	}
	sort.Strings(clean)
	return clean[0]
}
