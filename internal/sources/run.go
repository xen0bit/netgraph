package sources

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

// Sink takes events: the store's Ingest.
type Sink func(ctx context.Context, sensor, boot string, events []wire.Event) error

// DefaultLocal is what counts as "here" unless told otherwise.
var DefaultLocal = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// publisher sends a source's events the way a sensor would: numbered, batched, and
// introduced with a hello, so it reads as a sensor everywhere else.
type publisher struct {
	name, boot string
	local      []netip.Prefix
	sink       Sink
	log        *slog.Logger
	seq        uint64
	said       time.Time
}

func newPublisher(name string, local []netip.Prefix, sink Sink, log *slog.Logger) *publisher {
	if len(local) == 0 {
		local = DefaultLocal
	}
	return &publisher{name: name, boot: fmt.Sprint(time.Now().UnixNano()), local: local, sink: sink, log: log}
}

const helloEvery = time.Minute

func (p *publisher) send(ctx context.Context, evs []wire.Event) {
	now := time.Now()
	if now.Sub(p.said) >= helloEvery {
		p.said = now
		evs = append([]wire.Event{{Type: wire.TypeHello, TS: now, Hello: &wire.Hello{Name: p.name, Version: "source",
			Interfaces: []wire.Interface{{Name: p.name, Prefixes: p.local}}}}}, evs...)
	}
	if len(evs) == 0 {
		return
	}
	for i := range evs {
		p.seq++
		evs[i].Seq = p.seq
	}
	if err := p.sink(ctx, p.name, p.boot, evs); err != nil && ctx.Err() == nil {
		// Not retried: a source's next report says most of it again, and holding these
		// would grow without bound if the database stayed unhappy.
		p.log.Warn("source lost a batch", "source", p.name, "events", len(evs), "err", err)
	}
}

// NetFlow listens for exports. UDP has no authentication and a source address is easily
// faked on an open network, so Allow is required: it's what stops anyone reaching this
// port from writing traffic into the record.
type NetFlow struct {
	Listen string
	Allow  []netip.Prefix
	Local  []netip.Prefix
	Sink   Sink
	Log    *slog.Logger
	// Ready, if set, is told the address once it's listening.
	Ready func(addr string)
}

const (
	maxExporters    = 64
	netflowBatch    = 500
	netflowInterval = 2 * time.Second
)

type exporter struct {
	tmpl Templates
	pub  *publisher
	evs  []wire.Event
}

// Run listens until ctx ends.
func (n *NetFlow) Run(ctx context.Context) error {
	if len(n.Allow) == 0 {
		return errors.New("netflow: needs addresses to accept exports from")
	}
	if n.Log == nil {
		n.Log = slog.Default()
	}
	conn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", n.Listen)
	if err != nil {
		return err
	}
	defer conn.Close()
	if n.Ready != nil {
		n.Ready(conn.LocalAddr().String())
	}
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	exporters := map[netip.Addr]*exporter{}
	flush := func() {
		for _, e := range exporters {
			evs := e.evs
			e.evs = nil
			e.pub.send(ctx, evs)
		}
	}
	buf := make([]byte, 65535)
	last := time.Now()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(netflowInterval))
		size, addr, err := conn.ReadFrom(buf)
		if ctx.Err() != nil {
			flush()
			return nil
		}
		if time.Since(last) >= netflowInterval {
			flush()
			last = time.Now()
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		from := ua.AddrPort().Addr().Unmap()
		if !allowed(n.Allow, from) {
			continue
		}
		e := exporters[from]
		if e == nil {
			if len(exporters) >= maxExporters {
				continue
			}
			e = &exporter{pub: newPublisher("netflow-"+from.String(), n.Local, n.Sink, n.Log)}
			exporters[from] = e
			n.Log.Info("netflow: a new exporter", "from", from)
		}
		now := time.Now()
		flows, err := ParseNetFlow(buf[:size], &e.tmpl, now)
		if err != nil {
			n.Log.Debug("netflow: a datagram didn't parse", "from", from, "err", err)
		}
		for i := range flows {
			f := flows[i]
			e.evs = append(e.evs, wire.Event{Type: wire.TypeFlow, TS: f.End, Flow: &f})
		}
		if len(e.evs) >= netflowBatch {
			evs := e.evs
			e.evs = nil
			e.pub.send(ctx, evs)
		}
	}
}

func allowed(list []netip.Prefix, a netip.Addr) bool {
	for _, p := range list {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// DNSLog follows a DNS server's log file.
type DNSLog struct {
	Path   string
	Format string // dnsmasq (also Pi-hole) or adguard
	Local  []netip.Prefix
	Sink   Sink
	Log    *slog.Logger
	Every  time.Duration
	// FromStart reads what's already in the file. Otherwise it begins at the end: an
	// old log's lookups would arrive looking new.
	FromStart bool
}

// ValidDNSLogFormat says whether a format is one this reads.
func ValidDNSLogFormat(f string) bool { return f == "dnsmasq" || f == "adguard" }

// Run follows the file until ctx ends, across rotations, and through it not existing.
func (d *DNSLog) Run(ctx context.Context) error {
	if !ValidDNSLogFormat(d.Format) {
		return fmt.Errorf("dns log: format %q", d.Format)
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Every <= 0 {
		d.Every = 2 * time.Second
	}
	pub := newPublisher("dnslog", d.Local, d.Sink, d.Log)
	parser := &DNSMasqLog{History: d.FromStart}
	t := follower{path: d.Path, atEnd: !d.FromStart}
	tick := time.NewTicker(d.Every)
	defer tick.Stop()
	defer t.close()
	for {
		var evs []wire.Event
		t.read(func(line string) {
			if d.Format == "adguard" {
				if e, ok := AdGuardLine(line); ok {
					evs = append(evs, e)
				}
				return
			}
			evs = append(evs, parser.Line(line)...)
		})
		evs = append(evs, parser.Tick()...)
		pub.send(ctx, evs)
		select {
		case <-ctx.Done():
			pub.send(context.WithoutCancel(ctx), parser.Close())
			return nil
		case <-tick.C:
		}
	}
}

// follower reads lines added to a file, noticing when it's been replaced or cut short.
type follower struct {
	path   string
	atEnd  bool
	f      *os.File
	r      *bufio.Reader
	off    int64
	info   os.FileInfo
	partly strings.Builder
}

func (t *follower) close() {
	if t.f != nil {
		t.f.Close()
		t.f = nil
	}
}

func (t *follower) open() bool {
	f, err := os.Open(t.path)
	if err != nil {
		return false
	}
	t.info, err = f.Stat()
	if err != nil {
		f.Close()
		return false
	}
	t.f, t.off = f, 0
	if t.atEnd {
		t.off, _ = f.Seek(0, io.SeekEnd)
		t.atEnd = false
	}
	t.r = bufio.NewReaderSize(f, 64<<10)
	t.partly.Reset()
	return true
}

func (t *follower) read(line func(string)) {
	if st, err := os.Stat(t.path); t.f != nil && (err != nil || !os.SameFile(st, t.info) || st.Size() < t.off) {
		t.close() // rotated away, or truncated
	}
	if t.f == nil && !t.open() {
		return
	}
	for {
		part, err := t.r.ReadString('\n')
		t.off += int64(len(part))
		if t.partly.Len()+len(part) <= maxLogLine {
			t.partly.WriteString(part)
		}
		if err != nil {
			return // the rest of this line comes later
		}
		if t.partly.Len() <= maxLogLine {
			line(strings.TrimRight(t.partly.String(), "\r\n"))
		}
		t.partly.Reset()
	}
}

// LeaseFile watches a DHCP server's lease file.
type LeaseFile struct {
	Path  string
	Local []netip.Prefix
	Sink  Sink
	Log   *slog.Logger
	Every time.Duration
}

// Run reports the leases until ctx ends. Each lease is said again every time round, to
// keep the fact that a device holds the address open, just as hearing it would.
func (l *LeaseFile) Run(ctx context.Context) error {
	if l.Log == nil {
		l.Log = slog.Default()
	}
	if l.Every <= 0 {
		l.Every = time.Minute
	}
	pub := newPublisher("leases", l.Local, l.Sink, l.Log)
	tick := time.NewTicker(l.Every)
	defer tick.Stop()
	for {
		if b, err := os.ReadFile(l.Path); err != nil {
			l.Log.Debug("lease file", "err", err)
		} else {
			now := time.Now()
			var evs []wire.Event
			for _, lease := range ParseDNSMasqLeases(string(b)) {
				if lease.Expires.IsZero() || lease.Expires.After(now) {
					evs = append(evs, LeaseEvents(lease, now)...)
				}
			}
			pub.send(ctx, evs)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
