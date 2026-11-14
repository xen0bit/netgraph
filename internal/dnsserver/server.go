// Package dnsserver is netgraph's own DNS server: it answers lookups for the
// clients it is allowed to serve by forwarding them to upstream resolvers,
// refuses names a blocklist or a person's rule names, and records every
// lookup as a DNS event, as a sensor would.
//
// It is the second of two places netgraph acts on traffic rather than only
// watching it (the first is the host agent's opt-in nftables table). It is off
// unless netgraph serve is given -dns-listen; it answers only clients in its
// allow-list, so it can't become an open resolver; and it refuses only names
// an explicit rule or an enabled blocklist matched. It never touches a
// firewall. Requests are bytes from the network: every length is bounded and
// the request path has a fuzz target.
package dnsserver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/xen0bit/netgraph/internal/decode"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/sources"
	"github.com/xen0bit/netgraph/internal/wire"
)

// Block modes: what a refused name is answered with.
const (
	BlockNull     = "null"     // 0.0.0.0 and ::, so the client fails at once (AdGuard's default)
	BlockNXDomain = "nxdomain" // "no such name"
	BlockRefused  = "refused"  // REFUSED
)

const (
	// maxUDP is the largest answer sent over UDP, whatever a client's EDNS
	// says: the DNS Flag Day 2020 size, which avoids fragmentation.
	maxUDP = 1232
	// maxInflight bounds the lookups answered at once, over UDP and TCP.
	maxInflight = 256
	// maxTCPConns bounds TCP connections, and tcpIdle how long one may wait
	// between queries.
	maxTCPConns = 64
	// blockTTL is the TTL of a refused answer: short, so lifting a block
	// shows soon.
	blockTTL = 10
	// refusedPerSecond bounds the REFUSED answers sent to clients outside the
	// allow-list, so this can't be used to reflect traffic at someone.
	refusedPerSecond = 20
)

// tcpIdle is how long a TCP connection may wait between queries.
const tcpIdle = 10 * time.Second

// Config is how the server runs.
type Config struct {
	// Listen is the address for UDP and TCP, such as ":53".
	Listen string
	// Allow is who may ask. Empty means the private ranges, loopback and
	// link-local: never the whole internet.
	Allow     []netip.Prefix
	Upstreams []Upstream
	// BlockMode is BlockNull (the default), BlockNXDomain or BlockRefused.
	BlockMode string
	// Client says who holds an address. Nil: everyone is unknown.
	Client func(netip.Addr) Client
	// Record receives every answered lookup, in batches.
	Record func(ctx context.Context, events []wire.Event)
	Log    *slog.Logger
}

// DefaultAllow is who may ask when Config.Allow is empty.
var DefaultAllow = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("::1/128"),
}

// Server is a running DNS server.
type Server struct {
	cfg   Config
	pool  *pool
	cache *cache
	rules atomic.Pointer[Rules]
	log   *slog.Logger

	rulesAt  atomic.Int64
	rulesErr atomic.Pointer[string]

	queries, blocked, hits, refused, failed, dropped atomic.Uint64

	inflight chan struct{}
	events   chan wire.Event
	limiter  limiter
	listen   []string
	mu       sync.Mutex
	idle     time.Duration // tcpIdle, but a test's to shorten
	locals   sync.Map      // client -> this host's address toward it
	localsN  atomic.Int64
}

// New makes a server; Run starts it.
func New(cfg Config) (*Server, error) {
	if len(cfg.Upstreams) == 0 {
		return nil, errors.New("the DNS server needs an upstream resolver (-dns-upstream-file)")
	}
	switch cfg.BlockMode {
	case "":
		cfg.BlockMode = BlockNull
	case BlockNull, BlockNXDomain, BlockRefused:
	default:
		return nil, errors.New("-dns-block-mode must be null, nxdomain or refused")
	}
	if len(cfg.Allow) == 0 {
		cfg.Allow = DefaultAllow
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	s := &Server{cfg: cfg, pool: newPool(cfg.Upstreams), cache: newCache(), log: cfg.Log,
		inflight: make(chan struct{}, maxInflight), events: make(chan wire.Event, 4096), idle: tcpIdle}
	s.limiter.per = refusedPerSecond
	return s, nil
}

// SetRules swaps in a new snapshot of what is blocked. err, when not nil, says
// why the newest one couldn't be read (the old one stays).
func (s *Server) SetRules(r *Rules, err error) {
	if err != nil {
		msg := err.Error()
		s.rulesErr.Store(&msg)
		return
	}
	s.rules.Store(r)
	s.rulesErr.Store(nil)
	s.rulesAt.Store(time.Now().UnixMilli())
	// An answer kept from before may have a CNAME the new rules refuse.
	s.cache.clear()
}

// Run serves until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", s.cfg.Listen)
	if err != nil {
		return err
	}
	ln, err := lc.Listen(ctx, "tcp", s.cfg.Listen)
	if err != nil {
		pc.Close()
		return err
	}
	s.mu.Lock()
	s.listen = []string{"udp " + pc.LocalAddr().String(), "tcp " + ln.Addr().String()}
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		pc.Close()
		ln.Close()
	}()
	go s.recorder(ctx)
	errc := make(chan error, 2)
	go func() { errc <- s.serveUDP(ctx, pc) }()
	go func() { errc <- s.serveTCP(ctx, ln) }()
	err = <-errc
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// Addrs are the addresses it listens on, once running.
func (s *Server) Addrs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.listen...)
}

func (s *Server) serveUDP(ctx context.Context, pc net.PacketConn) error {
	buf := make([]byte, maxMessage)
	local := addrOf(pc.LocalAddr())
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		client := addrOf(from)
		here := local
		if !here.IsValid() || here.IsUnspecified() {
			here = s.localFor(client)
		}
		req := append([]byte(nil), buf[:n]...)
		select {
		case s.inflight <- struct{}{}:
		default:
			s.dropped.Add(1) // too busy: a client retries
			continue
		}
		go func() {
			defer func() { <-s.inflight }()
			if out := s.Handle(ctx, req, client, here, "udp"); out != nil {
				_, _ = pc.WriteTo(out, from)
			}
		}()
	}
}

func (s *Server) serveTCP(ctx context.Context, ln net.Listener) error {
	conns := make(chan struct{}, maxTCPConns)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case conns <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-conns }()
			defer c.Close()
			s.serveConn(ctx, c)
		}()
	}
}

// serveConn answers length-prefixed queries on one TCP connection, in turn,
// until it goes quiet.
func (s *Server) serveConn(ctx context.Context, c net.Conn) {
	client, local := addrOf(c.RemoteAddr()), addrOf(c.LocalAddr())
	var l [2]byte
	for ctx.Err() == nil {
		_ = c.SetDeadline(time.Now().Add(s.idle))
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(l[:])
		if n < 12 {
			return
		}
		req := make([]byte, n)
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		s.inflight <- struct{}{}
		out := s.Handle(ctx, req, client, local, "tcp")
		<-s.inflight
		if out == nil {
			return
		}
		msg := make([]byte, 2+len(out))
		binary.BigEndian.PutUint16(msg, uint16(len(out)))
		copy(msg[2:], out)
		if _, err := c.Write(msg); err != nil {
			return
		}
	}
}

// localFor is this host's address toward client: on a wildcard UDP socket
// the address a query came in on isn't known, and it is almost always the
// one the route back uses. It is found by connecting a UDP socket, which
// sends nothing, and kept per client.
func (s *Server) localFor(client netip.Addr) netip.Addr {
	if v, ok := s.locals.Load(client); ok {
		return v.(netip.Addr)
	}
	var here netip.Addr
	if c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(client, 9))); err == nil {
		here = addrOf(c.LocalAddr())
		c.Close()
	}
	if s.localsN.Add(1) > 4096 { // bounded: forget them all now and then
		s.locals.Clear()
		s.localsN.Store(0)
	}
	s.locals.Store(client, here)
	return here
}

func addrOf(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	}
	return netip.Addr{}
}

func (s *Server) allowed(a netip.Addr) bool {
	for _, p := range s.cfg.Allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Handle answers one query from client, received on local over proto (udp
// or tcp). It returns nil when there is nothing to send: not a query, or a
// refusal over the rate limit.
func (s *Server) Handle(ctx context.Context, req []byte, client, local netip.Addr, proto string) []byte {
	if len(req) < 12 || len(req) > maxMessage {
		return nil
	}
	start := time.Now()
	rd := req[2]&0x01 != 0
	id0, id1 := req[0], req[1]
	if req[2]&0x80 != 0 {
		return nil // a response: never answer one
	}
	// Strangers get a REFUSED, at most so many a second, whatever they sent:
	// nothing else is said to an address outside the allow-list.
	if !s.allowed(client) {
		s.refused.Add(1)
		if !s.limiter.allow(time.Now()) {
			return nil
		}
		return reply(id0, id1, rd, dnsmessage.RCodeRefused, nil)
	}
	m, err := decode.ParseDNS(req)
	if err != nil {
		// A header we can read is owed an answer: the question was bad.
		return reply(id0, id1, rd, dnsmessage.RCodeFormatError, nil)
	}
	if m.Opcode != 0 {
		return reply(id0, id1, rd, dnsmessage.RCodeNotImplemented, nil)
	}
	if len(m.Questions) != 1 {
		return reply(id0, id1, rd, dnsmessage.RCodeFormatError, nil)
	}
	q := m.Questions[0]
	s.queries.Add(1)
	limit := maxMessage
	edns := false
	do := false
	for _, a := range m.Additional {
		if a.Type == 41 { // OPT: its class is the client's UDP size
			edns = true
			do = a.TTL&0x8000 != 0
			if proto == "udp" {
				limit = min(max(int(a.Class), 512), maxUDP)
			}
		}
	}
	if proto == "udp" && !edns {
		limit = 512
	}
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	ev := &wire.DNS{Client: client, Server: local, Proto: proto, ID: binary.BigEndian.Uint16(req), QName: name, QType: decode.TypeName(q.Type)}
	var who Client
	if s.cfg.Client != nil {
		who = s.cfg.Client(client)
	}
	rules := s.rules.Load()
	if bad, by := rules.Blocked(name, who); bad {
		return s.refuse(ctx, ev, start, id0, id1, rd, q, edns, by)
	}
	key := name + "|" + ev.QType + "|" + strconv.Itoa(int(q.Class&0x7fff)) + "|" + boolKey(do)
	out, hit := s.cache.get(key, binary.BigEndian.Uint16(req))
	if hit {
		s.hits.Add(1)
	} else {
		fwd := append([]byte(nil), req...)
		var nid [2]byte
		_, _ = rand.Read(nid[:])
		fwd[0], fwd[1] = nid[0], nid[1]
		a, err := s.pool.exchange(ctx, fwd)
		if err != nil {
			s.failed.Add(1)
			ev.RCode = "SERVFAIL"
			s.record(ev, start)
			return reply(id0, id1, rd, dnsmessage.RCodeServerFailure, &q)
		}
		out = a
		out[0], out[1] = id0, id1
	}
	am, err := decode.ParseDNS(out)
	if err != nil || len(am.Questions) != 1 || !strings.EqualFold(strings.TrimSuffix(am.Questions[0].Name, "."), name) || am.Questions[0].Type != q.Type {
		s.failed.Add(1)
		ev.RCode = "SERVFAIL"
		s.record(ev, start)
		return reply(id0, id1, rd, dnsmessage.RCodeServerFailure, &q)
	}
	// A name can hide behind another: tracker.example CNAME cdn.ads.example.
	for _, rr := range am.Answers {
		if rr.Type == 5 && rr.Target != "" {
			if bad, by := rules.Blocked(rr.Target, who); bad {
				return s.refuse(ctx, ev, start, id0, id1, rd, q, edns, by)
			}
		}
	}
	if !hit {
		s.cache.put(key, out)
	}
	ev.RCode = decode.RCodeName(am.RCode)
	for _, rr := range am.Answers {
		if len(ev.Answers) >= 32 {
			break
		}
		if d := rr.Data(); d != "" {
			ev.Answers = append(ev.Answers, wire.Answer{Name: strings.TrimSuffix(rr.Name, "."), Type: decode.TypeName(rr.Type), TTL: rr.TTL, Data: strings.TrimSuffix(d, ".")})
		}
	}
	s.record(ev, start)
	if len(out) > limit {
		return truncated(id0, id1, rd, q)
	}
	return out
}

func boolKey(b bool) string {
	if b {
		return "do"
	}
	return ""
}

// refuse answers a blocked name as the block mode says, and records it.
func (s *Server) refuse(ctx context.Context, ev *wire.DNS, start time.Time, id0, id1 byte, rd bool, q decode.Question, edns bool, by string) []byte {
	s.blocked.Add(1)
	ev.RCode, ev.BlockedBy = sources.RCodeBlocked, by
	s.record(ev, start)
	switch s.cfg.BlockMode {
	case BlockNXDomain:
		return reply(id0, id1, rd, dnsmessage.RCodeNameError, &q)
	case BlockRefused:
		return reply(id0, id1, rd, dnsmessage.RCodeRefused, &q)
	}
	b := builder(id0, id1, rd, dnsmessage.RCodeSuccess)
	name, err := dnsmessage.NewName(fqdn(q.Name))
	if err != nil {
		return reply(id0, id1, rd, dnsmessage.RCodeNameError, &q)
	}
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.Type(q.Type), Class: dnsmessage.ClassINET})
	_ = b.StartAnswers()
	h := dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: blockTTL}
	switch q.Type {
	case 1:
		_ = b.AResource(h, dnsmessage.AResource{})
	case 28:
		_ = b.AAAAResource(h, dnsmessage.AAAAResource{})
	}
	out, err := b.Finish()
	if err != nil {
		return reply(id0, id1, rd, dnsmessage.RCodeNameError, &q)
	}
	return out
}

func fqdn(n string) string {
	if strings.HasSuffix(n, ".") {
		return n
	}
	return n + "."
}

func builder(id0, id1 byte, rd bool, rc dnsmessage.RCode) *dnsmessage.Builder {
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{
		ID: uint16(id0)<<8 | uint16(id1), Response: true, RecursionDesired: rd, RecursionAvailable: true, RCode: rc,
	})
	b.EnableCompression()
	return &b
}

// reply is an answer with no records: an error, or a refusal.
func reply(id0, id1 byte, rd bool, rc dnsmessage.RCode, q *decode.Question) []byte {
	b := builder(id0, id1, rd, rc)
	if q != nil {
		if name, err := dnsmessage.NewName(fqdn(q.Name)); err == nil {
			_ = b.StartQuestions()
			_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.Type(q.Type), Class: dnsmessage.Class(q.Class & 0x7fff)})
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// truncated says an answer was too big for UDP: ask again over TCP.
func truncated(id0, id1 byte, rd bool, q decode.Question) []byte {
	out := reply(id0, id1, rd, dnsmessage.RCodeSuccess, &q)
	if len(out) > 2 {
		out[2] |= 0x02 // TC
	}
	return out
}

// record hands a lookup to the recorder, dropping it if that has fallen
// behind: answering matters more than the record.
func (s *Server) record(ev *wire.DNS, start time.Time) {
	if s.cfg.Record == nil {
		return
	}
	ev.LatencyMS = float64(time.Since(start).Microseconds()) / 1000
	select {
	case s.events <- wire.Event{Type: wire.TypeDNS, TS: start, DNS: ev}:
	default:
		s.dropped.Add(1)
	}
}

// recorder sends lookups on in batches: every second, or every 500.
func (s *Server) recorder(ctx context.Context) {
	if s.cfg.Record == nil {
		return
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var batch []wire.Event
	flush := func() {
		if len(batch) > 0 {
			s.cfg.Record(ctx, batch)
			batch = nil
		}
	}
	for {
		select {
		case <-ctx.Done():
			// What's queued is still worth keeping.
			for {
				select {
				case ev := <-s.events:
					batch = append(batch, ev)
					continue
				default:
				}
				break
			}
			// The store's context may be the one that ended: give it its own.
			ctx = context.WithoutCancel(ctx)
			flush()
			return
		case ev := <-s.events:
			batch = append(batch, ev)
			if len(batch) >= 500 {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// Status says how it's doing.
func (s *Server) Status() *model.DNSServerStatus {
	st := &model.DNSServerStatus{Enabled: true, Listen: s.Addrs(), BlockMode: s.cfg.BlockMode,
		Queries: s.queries.Load(), Blocked: s.blocked.Load(), CacheHits: s.hits.Load(), Refused: s.refused.Load(),
		Failed: s.failed.Load(), Cached: s.cache.len(), RulesAt: s.rulesAt.Load()}
	if r := s.rules.Load(); r != nil {
		st.Rules, st.ListEntries = r.Count, r.Entries
	}
	if e := s.rulesErr.Load(); e != nil {
		st.RulesError = *e
	}
	now := time.Now()
	for i, u := range s.pool.ups {
		ps := &s.pool.state[i]
		ps.mu.Lock()
		healthy := !now.Before(ps.downUntil)
		ps.mu.Unlock()
		st.Upstreams = append(st.Upstreams, model.DNSUpstreamStatus{Name: u.Name(), Healthy: healthy,
			Answered: ps.answered.Load(), Failed: ps.failed.Load(), LatencyMS: float64(ps.latency.Load()) / 1000})
	}
	return st
}

// limiter allows per events a second.
type limiter struct {
	mu    sync.Mutex
	per   int
	at    time.Time
	count int
}

func (l *limiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.at) >= time.Second {
		l.at, l.count = now, 0
	}
	l.count++
	return l.count <= l.per
}
