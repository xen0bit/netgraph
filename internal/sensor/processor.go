// Package sensor is netgraph-sensor's pipeline: frames in from capture
// sources, events out to an Emitter. It parses link/IP/transport headers,
// feeds the flow table, routes identity protocols (DNS, DHCP, mDNS, ARP, NDP,
// ...) to their decoders and suppresses repeats of chatty announcements.
package sensor

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/decode"
	"github.com/xen0bit/netgraph/internal/flow"
	"github.com/xen0bit/netgraph/internal/rdns"
	"github.com/xen0bit/netgraph/internal/wifi"
	"github.com/xen0bit/netgraph/internal/wire"
)

// Config tunes the processor.
type Config struct {
	Flow       flow.Config
	DNSTimeout time.Duration // emit an unanswered query as TIMEOUT after this (default 5s)
	MaxPending int           // bound on outstanding DNS queries (default 10000)
	Dedupe     time.Duration // suppress identical identity events for this long (default 10m)
	BindingTTL time.Duration // re-announce a MAC/IP binding after this (default 5m)
	Logger     *slog.Logger
	// Ignore reports packets that must not be accounted, such as the
	// sensor's own connection to the server.
	Ignore func(src, dst netip.AddrPort) bool
	// RDNS, when set, resolves reverse DNS names for local addresses as
	// they are seen. Disabled by default so replays stay deterministic.
	RDNS *rdns.Lookup
	// IsLocal reports whether an address is on the LAN. Defaults to the
	// private, link-local and CGNAT ranges.
	IsLocal func(netip.Addr) bool
	// WiFi decodes monitor-mode 802.11 frames and feeds decrypted data
	// frames back into this processor as Ethernet.
	WiFi *wifi.Processor
}

// Processor turns frames into events. It is safe for concurrent use by one
// goroutine per capture source.
type Processor struct {
	cfg   Config
	out   wire.Emitter
	flows *flow.Table
	log   *slog.Logger
	rdns  *rdns.Lookup
	wifi  *wifi.Processor

	mu      sync.Mutex
	pending map[dnsKey]pendingQuery
	seen    map[uint64]time.Time

	packets, bytes, decodeErrors, pendingDropped atomic.Uint64
}

type dnsKey struct {
	client netip.AddrPort
	server netip.Addr
	id     uint16
	proto  uint8
}

type pendingQuery struct {
	ts    time.Time
	qname string
	qtype string
	cmac  string
}

// NewProcessor returns a processor emitting to out.
func NewProcessor(cfg Config, out wire.Emitter) *Processor {
	if cfg.DNSTimeout <= 0 {
		cfg.DNSTimeout = 5 * time.Second
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = 10000
	}
	if cfg.Dedupe <= 0 {
		cfg.Dedupe = 10 * time.Minute
	}
	if cfg.BindingTTL <= 0 {
		cfg.BindingTTL = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.IsLocal == nil {
		cfg.IsLocal = LocalAddr
	}
	p := &Processor{cfg: cfg, out: out, log: cfg.Logger, rdns: cfg.RDNS, wifi: cfg.WiFi, pending: map[dnsKey]pendingQuery{}, seen: map[uint64]time.Time{}}
	if p.wifi != nil {
		p.wifi.SetData(func(ts time.Time, eth []byte) {
			// A decrypted 802.11 data frame is an Ethernet frame: the
			// same IP, DNS, TLS and flow code handles it.
			p.handleEthernet(ts, eth, capture.LinkEthernet)
		})
	}
	p.flows = flow.New(cfg.Flow, func(f *wire.Flow) {
		out.Emit(wire.Event{Type: wire.TypeFlow, TS: f.End, Flow: f})
	})
	return p
}

// Counters returns packets and bytes seen, decode errors and the number of
// tracked flows and evictions.
func (p *Processor) Counters() (packets, bytes, decodeErrors uint64, flows int, evicted uint64) {
	return p.packets.Load(), p.bytes.Load(), p.decodeErrors.Load(), p.flows.Len(), p.flows.Evicted()
}

// Handle processes one captured frame.
func (p *Processor) Handle(ts time.Time, data []byte, link int) {
	// A decoder bug on hostile input must cost one packet, not the sensor.
	defer func() {
		if r := recover(); r != nil {
			p.decodeErrors.Add(1)
			p.log.Error("panic decoding packet", "err", r)
		}
	}()
	p.packets.Add(1)
	p.bytes.Add(uint64(len(data)))
	if capture.IsWiFi(link) {
		if p.wifi == nil {
			p.decodeErrors.Add(1)
			return
		}
		p.wifi.Handle(ts, data, link == capture.LinkIEEE80211Radiotap)
		return
	}
	p.handleEthernet(ts, data, link)
}

// handleEthernet processes an Ethernet-like frame. Wi-Fi capture calls it
// with frames rebuilt after decryption.
func (p *Processor) handleEthernet(ts time.Time, data []byte, link int) {
	var f frame
	if !parseFrame(data, link, &f) {
		p.decodeErrors.Add(1)
		return
	}
	mac := ""
	if f.hasMAC {
		mac = net.HardwareAddr(f.srcMAC[:]).String()
	}
	switch f.etherType {
	case etherARP:
		if b := decode.ARP(f.l3); b != nil {
			p.binding(ts, b)
		}
		return
	case etherLLDP:
		if ev, err := decode.LLDP(f.l3, mac); err == nil {
			p.dedupe(ts, wire.Event{Type: wire.TypeLLDP, TS: ts, LLDP: ev}, "lldp", ev.MAC, ev.ChassisID, ev.PortID, ev.SystemName)
		}
		return
	}
	if !f.ipValid {
		return
	}
	src := netip.AddrPortFrom(f.src, f.sport)
	dst := netip.AddrPortFrom(f.dst, f.dport)
	if p.cfg.Ignore != nil && p.cfg.Ignore(src, dst) {
		return
	}
	if p.rdns != nil {
		// A host is named from the first moment it is seen, not when the
		// resolver happens to answer.
		if p.cfg.IsLocal(f.src) {
			p.rdns.Observe(f.src, mac, ts)
		}
		if p.cfg.IsLocal(f.dst) && f.hasMAC {
			p.rdns.Observe(f.dst, net.HardwareAddr(f.dstMAC[:]).String(), ts)
		}
	}
	if f.proto == flow.ProtoICMPv6 && len(f.payload) > 0 && f.payload[0] >= 133 && f.payload[0] <= 136 {
		if b := decode.NDP(f.payload, f.src); b != nil {
			p.binding(ts, b)
		}
	}
	if !f.frag && (f.proto != flow.ProtoTCP && f.proto != flow.ProtoUDP || f.l4 != nil) {
		p.flows.Add(&flow.Packet{
			TS: ts, Proto: f.proto, Src: src, Dst: dst, SrcMAC: f.srcMAC,
			Len: f.ipLen, TCPFlags: f.tcpFlags, Seq: f.seq, Payload: f.payload,
		})
	}
	if len(f.payload) == 0 {
		return
	}
	switch f.proto {
	case flow.ProtoUDP:
		p.udp(ts, &f, mac)
	case flow.ProtoTCP:
		if f.sport == 53 || f.dport == 53 {
			p.tcpDNS(ts, &f, mac)
		}
	}
}

func (p *Processor) udp(ts time.Time, f *frame, mac string) {
	switch {
	case f.sport == 53 || f.dport == 53:
		p.dnsMessage(ts, f, mac, f.payload, flow.ProtoUDP)
	case f.dport == 5353 || f.sport == 5353:
		m, err := decode.ParseDNS(f.payload)
		if m == nil {
			p.decodeErrors.Add(1)
			return
		}
		_ = err
		if ev := decode.MDNS(m, f.src, mac); ev != nil {
			if p.rdns != nil {
				for _, h := range ev.Hosts {
					for _, a := range h.Addrs {
						if p.cfg.IsLocal(a) {
							p.rdns.Observe(a, "", ts)
						}
					}
				}
			}
			p.dedupe(ts, wire.Event{Type: wire.TypeMDNS, TS: ts, MDNS: ev}, "mdns", fmt.Sprint(ev))
		}
	case f.sport == 5355:
		if m, _ := decode.ParseDNS(f.payload); m != nil {
			for _, n := range decode.LLMNR(m, f.src, mac) {
				p.dedupe(ts, wire.Event{Type: wire.TypeName, TS: ts, Name: &n}, "name", n.Proto, n.MAC, n.IP.String(), n.Name)
			}
		}
	case f.sport == 137 || f.dport == 137:
		if m, _ := decode.ParseDNS(f.payload); m != nil {
			for _, n := range decode.NBNS(m, f.src, mac) {
				p.dedupe(ts, wire.Event{Type: wire.TypeName, TS: ts, Name: &n}, "name", n.Proto, n.MAC, n.IP.String(), n.Name, n.Suffix)
			}
		}
	case (f.sport == 67 || f.sport == 68) && (f.dport == 67 || f.dport == 68):
		if ev, err := decode.DHCPv4(f.payload); err == nil {
			p.observeDHCP(ts, ev)
			p.dedupe(ts, wire.Event{Type: wire.TypeDHCP, TS: ts, DHCP: ev}, "dhcp4", fmt.Sprint(ev))
		} else {
			p.decodeErrors.Add(1)
		}
	case (f.sport == 546 || f.sport == 547) && (f.dport == 546 || f.dport == 547):
		if ev, err := decode.DHCPv6(f.payload, mac); err == nil {
			p.observeDHCP(ts, ev)
			p.dedupe(ts, wire.Event{Type: wire.TypeDHCP, TS: ts, DHCP: ev}, "dhcp6", fmt.Sprint(ev))
		}
	case f.dport == 1900 || f.sport == 1900:
		if ev := decode.SSDP(f.payload, f.src, mac); ev != nil {
			p.dedupe(ts, wire.Event{Type: wire.TypeSSDP, TS: ts, SSDP: ev}, "ssdp", ev.IP.String(), ev.Method, ev.USN, ev.NT, ev.Server)
		}
	}
}

// tcpDNS handles DNS over TCP when a whole length-prefixed message fits in
// the segment, which covers the common case of short queries and answers.
func (p *Processor) tcpDNS(ts time.Time, f *frame, mac string) {
	b := f.payload
	for len(b) >= 2 {
		l := int(binary.BigEndian.Uint16(b))
		if 2+l > len(b) {
			return
		}
		p.dnsMessage(ts, f, mac, b[2:2+l], flow.ProtoTCP)
		b = b[2+l:]
	}
}

func (p *Processor) dnsMessage(ts time.Time, f *frame, mac string, b []byte, proto uint8) {
	m, err := decode.ParseDNS(b)
	if m == nil || len(m.Questions) == 0 {
		if err != nil {
			p.decodeErrors.Add(1)
		}
		return
	}
	q := m.Questions[0]
	qname, qtype := strings.ToLower(q.Name), decode.TypeName(q.Type)
	protoName := "udp"
	if proto == flow.ProtoTCP {
		protoName = "tcp"
	}
	if !m.Response {
		if f.dport != 53 {
			return
		}
		k := dnsKey{client: netip.AddrPortFrom(f.src, f.sport), server: f.dst, id: m.ID, proto: proto}
		p.mu.Lock()
		if len(p.pending) < p.cfg.MaxPending {
			if _, dup := p.pending[k]; !dup { // retransmission keeps the first send time
				p.pending[k] = pendingQuery{ts: ts, qname: qname, qtype: qtype, cmac: mac}
			}
		} else {
			p.pendingDropped.Add(1)
		}
		p.mu.Unlock()
		return
	}
	if f.sport != 53 {
		return
	}
	ev := &wire.DNS{
		Client: f.dst, Server: f.src, Proto: protoName, ID: m.ID,
		QName: qname, QType: qtype, RCode: decode.RCodeName(m.RCode), Answers: decode.Answers(m),
	}
	k := dnsKey{client: netip.AddrPortFrom(f.dst, f.dport), server: f.src, id: m.ID, proto: proto}
	p.mu.Lock()
	if pq, ok := p.pending[k]; ok {
		delete(p.pending, k)
		ev.ClientMAC = pq.cmac
		ev.LatencyMS = float64(ts.Sub(pq.ts).Microseconds()) / 1000
	}
	p.mu.Unlock()
	if p.rdns != nil && p.cfg.IsLocal(ev.Client) {
		p.rdns.Observe(ev.Client, ev.ClientMAC, ts)
	}
	p.out.Emit(wire.Event{Type: wire.TypeDNS, TS: ts, DNS: ev})
}

// observeDHCP asks for reverse names of addresses a DHCP message reveals.
// The client's MAC is the one that owns them.
func (p *Processor) observeDHCP(ts time.Time, d *wire.DHCP) {
	if p.rdns == nil || d.MAC == "" {
		return
	}
	for _, ip := range append([]netip.Addr{d.YourIP, d.ClientIP}, d.Addresses...) {
		if p.cfg.IsLocal(ip) {
			p.rdns.Observe(ip, d.MAC, ts)
		}
	}
}

func (p *Processor) binding(ts time.Time, b *wire.Binding) {
	if p.rdns != nil && p.cfg.IsLocal(b.IP) {
		p.rdns.Observe(b.IP, b.MAC, ts)
	}
	p.dedupeFor(ts, p.cfg.BindingTTL, wire.Event{Type: wire.TypeBinding, TS: ts, Binding: b}, "binding", b.MAC, b.IP.String())
}

func (p *Processor) dedupe(ts time.Time, ev wire.Event, parts ...string) {
	p.dedupeFor(ts, p.cfg.Dedupe, ev, parts...)
}

// dedupeFor emits ev unless an event with the same key parts was emitted in
// the last ttl. Devices re-announce mDNS, SSDP and LLDP every few seconds;
// the server needs to know they are still there, not every repetition.
func (p *Processor) dedupeFor(ts time.Time, ttl time.Duration, ev wire.Event, parts ...string) {
	h := fnv.New64a()
	for _, s := range parts {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	k := h.Sum64()
	p.mu.Lock()
	last, ok := p.seen[k]
	emit := !ok || ts.Sub(last) >= ttl || ts.Before(last)
	if emit {
		p.seen[k] = ts
	}
	p.mu.Unlock()
	if emit {
		p.out.Emit(ev)
	}
}

// Tick runs time-driven work as of now: flow expiry, DNS timeouts and
// dedupe cleanup. Live capture calls it every second with the wall clock;
// file replay calls it with packet time.
func (p *Processor) Tick(now time.Time) {
	p.flows.Expire(now)
	var timedOut []wire.Event
	p.mu.Lock()
	for k, q := range p.pending {
		if now.Sub(q.ts) >= p.cfg.DNSTimeout {
			delete(p.pending, k)
			timedOut = append(timedOut, wire.Event{Type: wire.TypeDNS, TS: q.ts, DNS: &wire.DNS{
				Client: k.client.Addr(), ClientMAC: q.cmac, Server: k.server, Proto: protoName(k.proto),
				ID: k.id, QName: q.qname, QType: q.qtype, RCode: "TIMEOUT",
			}})
		}
	}
	for k, t := range p.seen {
		if now.Sub(t) >= 2*max(p.cfg.Dedupe, p.cfg.BindingTTL) {
			delete(p.seen, k)
		}
	}
	p.mu.Unlock()
	sort.Slice(timedOut, func(i, j int) bool {
		a, b := timedOut[i], timedOut[j]
		if !a.TS.Equal(b.TS) {
			return a.TS.Before(b.TS)
		}
		return a.DNS.ID < b.DNS.ID
	})
	for _, ev := range timedOut {
		p.out.Emit(ev)
	}
}

func protoName(p uint8) string {
	if p == flow.ProtoTCP {
		return "tcp"
	}
	return "udp"
}

// Flush finishes every flow and outstanding query, for shutdown.
func (p *Processor) Flush(now time.Time, reason string) {
	p.flows.Flush(now, reason)
	p.Tick(now.Add(p.cfg.DNSTimeout))
}
