// Package flow tracks bidirectional flows and exports them as interval
// records, the way a NetFlow exporter does with an active timeout: a flow
// alive for an hour produces a record every ActiveTimeout carrying the bytes
// of that interval. Summing the records that overlap a time window gives
// exactly the traffic inside it, which is the property every netgraph
// time-slice query depends on.
//
// While a flow is young the table also looks at its first payload bytes from
// the initiator to learn what it is: a TLS ClientHello (SNI, ALPN, JA4), a
// QUIC Initial (decrypted for the same), or an HTTP request (Host,
// User-Agent).
package flow

import (
	"container/list"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xen0bit/netgraph/internal/decode"
	"github.com/xen0bit/netgraph/internal/wire"
)

// IP protocol numbers.
const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

// TCP flags.
const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
)

// Config holds the table's limits and timeouts.
type Config struct {
	ActiveTimeout time.Duration // export an interval record at least this often (default 30s)
	TCPIdle       time.Duration // expire an established TCP flow after this silence (default 5m)
	UDPIdle       time.Duration // expire a UDP/ICMP flow after this silence (default 60s)
	TCPClosed     time.Duration // linger after FIN/RST to absorb the last packets (default 2s)
	MaxFlows      int           // evict least recently used beyond this (default 65536)
}

func (c *Config) defaults() {
	if c.ActiveTimeout <= 0 {
		c.ActiveTimeout = 30 * time.Second
	}
	if c.TCPIdle <= 0 {
		c.TCPIdle = 5 * time.Minute
	}
	if c.UDPIdle <= 0 {
		c.UDPIdle = 60 * time.Second
	}
	if c.TCPClosed <= 0 {
		c.TCPClosed = 2 * time.Second
	}
	if c.MaxFlows <= 0 {
		c.MaxFlows = 65536
	}
}

// Packet is the part of a captured packet the table needs.
type Packet struct {
	TS       time.Time
	Proto    uint8
	Src, Dst netip.AddrPort
	SrcMAC   [6]byte
	Len      int // IP length: header plus payload, independent of snaplen
	TCPFlags uint8
	Seq      uint32
	Payload  []byte // L4 payload as captured (may be truncated)
}

type key struct {
	proto uint8
	a, b  netip.AddrPort // a < b, so both directions find the same entry
}

func keyOf(p *Packet) key {
	a, b := p.Src, p.Dst
	if b.Compare(a) < 0 {
		a, b = b, a
	}
	return key{p.Proto, a, b}
}

type entry struct {
	id             uint64
	proto          uint8
	src, dst       netip.AddrPort // src is the initiator
	srcMAC, dstMAC [6]byte

	first, last, intervalStart time.Time
	bout, bin, pout, pin       uint64 // deltas since intervalStart
	flags                      uint8
	finSrc, finDst, rst        bool
	closedAt                   time.Time

	app, sni, alpn, ja4, host, ua string

	inspect bool
	buf     []byte
	segs    int
	nextSeq uint32
	quic    *decode.CryptoStream
	quicN   int

	elem *list.Element
}

// Table is a flow table. It is safe for concurrent use.
type Table struct {
	cfg  Config
	emit func(*wire.Flow)

	mu      sync.Mutex
	flows   map[key]*entry
	lru     *list.List // front = most recently used
	nextID  uint64
	evicted uint64
}

// New returns a table that hands each exported record to emit. emit is
// called with the table locked; it must not call back into the table.
func New(cfg Config, emit func(*wire.Flow)) *Table {
	cfg.defaults()
	return &Table{cfg: cfg, emit: emit, flows: make(map[key]*entry), lru: list.New()}
}

// Len returns the number of tracked flows.
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.flows)
}

// Evicted returns how many flows were evicted for capacity.
func (t *Table) Evicted() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.evicted
}

// Inspection limits: how much of a flow's opening the table looks at.
const (
	maxInspectBytes = 16 << 10
	maxInspectSegs  = 8
	maxQUICPackets  = 6
)

// Add accounts one packet. It reports whether the packet opened a new flow.
func (t *Table) Add(p *Packet) (opened bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := keyOf(p)
	e, ok := t.flows[k]
	opened = !ok
	if !ok {
		if len(t.flows) >= t.cfg.MaxFlows {
			t.evictOldest(p.TS)
		}
		e = t.newEntry(p)
		t.flows[k] = e
		e.elem = t.lru.PushFront(k)
	} else {
		t.lru.MoveToFront(e.elem)
		if p.Proto == ProtoTCP && p.TCPFlags&(SYN|ACK) == SYN && (e.finSrc || e.finDst || e.rst) {
			// A fresh SYN on a closed tuple is a new connection (port
			// reuse); finish the old one first.
			t.finish(k, e, e.last, "fin")
			opened = true
			e = t.newEntry(p)
			t.flows[k] = e
			e.elem = t.lru.PushFront(k)
		}
	}
	if e.proto != ProtoTCP && e.pout == 0 && e.pin == 0 {
		// Non-TCP intervals start at their first packet: a quiet UDP flow
		// exports nothing, and the next interval must not claim the silence.
		e.intervalStart = p.TS
	}
	fromSrc := p.Src == e.src
	if fromSrc {
		e.bout += uint64(p.Len)
		e.pout++
		e.srcMAC = p.SrcMAC
	} else {
		e.bin += uint64(p.Len)
		e.pin++
		e.dstMAC = p.SrcMAC
	}
	if p.TS.After(e.last) {
		e.last = p.TS
	}
	if p.Proto == ProtoTCP {
		e.flags |= p.TCPFlags
		if p.TCPFlags&FIN != 0 {
			if fromSrc {
				e.finSrc = true
			} else {
				e.finDst = true
			}
		}
		if p.TCPFlags&RST != 0 {
			e.rst = true
		}
		if e.closedAt.IsZero() && (e.rst || e.finSrc && e.finDst) {
			e.closedAt = p.TS
		}
	}
	if e.inspect && fromSrc && len(p.Payload) > 0 {
		t.inspectPayload(e, p)
	}
	return opened
}

func (t *Table) newEntry(p *Packet) *entry {
	t.nextID++
	e := &entry{id: t.nextID, proto: p.Proto, src: p.Src, dst: p.Dst, first: p.TS, last: p.TS, intervalStart: p.TS, inspect: true}
	if reverse(p) {
		e.src, e.dst = p.Dst, p.Src
	}
	e.app = portApp(e.proto, e.dst.Port())
	return e
}

// reverse reports whether p was sent by the responder rather than the
// initiator of its flow, for the first packet the table sees of it.
func reverse(p *Packet) bool {
	if p.Proto == ProtoTCP {
		switch p.TCPFlags & (SYN | ACK) {
		case SYN:
			return false
		case SYN | ACK:
			return true
		}
	}
	if p.Proto != ProtoTCP && p.Proto != ProtoUDP {
		return false
	}
	// Mid-stream or UDP: the side on a service port is the responder.
	sp, dp := p.Src.Port(), p.Dst.Port()
	return isServicePort(sp) && !isServicePort(dp) || sp < 1024 && dp >= 1024 && !isServicePort(dp)
}

var servicePorts = map[uint16]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
	80: "http", 110: "pop3", 123: "ntp", 137: "netbios", 138: "netbios", 143: "imap", 161: "snmp",
	389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog", 546: "dhcpv6", 547: "dhcpv6",
	587: "submission", 631: "ipp", 636: "ldaps", 853: "dot", 873: "rsync", 993: "imaps", 995: "pop3s",
	1194: "openvpn", 1883: "mqtt", 1900: "ssdp", 3306: "mysql", 3389: "rdp", 3478: "stun", 5060: "sip",
	5222: "xmpp", 5353: "mdns", 5355: "llmnr", 5432: "postgres", 6379: "redis", 8080: "http-alt",
	8443: "https-alt", 8883: "mqtts", 9100: "jetdirect", 51820: "wireguard",
}

func isServicePort(p uint16) bool { _, ok := servicePorts[p]; return ok }

func portApp(proto uint8, port uint16) string {
	switch proto {
	case ProtoICMP:
		return "icmp"
	case ProtoICMPv6:
		return "icmpv6"
	}
	return servicePorts[port]
}

func (t *Table) inspectPayload(e *entry, p *Packet) {
	switch e.proto {
	case ProtoTCP:
		pl := p.Payload
		if e.segs == 0 {
			e.nextSeq = p.Seq
		}
		// Keep only in-order bytes. A retransmission overlapping what we
		// have is trimmed; a gap ends inspection — on a LAN the opening
		// segments essentially always arrive in order.
		switch d := int32(p.Seq - e.nextSeq); {
		case d < 0:
			if int(-d) >= len(pl) {
				return
			}
			pl = pl[-d:]
		case d > 0:
			e.stopInspect()
			return
		}
		e.segs++
		e.nextSeq += uint32(len(pl))
		e.buf = append(e.buf, pl...)
		e.inspectTCP()
		if e.inspect && (e.segs >= maxInspectSegs || len(e.buf) >= maxInspectBytes) {
			e.stopInspect()
		}
	case ProtoUDP:
		e.quicN++
		if !decode.IsQUICInitial(p.Payload) {
			if e.quic == nil || e.quicN > maxQUICPackets {
				e.stopInspect()
			}
			return
		}
		ini, err := decode.ParseQUICInitial(p.Payload)
		if err != nil {
			if e.quicN > maxQUICPackets {
				e.stopInspect()
			}
			return
		}
		if e.quic == nil {
			e.quic = &decode.CryptoStream{}
		}
		e.quic.Add(ini.Crypto)
		if ch, err := decode.ParseHandshake(e.quic.Prefix(), 'q'); err == nil {
			e.app = "quic"
			e.setHello(ch)
			e.stopInspect()
		} else if err != decode.ErrNeedMore || e.quicN > maxQUICPackets {
			e.stopInspect()
		}
	default:
		e.stopInspect()
	}
}

func (e *entry) inspectTCP() {
	ch, err := decode.ParseTLSRecords(e.buf)
	switch err {
	case nil:
		e.app = "tls"
		e.setHello(ch)
		e.stopInspect()
		return
	case decode.ErrNeedMore:
		return
	}
	host, ua, ok, complete := decode.HTTPRequest(e.buf)
	if !ok {
		e.stopInspect()
		return
	}
	e.app = "http"
	if host != "" {
		e.host = host
	}
	if ua != "" {
		e.ua = ua
	}
	if complete {
		e.stopInspect()
	}
}

func (e *entry) setHello(ch *decode.ClientHello) {
	e.sni, e.ja4 = ch.SNI, ch.JA4
	if len(ch.ALPN) > 0 {
		e.alpn = ch.ALPN[0]
	}
}

func (e *entry) stopInspect() {
	e.inspect = false
	e.buf = nil
	e.quic = nil
}

// Expire exports interval records for flows whose active timeout elapsed
// and final records for flows that went idle or closed, as of now.
func (t *Table) Expire(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Walk the LRU list oldest first rather than the map: the order of
	// exported records is then deterministic, so a replayed capture always
	// produces the same event stream.
	for el := t.lru.Back(); el != nil; {
		prev := el.Prev()
		k := el.Value.(key)
		e := t.flows[k]
		switch {
		case !e.closedAt.IsZero() && now.Sub(e.closedAt) >= t.cfg.TCPClosed:
			t.finish(k, e, e.last, e.closeReason())
		case now.Sub(e.last) >= t.idleTimeout(e):
			t.finish(k, e, e.last, "idle")
		case now.Sub(e.intervalStart) >= t.cfg.ActiveTimeout:
			t.export(e, now, false, "")
		}
		el = prev
	}
}

func (e *entry) closeReason() string {
	if e.rst {
		return "rst"
	}
	return "fin"
}

func (t *Table) idleTimeout(e *entry) time.Duration {
	if e.proto == ProtoTCP {
		return t.cfg.TCPIdle
	}
	return t.cfg.UDPIdle
}

// Flush finishes every flow, for shutdown or the end of a pcap file.
func (t *Table) Flush(now time.Time, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for el := t.lru.Back(); el != nil; {
		prev := el.Prev()
		k := el.Value.(key)
		e := t.flows[k]
		end, why := now, reason
		if e.last.Before(end) {
			end = e.last
		}
		if !e.closedAt.IsZero() {
			why = e.closeReason() // it closed; the flush only cut the linger short
		}
		t.finish(k, e, end, why)
		el = prev
	}
}

func (t *Table) evictOldest(now time.Time) {
	back := t.lru.Back()
	if back == nil {
		return
	}
	k := back.Value.(key)
	t.finish(k, t.flows[k], now, "evict")
	t.evicted++
}

func (t *Table) finish(k key, e *entry, end time.Time, reason string) {
	if e.proto != ProtoTCP && e.pout == 0 && e.pin == 0 {
		// Nothing since the last export: the flow ended at its last packet.
		e.intervalStart = e.last
		end = e.last
	}
	if end.Before(e.intervalStart) {
		end = e.intervalStart
	}
	t.export(e, end, true, reason)
	t.lru.Remove(e.elem)
	delete(t.flows, k)
}

// export emits the interval [intervalStart, end] and starts a new one.
//
// An interval with no packets is still exported for an open TCP flow: the
// record is the evidence the connection was held open through a quiet
// stretch, which is what lets a window ask "what was this client connected
// to at t0". Silent UDP has no such meaning and is skipped.
func (t *Table) export(e *entry, end time.Time, final bool, reason string) {
	empty := e.pout == 0 && e.pin == 0
	if empty && !final && e.proto != ProtoTCP {
		e.intervalStart = end
		return
	}
	f := &wire.Flow{
		ID: e.id, Proto: e.proto,
		Src: e.src.Addr(), SrcPort: e.src.Port(), Dst: e.dst.Addr(), DstPort: e.dst.Port(),
		SrcMAC: macString(e.srcMAC), DstMAC: macString(e.dstMAC),
		FirstSeen: e.first, Start: e.intervalStart, End: end,
		BytesOut: e.bout, BytesIn: e.bin, PktsOut: e.pout, PktsIn: e.pin,
		TCPFlags: e.flags, Final: final, EndReason: reason,
		App: e.app, SNI: e.sni, ALPN: e.alpn, JA4: e.ja4, HTTPHost: e.host, UserAgent: e.ua,
	}
	t.emit(f)
	e.bout, e.bin, e.pout, e.pin = 0, 0, 0, 0
	e.intervalStart = end
}

func macString(m [6]byte) string {
	if m == ([6]byte{}) {
		return ""
	}
	return net.HardwareAddr(m[:]).String()
}
