// Package conntrack reads the kernel's connection tracking table on the router, which
// knows about traffic a capture can't see: a connection handed to hardware offload stops
// reaching the CPU, and so stops reaching AF_PACKET, but the kernel still counts it.
//
// Decoding is a pure function over bytes, bounded by what they hold. The table is read over
// netlink rather than /proc/net/nf_conntrack, which many kernels no longer build.
package conntrack

import (
	"encoding/binary"
	"errors"
	"hash/fnv"
	"net/netip"
	"slices"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

// Mode says which entries become flows.
type Mode string

const (
	Off Mode = "off"
	// Offloaded reports only what capture can't see, so it can run beside a capture
	// without counting anything twice.
	Offloaded Mode = "offloaded"
	// All reports the whole table, for a sensor that isn't capturing.
	All Mode = "all"
)

// ParseMode reads a -conntrack value.
func ParseMode(s string) (Mode, bool) {
	switch m := Mode(s); m {
	case Off, Offloaded, All:
		return m, true
	}
	return Off, false
}

// MaxEntries bounds what a router's table can make the sensor hold. A busy table beyond
// it is read as far as this, and the rest is left out.
const MaxEntries = 65536

// Status bits, from the kernel's enum ip_conntrack_status.
const (
	statusOffload   = 1 << 14
	statusHWOffload = 1 << 15
)

// Entry is one connection in the table.
type Entry struct {
	Proto                  uint8
	OrigSrc, OrigDst       netip.Addr
	OrigSport, OrigDport   uint16
	ReplySrc, ReplyDst     netip.Addr
	ReplySport, ReplyDport uint16
	PktsOrig, BytesOrig    uint64
	PktsReply, BytesReply  uint64
	Counted                bool // the kernel keeps counters: nf_conntrack_acct is on
	Status                 uint32
	ID                     uint32
}

// Offloaded says the connection left the CPU path.
func (e *Entry) Offloaded() bool { return e.Status&(statusOffload|statusHWOffload) != 0 }

// Netlink's framing, which is in the host's byte order; what's inside conntrack's own
// attributes is in network order.
const (
	nlmsgHeader  = 16
	nfgenHeader  = 4
	nlmsgError   = 2
	nlmsgDone    = 3
	attrTypeMask = 0x3fff
	msgCTNew     = 1 << 8 // NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_NEW

	ctaTupleOrig     = 1
	ctaTupleReply    = 2
	ctaStatus        = 3
	ctaCountersOrig  = 9
	ctaCountersReply = 10
	ctaID            = 12
	ctaTupleIP       = 1
	ctaTupleProto    = 2
	ctaIPv4Src       = 1
	ctaIPv4Dst       = 2
	ctaIPv6Src       = 3
	ctaIPv6Dst       = 4
	ctaProtoNum      = 1
	ctaProtoSrcPort  = 2
	ctaProtoDstPort  = 3
	ctaProtoICMPID   = 4
	ctaProtoICMPv6ID = 7
	ctaCountPackets  = 1
	ctaCountBytes    = 2
)

// ErrKernel is the kernel refusing a request; the number is in the error's text.
var ErrKernel = errors.New("conntrack: the kernel returned an error")

// attrs calls f for each netlink attribute in b. It stops at the first that doesn't fit.
func attrs(b []byte, order binary.ByteOrder, f func(typ uint16, v []byte)) {
	for len(b) >= 4 {
		n := int(order.Uint16(b))
		if n < 4 || n > len(b) {
			return
		}
		f(order.Uint16(b[2:])&attrTypeMask, b[4:n])
		n = (n + 3) &^ 3
		if n > len(b) {
			return
		}
		b = b[n:]
	}
}

func beUint(v []byte) uint64 {
	var out uint64
	for _, c := range v[:min(len(v), 8)] {
		out = out<<8 | uint64(c)
	}
	return out
}

func readTuple(b []byte, order binary.ByteOrder, proto *uint8, src, dst *netip.Addr, sport, dport *uint16) {
	attrs(b, order, func(typ uint16, v []byte) {
		switch typ {
		case ctaTupleIP:
			attrs(v, order, func(typ uint16, a []byte) {
				switch {
				case typ == ctaIPv4Src && len(a) == 4:
					*src = netip.AddrFrom4([4]byte(a))
				case typ == ctaIPv4Dst && len(a) == 4:
					*dst = netip.AddrFrom4([4]byte(a))
				case typ == ctaIPv6Src && len(a) == 16:
					*src = netip.AddrFrom16([16]byte(a)).Unmap()
				case typ == ctaIPv6Dst && len(a) == 16:
					*dst = netip.AddrFrom16([16]byte(a)).Unmap()
				}
			})
		case ctaTupleProto:
			attrs(v, order, func(typ uint16, p []byte) {
				switch {
				case typ == ctaProtoNum && len(p) == 1:
					*proto = p[0]
				case typ == ctaProtoSrcPort && len(p) == 2:
					*sport = binary.BigEndian.Uint16(p)
				case typ == ctaProtoDstPort && len(p) == 2:
					*dport = binary.BigEndian.Uint16(p)
				case (typ == ctaProtoICMPID || typ == ctaProtoICMPv6ID) && len(p) == 2:
					// An echo's identifier, as capture records it: the
					// requester's port.
					*sport = binary.BigEndian.Uint16(p)
				}
			})
		}
	})
}

func readCounters(b []byte, order binary.ByteOrder, pkts, bytes *uint64) {
	attrs(b, order, func(typ uint16, v []byte) {
		switch typ {
		case ctaCountPackets:
			*pkts = beUint(v)
		case ctaCountBytes:
			*bytes = beUint(v)
		}
	})
}

// parseEntry reads one message's attributes, after its netfilter header.
func parseEntry(b []byte, order binary.ByteOrder) (Entry, bool) {
	var e Entry
	var unused uint8
	attrs(b, order, func(typ uint16, v []byte) {
		switch typ {
		case ctaTupleOrig:
			readTuple(v, order, &e.Proto, &e.OrigSrc, &e.OrigDst, &e.OrigSport, &e.OrigDport)
		case ctaTupleReply:
			readTuple(v, order, &unused, &e.ReplySrc, &e.ReplyDst, &e.ReplySport, &e.ReplyDport)
		case ctaStatus:
			e.Status = uint32(beUint(v))
		case ctaCountersOrig:
			e.Counted = true
			readCounters(v, order, &e.PktsOrig, &e.BytesOrig)
		case ctaCountersReply:
			e.Counted = true
			readCounters(v, order, &e.PktsReply, &e.BytesReply)
		case ctaID:
			e.ID = uint32(beUint(v))
		}
	})
	return e, e.OrigSrc.IsValid() && e.OrigDst.IsValid() && e.ReplySrc.IsValid()
}

// Parse decodes a buffer of netlink messages, adding to entries up to MaxEntries. done
// says the dump's end was reached. err is the kernel refusing, not a malformed message:
// those are skipped.
func Parse(b []byte, order binary.ByteOrder, entries []Entry) (out []Entry, done bool, err error) {
	out = entries
	for len(b) >= nlmsgHeader {
		n := int(order.Uint32(b))
		if n < nlmsgHeader || n > len(b) {
			return out, false, nil
		}
		typ := order.Uint16(b[4:])
		body := b[nlmsgHeader:n]
		switch typ {
		case nlmsgDone:
			return out, true, nil
		case nlmsgError:
			if len(body) >= 4 && order.Uint32(body) != 0 {
				return out, true, ErrKernel
			}
			return out, true, nil
		case msgCTNew:
			if len(body) >= nfgenHeader && len(out) < MaxEntries {
				if e, ok := parseEntry(body[nfgenHeader:], order); ok {
					out = append(out, e)
				}
			}
		}
		n = (n + 3) &^ 3
		if n > len(b) {
			return out, false, nil
		}
		b = b[n:]
	}
	return out, false, nil
}

type key struct {
	id       uint32
	src, dst netip.AddrPort
	proto    uint8
}

type tracked struct {
	flowID                                     uint64
	first, lastPoll                            time.Time
	pktsOrig, bytesOrig, pktsReply, bytesReply uint64
	src, dst                                   netip.AddrPort
	proto                                      uint8
	said                                       bool // a record has gone out for it
	missed                                     int
}

// Tracker turns the table's running totals into the records a flow table would send: what
// changed since last time. It isn't safe for concurrent use.
type Tracker struct {
	Mode Mode
	// Ignore, if set, drops connections: the sensor's own to its server.
	Ignore func(src, dst netip.AddrPort) bool

	seen   map[key]*tracked
	primed bool
}

// goneAfter is how many reads an entry must be missing from before it counts as ended. A
// dump can skip entries while the kernel resizes its table.
const goneAfter = 2

// Update takes one read of the table. complete says it was the whole table; if not, nothing
// is taken to have ended, and anything new may be old.
func (t *Tracker) Update(entries []Entry, complete bool, now time.Time) []wire.Flow {
	if t.seen == nil {
		t.seen = map[key]*tracked{}
	}
	var out []wire.Flow
	present := make(map[key]bool, len(entries))
	for i := range entries {
		e := &entries[i]
		if t.Mode != All && !e.Offloaded() {
			continue
		}
		// The reply tuple's source is who actually answered, past any port forward.
		src := netip.AddrPortFrom(e.OrigSrc, e.OrigSport)
		dst := netip.AddrPortFrom(e.ReplySrc, e.ReplySport)
		if e.Proto == 1 || e.Proto == 58 {
			dst = netip.AddrPortFrom(e.ReplySrc, 0)
		}
		if e.OrigSrc.IsLoopback() || e.ReplySrc.IsLoopback() || (t.Ignore != nil && t.Ignore(src, dst)) {
			continue
		}
		k := key{e.ID, src, dst, e.Proto}
		present[k] = true
		c := t.seen[k]
		if c == nil {
			if len(t.seen) >= MaxEntries {
				continue
			}
			c = &tracked{flowID: flowID(k, now), first: now, lastPoll: now, src: src, dst: dst, proto: e.Proto}
			// What it counted before now was either before this sensor started, or, for
			// offload, what capture already saw.
			if !t.primed || !complete || t.Mode != All {
				c.pktsOrig, c.bytesOrig, c.pktsReply, c.bytesReply = e.PktsOrig, e.BytesOrig, e.PktsReply, e.BytesReply
			}
			t.seen[k] = c
		}
		c.missed = 0
		dbo, dpo := delta(e.BytesOrig, c.bytesOrig), delta(e.PktsOrig, c.pktsOrig)
		dbr, dpr := delta(e.BytesReply, c.bytesReply), delta(e.PktsReply, c.pktsReply)
		c.bytesOrig, c.pktsOrig, c.bytesReply, c.pktsReply = e.BytesOrig, e.PktsOrig, e.BytesReply, e.PktsReply
		// With no counters there's still a connection to report, once.
		if dbo+dbr+dpo+dpr > 0 || (!e.Counted && !c.said) {
			out = append(out, c.record(c.lastPoll, now, dbo, dbr, dpo, dpr, false, ""))
		}
		c.lastPoll = now
	}
	if complete {
		var gone []key
		for k, c := range t.seen {
			if !present[k] {
				if c.missed++; c.missed >= goneAfter {
					gone = append(gone, k)
				}
			}
		}
		out = append(out, t.finish(gone, now, "conntrack")...)
		t.primed = true
	}
	return out
}

// Close ends every connection still open.
func (t *Tracker) Close(now time.Time) []wire.Flow {
	var all []key
	for k := range t.seen {
		all = append(all, k)
	}
	return t.finish(all, now, "shutdown")
}

// finish ends the given connections, in an order that doesn't depend on the map's.
func (t *Tracker) finish(keys []key, now time.Time, reason string) []wire.Flow {
	slices.SortFunc(keys, func(a, b key) int { return cmpUint64(t.seen[a].flowID, t.seen[b].flowID) })
	var out []wire.Flow
	for _, k := range keys {
		c := t.seen[k]
		delete(t.seen, k)
		if c.said { // one with no record has nothing to end
			out = append(out, c.record(now, now, 0, 0, 0, 0, true, reason))
		}
	}
	return out
}

func cmpUint64(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (c *tracked) record(start, end time.Time, bo, bi, po, pi uint64, final bool, reason string) wire.Flow {
	c.said = true
	return wire.Flow{
		ID: c.flowID, Proto: c.proto,
		Src: c.src.Addr(), SrcPort: c.src.Port(), Dst: c.dst.Addr(), DstPort: c.dst.Port(),
		FirstSeen: c.first, Start: start, End: end,
		BytesOut: bo, BytesIn: bi, PktsOut: po, PktsIn: pi,
		Final: final, EndReason: reason,
	}
}

func delta(cur, was uint64) uint64 {
	if cur < was {
		return 0 // the kernel's counter was reset; the new baseline is taken by the caller
	}
	return cur - was
}

// flowID stays clear of the flow table's ids, which count up from one, by setting the top bit.
func flowID(k key, now time.Time) uint64 {
	h := fnv.New64a()
	var b [12]byte
	binary.BigEndian.PutUint32(b[:], k.id)
	binary.BigEndian.PutUint64(b[4:], uint64(now.UnixNano()))
	h.Write(b[:])
	src, dst := k.src.Addr().As16(), k.dst.Addr().As16()
	h.Write(src[:])
	h.Write(dst[:])
	h.Write([]byte{k.proto, byte(k.src.Port() >> 8), byte(k.src.Port()), byte(k.dst.Port() >> 8), byte(k.dst.Port())})
	return h.Sum64() | 1<<63
}
