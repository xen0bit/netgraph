// Package sources turns what other systems already know into netgraph's events:
// NetFlow, IPFIX and sFlow from a router, DNS logs from dnsmasq, Pi-hole and AdGuard Home, and
// a DHCP server's leases. They run on the server, so the sensor stays small.
//
// All of it is input from outside. Decoders are pure functions that bound every length
// and never loop on what a packet claims, as the sensor's do.
package sources

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

// Limits on what an exporter can make the server remember.
const (
	maxTemplates      = 256 // per exporter
	maxTemplateFields = 64
	maxRecordsPerPkt  = 1024
)

var errShort = errors.New("netflow: truncated")

type field struct {
	id     uint16
	length uint16
}

type template struct {
	fields []field
	size   int
}

// Templates is what one exporter has announced: v9 and IPFIX records mean nothing
// without them. A zero Templates is ready to use. It isn't safe for concurrent use.
type Templates struct {
	byID map[uint32]template
}

func (t *Templates) set(domain uint32, id uint16, tmpl template) {
	if t.byID == nil {
		t.byID = map[uint32]template{}
	}
	key := domain<<16 ^ uint32(id)
	if _, ok := t.byID[key]; !ok && len(t.byID) >= maxTemplates {
		return // replacing one is fine; growing past the bound isn't
	}
	t.byID[key] = tmpl
}

func (t *Templates) get(domain uint32, id uint16) (template, bool) {
	tmpl, ok := t.byID[domain<<16^uint32(id)]
	return tmpl, ok
}

// ParseNetFlow decodes one datagram of NetFlow v5, v9 or IPFIX. received is when it
// arrived, for an exporter whose clock can't be trusted to say otherwise.
func ParseNetFlow(b []byte, tmpl *Templates, received time.Time) (flows []wire.Flow, err error) {
	// A decoder panic is a bug, but it's a bug one packet shouldn't get to turn into the
	// whole server going down.
	defer func() {
		if r := recover(); r != nil {
			flows, err = nil, fmt.Errorf("netflow: decoding panicked: %v", r)
		}
	}()
	if len(b) < 2 {
		return nil, errShort
	}
	switch binary.BigEndian.Uint16(b) {
	case 5:
		return parseV5(b, received)
	case 9:
		return parseV9(b, tmpl, received)
	case 10:
		return parseIPFIX(b, tmpl, received)
	}
	return nil, fmt.Errorf("netflow: version %d isn't supported", binary.BigEndian.Uint16(b))
}

func parseV5(b []byte, received time.Time) ([]wire.Flow, error) {
	const header, record = 24, 48
	if len(b) < header {
		return nil, errShort
	}
	count := int(binary.BigEndian.Uint16(b[2:]))
	if count > 30 || len(b) < header+count*record { // v5 allows 30 to a datagram
		return nil, errShort
	}
	uptime := binary.BigEndian.Uint32(b[4:])
	exported := time.Unix(int64(binary.BigEndian.Uint32(b[8:])), int64(binary.BigEndian.Uint32(b[12:])))
	base := exportBase(exported, uptime, received)
	out := make([]wire.Flow, 0, count)
	for i := range count {
		r := b[header+i*record:]
		first, last := binary.BigEndian.Uint32(r[24:]), binary.BigEndian.Uint32(r[28:])
		f := record5(r, base.Add(time.Duration(first)*time.Millisecond), base.Add(time.Duration(last)*time.Millisecond))
		if ok := finish(&f, received); ok {
			out = append(out, f)
		}
	}
	return out, nil
}

func record5(r []byte, start, end time.Time) wire.Flow {
	return wire.Flow{
		Src: netip.AddrFrom4([4]byte(r[0:4])), Dst: netip.AddrFrom4([4]byte(r[4:8])),
		PktsOut: uint64(binary.BigEndian.Uint32(r[16:])), BytesOut: uint64(binary.BigEndian.Uint32(r[20:])),
		Start: start, End: end,
		SrcPort: binary.BigEndian.Uint16(r[32:]), DstPort: binary.BigEndian.Uint16(r[34:]),
		TCPFlags: r[37], Proto: r[38],
	}
}

// exportBase is the wall-clock time of the exporter's boot, if its clock is believable.
func exportBase(exported time.Time, uptimeMS uint32, received time.Time) time.Time {
	// A router with no NTP says 1970. Trust the moment we heard it instead.
	if d := received.Sub(exported); d > time.Hour || d < -time.Hour {
		exported = received
	}
	return exported.Add(-time.Duration(uptimeMS) * time.Millisecond)
}

// finish checks what can't be right and fills in what's implied. A record's span is at
// most a day (ingest drops longer), and never in the future.
func finish(f *wire.Flow, received time.Time) bool {
	if !f.Src.IsValid() || !f.Dst.IsValid() {
		return false
	}
	if f.End.IsZero() || f.End.After(received.Add(time.Minute)) {
		f.End = received
	}
	if f.Start.IsZero() || f.Start.After(f.End) || f.End.Sub(f.Start) > 24*time.Hour {
		f.Start = f.End
	}
	orient(f)
	f.FirstSeen = f.Start
	// A connection's identity: both directions and every active timeout report the same
	// ends, and each time about the same start, so their records join up into one.
	h := fnv.New64a()
	h.Write(f.Src.AsSlice())
	h.Write(f.Dst.AsSlice())
	h.Write([]byte{f.Proto, byte(f.SrcPort >> 8), byte(f.SrcPort), byte(f.DstPort >> 8), byte(f.DstPort)})
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(f.Start.Unix()/connectionBucket))
	h.Write(t[:])
	f.ID = h.Sum64()
	return true
}

// connectionBucket is how close in seconds two directions' start times must be to count
// as one connection: they differ by a round trip, and a port reused within it is rare. A
// connection starting right at a boundary can come out as two.
const connectionBucket = 600

// orient makes a record read from client to server. NetFlow reports each direction on its
// own, with no idea who began, so the reply to a phone's HTTPS connection reads as someone
// at port 443 connecting to the phone, and would show as a connection in from outside.
// The side on the well-known port is taken to be the server, and failing that, the side
// outside the range systems pick client ports from (32768 up, on anything current). With
// two ports in that range there's nothing to go on, and it stays as reported, so that
// traffic can show as two connections.
func orient(f *wire.Flow) {
	if f.Proto != 6 && f.Proto != 17 {
		return
	}
	if swap := serverLike(f.SrcPort) && (!serverLike(f.DstPort) || f.SrcPort < f.DstPort) ||
		!serverLike(f.DstPort) && f.SrcPort > 0 && f.SrcPort < ephemeralPorts && f.DstPort >= ephemeralPorts; swap {
		f.Src, f.Dst = f.Dst, f.Src
		f.SrcPort, f.DstPort = f.DstPort, f.SrcPort
		f.BytesOut, f.BytesIn = 0, f.BytesOut
		f.PktsOut, f.PktsIn = 0, f.PktsOut
		f.SrcMAC, f.DstMAC = f.DstMAC, f.SrcMAC
	}
}

const ephemeralPorts = 32768

func serverLike(port uint16) bool {
	return port > 0 && port < 1024 || port == 8080 || port == 8443 || port == 3306 || port == 5432 || port == 5353 || port == 1900 || port == 5355
}

func parseV9(b []byte, tmpl *Templates, received time.Time) ([]wire.Flow, error) {
	const header = 20
	if len(b) < header {
		return nil, errShort
	}
	uptime := binary.BigEndian.Uint32(b[4:])
	base := exportBase(time.Unix(int64(binary.BigEndian.Uint32(b[8:])), 0), uptime, received)
	return flowSets(b[header:], tmpl, binary.BigEndian.Uint32(b[16:]), 0, 1, base, received)
}

func parseIPFIX(b []byte, tmpl *Templates, received time.Time) ([]wire.Flow, error) {
	const header = 16
	if len(b) < header {
		return nil, errShort
	}
	length := int(binary.BigEndian.Uint16(b[2:]))
	if length < header || length > len(b) {
		return nil, errShort
	}
	return flowSets(b[header:length], tmpl, binary.BigEndian.Uint32(b[12:]), 2, 3, time.Time{}, received)
}

// flowSets walks a message's sets, which both formats share in shape.
func flowSets(b []byte, tmpl *Templates, domain uint32, tmplSet, optSet uint16, base, received time.Time) ([]wire.Flow, error) {
	var out []wire.Flow
	for len(b) >= 4 {
		id, length := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		if length < 4 || length > len(b) {
			return out, errShort
		}
		body := b[4:length]
		b = b[length:]
		switch {
		case id == tmplSet:
			readTemplates(body, tmpl, domain)
		case id == optSet:
			// Options describe the exporter, not traffic.
		case id >= 256:
			t, ok := tmpl.get(domain, id)
			if !ok || t.size == 0 {
				continue // the template comes later; these records are lost
			}
			for n := 0; len(body) >= t.size && n < maxRecordsPerPkt; n++ {
				if f, ok := dataRecord(body[:t.size], t, base, received); ok {
					out = append(out, f)
				}
				body = body[t.size:]
			}
		}
	}
	return out, nil
}

func readTemplates(b []byte, tmpl *Templates, domain uint32) {
	for len(b) >= 4 {
		id, count := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if count > maxTemplateFields || len(b) < count*4 {
			return
		}
		t := template{fields: make([]field, 0, count)}
		for range count {
			// Checked each time: an enterprise field below uses more than the four bytes
			// each the check above allowed for.
			if len(b) < 4 {
				return
			}
			f := field{binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:])}
			b = b[4:]
			if f.id&0x8000 != 0 { // IPFIX enterprise field: a private number follows
				if len(b) < 4 {
					return
				}
				b = b[4:]
				f.id = 0 // one we don't read
			}
			if f.length == 0xffff { // variable length: this record can't be stepped through
				return
			}
			t.fields = append(t.fields, f)
			t.size += int(f.length)
		}
		if id >= 256 && t.size > 0 {
			tmpl.set(domain, id, t)
		}
	}
}

func uintOf(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

// dataRecord reads the fields it knows, by IANA number, the same in v9 and IPFIX.
func dataRecord(r []byte, t template, base, received time.Time) (wire.Flow, bool) {
	var f wire.Flow
	for _, fd := range t.fields {
		v := r[:fd.length]
		r = r[fd.length:]
		switch fd.id {
		case 1, 85: // octetDeltaCount, octetTotalCount
			if f.BytesOut == 0 {
				f.BytesOut = uintOf(v)
			}
		case 2, 86: // packetDeltaCount, packetTotalCount
			if f.PktsOut == 0 {
				f.PktsOut = uintOf(v)
			}
		case 4:
			f.Proto = uint8(uintOf(v))
		case 6:
			f.TCPFlags = uint8(uintOf(v))
		case 7:
			f.SrcPort = uint16(uintOf(v))
		case 11:
			f.DstPort = uint16(uintOf(v))
		case 8:
			if len(v) == 4 {
				f.Src = netip.AddrFrom4([4]byte(v))
			}
		case 12:
			if len(v) == 4 {
				f.Dst = netip.AddrFrom4([4]byte(v))
			}
		case 27:
			if len(v) == 16 {
				f.Src = netip.AddrFrom16([16]byte(v)).Unmap()
			}
		case 28:
			if len(v) == 16 {
				f.Dst = netip.AddrFrom16([16]byte(v)).Unmap()
			}
		case 22: // firstSwitched: since the exporter booted
			if !base.IsZero() {
				f.Start = base.Add(time.Duration(uintOf(v)) * time.Millisecond)
			}
		case 21:
			if !base.IsZero() {
				f.End = base.Add(time.Duration(uintOf(v)) * time.Millisecond)
			}
		case 150:
			f.Start = time.Unix(int64(uintOf(v)), 0)
		case 151:
			f.End = time.Unix(int64(uintOf(v)), 0)
		case 152:
			f.Start = time.UnixMilli(int64(uintOf(v)))
		case 153:
			f.End = time.UnixMilli(int64(uintOf(v)))
		}
	}
	return f, finish(&f, received)
}
