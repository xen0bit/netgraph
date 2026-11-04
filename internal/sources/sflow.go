package sources

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

// sFlow samples packets rather than reporting connections, so one sample stands for
// sampling-rate packets like it. Volumes are estimates, and a short connection between
// samples isn't seen at all.

const (
	sflowEthernet = 1
	sflowIPv4     = 11
	sflowIPv6     = 12

	sflowFlowSample         = 1
	sflowExpandedFlowSample = 3
	sflowRawHeader          = 1
	sflowIPv4Data           = 3
	sflowIPv6Data           = 4

	maxIPv6ExtHeaders = 8
	maxSFlowPending   = 65536
)

// ParseSFlow decodes one sFlow v5 datagram into a record per sample, with volumes scaled
// up by the sampling rate. Counter samples describe interfaces, not traffic, and are skipped.
func ParseSFlow(b []byte, received time.Time) (flows []wire.Flow, err error) {
	defer func() {
		if r := recover(); r != nil {
			flows, err = nil, fmt.Errorf("sflow: decoding panicked: %v", r)
		}
	}()
	if len(b) < 8 {
		return nil, errShort
	}
	if v := binary.BigEndian.Uint32(b); v != 5 {
		return nil, fmt.Errorf("sflow: version %d isn't supported", v)
	}
	var agent int
	switch binary.BigEndian.Uint32(b[4:]) {
	case 1:
		agent = 4
	case 2:
		agent = 16
	default:
		return nil, errShort
	}
	b = b[8:]
	if len(b) < agent+16 {
		return nil, errShort
	}
	count := binary.BigEndian.Uint32(b[agent+12:])
	b = b[agent+16:]
	for i := uint32(0); i < count && len(b) >= 8 && len(flows) < maxRecordsPerPkt; i++ {
		format, length := binary.BigEndian.Uint32(b), binary.BigEndian.Uint32(b[4:])
		if uint64(length) > uint64(len(b)-8) {
			return flows, errShort
		}
		body := b[8 : 8+length]
		b = b[8+length:]
		switch format { // an enterprise other than 0 reads as a number no case matches
		case sflowFlowSample:
			flows = sample(body, 8, 28, flows, received)
		case sflowExpandedFlowSample:
			flows = sample(body, 12, 40, flows, received)
		}
	}
	return flows, nil
}

// sample reads a flow sample. rateAt and recordsAt are where the two forms keep the
// sampling rate and the record count.
func sample(b []byte, rateAt, recordsAt int, flows []wire.Flow, received time.Time) []wire.Flow {
	if len(b) < recordsAt+4 {
		return flows
	}
	rate := uint64(binary.BigEndian.Uint32(b[rateAt:]))
	if rate == 0 {
		rate = 1
	}
	count := binary.BigEndian.Uint32(b[recordsAt:])
	b = b[recordsAt+4:]
	for i := uint32(0); i < count && len(b) >= 8; i++ {
		format, length := binary.BigEndian.Uint32(b), binary.BigEndian.Uint32(b[4:])
		if uint64(length) > uint64(len(b)-8) {
			return flows
		}
		body := b[8 : 8+length]
		b = b[8+length:]
		var f wire.Flow
		var frame uint32
		var ok bool
		switch format {
		case sflowRawHeader:
			f, frame, ok = rawHeader(body)
		case sflowIPv4Data:
			f, frame, ok = ipData(body, 4)
		case sflowIPv6Data:
			f, frame, ok = ipData(body, 16)
		}
		if !ok {
			continue
		}
		f.BytesOut, f.PktsOut = uint64(frame)*rate, rate
		if finish(&f, received) {
			return append(flows, f) // the other records describe the same packet
		}
	}
	return flows
}

// rawHeader reads the first bytes of the sampled packet.
func rawHeader(b []byte) (wire.Flow, uint32, bool) {
	if len(b) < 16 {
		return wire.Flow{}, 0, false
	}
	proto, frame, n := binary.BigEndian.Uint32(b), binary.BigEndian.Uint32(b[4:]), binary.BigEndian.Uint32(b[12:])
	h := b[16:]
	if uint64(n) < uint64(len(h)) {
		h = h[:n]
	}
	var f wire.Flow
	var ok bool
	switch proto {
	case sflowEthernet:
		f, ok = ethernet(h)
	case sflowIPv4:
		f, ok = ipv4(h)
	case sflowIPv6:
		f, ok = ipv6(h)
	}
	return f, frame, ok
}

// ipData reads the shorter record some agents send instead of a header. Its ports have
// the width of a 32-bit XDR integer.
func ipData(b []byte, addr int) (wire.Flow, uint32, bool) {
	size := 8 + 2*addr + 16
	if len(b) < size {
		return wire.Flow{}, 0, false
	}
	f := wire.Flow{Proto: uint8(binary.BigEndian.Uint32(b[4:]))}
	if addr == 4 {
		f.Src, f.Dst = netip.AddrFrom4([4]byte(b[8:12])), netip.AddrFrom4([4]byte(b[12:16]))
	} else {
		f.Src, f.Dst = netip.AddrFrom16([16]byte(b[8:24])).Unmap(), netip.AddrFrom16([16]byte(b[24:40])).Unmap()
	}
	r := b[8+2*addr:]
	f.SrcPort, f.DstPort = uint16(binary.BigEndian.Uint32(r)), uint16(binary.BigEndian.Uint32(r[4:]))
	f.TCPFlags = uint8(binary.BigEndian.Uint32(r[8:]))
	return f, binary.BigEndian.Uint32(b), true
}

func ethernet(b []byte) (wire.Flow, bool) {
	if len(b) < 14 {
		return wire.Flow{}, false
	}
	dmac, smac := b[0:6], b[6:12]
	typ := binary.BigEndian.Uint16(b[12:])
	b = b[14:]
	for range 2 { // QinQ at most
		if typ != 0x8100 && typ != 0x88a8 {
			break
		}
		if len(b) < 4 {
			return wire.Flow{}, false
		}
		typ = binary.BigEndian.Uint16(b[2:])
		b = b[4:]
	}
	var f wire.Flow
	var ok bool
	switch typ {
	case 0x0800:
		f, ok = ipv4(b)
	case 0x86dd:
		f, ok = ipv6(b)
	}
	if !ok {
		return f, false
	}
	f.SrcMAC = macString(smac)
	if dmac[0]&1 == 0 { // a group address isn't anyone's
		f.DstMAC = macString(dmac)
	}
	return f, true
}

func macString(m []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 17)
	for i, c := range m {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[c>>4], hex[c&15])
	}
	return string(out)
}

func ipv4(b []byte) (wire.Flow, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return wire.Flow{}, false
	}
	ihl := int(b[0]&15) * 4
	if ihl < 20 || ihl > len(b) {
		return wire.Flow{}, false
	}
	f := wire.Flow{Proto: b[9], Src: netip.AddrFrom4([4]byte(b[12:16])), Dst: netip.AddrFrom4([4]byte(b[16:20]))}
	if binary.BigEndian.Uint16(b[6:])&0x1fff == 0 { // later fragments have no ports
		transport(&f, b[ihl:])
	}
	return f, true
}

func ipv6(b []byte) (wire.Flow, bool) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return wire.Flow{}, false
	}
	f := wire.Flow{Src: netip.AddrFrom16([16]byte(b[8:24])).Unmap(), Dst: netip.AddrFrom16([16]byte(b[24:40])).Unmap()}
	next := b[6]
	b = b[40:]
	for range maxIPv6ExtHeaders {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(b) < 8 {
				f.Proto = next
				return f, true
			}
			n := (int(b[1]) + 1) * 8
			if n > len(b) {
				f.Proto = next
				return f, true
			}
			next, b = b[0], b[n:]
			continue
		case 44: // fragment
			if len(b) < 8 {
				f.Proto = next
				return f, true
			}
			offset := binary.BigEndian.Uint16(b[2:]) >> 3
			next, b = b[0], b[8:]
			if offset != 0 {
				f.Proto = next
				return f, true
			}
			continue
		case 51: // authentication
			if len(b) < 8 {
				f.Proto = next
				return f, true
			}
			n := (int(b[1]) + 2) * 4
			if n > len(b) {
				f.Proto = next
				return f, true
			}
			next, b = b[0], b[n:]
			continue
		}
		break
	}
	f.Proto = next
	transport(&f, b)
	return f, true
}

func transport(f *wire.Flow, b []byte) {
	if (f.Proto != 6 && f.Proto != 17) || len(b) < 4 {
		return
	}
	f.SrcPort, f.DstPort = binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:])
	if f.Proto == 6 && len(b) >= 14 {
		f.TCPFlags = b[13]
	}
}

// sampleTotals gathers samples of a connection, which each read as a record of their own
// otherwise: one a packet, at the sampling rate.
type sampleTotals struct {
	byID  map[uint64]*wire.Flow
	order []uint64
}

func (s *sampleTotals) add(f wire.Flow) {
	if s.byID == nil {
		s.byID = map[uint64]*wire.Flow{}
	}
	cur := s.byID[f.ID]
	if cur == nil {
		if len(s.byID) >= maxSFlowPending {
			return
		}
		s.byID[f.ID] = &f
		s.order = append(s.order, f.ID)
		return
	}
	cur.BytesOut += f.BytesOut
	cur.BytesIn += f.BytesIn
	cur.PktsOut += f.PktsOut
	cur.PktsIn += f.PktsIn
	cur.TCPFlags |= f.TCPFlags
	if f.Start.Before(cur.Start) {
		cur.Start = f.Start
	}
	if f.End.After(cur.End) {
		cur.End = f.End
	}
	if cur.SrcMAC == "" {
		cur.SrcMAC = f.SrcMAC
	}
	if cur.DstMAC == "" {
		cur.DstMAC = f.DstMAC
	}
}

func (s *sampleTotals) drain() []wire.Event {
	out := make([]wire.Event, 0, len(s.order))
	for _, id := range s.order {
		f := s.byID[id]
		f.FirstSeen = f.Start
		out = append(out, wire.Event{Type: wire.TypeFlow, TS: f.End, Flow: f})
	}
	s.byID, s.order = nil, nil
	return out
}
