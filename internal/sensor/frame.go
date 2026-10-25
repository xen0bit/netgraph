package sensor

import (
	"encoding/binary"
	"net/netip"

	"github.com/xen0bit/netgraph/internal/capture"
)

// EtherTypes the sensor looks at.
const (
	etherIPv4 = 0x0800
	etherARP  = 0x0806
	etherVLAN = 0x8100
	etherQinQ = 0x88a8
	etherIPv6 = 0x86dd
	etherLLDP = 0x88cc
)

// frame is one parsed packet. It aliases the capture buffer and is only
// valid while handling that packet.
type frame struct {
	srcMAC, dstMAC [6]byte
	hasMAC         bool
	etherType      uint16
	l3             []byte // payload after the link layer

	ipValid  bool
	src, dst netip.Addr
	proto    uint8
	ipLen    int  // header + payload, from the IP header (not the capture)
	frag     bool // a non-first fragment: no L4 header
	l4       []byte

	sport, dport uint16
	tcpFlags     uint8
	seq          uint32
	payload      []byte
}

// parseFrame decodes the link, network and transport headers of data. It
// returns false only when the link layer itself is unreadable; an IP header
// it cannot parse just leaves ipValid false.
func parseFrame(data []byte, link int, f *frame) bool {
	*f = frame{}
	switch link {
	case capture.LinkEthernet:
		if len(data) < 14 {
			return false
		}
		copy(f.dstMAC[:], data[0:6])
		copy(f.srcMAC[:], data[6:12])
		f.hasMAC = true
		et := binary.BigEndian.Uint16(data[12:])
		off := 14
		for (et == etherVLAN || et == etherQinQ) && off+4 <= len(data) {
			et = binary.BigEndian.Uint16(data[off+2:])
			off += 4
		}
		f.etherType, f.l3 = et, data[off:]
	case capture.LinkSLL: // Linux cooked v1: 16-byte header, protocol at 14
		if len(data) < 16 {
			return false
		}
		if binary.BigEndian.Uint16(data[2:]) == 1 && binary.BigEndian.Uint16(data[4:]) == 6 { // ARPHRD_ETHER, 6-byte address
			copy(f.srcMAC[:], data[6:12])
			f.hasMAC = true
		}
		f.etherType, f.l3 = binary.BigEndian.Uint16(data[14:]), data[16:]
	case capture.LinkSLL2: // Linux cooked v2: 20-byte header, protocol at 0
		if len(data) < 20 {
			return false
		}
		if binary.BigEndian.Uint16(data[8:]) == 1 && data[11] == 6 {
			copy(f.srcMAC[:], data[12:18])
			f.hasMAC = true
		}
		f.etherType, f.l3 = binary.BigEndian.Uint16(data), data[20:]
	case capture.LinkRaw, capture.LinkIPv4, capture.LinkIPv6:
		if len(data) < 1 {
			return false
		}
		switch data[0] >> 4 {
		case 4:
			f.etherType = etherIPv4
		case 6:
			f.etherType = etherIPv6
		default:
			return false
		}
		f.l3 = data
	default:
		return false
	}
	switch f.etherType {
	case etherIPv4:
		parseIPv4(f)
	case etherIPv6:
		parseIPv6(f)
	}
	if f.ipValid && !f.frag {
		parseL4(f)
	}
	return true
}

func parseIPv4(f *frame) {
	b := f.l3
	if len(b) < 20 || b[0]>>4 != 4 {
		return
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return
	}
	f.ipLen = int(binary.BigEndian.Uint16(b[2:]))
	f.proto = b[9]
	f.src = netip.AddrFrom4([4]byte(b[12:16]))
	f.dst = netip.AddrFrom4([4]byte(b[16:20]))
	f.frag = binary.BigEndian.Uint16(b[6:])&0x1fff != 0
	end := min(max(f.ipLen, ihl), len(b))
	f.l4 = b[ihl:end]
	f.ipValid = true
}

func parseIPv6(f *frame) {
	b := f.l3
	if len(b) < 40 || b[0]>>4 != 6 {
		return
	}
	f.ipLen = 40 + int(binary.BigEndian.Uint16(b[4:]))
	f.src = netip.AddrFrom16([16]byte(b[8:24]))
	f.dst = netip.AddrFrom16([16]byte(b[24:40]))
	next := b[6]
	off := 40
	// Walk extension headers to the transport header.
	for range 8 {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if off+8 > len(b) {
				return
			}
			next, off = b[off], off+(int(b[off+1])+1)*8
		case 44: // fragment
			if off+8 > len(b) {
				return
			}
			f.frag = binary.BigEndian.Uint16(b[off+2:])&0xfff8 != 0
			next, off = b[off], off+8
		case 51: // AH
			if off+8 > len(b) {
				return
			}
			next, off = b[off], off+(int(b[off+1])+2)*4
		default:
			goto done
		}
	}
done:
	if off > len(b) {
		return
	}
	f.proto = next
	if end := min(f.ipLen, len(b)); off <= end {
		f.l4 = b[off:end]
	}
	f.ipValid = true
}

func parseL4(f *frame) {
	b := f.l4
	switch f.proto {
	case 6:
		if len(b) < 20 {
			return
		}
		f.sport, f.dport = binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:])
		f.seq = binary.BigEndian.Uint32(b[4:])
		hl := int(b[12]>>4) * 4
		f.tcpFlags = b[13]
		if hl >= 20 && hl <= len(b) {
			f.payload = b[hl:]
		}
	case 17:
		if len(b) < 8 {
			return
		}
		f.sport, f.dport = binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:])
		f.payload = b[8:]
	case 1, 58:
		f.payload = b
	}
}
