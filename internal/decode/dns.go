// Package decode turns packet payloads into the facts netgraph records.
//
// Every parser here is a pure function over bytes captured off the wire:
// no state, no I/O. Each must survive arbitrary input — bytes from the LAN
// are attacker-controlled — so each has a Fuzz target that asserts it never
// panics and never loops, and bounds every length it reads before using it.
package decode

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// DNS record types netgraph names. Others are reported as TYPE<n>.
const (
	TypeA      = 1
	TypeNS     = 2
	TypeCNAME  = 5
	TypeSOA    = 6
	TypePTR    = 12
	TypeMX     = 15
	TypeTXT    = 16
	TypeAAAA   = 28
	TypeSRV    = 33
	TypeOPT    = 41
	TypeSVCB   = 64
	TypeHTTPS  = 65
	TypeANY    = 255
	typeNB     = 32 // NetBIOS NB; only meaningful in NBNS
	typeNBSTAT = 33 // NetBIOS NBSTAT; collides with SRV, only meaningful in NBNS
)

var typeNames = map[uint16]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA", TypePTR: "PTR",
	TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA", TypeSRV: "SRV", 35: "NAPTR",
	TypeOPT: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3",
	TypeSVCB: "SVCB", TypeHTTPS: "HTTPS", 99: "SPF", 252: "AXFR", TypeANY: "ANY", 257: "CAA",
}

// TypeName names a DNS record type.
func TypeName(t uint16) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE%d", t)
}

var rcodeNames = []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"}

// RCodeName names a DNS response code.
func RCodeName(c uint8) string {
	if int(c) < len(rcodeNames) {
		return rcodeNames[c]
	}
	return fmt.Sprintf("RCODE%d", c)
}

// DNSMsg is a parsed DNS message (also mDNS, LLMNR and NBNS, which share the
// format).
type DNSMsg struct {
	ID         uint16
	Response   bool
	Opcode     uint8
	RCode      uint8
	Truncated  bool
	Questions  []Question
	Answers    []RR
	Authority  []RR
	Additional []RR
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16 // top bit is mDNS "unicast response wanted"
}

// RR is a resource record with its data decoded where netgraph cares.
type RR struct {
	Name  string
	Type  uint16
	Class uint16 // top bit is mDNS "cache flush"
	TTL   uint32
	Raw   []byte // rdata, aliasing the packet

	Addr   netip.Addr   // A, AAAA
	Target string       // CNAME, PTR, NS, MX, SRV, SVCB/HTTPS target
	Port   uint16       // SRV
	TXT    []string     // TXT
	Hints  []netip.Addr // SVCB/HTTPS ipv4hint/ipv6hint
}

// Data renders an RR's data as text: the address, the target, or the TXT
// strings joined by spaces.
func (r *RR) Data() string {
	switch {
	case r.Addr.IsValid():
		return r.Addr.String()
	case r.Target != "":
		return r.Target
	case len(r.TXT) > 0:
		return strings.Join(r.TXT, " ")
	}
	return ""
}

var (
	errShort   = errors.New("dns: message too short")
	errName    = errors.New("dns: malformed name")
	errTooMany = errors.New("dns: too many records")
)

// maxRecords bounds the records accepted from one message. A UDP message
// cannot legitimately hold more, and the bound keeps a crafted header from
// making the parser allocate for 65535×4 records it will never find.
const maxRecords = 512

// ParseDNS parses a DNS message.
func ParseDNS(b []byte) (*DNSMsg, error) {
	if len(b) < 12 {
		return nil, errShort
	}
	flags := binary.BigEndian.Uint16(b[2:])
	m := &DNSMsg{
		ID:        binary.BigEndian.Uint16(b),
		Response:  flags&0x8000 != 0,
		Opcode:    uint8(flags>>11) & 0xf,
		Truncated: flags&0x0200 != 0,
		RCode:     uint8(flags & 0xf),
	}
	qd := int(binary.BigEndian.Uint16(b[4:]))
	an := int(binary.BigEndian.Uint16(b[6:]))
	ns := int(binary.BigEndian.Uint16(b[8:]))
	ar := int(binary.BigEndian.Uint16(b[10:]))
	if qd+an+ns+ar > maxRecords {
		return nil, errTooMany
	}
	off := 12
	for range qd {
		name, n, err := readName(b, off)
		if err != nil {
			return nil, err
		}
		off = n
		if off+4 > len(b) {
			return nil, errShort
		}
		m.Questions = append(m.Questions, Question{Name: name, Type: binary.BigEndian.Uint16(b[off:]), Class: binary.BigEndian.Uint16(b[off+2:])})
		off += 4
	}
	var err error
	if m.Answers, off, err = readRRs(b, off, an); err != nil {
		return m, err
	}
	if m.Authority, off, err = readRRs(b, off, ns); err != nil {
		return m, err
	}
	// A truncated additional section still leaves a useful message; return
	// what was read alongside the error.
	m.Additional, _, err = readRRs(b, off, ar)
	return m, err
}

func readRRs(b []byte, off, n int) ([]RR, int, error) {
	var out []RR
	for range n {
		name, next, err := readName(b, off)
		if err != nil {
			return out, off, err
		}
		off = next
		if off+10 > len(b) {
			return out, off, errShort
		}
		rr := RR{
			Name:  name,
			Type:  binary.BigEndian.Uint16(b[off:]),
			Class: binary.BigEndian.Uint16(b[off+2:]),
			TTL:   binary.BigEndian.Uint32(b[off+4:]),
		}
		rdlen := int(binary.BigEndian.Uint16(b[off+8:]))
		off += 10
		if off+rdlen > len(b) {
			return out, off, errShort
		}
		rr.Raw = b[off : off+rdlen]
		decodeRData(b, off, &rr)
		off += rdlen
		out = append(out, rr)
	}
	return out, off, nil
}

// decodeRData fills the typed fields of rr. Malformed rdata leaves them
// empty rather than failing the message: one bad record should not hide the
// rest.
func decodeRData(msg []byte, off int, rr *RR) {
	d := rr.Raw
	switch rr.Type {
	case TypeA:
		if len(d) == 4 {
			rr.Addr = netip.AddrFrom4([4]byte(d))
		}
	case TypeAAAA:
		if len(d) == 16 {
			rr.Addr = netip.AddrFrom16([16]byte(d))
		}
	case TypeCNAME, TypePTR, TypeNS:
		if name, _, err := readName(msg, off); err == nil {
			rr.Target = name
		}
	case TypeMX:
		if len(d) > 2 {
			if name, _, err := readName(msg, off+2); err == nil {
				rr.Target = name
			}
		}
	case TypeSRV:
		if len(d) > 6 {
			rr.Port = binary.BigEndian.Uint16(d[4:])
			if name, _, err := readName(msg, off+6); err == nil {
				rr.Target = name
			}
		}
	case TypeTXT:
		for i := 0; i < len(d); {
			l := int(d[i])
			i++
			if i+l > len(d) {
				break
			}
			rr.TXT = append(rr.TXT, string(d[i:i+l]))
			i += l
		}
	case TypeSVCB, TypeHTTPS:
		decodeSVCB(msg, off, rr)
	}
}

// decodeSVCB reads the target and the address hints of an SVCB/HTTPS
// record. The hints matter: a client may connect straight to them without an
// A/AAAA lookup, and correlation needs to know those addresses came from
// this name.
func decodeSVCB(msg []byte, off int, rr *RR) {
	d := rr.Raw
	if len(d) < 3 {
		return
	}
	// RFC 9460 §2.2: the target name is not compressed, so it is read from
	// the rdata alone; readName on the slice guarantees that.
	name, n, err := readName(d, 2)
	if err != nil {
		return
	}
	if name == "" {
		name = "."
	}
	rr.Target = name
	for i := n; i+4 <= len(d); {
		key := binary.BigEndian.Uint16(d[i:])
		l := int(binary.BigEndian.Uint16(d[i+2:]))
		i += 4
		if i+l > len(d) {
			return
		}
		v := d[i : i+l]
		switch key {
		case 4: // ipv4hint
			for j := 0; j+4 <= len(v); j += 4 {
				rr.Hints = append(rr.Hints, netip.AddrFrom4([4]byte(v[j:j+4])))
			}
		case 6: // ipv6hint
			for j := 0; j+16 <= len(v); j += 16 {
				rr.Hints = append(rr.Hints, netip.AddrFrom16([16]byte(v[j:j+16])))
			}
		}
		i += l
	}
}

// readName reads a possibly compressed name at off and returns it without
// the trailing dot (the root is ""), with the offset just past it in b.
//
// Compression pointers must point strictly backwards, which is what makes
// the loop terminate: every jump moves to a smaller offset.
func readName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	end := -1 // offset after the name in the original position
	limit := off
	for {
		if off >= len(b) {
			return "", 0, errName
		}
		l := int(b[off])
		switch l & 0xc0 {
		case 0x00:
			off++
			if l == 0 {
				if end < 0 {
					end = off
				}
				return sb.String(), end, nil
			}
			if off+l > len(b) {
				return "", 0, errName
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			writeLabel(&sb, b[off:off+l])
			if sb.Len() > 255+64 {
				return "", 0, errName
			}
			off += l
		case 0xc0:
			if off+1 >= len(b) {
				return "", 0, errName
			}
			ptr := int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
			if end < 0 {
				end = off + 2
			}
			if ptr >= limit {
				return "", 0, errName
			}
			limit = ptr
			off = ptr
		default:
			return "", 0, errName // 0x40/0x80: extended label types, obsolete
		}
	}
}

// writeLabel writes a label, escaping the bytes that would make the dotted
// form ambiguous or unprintable.
func writeLabel(sb *strings.Builder, l []byte) {
	for _, c := range l {
		switch {
		case c == '.' || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c < 0x21 && c != ' ' || c > 0x7e:
			fmt.Fprintf(sb, "\\%03d", c)
		default:
			sb.WriteByte(c)
		}
	}
}

// encodeName is the inverse of readName without compression; used by tests
// and by the QUIC/TLS fixtures that need a wire name.
func encodeName(name string) []byte {
	var out []byte
	if name != "" && name != "." {
		for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
			out = append(out, byte(len(l)))
			out = append(out, l...)
		}
	}
	return append(out, 0)
}
