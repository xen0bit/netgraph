package decode

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/xen0bit/netgraph/internal/wire"
)

var errDHCP = errors.New("dhcp: malformed message")

var dhcp4Types = []string{"", "DISCOVER", "OFFER", "REQUEST", "DECLINE", "ACK", "NAK", "RELEASE", "INFORM"}

// DHCPv4 parses a BOOTP/DHCP message (RFC 2131/2132).
func DHCPv4(b []byte) (*wire.DHCP, error) {
	if len(b) < 240 || binary.BigEndian.Uint32(b[236:]) != 0x63825363 {
		return nil, errDHCP
	}
	ev := &wire.DHCP{Version: 4}
	if htype, hlen := b[1], int(b[2]); htype == 1 && hlen == 6 {
		ev.MAC = net.HardwareAddr(b[28:34]).String()
	}
	ev.ClientIP = nonZero4(b[12:16])
	ev.YourIP = nonZero4(b[16:20])
	for off := 240; off < len(b); {
		code := b[off]
		if code == 0 { // pad
			off++
			continue
		}
		if code == 255 || off+1 >= len(b) {
			break
		}
		l := int(b[off+1])
		off += 2
		if off+l > len(b) {
			return ev, errDHCP
		}
		v := b[off : off+l]
		off += l
		switch code {
		case 53:
			if l == 1 && int(v[0]) < len(dhcp4Types) {
				ev.MsgType = dhcp4Types[v[0]]
			}
		case 12:
			ev.Hostname = cleanText(v)
		case 50:
			if l == 4 {
				ev.RequestedIP = nonZero4(v)
			}
		case 51:
			if l == 4 {
				ev.LeaseSecs = binary.BigEndian.Uint32(v)
			}
		case 54:
			if l == 4 {
				ev.ServerID = nonZero4(v)
			}
		case 55:
			parts := make([]string, len(v))
			for i, c := range v {
				parts[i] = strconv.Itoa(int(c))
			}
			ev.ParamList = strings.Join(parts, ",")
		case 60:
			ev.VendorClass = cleanText(v)
		case 61:
			ev.ClientID = hex.EncodeToString(v)
		case 81: // client FQDN, RFC 4702: flags, rcode1, rcode2, name
			if l > 3 {
				if v[0]&0x04 != 0 { // E: canonical wire encoding
					if name, _, err := readName(v, 3); err == nil {
						ev.FQDN = strings.ToLower(name)
					}
				} else {
					ev.FQDN = strings.ToLower(strings.TrimSuffix(cleanText(v[3:]), "."))
				}
			}
		}
	}
	if ev.MsgType == "" {
		ev.MsgType = "BOOTP"
	}
	return ev, nil
}

var dhcp6Types = []string{"", "SOLICIT", "ADVERTISE", "REQUEST", "CONFIRM", "RENEW", "REBIND", "REPLY", "RELEASE", "DECLINE", "RECONFIGURE", "INFORMATION-REQUEST"}

// DHCPv6 parses a client/server DHCPv6 message (RFC 8415). Relay messages
// are not unwrapped: a sensor on the LAN sees the client's own message
// before any relay does. srcMAC is the Ethernet source, used when the DUID
// carries no link-layer address.
func DHCPv6(b []byte, srcMAC string) (*wire.DHCP, error) {
	if len(b) < 4 || b[0] == 0 || int(b[0]) >= len(dhcp6Types) {
		return nil, errDHCP
	}
	ev := &wire.DHCP{Version: 6, MsgType: dhcp6Types[b[0]]}
	server := b[0] == 2 || b[0] == 7 || b[0] == 10
	if !server {
		ev.MAC = srcMAC
	}
	err := walkOpts6(b[4:], func(code uint16, v []byte) {
		switch code {
		case 1: // client ID
			ev.ClientID = hex.EncodeToString(v)
			if mac := duidMAC(v); mac != "" {
				ev.MAC = mac
			}
		case 3: // IA_NA: IAID, T1, T2, options
			if len(v) > 12 {
				_ = walkOpts6(v[12:], func(c uint16, a []byte) {
					if c == 5 && len(a) >= 24 { // IAADDR
						ev.Addresses = append(ev.Addresses, netip.AddrFrom16([16]byte(a[:16])))
						if valid := binary.BigEndian.Uint32(a[20:]); valid > ev.LeaseSecs {
							ev.LeaseSecs = valid
						}
					}
				})
			}
		case 16: // vendor class: enterprise number, then length-prefixed data
			if len(v) > 6 {
				ev.VendorClass = cleanText(v[6:])
			}
		case 39: // client FQDN: flags, wire-encoded name
			if len(v) > 1 {
				if name, _, err := readName(v, 1); err == nil {
					ev.FQDN = strings.ToLower(name)
					ev.Hostname, _, _ = strings.Cut(ev.FQDN, ".")
				}
			}
		}
	})
	return ev, err
}

func walkOpts6(b []byte, fn func(code uint16, v []byte)) error {
	for off := 0; off+4 <= len(b); {
		code := binary.BigEndian.Uint16(b[off:])
		l := int(binary.BigEndian.Uint16(b[off+2:]))
		off += 4
		if off+l > len(b) {
			return errDHCP
		}
		fn(code, b[off:off+l])
		off += l
	}
	return nil
}

// duidMAC extracts the link-layer address from a DUID-LLT or DUID-LL with
// hardware type Ethernet.
func duidMAC(d []byte) string {
	if len(d) < 4 || binary.BigEndian.Uint16(d[2:]) != 1 {
		return ""
	}
	switch binary.BigEndian.Uint16(d) {
	case 1: // LLT: type, hwtype, time, address
		if len(d) == 14 {
			return net.HardwareAddr(d[8:14]).String()
		}
	case 3: // LL: type, hwtype, address
		if len(d) == 10 {
			return net.HardwareAddr(d[4:10]).String()
		}
	}
	return ""
}

func nonZero4(b []byte) netip.Addr {
	a := netip.AddrFrom4([4]byte(b))
	if a.IsUnspecified() {
		return netip.Addr{}
	}
	return a
}

// cleanText makes an on-the-wire string safe to store and print: invalid
// UTF-8 and control characters are dropped, and it is trimmed and bounded.
func cleanText(b []byte) string {
	s := strings.ToValidUTF8(string(b), "")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 256 {
		s = strings.ToValidUTF8(s[:256], "")
	}
	return s
}
