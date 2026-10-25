package decode

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/xen0bit/netgraph/internal/wire"
)

// ARP returns the binding announced by an ARP request or reply: the sender
// MAC owns the sender IP. Probes (sender 0.0.0.0) claim nothing.
func ARP(b []byte) *wire.Binding {
	// Ethernet/IPv4 ARP only: htype 1, ptype 0x0800, hlen 6, plen 4.
	if len(b) < 28 || binary.BigEndian.Uint16(b) != 1 || binary.BigEndian.Uint16(b[2:]) != 0x0800 || b[4] != 6 || b[5] != 4 {
		return nil
	}
	ip := netip.AddrFrom4([4]byte(b[14:18]))
	mac := net.HardwareAddr(b[8:14])
	if ip.IsUnspecified() || isZeroMAC(mac) {
		return nil
	}
	return &wire.Binding{MAC: mac.String(), IP: ip, Source: "arp"}
}

// NDP returns the binding carried by an ICMPv6 neighbour/router message
// (RFC 4861), given the ICMPv6 message (type onward) and the IPv6 source.
//
//   - NS and RS: the source address belongs to the source link-layer option.
//   - NA: the target address belongs to the target link-layer option.
//   - RA: as RS, and the sender is a router.
//
// DAD probes (source ::) claim nothing.
func NDP(icmp []byte, src netip.Addr) *wire.Binding {
	if len(icmp) < 8 {
		return nil
	}
	var optOff int
	var ip netip.Addr
	var want byte // option type carrying the MAC
	router := false
	switch icmp[0] {
	case 133: // RS
		optOff, ip, want = 8, src, 1
	case 134: // RA
		optOff, ip, want, router = 16, src, 1, true
	case 135: // NS
		optOff, ip, want = 24, src, 1
	case 136: // NA
		if len(icmp) < 24 {
			return nil
		}
		optOff, ip, want = 24, netip.AddrFrom16([16]byte(icmp[8:24])), 2
	default:
		return nil
	}
	if !ip.IsValid() || ip.IsUnspecified() {
		return nil
	}
	for off := optOff; off+2 <= len(icmp); {
		t, l := icmp[off], int(icmp[off+1])*8
		if l == 0 || off+l > len(icmp) {
			return nil
		}
		if t == want && l >= 8 {
			mac := net.HardwareAddr(icmp[off+2 : off+8])
			if isZeroMAC(mac) {
				return nil
			}
			return &wire.Binding{MAC: mac.String(), IP: ip, Source: "ndp", Router: router}
		}
		off += l
	}
	return nil
}

func isZeroMAC(m net.HardwareAddr) bool {
	for _, c := range m {
		if c != 0 {
			return false
		}
	}
	return true
}

// LLDP parses an LLDPDU (IEEE 802.1AB), the payload after the Ethernet
// header. srcMAC is the sending port's MAC.
func LLDP(b []byte, srcMAC string) (*wire.LLDP, error) {
	ev := &wire.LLDP{MAC: srcMAC}
	for off := 0; off+2 <= len(b); {
		hdr := binary.BigEndian.Uint16(b[off:])
		t, l := hdr>>9, int(hdr&0x1ff)
		off += 2
		if off+l > len(b) {
			return nil, fmt.Errorf("lldp: tlv overruns frame")
		}
		v := b[off : off+l]
		off += l
		switch t {
		case 0:
			return ev, nil
		case 1:
			ev.ChassisID = lldpID(v)
		case 2:
			ev.PortID = lldpID(v)
		case 4:
			ev.PortDesc = cleanText(v)
		case 5:
			ev.SystemName = cleanText(v)
		case 6:
			ev.SystemDesc = cleanText(v)
		case 8: // management address: length, subtype, address, ...
			if len(v) >= 2 {
				alen := int(v[0])
				if alen >= 1 && 1+alen <= len(v) {
					switch a := v[2 : 1+alen]; v[1] {
					case 1:
						if len(a) == 4 {
							ev.MgmtAddress = netip.AddrFrom4([4]byte(a)).String()
						}
					case 2:
						if len(a) == 16 {
							ev.MgmtAddress = netip.AddrFrom16([16]byte(a)).String()
						}
					}
				}
			}
		}
	}
	if ev.ChassisID == "" {
		return nil, fmt.Errorf("lldp: no chassis id")
	}
	return ev, nil
}

// lldpID renders a chassis or port ID by its subtype.
func lldpID(v []byte) string {
	if len(v) < 2 {
		return ""
	}
	switch v[0] {
	case 4, 3: // MAC address (chassis subtype 4, port subtype 3)
		if len(v) == 7 {
			return net.HardwareAddr(v[1:]).String()
		}
	case 5: // network address: family, address
		if len(v) == 6 && v[1] == 1 {
			return netip.AddrFrom4([4]byte(v[2:])).String()
		}
	}
	return cleanText(v[1:])
}

// SSDP parses an SSDP datagram (UPnP Device Architecture §1): NOTIFY or
// M-SEARCH requests and HTTP-over-UDP responses.
func SSDP(b []byte, src netip.Addr, mac string) *wire.SSDP {
	line, rest, ok := strings.Cut(string(b), "\r\n")
	if !ok {
		return nil
	}
	ev := &wire.SSDP{MAC: mac, IP: src}
	switch {
	case strings.HasPrefix(line, "NOTIFY "):
		ev.Method = "NOTIFY"
	case strings.HasPrefix(line, "M-SEARCH "):
		ev.Method = "M-SEARCH"
	case strings.HasPrefix(line, "HTTP/1."):
		ev.Method = "RESPONSE"
	default:
		return nil
	}
	for _, h := range strings.Split(rest, "\r\n") {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		v = cleanText([]byte(v))
		switch strings.ToUpper(strings.TrimSpace(k)) {
		case "SERVER":
			ev.Server = v
		case "USN":
			ev.USN = v
		case "NT", "ST":
			ev.NT = v
		case "LOCATION":
			ev.Location = v
		case "USER-AGENT":
			ev.UserAgent = v
		}
	}
	return ev
}

// HTTPRequest recognises the start of an HTTP/1.x request and returns its
// Host and User-Agent. ok is false when b is not an HTTP request; complete
// is false when the header block has not all arrived yet.
func HTTPRequest(b []byte) (host, ua string, ok, complete bool) {
	if !looksLikeHTTP(b) {
		return "", "", false, false
	}
	s := string(b)
	head, _, complete := strings.Cut(s, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	if len(lines) == 0 || !strings.Contains(lines[0], " HTTP/1.") && complete {
		return "", "", false, false
	}
	for _, h := range lines[1:] {
		k, v, found := strings.Cut(h, ":")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "host":
			host = strings.ToLower(cleanText([]byte(v)))
		case "user-agent":
			ua = cleanText([]byte(v))
		}
	}
	return host, ua, true, complete
}

var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}

func looksLikeHTTP(b []byte) bool {
	for _, m := range httpMethods {
		if len(b) >= len(m) && string(b[:len(m)]) == m {
			return true
		}
	}
	return false
}
