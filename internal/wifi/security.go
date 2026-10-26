package wifi

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Security is what a beacon or probe response says protects the network.
type Security struct {
	Kind     string   // open, wep, wpa, wpa2, wpa3, wpa2/wpa3, owe
	Group    string   // group cipher
	Pairwise []string // pairwise ciphers
	AKMs     []string // authentication and key management suites
}

// Kinds reported in Security.Kind.
const (
	Open     = "open"
	WEP      = "wep"
	WPA      = "wpa"
	WPA2     = "wpa2"
	WPA3     = "wpa3"
	WPA2WPA3 = "wpa2/wpa3"
	OWE      = "owe"
)

func (s Security) String() string {
	if s.Kind == "" {
		return Open
	}
	return s.Kind
}

// Protected reports whether the network encrypts data frames.
func (s Security) Protected() bool { return s.Kind != "" && s.Kind != Open }

// UsesCCMP reports whether CCMP is among the pairwise ciphers.
func (s Security) UsesCCMP() bool {
	for _, c := range s.Pairwise {
		if c == "CCMP" {
			return true
		}
	}
	return false
}

// UsesTKIP reports whether TKIP is among the pairwise ciphers.
func (s Security) UsesTKIP() bool {
	for _, c := range s.Pairwise {
		if c == "TKIP" {
			return true
		}
	}
	return false
}

// UsesGCMP reports a cipher netgraph does not decrypt yet.
func (s Security) UsesGCMP() bool {
	for _, c := range s.Pairwise {
		if strings.HasPrefix(c, "GCMP") {
			return true
		}
	}
	return false
}

// WPA3Only reports whether the network requires SAE and cannot be decrypted
// from a passphrase and a 4-way handshake (SAE establishes the PMK itself).
func (s Security) WPA3Only() bool {
	return s.Kind == WPA3 || s.Kind == OWE
}

const (
	ieSSID    = 0
	ieRates   = 1
	ieDS      = 3
	ieRSN     = 48
	ieVendor  = 221
	ieExtCap  = 127
	ieHTCap   = 45
	ieVHTCap  = 191
	ieHECap   = 255
	ieCountry = 7
)

const (
	ouiMicrosoft = 0x0050f2
	ouiIEEE      = 0x000fac
)

// IE is one 802.11 information element.
type IE struct {
	ID   byte
	Body []byte
}

// IEs is a parsed information element list.
type IEs []IE

// parseIEs reads a bounded sequence of information elements.
func parseIEs(b []byte) (IEs, error) {
	var out IEs
	for len(b) >= 2 {
		id, n := b[0], int(b[1])
		if n > len(b)-2 {
			return out, fmt.Errorf("information element %d overruns frame", id)
		}
		out = append(out, IE{ID: id, Body: b[2 : 2+n]})
		b = b[2+n:]
	}
	if len(b) == 1 {
		return out, fmt.Errorf("truncated information element")
	}
	return out, nil
}

func (ies IEs) find(id byte) ([]byte, bool) {
	for _, ie := range ies {
		if ie.ID == id {
			return ie.Body, true
		}
	}
	return nil, false
}

// SSID returns the network name; empty for a hidden network.
func (ies IEs) SSID() string {
	b, ok := ies.find(ieSSID)
	if !ok || len(b) == 0 || allZero(b) {
		return ""
	}
	return cleanText(b)
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func cleanText(b []byte) string {
	// SSIDs are arbitrary bytes; keep printable ASCII and replace the
	// rest so the UI never receives control characters from the air.
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == ' ' || c >= '!' && c <= '~':
			sb.WriteByte(c)
		case c == 0:
			// hidden-network padding
		default:
			sb.WriteByte('?')
		}
	}
	return sb.String()
}

// securityFromIEs classifies a network. capability is the beacon/probe
// capability field, whose privacy bit means "encrypted" on its own (WEP).
func securityFromIEs(ies IEs, capability uint16) Security {
	var s Security
	haveRSN, wpaVendor := false, false
	if body, ok := ies.find(ieRSN); ok && len(body) >= 2 {
		if r, err := parseSuiteIE(body, true); err == nil {
			s, haveRSN = r, true
		}
	}
	if !haveRSN {
		for _, ie := range ies {
			if ie.ID != ieVendor || len(ie.Body) < 6 || binary.BigEndian.Uint32(append([]byte{0}, ie.Body[:3]...)) != ouiMicrosoft || ie.Body[3] != 1 {
				continue
			}
			if r, err := parseSuiteIE(ie.Body[4:], false); err == nil {
				s, haveRSN, wpaVendor = r, true, true
				break
			}
		}
	}
	privacy := capability&0x0010 != 0
	if !haveRSN {
		if privacy {
			s.Kind = WEP
			s.Group = "WEP"
		} else {
			s.Kind = Open
		}
		return s
	}
	if wpaVendor {
		// A WPA IE is always WPA1, even with a CCMP pairwise cipher.
		s.Kind = WPA
	} else {
		s.Kind = classifyAKM(s.AKMs)
	}
	return s
}

// parseSuiteIE decodes the body of an RSN IE or the WPA vendor IE (without
// its OUI/type prefix).
func parseSuiteIE(b []byte, rsn bool) (Security, error) {
	var s Security
	if len(b) < 2 {
		return s, fmt.Errorf("short security element")
	}
	if binary.LittleEndian.Uint16(b) != 1 {
		return s, fmt.Errorf("unsupported security version")
	}
	b = b[2:]
	if len(b) < 4 {
		return s, fmt.Errorf("short group cipher")
	}
	s.Group = cipherName(b[:4])
	b = b[4:]
	if len(b) < 2 {
		return s, fmt.Errorf("short pairwise count")
	}
	n := int(binary.LittleEndian.Uint16(b))
	b = b[2:]
	if n == 0 || len(b) < 4*n {
		return s, fmt.Errorf("short pairwise list")
	}
	for i := 0; i < n; i++ {
		s.Pairwise = append(s.Pairwise, cipherName(b[4*i:4*i+4]))
	}
	b = b[4*n:]
	if len(b) < 2 {
		return s, fmt.Errorf("short AKM count")
	}
	n = int(binary.LittleEndian.Uint16(b))
	b = b[2:]
	if len(b) < 4*n {
		return s, fmt.Errorf("short AKM list")
	}
	for i := 0; i < n; i++ {
		s.AKMs = append(s.AKMs, akmName(b[4*i:4*i+4]))
	}
	if !rsn {
		_ = b // WPA defines capabilities after the lists; nothing else is needed.
	}
	return s, nil
}

func suiteOUI(b []byte) (oui uint32, typ byte) {
	if len(b) < 4 {
		return 0, 0
	}
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), b[3]
}

func cipherName(b []byte) string {
	oui, typ := suiteOUI(b)
	if oui == ouiIEEE {
		switch typ {
		case 1:
			return "WEP-40"
		case 2:
			return "TKIP"
		case 4:
			return "CCMP"
		case 5:
			return "WEP-104"
		case 8:
			return "GCMP-128"
		case 9:
			return "GCMP-256"
		case 10:
			return "CCMP-256"
		case 11:
			return "BIP-CMAC-128"
		case 12:
			return "BIP-GMAC-128"
		case 13:
			return "BIP-GMAC-256"
		}
	}
	return fmt.Sprintf("%02x:%02x:%02x:%d", b[0], b[1], b[2], typ)
}

func akmName(b []byte) string {
	oui, typ := suiteOUI(b)
	if oui == ouiIEEE {
		switch typ {
		case 1:
			return "802.1X"
		case 2:
			return "PSK"
		case 3:
			return "FT-802.1X"
		case 4:
			return "FT-PSK"
		case 5:
			return "802.1X-SHA256"
		case 6:
			return "PSK-SHA256"
		case 7:
			return "TDLS"
		case 8:
			return "SAE"
		case 9:
			return "FT-SAE"
		case 11:
			return "802.1X-SUITE-B-192"
		case 12:
			return "OWE"
		case 13:
			return "FT-802.1X-SHA384"
		case 14:
			return "FILS-SHA256"
		case 15:
			return "FILS-SHA384"
		case 16:
			return "FT-FILS-SHA256"
		case 17:
			return "FT-FILS-SHA384"
		case 18:
			return "OWE-TRANSITION"
		case 19:
			return "SAE-EXT-KEY"
		}
	}
	if oui == ouiMicrosoft && typ == 2 {
		return "PSK"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%d", b[0], b[1], b[2], typ)
}

func classifyAKM(akms []string) string {
	var sae, owe, psk, enterprise bool
	for _, a := range akms {
		switch {
		case a == "SAE" || a == "FT-SAE" || a == "SAE-EXT-KEY":
			sae = true
		case a == "OWE":
			owe = true
		case strings.Contains(a, "PSK"):
			psk = true
		case strings.Contains(a, "802.1X"):
			enterprise = true
		}
	}
	switch {
	case owe:
		return OWE
	case sae && (psk || enterprise):
		return WPA2WPA3
	case sae:
		return WPA3
	default:
		return WPA2
	}
}
