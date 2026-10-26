// Package wifi decodes 802.11 frames, derives WEP/WPA/WPA2 keys from what
// the air exposes, and decrypts data frames. It is scaffolding for monitor
// mode capture: a sensor can hand it radiotap frames, receive identity
// events, and pass decrypted Ethernet frames back into the normal pipeline.
//
// Nothing here transmits. SAE/WPA3 and 802.1X establish their keys in ways a
// passive observer cannot follow; those networks are parsed and reported but
// need a supplied PMK to be decrypted.
package wifi

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

// Frame types and subtypes.
const (
	TypeManagement = 0
	TypeControl    = 1
	TypeData       = 2
	TypeExtension  = 3

	SubtypeAssocReq    = 0
	SubtypeAssocResp   = 1
	SubtypeReassocReq  = 2
	SubtypeReassocResp = 3
	SubtypeProbeReq    = 4
	SubtypeProbeResp   = 5
	SubtypeBeacon      = 8
	SubtypeATIM        = 9
	SubtypeDisassoc    = 10
	SubtypeAuth        = 11
	SubtypeDeauth      = 12
	SubtypeAction      = 13
	SubtypeActionNoAck = 14

	SubtypeQoSData = 0x08
)

// Frame is one parsed 802.11 frame. The body aliases the capture buffer.
type Frame struct {
	Type, Subtype uint8
	ToDS, FromDS  bool
	Protected     bool
	Retry         bool
	Order         bool
	QoS           bool

	Addr1, Addr2, Addr3, Addr4 net.HardwareAddr
	Src, Dst, BSSID            net.HardwareAddr
	Seq                        uint16
	HeaderLen                  int
	Body                       []byte

	header                     []byte // MAC header, for CCMP AAD and Michael
	addr1, addr2, addr3, addr4 []byte

	Capability uint16
	Reason     uint16
	Status     uint16

	SSID     string
	Hidden   bool
	Security Security
	IEs      IEs

	// Radio is filled by ParseRadiotap.
	Radio Radio
	// TS is the capture time, set by the processor.
	TS time.Time
}

// Parse decodes a frame without a radiotap header.
func Parse(b []byte) (*Frame, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("802.11: short frame")
	}
	fc := binary.LittleEndian.Uint16(b)
	if fc&0x3 != 0 {
		return nil, fmt.Errorf("802.11: version %d", fc&0x3)
	}
	f := &Frame{
		Type:      uint8(fc>>2) & 0x3,
		Subtype:   uint8(fc>>4) & 0xf,
		ToDS:      fc&0x0100 != 0,
		FromDS:    fc&0x0200 != 0,
		Retry:     fc&0x0800 != 0,
		Protected: fc&0x4000 != 0,
		Order:     fc&0x8000 != 0,
		QoS:       uint8(fc>>2)&0x3 == TypeData && uint8(fc>>4)&0x8 != 0,
	}
	n := f.headerLen()
	if n == 0 || len(b) < n {
		return nil, fmt.Errorf("802.11: truncated %s frame", f.Kind())
	}
	f.HeaderLen, f.header, f.Body = n, b[:n], b[n:]
	switch f.Type {
	case TypeManagement:
		f.addr1, f.addr2, f.addr3 = b[4:10], b[10:16], b[16:22]
	case TypeControl:
		if len(b) >= 10 {
			f.addr1 = b[4:10]
		}
	case TypeData:
		if len(b) >= 24 {
			f.addr1, f.addr2, f.addr3 = b[4:10], b[10:16], b[16:22]
			if f.ToDS && f.FromDS && len(b) >= 30 {
				f.addr4 = b[24:30]
			}
		}
	}
	if len(b) >= 24 {
		f.Seq = (binary.LittleEndian.Uint16(b[22:]) >> 4) & 0xfff
	}
	f.mapAddresses()
	if f.Type != TypeManagement {
		return f, nil
	}
	if err := f.parseManagement(); err != nil {
		return f, err
	}
	return f, nil
}

func (f *Frame) headerLen() int {
	switch f.Type {
	case TypeManagement:
		if f.Order {
			return 28 // +HTC: HT/VHT/HE control follows the sequence field
		}
		return 24
	case TypeControl:
		switch f.Subtype {
		case 7, 8, 12: // control wrapper, block ack req, block ack
			return 24
		case 9: // PS-Poll
			return 16
		case 10: // RTS
			return 16
		case 11, 13: // CTS, ACK
			return 10
		default:
			return 24
		}
	case TypeData:
		n := 24
		if f.ToDS && f.FromDS {
			n += 6
		}
		if f.QoS {
			n += 2
		}
		if f.Order && f.QoS {
			n += 4 // HT control
		}
		return n
	}
	return 0
}

func (f *Frame) mapAddresses() {
	// Addresses per IEEE 802.11 Table 8-19. Management frames always put
	// the BSSID in address 3.
	if f.Type == TypeManagement {
		f.Dst, f.Src, f.BSSID = f.addr1, f.addr2, f.addr3
		return
	}
	switch {
	case !f.ToDS && !f.FromDS:
		f.Dst, f.Src, f.BSSID = f.addr1, f.addr2, f.addr3
	case f.ToDS && !f.FromDS:
		f.BSSID, f.Src, f.Dst = f.addr1, f.addr2, f.addr3
	case !f.ToDS && f.FromDS:
		f.Dst, f.BSSID, f.Src = f.addr1, f.addr2, f.addr3
	default:
		// Wireless distribution: RA/TA are not the endpoints.
		f.Dst, f.Src = f.addr3, f.addr4
	}
}

func (f *Frame) parseManagement() error {
	b := f.Body
	switch f.Subtype {
	case SubtypeBeacon, SubtypeProbeResp:
		if len(b) < 12 {
			return fmt.Errorf("802.11: short beacon")
		}
		f.Capability = binary.LittleEndian.Uint16(b[10:])
		return f.parseIEs(b[12:])
	case SubtypeProbeReq:
		return f.parseIEs(b)
	case SubtypeAssocReq, SubtypeReassocReq:
		fixed := 4
		if f.Subtype == SubtypeReassocReq {
			fixed = 10
		}
		if len(b) < fixed {
			return fmt.Errorf("802.11: short association request")
		}
		f.Capability = binary.LittleEndian.Uint16(b)
		return f.parseIEs(b[fixed:])
	case SubtypeAssocResp, SubtypeReassocResp:
		if len(b) < 6 {
			return fmt.Errorf("802.11: short association response")
		}
		f.Capability = binary.LittleEndian.Uint16(b)
		f.Status = binary.LittleEndian.Uint16(b[2:])
		return f.parseIEs(b[6:])
	case SubtypeAuth:
		if len(b) >= 6 {
			f.Status = binary.LittleEndian.Uint16(b[4:])
		}
	case SubtypeDeauth, SubtypeDisassoc:
		if len(b) >= 2 {
			f.Reason = binary.LittleEndian.Uint16(b)
		}
	case SubtypeAction, SubtypeActionNoAck:
		if len(b) >= 1 && b[0] == 8 {
			// SAE commit/confirm; the body is a management frame but
			// carries no IEs netgraph needs.
			f.Security.Kind = WPA3
		}
	}
	return nil
}

func (f *Frame) parseIEs(b []byte) error {
	ies, err := parseIEs(b)
	f.IEs = ies
	f.SSID = ies.SSID()
	f.Hidden = len(f.SSID) == 0 && f.Type == TypeManagement && f.hasSSIDIE()
	f.Security = securityFromIEs(ies, f.Capability)
	return err
}

func (f *Frame) hasSSIDIE() bool {
	for _, ie := range f.IEs {
		if ie.ID == ieSSID {
			return true
		}
	}
	return false
}

// channel is the AP's operating channel. A beacon or probe response
// advertises it in the DS Parameter Set (or HT Operation) IE, which is
// authoritative; the radiotap channel is only where the card was listening,
// and while hopping that is often an adjacent channel the beacon bled into.
// Frames without those IEs fall back to the radiotap channel.
func (f *Frame) channel() int {
	if c := f.IEs.channel(); c != 0 {
		return c
	}
	return f.Radio.Channel
}

// Kind names the frame for events and logs.
func (f *Frame) Kind() string {
	switch f.Type {
	case TypeManagement:
		switch f.Subtype {
		case SubtypeBeacon:
			return "beacon"
		case SubtypeProbeReq:
			return "probe_request"
		case SubtypeProbeResp:
			return "probe_response"
		case SubtypeAssocReq, SubtypeReassocReq:
			return "association_request"
		case SubtypeAssocResp, SubtypeReassocResp:
			return "association_response"
		case SubtypeAuth:
			return "authentication"
		case SubtypeDeauth:
			return "deauthentication"
		case SubtypeDisassoc:
			return "disassociation"
		case SubtypeAction, SubtypeActionNoAck:
			return "action"
		}
		return "management"
	case TypeControl:
		return "control"
	case TypeData:
		return "data"
	default:
		return "extension"
	}
}

// LLC returns the EtherType and payload of an unprotected data frame.
func (f *Frame) LLC() (uint16, []byte, error) {
	if f.Type != TypeData {
		return 0, nil, fmt.Errorf("802.11: not a data frame")
	}
	if f.Protected {
		return 0, nil, fmt.Errorf("802.11: data frame is encrypted")
	}
	b := f.Body
	if len(b) < 8 || b[0] != 0xaa || b[1] != 0xaa || b[2] != 0x03 {
		return 0, nil, fmt.Errorf("802.11: no SNAP header")
	}
	return binary.BigEndian.Uint16(b[6:]), b[8:], nil
}

// DataOffset is where the link-layer payload starts: after the 802.11
// header (and its data-pad, if any).
func (f *Frame) DataOffset(pad bool) int {
	n := f.HeaderLen
	if pad && f.Type == TypeData {
		n = (n + 3) &^ 3
	}
	return n
}

// Ethernet rebuilds the Ethernet frame a data frame carries, so decrypted
// Wi-Fi traffic can go through the same IP and application pipeline as a
// bridge capture. It returns nil for management/control, encrypted frames,
// and non-SNAP payloads.
func (f *Frame) Ethernet(dst, src net.HardwareAddr, etherType uint16, payload []byte) []byte {
	if len(dst) != 6 || len(src) != 6 || len(payload) > 65535-14 {
		return nil
	}
	b := make([]byte, 14+len(payload))
	copy(b[0:6], dst)
	copy(b[6:12], src)
	binary.BigEndian.PutUint16(b[12:], etherType)
	copy(b[14:], payload)
	return b
}

// WireEvent turns what a management frame said into the server's event.
func (f *Frame) WireEvent() *wire.WiFi {
	// Only management frames carry security IEs. For data frames (including
	// the EAPOL handshake) f.Security is zero, whose String() is "open";
	// leaving Security empty lets the processor fill it from the network's
	// beacon instead of mislabelling an encrypted network "open".
	security := ""
	if f.Security.Kind != "" {
		security = f.Security.String()
	}
	e := &wire.WiFi{
		Kind:      f.Kind(),
		BSSID:     f.BSSID.String(),
		SSID:      f.SSID,
		Channel:   f.channel(),
		Frequency: f.Radio.Frequency,
		Signal:    f.Radio.SignalDBM,
		Security:  security,
		Ciphers:   f.Security.Pairwise,
		AKMs:      f.Security.AKMs,
		Hidden:    f.Hidden,
		Protected: f.Protected,
		Reason:    int(f.Reason),
	}
	if f.Type == TypeManagement {
		switch f.Subtype {
		case SubtypeAssocReq, SubtypeReassocReq, SubtypeProbeReq, SubtypeAuth:
			e.Client = f.Src.String()
		case SubtypeAssocResp, SubtypeReassocResp:
			e.Client = f.Dst.String()
		case SubtypeDeauth, SubtypeDisassoc:
			e.Client = f.Src.String()
		}
	}
	if f.Type == TypeData && f.Src != nil && f.Dst != nil {
		e.Client = f.Src.String()
		if f.BSSID != nil && f.Src.String() == f.BSSID.String() {
			e.Client = f.Dst.String()
		}
	}
	return e
}
