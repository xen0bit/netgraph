package decode

import (
	"net/netip"
	"testing"
)

// ber builds one definite-length TLV. Test messages are small, so only the
// one- and two-byte length forms are needed.
func ber(tag byte, v []byte) []byte {
	switch {
	case len(v) < 128:
		return append([]byte{tag, byte(len(v))}, v...)
	case len(v) < 256:
		return append([]byte{tag, 0x81, byte(len(v))}, v...)
	default:
		return append([]byte{tag, 0x82, byte(len(v) >> 8), byte(len(v))}, v...)
	}
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// snmpResponse builds an SNMPv2c GetResponse carrying one sysName varbind.
func snmpResponse(name string) []byte {
	return snmpMessage(0xa2, cat(
		ber(0x06, []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00}),
		ber(0x04, []byte(name)),
	))
}

// snmpMessage wraps one varbind in a message whose PDU has the given tag.
func snmpMessage(pduTag byte, varbind []byte) []byte {
	vbl := ber(0x30, ber(0x30, varbind))
	pdu := ber(pduTag, cat(ber(0x02, []byte{1}), ber(0x02, []byte{0}), ber(0x02, []byte{0}), vbl))
	return ber(0x30, cat(ber(0x02, []byte{1}), ber(0x04, []byte("public")), pdu))
}

func TestSNMPSysName(t *testing.T) {
	src := netip.MustParseAddr("192.168.1.5")
	n := SNMP(snmpResponse("core-switch"), src, "aa:bb:cc:dd:ee:ff")
	if n == nil || n.Name != "core-switch" || n.Proto != "snmp" || n.IP != src || n.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("got %+v", n)
	}
	// A request is not a claim: its PDU tag is 0xa0, not 0xa2.
	if got := SNMP(snmpMessage(0xa0, cat(ber(0x06, []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00}), ber(0x04, []byte("x")))), src, ""); got != nil {
		t.Errorf("a request named the sender: %+v", got)
	}
	// Another OID is not a hostname.
	other := snmpMessage(0xa2, cat(ber(0x06, []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}), ber(0x04, []byte("desc"))))
	if got := SNMP(other, src, ""); got != nil {
		t.Errorf("sysDescr became a name: %+v", got)
	}
	// A two-byte version ending in 1 (257) is not v2c.
	v257 := snmpResponse("x")
	v257 = ber(0x30, cat(ber(0x02, []byte{1, 1}), v257[5:]))
	if got := SNMP(v257, src, ""); got != nil {
		t.Errorf("version 257 read as v2c: %+v", got)
	}
	// Truncated and overlong shapes end cleanly.
	full := snmpResponse("x")
	for i := range len(full) {
		SNMP(full[:i], src, "")
	}
	if got := SNMP([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, src, ""); got != nil {
		t.Errorf("bogus length read as %+v", got)
	}
	if got := SNMP([]byte{0x30, 0x03, 0x02, 0x01, 0x01}, src, ""); got != nil {
		t.Errorf("header-only message read as %+v", got)
	}
}
