package decode

import (
	"bytes"
	"net/netip"
	"strings"

	"github.com/xen0bit/netgraph/internal/wire"
)

// sysNameOID is 1.3.6.1.2.1.1.5.0 (SNMPv2-MIB::sysName.0), in DER.
var sysNameOID = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00}

// SNMP returns the sysName a host put in an SNMP GET-RESPONSE, as a name the
// device claims about itself. Only SNMPv1 and v2c are read, and only a
// response: a request says nothing about the sender's name. The community
// string is neither stored nor returned.
//
// The message is attacker-controlled bytes, so every length is bound and the
// walk is capped: maxVarbinds varbinds, an OID no longer than the one
// compared, and a value of at most 255 bytes.
func SNMP(b []byte, src netip.Addr, mac string) *wire.Name {
	const maxVarbinds = 64
	tag, msg, _, ok := berTLV(b)
	if !ok || tag != 0x30 {
		return nil
	}
	// version INTEGER, community OCTET STRING
	tag, ver, rest, ok := berTLV(msg)
	// Only 0 (v1) and 1 (v2c), each one byte: v3 has a different shape, and a
	// longer INTEGER ending in 0 or 1 is not either of them.
	if !ok || tag != 0x02 || len(ver) != 1 || ver[0] > 1 {
		return nil
	}
	if tag, _, rest, ok = berTLV(rest); !ok || tag != 0x04 {
		return nil
	}
	// PDU: GetResponse is context-specific constructed 2 (0xa2).
	var pdu []byte
	if tag, pdu, rest, ok = berTLV(rest); !ok || tag != 0xa2 {
		return nil
	}
	_ = rest
	// request-id, error-status, error-index
	for range 3 {
		if _, _, pdu, ok = berTLV(pdu); !ok {
			return nil
		}
	}
	tag, vbl, _, ok := berTLV(pdu)
	if !ok || tag != 0x30 {
		return nil
	}
	for range maxVarbinds {
		tag, vb, next, ok := berTLV(vbl)
		if !ok || tag != 0x30 {
			return nil
		}
		vbl = next
		tag, oid, body, ok := berTLV(vb)
		if !ok || tag != 0x06 || len(oid) > 16 {
			continue
		}
		tag, val, _, ok := berTLV(body)
		if !ok || tag != 0x04 || len(val) > 255 {
			continue
		}
		if bytes.Equal(oid, sysNameOID) {
			name := cleanText(val)
			// A sysName is a hostname, not a sentence: take its first
			// whitespace-separated word if the whole is unreasonable.
			if i := strings.IndexAny(name, " \t"); i > 0 && len(name) > 64 {
				name = name[:i]
			}
			if name == "" {
				return nil
			}
			return &wire.Name{MAC: mac, IP: src, Name: name, Proto: "snmp"}
		}
	}
	return nil
}

// berTLV splits one BER/DER tag-length-value. It accepts a definite length
// only and refuses one longer than what is left, which is all an SNMP
// message needs and keeps a bogus length from reading past the buffer.
func berTLV(b []byte) (tag byte, val, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	n := 2
	l := int(b[1])
	if l&0x80 != 0 {
		k := l & 0x7f
		if k == 0 || k > 4 || len(b) < 2+k {
			return 0, nil, nil, false
		}
		l = 0
		for i := range int(k) {
			l = l<<8 | int(b[2+i])
		}
		n += int(k)
	}
	if l < 0 || l > len(b)-n {
		return 0, nil, nil, false
	}
	return tag, b[n : n+l], b[n+l:], true
}
