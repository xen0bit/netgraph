package decode

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ClientHello is what netgraph keeps from a TLS ClientHello.
type ClientHello struct {
	SNI  string
	ALPN []string
	JA4  string

	legacyVersion uint16
	versions      []uint16 // supported_versions
	ciphers       []uint16
	extensions    []uint16 // in wire order
	sigAlgs       []uint16
}

var (
	// ErrNeedMore means the input is a plausible prefix of a ClientHello
	// and more bytes are needed.
	ErrNeedMore = errors.New("tls: need more data")
	// ErrNotTLS means the input is not a TLS ClientHello.
	ErrNotTLS = errors.New("tls: not a client hello")
)

// maxHelloBytes bounds how much handshake data is accumulated. Post-quantum
// key shares push real ClientHellos past 1.5 KB; 16 KB is a full TLS record
// and far beyond any real hello.
const maxHelloBytes = 16 << 10

// ParseTLSRecords parses a ClientHello from the start of a TCP stream:
// one or more TLS records of content type handshake whose fragments
// concatenate into the handshake message.
func ParseTLSRecords(b []byte) (*ClientHello, error) {
	var hs []byte
	for off := 0; ; {
		if off+5 > len(b) {
			if len(b) == 0 || (off < len(b) && b[off] != 0x16) {
				return nil, ErrNotTLS
			}
			return nil, ErrNeedMore
		}
		if b[off] != 0x16 || b[off+1] != 0x03 {
			return nil, ErrNotTLS
		}
		l := int(binary.BigEndian.Uint16(b[off+3:]))
		if l == 0 || l > maxHelloBytes+2048 {
			return nil, ErrNotTLS
		}
		if off+5+l > len(b) {
			// Parse what has arrived: the message may already be complete
			// if the record is padded, and if not this returns ErrNeedMore.
			hs = append(hs, b[off+5:]...)
			ch, err := ParseHandshake(hs, 't')
			if err == nil {
				return ch, nil
			}
			return nil, ErrNeedMore
		}
		hs = append(hs, b[off+5:off+5+l]...)
		off += 5 + l
		if ch, err := ParseHandshake(hs, 't'); err != ErrNeedMore {
			return ch, err
		}
		if len(hs) > maxHelloBytes {
			return nil, ErrNotTLS
		}
	}
}

// ParseHandshake parses a ClientHello handshake message (type 1, 24-bit
// length, body) as carried in TLS records or QUIC CRYPTO frames. proto is the
// JA4 transport letter: 't' for TCP, 'q' for QUIC.
func ParseHandshake(b []byte, proto byte) (*ClientHello, error) {
	if len(b) < 4 {
		if len(b) > 0 && b[0] != 1 {
			return nil, ErrNotTLS
		}
		return nil, ErrNeedMore
	}
	if b[0] != 1 {
		return nil, ErrNotTLS
	}
	l := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if l > maxHelloBytes {
		return nil, ErrNotTLS
	}
	if len(b) < 4+l {
		return nil, ErrNeedMore
	}
	ch, err := parseHelloBody(b[4 : 4+l])
	if err != nil {
		return nil, err
	}
	ch.JA4 = ch.ja4(proto)
	return ch, nil
}

func parseHelloBody(b []byte) (*ClientHello, error) {
	r := reader{b: b}
	ch := &ClientHello{legacyVersion: r.u16()}
	r.skip(32)          // random
	r.skip(int(r.u8())) // session id
	cs := r.bytes(int(r.u16()))
	r.skip(int(r.u8())) // compression methods
	if r.err {
		return nil, ErrNotTLS
	}
	for i := 0; i+1 < len(cs); i += 2 {
		ch.ciphers = append(ch.ciphers, binary.BigEndian.Uint16(cs[i:]))
	}
	if r.left() == 0 {
		return ch, nil // no extensions: a pre-TLS 1.2 hello
	}
	exts := reader{b: r.bytes(int(r.u16()))}
	if r.err {
		return nil, ErrNotTLS
	}
	for exts.left() > 0 {
		typ := exts.u16()
		data := exts.bytes(int(exts.u16()))
		if exts.err {
			return nil, ErrNotTLS
		}
		ch.extensions = append(ch.extensions, typ)
		d := reader{b: data}
		switch typ {
		case 0: // server_name
			list := reader{b: d.bytes(int(d.u16()))}
			for list.left() > 0 && !list.err {
				nt := list.u8()
				name := list.bytes(int(list.u16()))
				if nt == 0 && !list.err && ch.SNI == "" {
					ch.SNI = strings.ToLower(cleanText(name))
				}
			}
		case 16: // ALPN
			list := reader{b: d.bytes(int(d.u16()))}
			for list.left() > 0 && !list.err {
				p := list.bytes(int(list.u8()))
				if !list.err {
					ch.ALPN = append(ch.ALPN, string(p))
				}
			}
		case 43: // supported_versions
			vs := d.bytes(int(d.u8()))
			for i := 0; i+1 < len(vs); i += 2 {
				ch.versions = append(ch.versions, binary.BigEndian.Uint16(vs[i:]))
			}
		case 13: // signature_algorithms
			sa := d.bytes(int(d.u16()))
			for i := 0; i+1 < len(sa); i += 2 {
				ch.sigAlgs = append(ch.sigAlgs, binary.BigEndian.Uint16(sa[i:]))
			}
		}
	}
	return ch, nil
}

// isGREASE reports the RFC 8701 reserved values (0x0a0a, 0x1a1a, ... 0xfafa).
func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// ja4 computes the JA4 TLS client fingerprint (FoxIO, BSD 3-Clause):
//
//	t13d1516h2_8daaf6152771_e5627efa2ab1
//	│││ │ │ │  │            └ sha256(sorted extensions [minus SNI, ALPN] "_" sigalgs)[:12]
//	│││ │ │ │  └ sha256(sorted ciphers)[:12]
//	│││ │ │ └ first and last character of the first ALPN value
//	│││ │ └ extension count (GREASE excluded)
//	│││ └ cipher count (GREASE excluded)
//	││└ 'd' if SNI present, else 'i'
//	│└ highest TLS version
//	└ transport: t (TCP), q (QUIC)
func (ch *ClientHello) ja4(proto byte) string {
	ver := ch.legacyVersion
	if vs := withoutGREASE(ch.versions); len(vs) > 0 {
		ver = slices.Max(vs)
	}
	sni := byte('i')
	if ch.SNI != "" {
		sni = 'd'
	}
	ciphers := withoutGREASE(ch.ciphers)
	exts := withoutGREASE(ch.extensions)
	alpn := "00"
	if len(ch.ALPN) > 0 && ch.ALPN[0] != "" {
		alpn = alpnChars(ch.ALPN[0])
	}
	a := fmt.Sprintf("%c%s%c%02d%02d%s", proto, tlsVersionCode(ver), sni, min(len(ciphers), 99), min(len(exts), 99), alpn)

	b := "000000000000"
	if len(ciphers) > 0 {
		b = hash12(hexList(sorted(ciphers)))
	}
	var hashed []uint16
	for _, e := range exts {
		if e != 0 && e != 16 {
			hashed = append(hashed, e)
		}
	}
	c := "000000000000"
	if len(hashed) > 0 {
		s := hexList(sorted(hashed))
		if sa := withoutGREASE(ch.sigAlgs); len(sa) > 0 {
			s += "_" + hexList(sa)
		}
		c = hash12(s)
	}
	return a + "_" + b + "_" + c
}

func tlsVersionCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

// alpnChars is the JA4 ALPN field: the first and last characters of the
// value, or of its hex form when either is not alphanumeric.
func alpnChars(p string) string {
	first, last := p[0], p[len(p)-1]
	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}
	h := hex.EncodeToString([]byte(p))
	return string([]byte{h[0], h[len(h)-1]})
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func withoutGREASE(vs []uint16) []uint16 {
	var out []uint16
	for _, v := range vs {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func sorted(vs []uint16) []uint16 {
	out := slices.Clone(vs)
	slices.Sort(out)
	return out
}

func hexList(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// reader is a bounds-checked big-endian cursor. Reads past the end set err
// and return zero values, so a parser can read a whole structure and check
// once.
type reader struct {
	b   []byte
	off int
	err bool
}

func (r *reader) left() int { return len(r.b) - r.off }

func (r *reader) u8() uint8 {
	if r.left() < 1 {
		r.err = true
		return 0
	}
	v := r.b[r.off]
	r.off++
	return v
}

func (r *reader) u16() uint16 {
	if r.left() < 2 {
		r.err = true
		return 0
	}
	v := binary.BigEndian.Uint16(r.b[r.off:])
	r.off += 2
	return v
}

func (r *reader) bytes(n int) []byte {
	if n < 0 || r.left() < n {
		r.err = true
		r.off = len(r.b)
		return nil
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v
}

func (r *reader) skip(n int) { r.bytes(n) }

// varint reads a QUIC variable-length integer (RFC 9000 §16).
func (r *reader) varint() uint64 {
	if r.left() < 1 {
		r.err = true
		return 0
	}
	l := 1 << (r.b[r.off] >> 6)
	if r.left() < l {
		r.err = true
		r.off = len(r.b)
		return 0
	}
	v := uint64(r.b[r.off] & 0x3f)
	for i := 1; i < l; i++ {
		v = v<<8 | uint64(r.b[r.off+i])
	}
	r.off += l
	return v
}
