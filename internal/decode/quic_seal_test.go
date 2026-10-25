package decode

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
)

func hkdfExtractForTest(dcid []byte) ([]byte, error) {
	return hkdf.Extract(sha256.New, dcid, quicSaltV1)
}

// buildHello builds a minimal TLS 1.3 ClientHello record with SNI, ALPN,
// supported_versions and signature_algorithms. It is deterministic, unlike
// goClientHello, which is what fuzz seeds need: a fuzz worker re-runs seed
// setup, and a real handshake there costs seconds.
func buildHello(sni string, alpn ...string) []byte {
	ext := func(typ uint16, data []byte) []byte {
		b := binary.BigEndian.AppendUint16(nil, typ)
		b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
		return append(b, data...)
	}
	var exts []byte
	name := append([]byte{0}, binary.BigEndian.AppendUint16(nil, uint16(len(sni)))...)
	name = append(name, sni...)
	exts = append(exts, ext(0, append(binary.BigEndian.AppendUint16(nil, uint16(len(name))), name...))...)
	var protos []byte
	for _, p := range alpn {
		protos = append(append(protos, byte(len(p))), p...)
	}
	exts = append(exts, ext(16, append(binary.BigEndian.AppendUint16(nil, uint16(len(protos))), protos...))...)
	exts = append(exts, ext(43, []byte{4, 0x03, 0x04, 0x03, 0x03})...)
	exts = append(exts, ext(13, []byte{0, 4, 0x04, 0x03, 0x08, 0x04})...)

	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)          // random
	body = append(body, 0)                            // session id
	body = append(body, 0, 4, 0x13, 0x01, 0x13, 0x02) // ciphers
	body = append(body, 1, 0)                         // compression
	body = append(body, binary.BigEndian.AppendUint16(nil, uint16(len(exts)))...)
	body = append(body, exts...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}
