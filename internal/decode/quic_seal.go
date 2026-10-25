package decode

import "encoding/binary"

// SealInitial builds a protected client Initial carrying frames,
// padded to the 1200-byte minimum: the inverse of ParseQUICInitial,
// following RFC 9001 §5.3-5.4 step by step.
//
// It exists for tests and fixture generation: the sensor only ever opens
// Initials. CryptoFrame builds the frames to put in one.
func SealInitial(version uint32, dcid []byte, pn uint32, frames []byte) []byte {
	keys, err := deriveInitialKeys(version, dcid)
	if err != nil {
		panic(err) // only fails for invalid AES key sizes, which are constants here
	}
	first := byte(0xc0 | 0x03) // long header, 4-byte packet number
	if version == QUICv2 {
		first |= 0x10
	}
	hdr := []byte{first}
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0) // scid length
	hdr = append(hdr, 0) // token length
	payloadLen := 1200 - len(hdr) - 2 - 4 - keys.aead.Overhead()
	for len(frames) < payloadLen {
		frames = append(frames, 0) // PADDING
	}
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(4+len(frames)+keys.aead.Overhead())|0x4000)
	pnOff := len(hdr)
	hdr = binary.BigEndian.AppendUint32(hdr, pn)

	nonce := append([]byte(nil), keys.iv...)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(uint64(pn) >> (8 * i))
	}
	pkt := keys.aead.Seal(append([]byte(nil), hdr...), nonce, frames, hdr)

	mask := make([]byte, 16)
	keys.hp.Encrypt(mask, pkt[pnOff+4:pnOff+4+16])
	pkt[0] ^= mask[0] & 0x0f
	for i := range 4 {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}

// CryptoFrame encodes a QUIC CRYPTO frame.
func CryptoFrame(off uint64, data []byte) []byte {
	b := []byte{0x06}
	b = appendVarint(b, off)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return binary.BigEndian.AppendUint16(b, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(b, uint32(v)|0x80000000)
	}
	return binary.BigEndian.AppendUint64(b, v|0xc0<<56)
}
