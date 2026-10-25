package decode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
)

// QUIC versions whose Initial packets netgraph can open.
const (
	QUICv1 = 0x00000001 // RFC 9000
	QUICv2 = 0x6b3343cf // RFC 9369
)

var (
	quicSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicSaltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}

	errQUIC = errors.New("quic: not a decryptable client initial")
)

// QUICInitial is a decrypted client Initial packet: its destination
// connection ID (which keys the whole handshake) and the CRYPTO frame
// fragments it carried.
type QUICInitial struct {
	Version uint32
	DCID    []byte
	Crypto  []CryptoFrag
}

// CryptoFrag is one CRYPTO frame: Data belongs at Offset in the handshake
// stream. Clients split and reorder these on purpose (Chrome's "chaos
// protection"), so fragments are reassembled by offset, never by arrival.
type CryptoFrag struct {
	Offset uint64
	Data   []byte
}

// initialKeys are the client's Initial packet protection keys.
type initialKeys struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

// deriveInitialKeys derives client Initial keys from the client's first
// destination connection ID (RFC 9001 §5.2; RFC 9369 §3.3.1 for v2).
func deriveInitialKeys(version uint32, dcid []byte) (*initialKeys, error) {
	salt, keyL, ivL, hpL := quicSaltV1, "quic key", "quic iv", "quic hp"
	if version == QUICv2 {
		salt, keyL, ivL, hpL = quicSaltV2, "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, err
	}
	client, err := expandLabel(initial, "client in", 32)
	if err != nil {
		return nil, err
	}
	key, err := expandLabel(client, keyL, 16)
	if err != nil {
		return nil, err
	}
	iv, err := expandLabel(client, ivL, 12)
	if err != nil {
		return nil, err
	}
	hpKey, err := expandLabel(client, hpL, 16)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	hp, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	return &initialKeys{aead: aead, iv: iv, hp: hp}, nil
}

// expandLabel is TLS 1.3 HKDF-Expand-Label with an empty context.
func expandLabel(secret []byte, label string, n int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	return hkdf.Expand(sha256.New, secret, string(info), n)
}

// IsQUICInitial reports whether a UDP payload starts with a long-header
// Initial packet of a version netgraph can decrypt, without decrypting it.
func IsQUICInitial(b []byte) bool {
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return false
	}
	switch v := binary.BigEndian.Uint32(b[1:]); v {
	case QUICv1:
		return b[0]&0x30 == 0x00
	case QUICv2:
		return b[0]&0x30 == 0x10
	}
	return false
}

// ParseQUICInitial removes header protection from and decrypts the first
// packet of a UDP datagram, if it is a client Initial (RFC 9001 §5.4).
// Coalesced packets after it are ignored: the ClientHello only travels in
// Initials.
func ParseQUICInitial(datagram []byte) (*QUICInitial, error) {
	if !IsQUICInitial(datagram) {
		return nil, errQUIC
	}
	version := binary.BigEndian.Uint32(datagram[1:])
	r := reader{b: datagram, off: 5}
	dcid := r.bytes(int(r.u8()))
	r.skip(int(r.u8())) // scid
	r.skip(int(r.varint()))
	length := r.varint()
	if r.err || len(dcid) == 0 || len(dcid) > 20 || length > uint64(r.left()) || length < 20 {
		return nil, errQUIC
	}
	pnOff := r.off
	end := pnOff + int(length)

	keys, err := deriveInitialKeys(version, dcid)
	if err != nil {
		return nil, errQUIC
	}
	// The sample starts 4 bytes after the packet number's start, as if it
	// were 4 bytes long (RFC 9001 §5.4.2).
	if pnOff+4+16 > end {
		return nil, errQUIC
	}
	mask := make([]byte, 16)
	keys.hp.Encrypt(mask, datagram[pnOff+4:pnOff+4+16])

	// Work on a copy: the header bytes are unmasked in place to form the AAD.
	pkt := append([]byte(nil), datagram[:end]...)
	pkt[0] ^= mask[0] & 0x0f
	pnLen := int(pkt[0]&0x03) + 1
	var pn uint64
	for i := range pnLen {
		pkt[pnOff+i] ^= mask[1+i]
		pn = pn<<8 | uint64(pkt[pnOff+i])
	}
	nonce := append([]byte(nil), keys.iv...)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	payload, err := keys.aead.Open(nil, nonce, pkt[pnOff+pnLen:], pkt[:pnOff+pnLen])
	if err != nil {
		return nil, errQUIC
	}
	frags, err := cryptoFrames(payload)
	if err != nil {
		return nil, errQUIC
	}
	return &QUICInitial{Version: version, DCID: dcid, Crypto: frags}, nil
}

// cryptoFrames extracts CRYPTO frames from a decrypted Initial payload,
// skipping the other frames an Initial may carry (RFC 9000 §17.2.2).
func cryptoFrames(p []byte) ([]CryptoFrag, error) {
	var out []CryptoFrag
	r := reader{b: p}
	for r.left() > 0 && !r.err {
		switch ft := r.varint(); ft {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK
			r.varint() // largest acknowledged
			r.varint() // ack delay
			n := r.varint()
			r.varint() // first range
			for i := uint64(0); i < n && !r.err; i++ {
				r.varint()
				r.varint()
			}
			if ft == 0x03 {
				r.varint()
				r.varint()
				r.varint()
			}
		case 0x06: // CRYPTO
			off := r.varint()
			data := r.bytes(int(r.varint()))
			if !r.err {
				out = append(out, CryptoFrag{Offset: off, Data: data})
			}
		case 0x1c: // CONNECTION_CLOSE
			r.varint()
			r.varint()
			r.skip(int(r.varint()))
		default:
			// Any other frame is not allowed in an Initial; stop rather
			// than misparse.
			return out, nil
		}
	}
	if r.err {
		return out, errQUIC
	}
	return out, nil
}

// CryptoStream reassembles CRYPTO fragments from one or more Initials of a
// connection into the contiguous handshake prefix.
type CryptoStream struct {
	frags []CryptoFrag
	size  int
}

// Add records fragments; it ignores them once maxHelloBytes is buffered.
func (c *CryptoStream) Add(frags []CryptoFrag) {
	for _, f := range frags {
		if c.size+len(f.Data) > maxHelloBytes || f.Offset > maxHelloBytes {
			return
		}
		c.frags = append(c.frags, CryptoFrag{Offset: f.Offset, Data: append([]byte(nil), f.Data...)})
		c.size += len(f.Data)
	}
}

// Prefix returns the contiguous bytes from offset 0.
func (c *CryptoStream) Prefix() []byte {
	sort.Slice(c.frags, func(i, j int) bool { return c.frags[i].Offset < c.frags[j].Offset })
	var out []byte
	for _, f := range c.frags {
		end := f.Offset + uint64(len(f.Data))
		switch {
		case f.Offset > uint64(len(out)):
			return out // gap
		case end > uint64(len(out)):
			out = append(out, f.Data[uint64(len(out))-f.Offset:]...)
		}
	}
	return out
}
