package wifi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// CCMP uses AES-CCM with an 8-byte MIC and a 2-byte length field (RFC 3610
// with L=2). The 802.11i nonce and AAD construction is below.

var errCCMP = errors.New("ccmp: authentication failed")

// ccmSeal encrypts and authenticates plaintext under key and nonce, with
// aad as additional authenticated data. It returns ciphertext followed by
// tagLen bytes of authentication tag.
func ccmSeal(key, nonce, plaintext, aad []byte, tagLen int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return ccmSealBlock(block, nonce, plaintext, aad, tagLen)
}

func ccmSealBlock(block cipher.Block, nonce, plaintext, aad []byte, tagLen int) ([]byte, error) {
	if len(nonce) < 7 || len(nonce) > 13 {
		return nil, fmt.Errorf("ccm: nonce length %d", len(nonce))
	}
	if tagLen < 4 || tagLen > 16 || tagLen%2 != 0 {
		return nil, fmt.Errorf("ccm: tag length %d", tagLen)
	}
	L := 15 - len(nonce)
	if uint64(len(plaintext)) >= uint64(1)<<(8*L) {
		return nil, fmt.Errorf("ccm: message too long")
	}
	// B_0: flags, nonce, length.
	var b0 [16]byte
	b0[0] = byte((tagLen-2)/2)<<3 | byte(L-1)
	if len(aad) > 0 {
		b0[0] |= 1 << 6
	}
	copy(b0[1:], nonce)
	putLength(b0[16-L:], uint64(len(plaintext)))

	mac := make([]byte, 16)
	block.Encrypt(mac, b0[:])
	if len(aad) > 0 {
		auth := encodeAAD(aad)
		cbcMAC(block, mac, auth)
	}
	cbcMAC(block, mac, plaintext)
	tag := append([]byte(nil), mac[:tagLen]...)

	out := make([]byte, len(plaintext)+tagLen)
	ctr := make([]byte, 16)
	ctr[0] = byte(L - 1)
	copy(ctr[1:], nonce)
	var stream [16]byte
	for i := 0; i < len(plaintext); i += 16 {
		putLength(ctr[16-L:], uint64(i/16+1))
		block.Encrypt(stream[:], ctr)
		n := min(16, len(plaintext)-i)
		for j := 0; j < n; j++ {
			out[i+j] = plaintext[i+j] ^ stream[j]
		}
	}
	// U = T xor S_0.
	putLength(ctr[16-L:], 0)
	block.Encrypt(stream[:], ctr)
	for i := range tag {
		out[len(plaintext)+i] = tag[i] ^ stream[i]
	}
	return out, nil
}

// ccmOpen decrypts ciphertext||tag and verifies the tag. It returns no
// plaintext when authentication fails.
func ccmOpen(key, nonce, ciphertext, aad []byte, tagLen int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < tagLen {
		return nil, errCCMP
	}
	if len(nonce) < 7 || len(nonce) > 13 || tagLen < 4 || tagLen > 16 || tagLen%2 != 0 {
		return nil, fmt.Errorf("ccm: bad parameters")
	}
	L := 15 - len(nonce)
	body, gotTag := ciphertext[:len(ciphertext)-tagLen], ciphertext[len(ciphertext)-tagLen:]

	var b0 [16]byte
	b0[0] = byte((tagLen-2)/2)<<3 | byte(L-1)
	if len(aad) > 0 {
		b0[0] |= 1 << 6
	}
	copy(b0[1:], nonce)
	putLength(b0[16-L:], uint64(len(body)))

	// Decrypt first: authentication must be checked before the caller sees
	// anything, but the MAC is computed over the recovered plaintext.
	plain := make([]byte, len(body))
	ctr := make([]byte, 16)
	ctr[0] = byte(L - 1)
	copy(ctr[1:], nonce)
	var stream [16]byte
	for i := 0; i < len(body); i += 16 {
		putLength(ctr[16-L:], uint64(i/16+1))
		block.Encrypt(stream[:], ctr)
		n := min(16, len(body)-i)
		for j := 0; j < n; j++ {
			plain[i+j] = body[i+j] ^ stream[j]
		}
	}

	mac := make([]byte, 16)
	block.Encrypt(mac, b0[:])
	if len(aad) > 0 {
		cbcMAC(block, mac, encodeAAD(aad))
	}
	cbcMAC(block, mac, plain)

	putLength(ctr[16-L:], 0)
	block.Encrypt(stream[:], ctr)
	want := make([]byte, tagLen)
	for i := range want {
		want[i] = mac[i] ^ stream[i]
	}
	if subtle.ConstantTimeCompare(want, gotTag) != 1 {
		clear(plain)
		return nil, errCCMP
	}
	return plain, nil
}

func putLength(dst []byte, n uint64) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = byte(n)
		n >>= 8
	}
}

func encodeAAD(aad []byte) []byte {
	var prefix []byte
	switch {
	case len(aad) < 0xff00:
		prefix = binary.BigEndian.AppendUint16(nil, uint16(len(aad)))
	case uint64(len(aad)) < 1<<32:
		prefix = []byte{0xff, 0xfe}
		prefix = binary.BigEndian.AppendUint32(prefix, uint32(len(aad)))
	default:
		prefix = []byte{0xff, 0xff}
		prefix = binary.BigEndian.AppendUint64(prefix, uint64(len(aad)))
	}
	return pad16(append(prefix, aad...))
}

func cbcMAC(block cipher.Block, mac, data []byte) {
	padded := pad16(data)
	var x [16]byte
	copy(x[:], mac)
	for i := 0; i < len(padded); i += 16 {
		for j := 0; j < 16; j++ {
			x[j] ^= padded[i+j]
		}
		block.Encrypt(x[:], x[:])
	}
	copy(mac, x[:])
}

func pad16(b []byte) []byte {
	if len(b)%16 == 0 {
		return b
	}
	out := make([]byte, (len(b)+15)&^15)
	copy(out, b)
	return out
}

// ccmpDecrypt decrypts a data frame body: the 8-byte CCMP header followed by
// ciphertext and the 8-byte MIC. header is the 802.11 MAC header (without the
// CCMP header), exactly as transmitted.
func ccmpDecrypt(header, body, tk []byte) ([]byte, error) {
	if len(tk) != 16 {
		return nil, fmt.Errorf("ccmp: temporal key length %d", len(tk))
	}
	if len(body) < 16 {
		return nil, fmt.Errorf("ccmp: short body")
	}
	hdr := body[:8]
	if hdr[3]&0x20 == 0 { // ExtIV
		return nil, fmt.Errorf("ccmp: missing extended IV")
	}
	nonce, aad, err := ccmpNonceAAD(header)
	if err != nil {
		return nil, err
	}
	// PN is transmitted as PN5 PN4 Rsvd KeyID PN3 PN2 PN1 PN0.
	nonce[7] = hdr[7]
	nonce[8] = hdr[6]
	nonce[9] = hdr[5]
	nonce[10] = hdr[4]
	nonce[11] = hdr[1]
	nonce[12] = hdr[0]
	return ccmOpen(tk, nonce, body[8:], aad, 8)
}

// ccmpSeal is the inverse of ccmpDecrypt, used by tests and by an eventual
// active harness. pn is the 48-bit packet number.
func ccmpSeal(header, plaintext, tk []byte, pn uint64) ([]byte, error) {
	if len(tk) != 16 {
		return nil, fmt.Errorf("ccmp: temporal key length %d", len(tk))
	}
	nonce, aad, err := ccmpNonceAAD(header)
	if err != nil {
		return nil, err
	}
	nonce[7] = byte(pn)
	nonce[8] = byte(pn >> 8)
	nonce[9] = byte(pn >> 16)
	nonce[10] = byte(pn >> 24)
	nonce[11] = byte(pn >> 32)
	nonce[12] = byte(pn >> 40)
	sealed, err := ccmSeal(tk, nonce, plaintext, aad, 8)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 8, 8+len(sealed))
	body[0] = byte(pn >> 40)
	body[1] = byte(pn >> 32)
	body[2] = 0
	body[3] = 0x20 // ExtIV, key id 0
	body[4] = byte(pn >> 24)
	body[5] = byte(pn >> 16)
	body[6] = byte(pn >> 8)
	body[7] = byte(pn)
	return append(body, sealed...), nil
}

// ccmpNonceAAD builds the nonce prefix and the AAD from the 802.11 header.
// The nonce's last six bytes (the PN) are filled in by the caller. This is
// the mac80211 construction: volatile FC bits are masked, the sequence
// number is zeroed, and A4/QoS control are included when present.
func ccmpNonceAAD(header []byte) (nonce, aad []byte, err error) {
	if len(header) < 24 {
		return nil, nil, fmt.Errorf("ccmp: short MAC header")
	}
	fc := binary.LittleEndian.Uint16(header)
	typ := (fc >> 2) & 0x3
	if typ != TypeData {
		return nil, nil, fmt.Errorf("ccmp: not a data frame")
	}
	qos := (fc>>4)&0x8 != 0
	bothDS := fc&0x0100 != 0 && fc&0x0200 != 0
	if bothDS && len(header) < 30 {
		return nil, nil, fmt.Errorf("ccmp: short four-address header")
	}

	mask := fc
	mask &^= 0x0800 // Retry
	mask &^= 0x1000 // Power Management
	mask &^= 0x2000 // More Data
	mask &^= 0x0070 // data subtype bits b4..b6, as mac80211 does
	mask |= 0x4000  // Protected
	var qc byte
	if qos {
		mask &^= 0x8000 // Order
		off := 24
		if bothDS {
			off += 6
		}
		if off >= len(header) {
			return nil, nil, fmt.Errorf("ccmp: short QoS header")
		}
		qc = header[off] & 0x0f
	}
	nlen := 22
	if bothDS {
		nlen += 6
	}
	if qos {
		nlen += 2
	}
	aad = make([]byte, nlen)
	binary.LittleEndian.PutUint16(aad, mask)
	copy(aad[2:8], header[4:10])   // A1
	copy(aad[8:14], header[10:16]) // A2
	copy(aad[14:20], header[16:22])
	aad[20] = header[22] & 0x0f
	aad[21] = 0
	off := 22
	if bothDS {
		copy(aad[off:off+6], header[24:30])
		off += 6
	}
	if qos {
		aad[off], aad[off+1] = qc, 0
	}
	nonce = make([]byte, 13)
	nonce[0] = qc
	copy(nonce[1:7], header[10:16]) // A2
	return nonce, aad, nil
}

// ccmpAADSize is exported for tests that build a frame by hand.
func ccmpAADSize(header []byte) int {
	_, aad, err := ccmpNonceAAD(header)
	if err != nil {
		return 0
	}
	return len(aad)
}
