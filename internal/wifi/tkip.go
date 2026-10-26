package wifi

import (
	"crypto/rc4"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math/bits"
)

// TKIP S-box from IEEE 802.11i. tkipS(v) combines the two byte lookups.
var tkipSbox = [256]uint16{
	0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154,
	0x6050, 0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A,
	0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
	0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B,
	0x75C2, 0xE11C, 0x3DAE, 0x4C6A, 0x6C5A, 0x7E41, 0xF502, 0x834F,
	0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
	0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5,
	0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD, 0xEA9F,
	0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
	0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397,
	0xA6F5, 0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED,
	0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
	0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194,
	0x8ACF, 0xE910, 0x0406, 0xFE81, 0xA0F0, 0x7844, 0x25BA, 0x4BE3,
	0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
	0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D,
	0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC, 0x2E39,
	0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
	0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83,
	0x8CCA, 0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76,
	0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
	0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B,
	0xD532, 0x8B43, 0x6E59, 0xDAB7, 0x018C, 0xB164, 0x9CD2, 0x49E0,
	0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
	0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751,
	0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86, 0x0F85,
	0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
	0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9,
	0xD938, 0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7,
	0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
	0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8,
	0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A,
}

func tkipS(v uint16) uint16 {
	return tkipSbox[v&0xff] ^ bits.RotateLeft16(tkipSbox[v>>8], 8)
}

func ror16(v uint16, n int) uint16 { return bits.RotateLeft16(v, -n) }

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }

// tkipPhase1 mixes the transmitter address and the 32-bit TSC into the
// five-word P1K.
func tkipPhase1(tk, ta []byte, iv32 uint32) [5]uint16 {
	var p1k [5]uint16
	p1k[0], p1k[1] = uint16(iv32), uint16(iv32>>16)
	p1k[2], p1k[3], p1k[4] = le16(ta[0:]), le16(ta[2:]), le16(ta[4:])
	for i := 0; i < 8; i++ {
		j := 2 * (i & 1)
		p1k[0] += tkipS(p1k[4] ^ le16(tk[0+j:]))
		p1k[1] += tkipS(p1k[0] ^ le16(tk[4+j:]))
		p1k[2] += tkipS(p1k[1] ^ le16(tk[8+j:]))
		p1k[3] += tkipS(p1k[2] ^ le16(tk[12+j:]))
		p1k[4] += tkipS(p1k[3]^le16(tk[0+j:])) + uint16(i)
	}
	return p1k
}

// tkipPhase2 turns P1K and the 16-bit TSC into the 16-byte RC4 key.
func tkipPhase2(tk []byte, p1k [5]uint16, iv16 uint16) [16]byte {
	var ppk [6]uint16
	copy(ppk[:5], p1k[:])
	ppk[5] = p1k[4] + iv16
	ppk[0] += tkipS(ppk[5] ^ le16(tk[0:]))
	ppk[1] += tkipS(ppk[0] ^ le16(tk[2:]))
	ppk[2] += tkipS(ppk[1] ^ le16(tk[4:]))
	ppk[3] += tkipS(ppk[2] ^ le16(tk[6:]))
	ppk[4] += tkipS(ppk[3] ^ le16(tk[8:]))
	ppk[5] += tkipS(ppk[4] ^ le16(tk[10:]))
	ppk[0] += ror16(ppk[5]^le16(tk[12:]), 1)
	ppk[1] += ror16(ppk[0]^le16(tk[14:]), 1)
	ppk[2] += ror16(ppk[1], 1)
	ppk[3] += ror16(ppk[2], 1)
	ppk[4] += ror16(ppk[3], 1)
	ppk[5] += ror16(ppk[4], 1)

	var key [16]byte
	key[0] = byte(iv16 >> 8)
	key[1] = byte((iv16>>8)|0x20) & 0x7f
	key[2] = byte(iv16)
	key[3] = byte(((ppk[5] ^ le16(tk[0:])) >> 1) & 0xff)
	for i := range 6 {
		binary.LittleEndian.PutUint16(key[4+2*i:], ppk[i])
	}
	return key
}

// michaelMIC computes the 8-byte Michael MIC over data. key is 8 bytes.
func michaelMIC(key, data []byte) [8]byte {
	if len(key) < 8 {
		return [8]byte{}
	}
	l, r := binary.LittleEndian.Uint32(key), binary.LittleEndian.Uint32(key[4:])
	for len(data) >= 4 {
		l, r = michaelBlock(l, r, binary.LittleEndian.Uint32(data))
		data = data[4:]
	}
	var last [4]byte
	copy(last[:], data)
	last[len(data)] = 0x5a
	l, r = michaelBlock(l, r, binary.LittleEndian.Uint32(last[:]))
	var out [8]byte
	binary.LittleEndian.PutUint32(out[:], l)
	binary.LittleEndian.PutUint32(out[4:], r)
	return out
}

func michaelBlock(l, r, v uint32) (uint32, uint32) {
	l ^= v
	r ^= bits.RotateLeft32(l, 17)
	l += r
	r ^= bits.ReverseBytes32(l)
	l += r
	r ^= bits.RotateLeft32(l, 3)
	l += r
	r ^= bits.RotateLeft32(l, -2)
	l += r
	return l, r
}

// tkipDecrypt decrypts a TKIP frame body (8-byte IV/ExtIV, ciphertext,
// 8-byte Michael MIC, 4-byte ICV) with a 32-byte TKIP temporal key. fromAP
// selects the Michael key for the direction: a frame from the access point
// uses the AP's TX MIC key, one from the station uses its RX MIC key.
func tkipDecrypt(header, body, tk []byte, fromAP bool) ([]byte, error) {
	if len(tk) < 32 {
		return nil, fmt.Errorf("tkip: temporal key length %d", len(tk))
	}
	if len(header) < 24 || len(body) < 8+8+4 {
		return nil, fmt.Errorf("tkip: short frame")
	}
	if body[3]&0x20 == 0 {
		return nil, fmt.Errorf("tkip: missing extended IV")
	}
	iv16 := uint16(body[0])<<8 | uint16(body[2])
	iv32 := binary.LittleEndian.Uint32(body[4:])
	rc4key := tkipPhase2(tk[:16], tkipPhase1(tk[:16], header[10:16], iv32), iv16)
	plain, err := wepOpen(rc4key[:], body[8:len(body)-4], body[len(body)-4:])
	if err != nil {
		return nil, err
	}
	if len(plain) < 8 {
		return nil, fmt.Errorf("tkip: short plaintext")
	}
	data := plain[:len(plain)-8]
	mic := plain[len(plain)-8:]
	micKey := tk[24:32]
	if fromAP {
		micKey = tk[16:24]
	}
	want := michaelMIC(micKey, append(append([]byte(nil), header...), data...))
	if subtle.ConstantTimeCompare(mic, want[:]) != 1 {
		clear(plain)
		return nil, fmt.Errorf("tkip: Michael MIC failed")
	}
	return data, nil
}

// tkipSeal produces a TKIP body, for tests and an eventual active harness.
func tkipSeal(header, plaintext, tk []byte, iv16 uint16, iv32 uint32) []byte {
	rc4key := tkipPhase2(tk[:16], tkipPhase1(tk[:16], header[10:16], iv32), iv16)
	mic := michaelMIC(tk[24:32], append(append([]byte(nil), header...), plaintext...))
	plain := append(append([]byte(nil), plaintext...), mic[:]...)
	body := make([]byte, 8, 8+len(plain)+4)
	body[0] = byte(iv16 >> 8)
	body[1] = byte((iv16>>8)|0x20) & 0x7f
	body[2] = byte(iv16)
	body[3] = 0x20
	binary.LittleEndian.PutUint32(body[4:], iv32)
	return append(body, wepSealRaw(rc4key[:], plain)...)
}

// wepOpen decrypts RC4-protected bytes and checks the 4-byte ICV.
func wepOpen(key, ct, icv []byte) ([]byte, error) {
	rc, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	rc.XORKeyStream(out, ct)
	if crc32.ChecksumIEEE(out) != binary.LittleEndian.Uint32(icv) {
		clear(out)
		return nil, fmt.Errorf("tkip: integrity check failed")
	}
	return out, nil
}

// wepSealRaw encrypts bytes and appends the WEP ICV, for TKIP's payload.
func wepSealRaw(key, plain []byte) []byte {
	rc, _ := rc4.NewCipher(key)
	ct := make([]byte, len(plain))
	rc.XORKeyStream(ct, plain)
	var icv [4]byte
	binary.LittleEndian.PutUint32(icv[:], crc32.ChecksumIEEE(plain))
	return append(ct, icv[:]...)
}
