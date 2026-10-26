package wifi

import (
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// wepDecrypt decrypts a WEP-protected data frame body (IV, key index,
// ciphertext, ICV). keys holds the four shared keys; nil entries are unset.
func wepDecrypt(body []byte, keys [4][]byte) ([]byte, error) {
	if len(body) < 8 {
		return nil, fmt.Errorf("wep: short body")
	}
	if body[3]&0x20 != 0 {
		return nil, fmt.Errorf("wep: extended IV (TKIP), not WEP")
	}
	idx := int(body[3]>>6) & 0x3
	key := keys[idx]
	if len(key) == 0 {
		return nil, fmt.Errorf("wep: key %d not configured", idx)
	}
	iv := body[:3]
	ct := body[4 : len(body)-4]
	icv := body[len(body)-4:]

	rc, err := rc4.NewCipher(append(append([]byte(nil), iv...), key...))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	rc.XORKeyStream(out, ct)
	if crc32.ChecksumIEEE(out) != binary.LittleEndian.Uint32(icv) {
		clear(out)
		return nil, fmt.Errorf("wep: integrity check failed")
	}
	return out, nil
}

// wepSeal produces the body of a WEP-protected frame, for tests.
func wepSeal(plaintext, key []byte, idx byte, iv [3]byte) []byte {
	out := make([]byte, 4, 4+len(plaintext)+4)
	copy(out, iv[:])
	out[3] = idx << 6
	rc, _ := rc4.NewCipher(append(append([]byte(nil), iv[:]...), key...))
	ct := make([]byte, len(plaintext))
	rc.XORKeyStream(ct, plaintext)
	out = append(out, ct...)
	var icv [4]byte
	binary.LittleEndian.PutUint32(icv[:], crc32.ChecksumIEEE(plaintext))
	return append(out, icv[:]...)
}
