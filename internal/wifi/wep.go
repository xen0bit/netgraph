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
	// WEP encrypts the payload and its CRC-32 ICV as one RC4 stream.
	// Decrypt the whole body, then verify the now-plaintext ICV.
	ct := body[4:]
	if len(ct) < 4 {
		return nil, fmt.Errorf("wep: short body")
	}

	rc, err := rc4.NewCipher(append(append([]byte(nil), iv...), key...))
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ct))
	rc.XORKeyStream(plain, ct)
	data, icv := plain[:len(plain)-4], plain[len(plain)-4:]
	if crc32.ChecksumIEEE(data) != binary.LittleEndian.Uint32(icv) {
		clear(plain)
		return nil, fmt.Errorf("wep: integrity check failed")
	}
	return data, nil
}

// wepSeal produces the body of a WEP-protected frame, for tests.
func wepSeal(plaintext, key []byte, idx byte, iv [3]byte) []byte {
	head := make([]byte, 4, 4+len(plaintext)+4)
	copy(head, iv[:])
	head[3] = idx << 6
	rc, _ := rc4.NewCipher(append(append([]byte(nil), iv[:]...), key...))
	plain := make([]byte, len(plaintext), len(plaintext)+4)
	copy(plain, plaintext)
	var icv [4]byte
	binary.LittleEndian.PutUint32(icv[:], crc32.ChecksumIEEE(plaintext))
	plain = append(plain, icv[:]...)
	// The ICV is encrypted with the payload, as mac80211 does.
	rc.XORKeyStream(plain, plain)
	return append(head, plain...)
}
