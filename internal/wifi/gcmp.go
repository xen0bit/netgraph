package wifi

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// GCMP is AES-GCM with a 12-byte nonce built from the transmitter address
// and packet number. It is the cipher of WPA3 (and of some WPA2 APs); with a
// supplied PMK and a captured 4-way handshake the key is derivable just as
// for CCMP. The MAC header/AAD construction is the same as CCMP's.
func gcmpDecrypt(header, body, tk []byte) ([]byte, error) {
	gcm, nonce, aad, err := gcmpState(header, body, tk)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, body[8:], aad)
	if err != nil {
		return nil, fmt.Errorf("gcmp: authentication failed")
	}
	return plain, nil
}

func gcmpState(header, body, tk []byte) (cipher.AEAD, []byte, []byte, error) {
	if len(tk) != 16 && len(tk) != 32 {
		return nil, nil, nil, fmt.Errorf("gcmp: temporal key length %d", len(tk))
	}
	if len(body) < 8+16 {
		return nil, nil, nil, fmt.Errorf("gcmp: short body")
	}
	_, aad, err := ccmpNonceAAD(header)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce := make([]byte, 12)
	copy(nonce[:6], header[10:16]) // A2
	// PN is transmitted PN5 PN4 Rsvd KeyID PN3 PN2 PN1 PN0.
	nonce[6] = body[7]
	nonce[7] = body[6]
	nonce[8] = body[5]
	nonce[9] = body[4]
	nonce[10] = body[1]
	nonce[11] = body[0]
	block, err := aes.NewCipher(tk)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	return gcm, nonce, aad, nil
}

// gcmpSeal is the inverse of gcmpDecrypt, for tests and an eventual active
// harness.
func gcmpSeal(header, plaintext, tk []byte, pn uint64) ([]byte, error) {
	gcm, nonce, aad, err := gcmpState(header, make([]byte, 24), tk)
	if err != nil {
		return nil, err
	}
	// gcmpState read a zero PN from the placeholder; replace it with pn.
	nonce[6] = byte(pn)
	nonce[7] = byte(pn >> 8)
	nonce[8] = byte(pn >> 16)
	nonce[9] = byte(pn >> 24)
	nonce[10] = byte(pn >> 32)
	nonce[11] = byte(pn >> 40)
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	body := make([]byte, 8, 8+len(sealed))
	body[0] = byte(pn >> 40)
	body[1] = byte(pn >> 32)
	body[2] = 0
	body[3] = 0x20
	body[4] = byte(pn >> 24)
	body[5] = byte(pn >> 16)
	body[6] = byte(pn >> 8)
	body[7] = byte(pn)
	return append(body, sealed...), nil
}
