package wifi

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
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
	_, aad, err := gcmpNonceAAD(header)
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
	// The nonce is A2 || PN5..PN0, while the header carries PN0..PN5 in
	// its first, second and fourth through seventh octets.
	nonce[6] = byte(pn >> 40)
	nonce[7] = byte(pn >> 32)
	nonce[8] = byte(pn >> 24)
	nonce[9] = byte(pn >> 16)
	nonce[10] = byte(pn >> 8)
	nonce[11] = byte(pn)
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	body := make([]byte, 8, 8+len(sealed))
	body[0] = byte(pn)
	body[1] = byte(pn >> 8)
	body[2] = 0
	body[3] = 0x20
	body[4] = byte(pn >> 16)
	body[5] = byte(pn >> 24)
	body[6] = byte(pn >> 32)
	body[7] = byte(pn >> 40)
	return append(body, sealed...), nil
}

// gcmpNonceAAD builds the 12-byte nonce prefix and AAD from the MAC header.
// Unlike CCMP, GCMP's AAD does not add the Protected bit; a real protected
// frame already carries it, while the published 802.11ad test vector does
// not. The subtype, retry, power and more-data bits are masked as mac80211
// does.
func gcmpNonceAAD(header []byte) (nonce, aad []byte, err error) {
	if len(header) < 24 {
		return nil, nil, fmt.Errorf("gcmp: short MAC header")
	}
	fc := binary.LittleEndian.Uint16(header)
	qos := (fc>>4)&0x8 != 0
	bothDS := fc&0x0100 != 0 && fc&0x0200 != 0
	if bothDS && len(header) < 30 {
		return nil, nil, fmt.Errorf("gcmp: short four-address header")
	}
	mask := fc
	if (fc>>2)&0x3 == TypeData {
		mask &^= 0x0070 // data subtype bits
	}
	mask &^= 0x0800 // Retry
	mask &^= 0x1000 // Power Management
	mask &^= 0x2000 // More Data
	var qc byte
	if qos {
		mask &^= 0x8000 // Order
		off := 24
		if bothDS {
			off += 6
		}
		if off >= len(header) {
			return nil, nil, fmt.Errorf("gcmp: short QoS header")
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
	copy(aad[2:8], header[4:10])
	copy(aad[8:14], header[10:16])
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
	nonce = make([]byte, 12)
	copy(nonce[:6], header[10:16])
	return nonce, aad, nil
}
