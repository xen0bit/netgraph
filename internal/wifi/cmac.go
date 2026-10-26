package wifi

import "crypto/aes"

// aesCMAC computes AES-CMAC (RFC 4493) over msg. It is the MIC algorithm for
// WPA3/WPA2 key descriptor version 3.
func aesCMAC(key, msg []byte) [16]byte {
	var out [16]byte
	block, err := aes.NewCipher(key)
	if err != nil {
		return out
	}
	var zero, sub [16]byte
	block.Encrypt(zero[:], zero[:])
	subkey(&sub, zero[:])
	var k1, k2 [16]byte
	k1 = sub
	subkey(&k2, k1[:])

	n := (len(msg) + 15) / 16
	last := make([]byte, 16)
	if n == 0 {
		last[0] ^= 0x80
		xor16(last, k2[:])
	} else {
		if len(msg)%16 == 0 {
			copy(last, msg[(n-1)*16:])
			xor16(last, k1[:])
		} else {
			copy(last, msg[(n-1)*16:])
			last[len(msg)%16] = 0x80
			xor16(last, k2[:])
		}
	}
	var x [16]byte
	for i := 0; i < n-1; i++ {
		xor16(x[:], msg[i*16:(i+1)*16])
		block.Encrypt(x[:], x[:])
	}
	xor16(x[:], last)
	block.Encrypt(out[:], x[:])
	return out
}

func subkey(dst *[16]byte, in []byte) {
	carry := byte(0)
	for i := 15; i >= 0; i-- {
		next := in[i] >> 7
		dst[i] = in[i]<<1 | carry
		carry = next
	}
	if in[0]&0x80 != 0 {
		dst[15] ^= 0x87
	}
}

func xor16(a, b []byte) {
	for i := 0; i < 16; i++ {
		a[i] ^= b[i]
	}
}
