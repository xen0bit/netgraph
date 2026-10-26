package wifi

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 3610 packet vector #1, with an 8-octet tag: the first 8 octets are
// AAD and the rest is the message.
func TestCCMRFC3610Vector(t *testing.T) {
	key := mustHex(t, "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
	nonce := mustHex(t, "00000003020100a0a1a2a3a4a5")
	input := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
	want := mustHex(t, "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0")

	got, err := ccmSeal(key, nonce, input[8:], input[:8], 8)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("seal:\n got %x\nwant %x", got, want)
	}
	plain, err := ccmOpen(key, nonce, want, input[:8], 8)
	if err != nil || !bytes.Equal(plain, input[8:]) {
		t.Fatalf("open: %v %x", err, plain)
	}
	bad := append([]byte(nil), want...)
	bad[0] ^= 1
	if _, err := ccmOpen(key, nonce, bad, input[:8], 8); err == nil {
		t.Fatal("tampered ciphertext authenticated")
	}
}

func TestCCMPRoundTrip(t *testing.T) {
	tk := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	llc := mustHex(t, "aaaa0300000008004500001c00000000401100000a0000010a000002")
	pn := uint64(0x010203040506)

	t.Run("toDS", func(t *testing.T) {
		h := dataHeader(0x0108, false, false)
		body, err := ccmpSeal(h, llc, tk, pn)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ccmpDecrypt(h, body, tk)
		if err != nil || !bytes.Equal(got, llc) {
			t.Fatalf("decrypt: %v %x", err, got)
		}
		body[8] ^= 1
		if _, err := ccmpDecrypt(h, body, tk); err == nil {
			t.Fatal("tampered frame decrypted")
		}
	})

	t.Run("qos+fromDS", func(t *testing.T) {
		h := dataHeader(0x0208|0x0080, false, false) // QoS data, FromDS
		body, err := ccmpSeal(h, llc, tk, pn)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ccmpDecrypt(h, body, tk)
		if err != nil || !bytes.Equal(got, llc) {
			t.Fatalf("decrypt: %v %x", err, got)
		}
		if n := ccmpAADSize(h); n != 24 {
			t.Errorf("QoS AAD size = %d, want 24", n)
		}
	})

	t.Run("bothDS", func(t *testing.T) {
		h := dataHeader(0x0308, true, false) // ToDS+FromDS, A4
		body, err := ccmpSeal(h, llc, tk, pn)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ccmpDecrypt(h, body, tk)
		if err != nil || !bytes.Equal(got, llc) {
			t.Fatalf("decrypt: %v %x", err, got)
		}
		if n := ccmpAADSize(h); n != 28 {
			t.Errorf("A4 AAD size = %d, want 28", n)
		}
	})
}

// dataHeader builds a minimal 802.11 data MAC header. fc selects ToDS,
// FromDS, QoS and the protected bit; a4 adds a fourth address.
func dataHeader(fc uint16, a4, _ bool) []byte {
	n := 24
	if fc&0x0100 != 0 && fc&0x0200 != 0 {
		n += 6
	}
	if fc&0x0080 != 0 {
		n += 2
	}
	h := make([]byte, n)
	h[0], h[1] = byte(fc), byte(fc>>8)
	copy(h[4:10], []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01})  // A1
	copy(h[10:16], []byte{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03}) // A2
	copy(h[16:22], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) // A3
	h[22], h[23] = 0x30, 0x12                                  // fragment 0, sequence 0x123
	if a4 {
		copy(h[24:30], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x66})
	}
	return h
}
