package wifi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestGCMPRoundTrip(t *testing.T) {
	ap := []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
	sta := []byte{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03}
	header := make([]byte, 24)
	binary.LittleEndian.PutUint16(header, 0x0108)
	copy(header[4:10], ap)
	copy(header[10:16], sta)
	copy(header[16:22], ap)
	plain := []byte{0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00, 0xde, 0xad}
	for _, tk := range [][]byte{bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32)} {
		body, err := gcmpSeal(header, plain, tk, 0x0102030405)
		if err != nil {
			t.Fatal(err)
		}
		got, err := gcmpDecrypt(header, body, tk)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("plaintext = %x, want %x", got, plain)
		}
		body[len(body)-1] ^= 1
		if _, err := gcmpDecrypt(header, body, tk); err == nil {
			t.Fatal("tampered GCMP frame accepted")
		}
	}
}
