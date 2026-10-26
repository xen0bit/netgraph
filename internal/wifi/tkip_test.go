package wifi

import (
	"bytes"
	"testing"
)

func TestTKIPRoundTrip(t *testing.T) {
	// TKIP temporal key: 16-byte encryption key, 8-byte TX MIC key,
	// 8-byte RX MIC key.
	tk := mustHex(t, "000102030405060708090a0b0c0d0e0f"+
		"1011121314151617"+"18191a1b1c1d1e1f")
	header := dataHeader(0x4108, false, false) // protected ToDS data
	plain := []byte("TKIP payload with a Michael MIC")

	body := tkipSeal(header, plain, tk, 0x1234, 0x01020304)
	got, err := tkipDecrypt(header, body, tk, false)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("decrypt: %v %q", err, got)
	}

	// A changed payload byte fails the ICV, a changed MIC fails Michael.
	body[10] ^= 1
	if _, err := tkipDecrypt(header, body, tk, false); err == nil {
		t.Fatal("tampered TKIP frame decrypted")
	}
	body = tkipSeal(header, plain, tk, 0x1234, 0x01020304)
	body[len(body)-6] ^= 1
	if _, err := tkipDecrypt(header, body, tk, false); err == nil {
		t.Fatal("tampered Michael MIC passed")
	}
}

func TestMichaelMICKnownShape(t *testing.T) {
	key := mustHex(t, "0001020304050607")
	mic := michaelMIC(key, []byte("hello"))
	if mic == [8]byte{} {
		t.Fatal("empty MIC")
	}
	// The MIC is deterministic and key-dependent.
	if michaelMIC(key, []byte("hello")) != mic {
		t.Fatal("MIC is not deterministic")
	}
	key[0] ^= 1
	if michaelMIC(key, []byte("hello")) == mic {
		t.Fatal("MIC does not depend on the key")
	}
}

func BenchmarkTKIPPhase(b *testing.B) {
	tk := make([]byte, 32)
	ta := []byte{1, 2, 3, 4, 5, 6}
	for range b.N {
		p1k := tkipPhase1(tk[:16], ta, 1)
		tkipPhase2(tk[:16], p1k, 2)
	}
}
