package wifi

import (
	"bytes"
	"testing"
)

func TestWEPRoundTrip(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
	var keys [4][]byte
	keys[2] = key

	plain := []byte("the quick brown fox jumps over the lazy dog")
	body := wepSeal(plain, key, 2, [3]byte{0xaa, 0xbb, 0xcc})
	got, err := wepDecrypt(body, keys)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("decrypt: %v %q", err, got)
	}
	body[5] ^= 1
	if _, err := wepDecrypt(body, keys); err == nil {
		t.Fatal("tampered frame passed the ICV")
	}
	if _, err := wepDecrypt(wepSeal(plain, key, 1, [3]byte{1, 2, 3}), keys); err == nil {
		t.Fatal("frame with an unset key decrypted")
	}
}
