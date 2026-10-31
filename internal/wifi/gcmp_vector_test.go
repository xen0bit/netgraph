package wifi

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// IEEE Std 802.11ad-2012, M.11.1 GCMP test MPDU #1. The body is the
// GCMP header followed by the published ciphertext and MIC; the plaintext
// is 256 zero octets.
func TestGCMPTestVector(t *testing.T) {
	header, _ := hex.DecodeString("20020000000000000000ffffffffffffffffffffffff0000")
	body, _ := hex.DecodeString("01000020000000005f5578c18f137ad279bf3f2b24c7bd8f277a1be6770da1d98b70c6d28ae01c559ecba6a01db067c5a27e4db08cdadc7752ad637eaf0a18ed13fbaa143bafef18f8fbce4c65e86bd02a87b601b7eab93f2bbc874c8a710580f502341a6a53393143de4c9ec6a286f125718378aedc84eba2b30f5c28bb5d75c6b025466d0651c722dc71151f212d6887828a0382e9288a7f43d52b7d25086157646954bb43b57ea587a025f40ce74511e4dd2285b40ba3f3b96262cbc28c6aa7be443e7b41e1ebff524857a6816897750115b0231ab7c28472c06dd0b49be9f369a8c39ccd0db7983510e1ae8f05d77545e0235cdbd612f3150754cee5ce6a1225d99525026f7480cb0662ea71abfd9f04c7f872f58090")
	plain, err := gcmpDecrypt(header, body, bytes.Repeat([]byte{0xaa}, 16))
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 256 || !bytes.Equal(plain, make([]byte, 256)) {
		t.Fatalf("plaintext = %x", plain)
	}
}

func TestGCMPTamper(t *testing.T) {
	header, _ := hex.DecodeString("20020000000000000000ffffffffffffffffffffffff0000")
	body, _ := hex.DecodeString("01000020000000005f5578c18f137ad279bf3f2b24c7bd8f277a1be6770da1d98b70c6d28ae01c559ecba6a01db067c5a27e4db08cdadc7752ad637eaf0a18ed13fbaa143bafef18f8fbce4c65e86bd02a87b601b7eab93f2bbc874c8a710580f502341a6a53393143de4c9ec6a286f125718378aedc84eba2b30f5c28bb5d75c6b025466d0651c722dc71151f212d6887828a0382e9288a7f43d52b7d25086157646954bb43b57ea587a025f40ce74511e4dd2285b40ba3f3b96262cbc28c6aa7be443e7b41e1ebff524857a6816897750115b0231ab7c28472c06dd0b49be9f369a8c39ccd0db7983510e1ae8f05d77545e0235cdbd612f3150754cee5ce6a1225d99525026f7480cb0662ea71abfd9f04c7f872f58090")
	body[len(body)-1] ^= 1
	if _, err := gcmpDecrypt(header, body, bytes.Repeat([]byte{0xaa}, 16)); err == nil {
		t.Fatal("tampered frame accepted")
	}
}

// IEEE P802.11ac/D7.0, M.11.1 GCMP-256 test vector. This also exercises
// the QoS control field in the AAD and a 256-bit temporal key.
func TestGCMP256TestVector(t *testing.T) {
	header, _ := hex.DecodeString("88480b000fd2e128a57c5030f18444085030f184440880330300")
	body, _ := hex.DecodeString("082b00205f5f8900658343c8b14447d9211defd46ad89c710c6fc33333236e3997b9176a5a8be779b21266555e70ad79114316859095473d5b1bd596b3dea3bf")
	tk, _ := hex.DecodeString("c97c1f67ce371185514a8a19f2bdd52f000102030405060708090a0b0c0d0e0f")
	want, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627")
	plain, err := gcmpDecrypt(header, body, tk)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, want) {
		t.Fatalf("plaintext = %x, want %x", plain, want)
	}
}

func FuzzGCMPDecrypt(f *testing.F) {
	header, _ := hex.DecodeString("20020000000000000000ffffffffffffffffffffffff0000")
	body, _ := hex.DecodeString("01000020000000005f5578c18f137ad279bf3f2b24c7bd8f")
	tk := bytes.Repeat([]byte{0xaa}, 16)
	f.Add(header, body, tk)
	f.Fuzz(func(t *testing.T, h, b, k []byte) {
		_, _ = gcmpDecrypt(h, b, k)
	})
}
