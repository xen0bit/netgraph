package wifi

import (
	"bytes"
	"encoding/binary"
	"net"
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

// The cipher follows the network's suites, not the EAPOL descriptor
// version: a WPA2 handshake (version 2) on a GCMP-256-only network yields a
// 32-byte temporal key that decrypts its data frames.
func TestHandshakeOnGCMP256Network(t *testing.T) {
	ap := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
	sta := net.HardwareAddr{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03}
	k := NewKeyring()
	if err := k.AddPassphrase("gcmp-net", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	k.setNetwork(ap.String(), "gcmp-net", Security{Kind: WPA2, Group: "GCMP-256", Pairwise: []string{"GCMP-256"}})
	anonce := bytes.Repeat([]byte{0x11}, 32)
	snonce := bytes.Repeat([]byte{0x22}, 32)
	ptk, err := DerivePTK(k.pmkFor("gcmp-net"), ap, sta, anonce, snonce, 512)
	if err != nil {
		t.Fatal(err)
	}
	split := splitPTK(ptk, false)
	k.ProcessEAPOL(&Frame{BSSID: ap, Src: ap, Dst: sta}, ParseTestEAPOL(t, 0x008a, anonce, nil, nil))
	if info := k.ProcessEAPOL(&Frame{BSSID: ap, Src: sta, Dst: ap}, ParseTestEAPOL(t, 0x010a, snonce, nil, split.KCK)); !info.Installed {
		t.Fatalf("msg2 = %+v", info)
	}
	header := dataHeader(0x4108, false, false)
	llc := mustHex(t, "aaaa0300000008004500001c00000000401100000a0000010a000002")
	body, err := gcmpSeal(header, llc, ptk[32:64], 7)
	if err != nil {
		t.Fatal(err)
	}
	f := &Frame{Protected: true, ToDS: true, BSSID: ap, Src: sta, Dst: net.HardwareAddr{0, 1, 2, 3, 4, 5}, Body: body, header: header}
	out, method, err := k.Decrypt(f)
	if err != nil || method != "GCMP-256" || !bytes.Equal(out, llc) {
		t.Fatalf("decrypt: %v %s %x", err, method, out)
	}
}
