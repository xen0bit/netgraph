package wifi

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

// RFC 3394 section 4.1: 128-bit key data with a 128-bit KEK.
func TestAESUnwrapRFC3394(t *testing.T) {
	kek := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	c := mustHex(t, "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5")
	got, err := aesUnwrap(kek, c)
	if err != nil || hex.EncodeToString(got) != "00112233445566778899aabbccddeeff" {
		t.Fatalf("unwrap = %x, %v", got, err)
	}
	if w, _ := aesWrap(kek, got); !bytes.Equal(w, c) {
		t.Fatalf("wrap = %x", w)
	}
	c[5] ^= 1
	if _, err := aesUnwrap(kek, c); err == nil {
		t.Fatal("unwrapped tampered key data")
	}
}

// gtkKeyData is RSN key data carrying a GTK KDE, wrapped with kek.
func gtkKeyData(t *testing.T, kek []byte, id byte, gtk []byte) []byte {
	t.Helper()
	kd := append([]byte{0xdd, byte(6 + len(gtk)), 0x00, 0x0f, 0xac, 0x01, id, 0x00}, gtk...)
	if len(kd)%8 != 0 {
		kd = append(kd, 0xdd)
		for len(kd)%8 != 0 {
			kd = append(kd, 0)
		}
	}
	w, err := aesWrap(kek, kd)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// A sensor that follows a client's 4-way handshake learns the AP's GTK from
// message 3, decrypts the AP's broadcasts with it, follows group rekeys,
// skips the AP's relay of a client it already decrypts, and forgets the GTK
// when the network's key is revoked.
func TestGroupKey(t *testing.T) {
	ap := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
	sta := net.HardwareAddr{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03}
	k := NewKeyring()
	if err := k.AddPassphrase("test-net", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	k.setNetwork(ap.String(), "test-net", Security{Kind: WPA2, Pairwise: []string{"CCMP"}, Group: "CCMP"})
	anonce := bytes.Repeat([]byte{0x11}, 32)
	snonce := bytes.Repeat([]byte{0x22}, 32)
	ptk, err := DerivePTK(k.pmkFor("test-net"), ap, sta, anonce, snonce, 384)
	if err != nil {
		t.Fatal(err)
	}
	split := splitPTK(ptk, false)
	fromAP := &Frame{BSSID: ap, Src: ap, Dst: sta}
	fromSTA := &Frame{BSSID: ap, Src: sta, Dst: ap}

	k.ProcessEAPOL(fromAP, ParseTestEAPOL(t, 0x008a, anonce, nil, nil))
	k.ProcessEAPOL(fromSTA, ParseTestEAPOL(t, 0x010a, snonce, nil, split.KCK))
	gtk1 := bytes.Repeat([]byte{0x5a}, 16)
	msg3 := ParseTestEAPOL(t, 0x13ca, anonce, gtkKeyData(t, split.KEK, 1, gtk1), split.KCK)
	if info := k.ProcessEAPOL(fromAP, msg3); !info.Installed || !info.GTK || info.Err != nil {
		t.Fatalf("message 3 = %+v", info)
	}
	if g := k.group(ap.String(), 1); g == nil || !bytes.Equal(g.tk, gtk1) || g.tkip {
		t.Fatalf("GTK = %+v", g)
	}

	var got [][]byte
	p := NewProcessor(Config{Keys: k, Data: func(_ time.Time, eth []byte) { got = append(got, append([]byte(nil), eth...)) }})
	broadcast := func(sa net.HardwareAddr, keyID byte, gtk []byte) {
		h := make([]byte, 24)
		h[0], h[1] = 0x08, 0x42 // data, from DS, protected
		copy(h[4:10], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
		copy(h[10:16], ap)
		copy(h[16:22], sa)
		llc := append([]byte{0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00}, make([]byte, 28)...)
		body, err := ccmpSeal(h, llc, gtk, 3)
		if err != nil {
			t.Fatal(err)
		}
		body[3] |= keyID << 6
		p.Handle(time.Unix(0, 0), append(h, body...), false)
	}
	wired := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x99}
	broadcast(wired, 1, gtk1)
	if len(got) != 1 || !bytes.Equal(got[0][0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) || !bytes.Equal(got[0][6:12], wired) {
		t.Fatalf("broadcast from a wired host: %x", got)
	}
	// The AP relaying the client's own broadcast: already seen on the way up.
	broadcast(sta, 1, gtk1)
	if len(got) != 1 {
		t.Fatalf("relayed copy decoded: %d frames", len(got))
	}

	// A group rekey to the client, protected with its KEK, installs the
	// next GTK under the next key ID.
	gtk2 := bytes.Repeat([]byte{0xa5}, 16)
	rekey := ParseTestEAPOL(t, 0x1382, make([]byte, 32), gtkKeyData(t, split.KEK, 2, gtk2), split.KCK)
	if info := k.ProcessEAPOL(fromAP, rekey); !info.Group || !info.Valid || !info.GTK {
		t.Fatalf("rekey = %+v", info)
	}
	broadcast(wired, 2, gtk2)
	if len(got) != 2 {
		t.Fatalf("broadcast after rekey not decoded: %d frames", len(got))
	}
	// A rekey with a bad MIC is ignored.
	forged := ParseTestEAPOL(t, 0x1382, make([]byte, 32), gtkKeyData(t, split.KEK, 3, gtk2), bytes.Repeat([]byte{9}, 16))
	if info := k.ProcessEAPOL(fromAP, forged); info.GTK || k.group(ap.String(), 3) != nil {
		t.Fatalf("forged rekey installed a key: %+v", info)
	}

	k.SetSecrets(nil)
	if k.GroupKeys() != 0 {
		t.Fatal("GTK survived revoking the network's key")
	}
}

func FuzzGroupKeyData(f *testing.F) {
	f.Add([]byte{0xdd, 22, 0x00, 0x0f, 0xac, 0x01, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0xdd, 0})
	kek := bytes.Repeat([]byte{7}, 16)
	f.Fuzz(func(t *testing.T, b []byte) {
		if id, gtk, ok := gtkKDE(b); ok && (id > 3 || len(gtk) > len(b)) {
			t.Fatalf("bad KDE %d %x", id, gtk)
		}
		_, _ = aesUnwrap(kek, b)
	})
}
