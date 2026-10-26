package wifi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

func TestPMK(t *testing.T) {
	// The well-known 802.11i passphrase test vector.
	pmk, err := PMK("password", "IEEE")
	if err != nil {
		t.Fatal(err)
	}
	want := "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e"
	if got := hex.EncodeToString(pmk); got != want {
		t.Fatalf("PMK = %s, want %s", got, want)
	}
	// A 64-digit PSK is taken as the key itself.
	raw := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	if got, err := PMK(raw, "whatever"); err != nil || hex.EncodeToString(got) != raw {
		t.Fatalf("raw PSK: %v %s", err, got)
	}
	if _, err := PMK("short", "IEEE"); err == nil {
		t.Fatal("accepted a too-short passphrase")
	}
}

func TestHandshakeDerivesPTKAndDecrypts(t *testing.T) {
	ap := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
	sta := net.HardwareAddr{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03}
	k := NewKeyring()
	if err := k.AddPassphrase("test-net", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	k.setNetwork(ap.String(), "test-net", Security{Kind: WPA2, Pairwise: []string{"CCMP"}})
	pmk := k.pmkFor("test-net")

	anonce := bytes.Repeat([]byte{0x11}, 32)
	snonce := bytes.Repeat([]byte{0x22}, 32)
	ptk, err := DerivePTK(pmk, ap, sta, anonce, snonce, 384)
	if err != nil {
		t.Fatal(err)
	}
	split := splitPTK(ptk, false)

	msg1 := ParseTestEAPOL(t, 0x008a, anonce, nil, nil) // pairwise, ACK, version 2
	if info := k.ProcessEAPOL(&Frame{BSSID: ap, Src: ap, Dst: sta}, msg1); info.Message != 1 || info.Installed {
		t.Fatalf("msg1 = %+v", info)
	}
	msg2 := ParseTestEAPOL(t, 0x010a, snonce, nil, split.KCK) // MIC, pairwise
	if info := k.ProcessEAPOL(&Frame{BSSID: ap, Src: sta, Dst: ap}, msg2); info.Message != 2 || !info.Valid || !info.Installed {
		t.Fatalf("msg2 = %+v", info)
	}
	if k.Keys() != 1 {
		t.Fatalf("keys = %d", k.Keys())
	}

	header := dataHeader(0x4108, false, false)
	llc := mustHex(t, "aaaa0300000008004500001c00000000401100000a0000010a000002")
	body, err := ccmpSeal(header, llc, split.TK, 7)
	if err != nil {
		t.Fatal(err)
	}
	f := &Frame{Protected: true, ToDS: true, BSSID: ap, Src: sta, Dst: net.HardwareAddr{0, 1, 2, 3, 4, 5}, Body: body, header: header}
	out, method, err := k.Decrypt(f)
	if err != nil || method != "CCMP" || !bytes.Equal(out, llc) {
		t.Fatalf("decrypt: %v %s %x", err, method, out)
	}
}

func TestParseKeyFile(t *testing.T) {
	k, err := ParseKeyFile(strings.NewReader(`
# comment
wpa2 home pass phrase with spaces
wep 1 0102030405060708090a0b0c0d
pmk sae 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
`))
	if err != nil {
		t.Fatal(err)
	}
	if pmk := k.pmkFor("home"); len(pmk) != 32 {
		t.Errorf("home PMK length %d", len(pmk))
	}
	if pmk := k.pmkFor("sae"); len(pmk) != 32 {
		t.Errorf("SAE PMK length %d", len(pmk))
	}
	k.mu.RLock()
	wep := k.wep[1]
	k.mu.RUnlock()
	if len(wep) != 13 {
		t.Errorf("WEP key = %x", wep)
	}
	for _, bad := range []string{
		"wpa2\n",
		"wpa2 only-ssid\n",
		"pmk net 00\n",
		"wep x 0102\n",
		"wep 0 0102\n",
		"nope a b\n",
	} {
		if _, err := ParseKeyFile(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// A frame from the access point has the station in address 1, not address 2;
// the key lookup must follow the DS bits rather than assume the sender is the
// station.
func TestDecryptFromAccessPoint(t *testing.T) {
	ap := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x0a}
	sta := net.HardwareAddr{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x0a}
	remote := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0xaa}
	k := NewKeyring()
	ptk := bytes.Repeat([]byte{0x42}, 48)
	split := splitPTK(ptk, false)
	k.pairs[pairKey(ap, sta)] = split

	h := dataHeader(0x4208, false, false) // FromDS, protected
	copy(h[4:10], sta)
	copy(h[10:16], ap)
	copy(h[16:22], remote)
	llc := mustHex(t, "aaaa0300000008004500001c")
	body, err := ccmpSeal(h, llc, split.TK, 9)
	if err != nil {
		t.Fatal(err)
	}
	f := &Frame{Protected: true, FromDS: true, BSSID: ap, Src: remote, Dst: sta, Body: body, header: h}
	out, method, err := k.Decrypt(f)
	if err != nil || method != "CCMP" || !bytes.Equal(out, llc) {
		t.Fatalf("from AP: %v %s %x", err, method, out)
	}
}

func TestHandshakeRejectsBadMIC(t *testing.T) {
	ap := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02}
	sta := net.HardwareAddr{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x04}
	k := NewKeyring()
	if err := k.AddPassphrase("net", "passphrase123"); err != nil {
		t.Fatal(err)
	}
	k.setNetwork(ap.String(), "net", Security{Kind: WPA2})
	anonce := bytes.Repeat([]byte{1}, 32)
	snonce := bytes.Repeat([]byte{2}, 32)
	pmk := k.pmkFor("net")
	if _, err := DerivePTK(pmk, ap, sta, anonce, snonce, 384); err != nil {
		t.Fatal(err)
	}
	k.ProcessEAPOL(&Frame{BSSID: ap, Src: ap, Dst: sta}, ParseTestEAPOL(t, 0x008a, anonce, nil, nil))
	bad := ParseTestEAPOL(t, 0x010a, snonce, nil, bytes.Repeat([]byte{9}, 16))
	if info := k.ProcessEAPOL(&Frame{BSSID: ap, Src: sta, Dst: ap}, bad); info.Valid || info.Installed {
		t.Fatalf("bad MIC accepted: %+v", info)
	}
	if k.Keys() != 0 {
		t.Fatal("installed a key after a bad MIC")
	}
}

// ParseEAPOL parses a frame built here, so the test exercises the offsets.
func ParseTestEAPOL(t *testing.T, info uint16, nonce []byte, keyData, kck []byte) *EAPOLKey {
	t.Helper()
	body := make([]byte, 95+len(keyData))
	body[0] = 2 // RSN key descriptor
	binary.BigEndian.PutUint16(body[1:], info)
	binary.BigEndian.PutUint16(body[3:], 16)
	binary.BigEndian.PutUint64(body[5:], 1)
	copy(body[13:45], nonce)
	binary.BigEndian.PutUint16(body[93:], uint16(len(keyData)))
	copy(body[95:], keyData)
	buf := make([]byte, 4+len(body))
	buf[0] = 2
	buf[1] = 3
	binary.BigEndian.PutUint16(buf[2:], uint16(len(body)))
	copy(buf[4:], body)
	if kck != nil {
		bufCopy := append([]byte(nil), buf...)
		for i := 81; i < 97; i++ {
			bufCopy[i] = 0
		}
		// Fill the MIC over the whole frame, as a real supplicant does.
		k := &EAPOLKey{Raw: bufCopy, KeyInfo: info}
		copy(buf[81:97], eapolMIC(k, kck))
	}
	got, err := ParseEAPOL(buf)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func eapolMIC(k *EAPOLKey, kck []byte) []byte {
	// Only version 2 is used by these tests. The MIC covers the whole
	// EAPOL-Key frame, 802.1X header included.
	h := hmac.New(sha1.New, kck)
	h.Write(k.Raw)
	return h.Sum(nil)[:16]
}

// TestHandshakeKnownAnswer locks the PRF counter and the EAPOL MIC scope
// against vectors computed by an independent implementation (Python
// hashlib/hmac), not by this package. Both values were also confirmed to
// match a real access point's MIC on a live WPA2 capture. A self-consistent
// round-trip test passed while the PRF counter started at 1 and the MIC was
// taken over the descriptor alone; only an external vector catches that.
func TestHandshakeKnownAnswer(t *testing.T) {
	const (
		ssid    = "netgraph-test"
		pass    = "testpassword"
		wantPMK = "f67a13b1e04bb5d0d3aca16b58c1f047f38575ff8eae6b6990c774ffc2124dde"
		wantPTK = "a923db87b155665b48636c658f7df1ccd0d8b5d94d26f3a2b6bca5d36287860cc1346af93f750b99dc75955ee36c78c2"
		frameHx = "0203007502010a00100000000000000001202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0000000000000000000000000000000000000000000000000000000000000000fd2620ce35fa7f9f163258cfaa957f44001630140100000fac040100000fac040100000fac020000"
	)
	aa := net.HardwareAddr{0x02, 0, 0, 0, 0xaa, 0}
	spa := net.HardwareAddr{0x02, 0, 0, 0, 0xbb, 0}
	anonce := make([]byte, 32)
	snonce := make([]byte, 32)
	for i := range anonce {
		anonce[i] = byte(i)
		snonce[i] = byte(i + 32)
	}

	pmk, err := PMK(pass, ssid)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(pmk); got != wantPMK {
		t.Fatalf("PMK = %s, want %s", got, wantPMK)
	}
	ptk, err := DerivePTK(pmk, aa, spa, anonce, snonce, 384)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(ptk); got != wantPTK {
		t.Fatalf("PTK = %s, want %s", got, wantPTK)
	}
	frame, err := hex.DecodeString(frameHx)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseEAPOL(frame)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := k.VerifyMIC(ptk[0:16])
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("VerifyMIC rejected a MIC a real AP would accept (MIC must cover the 802.1X header)")
	}
}

// TestLoadHandshake checks that a key recovered from stored handshake nonces
// (the server-sync path) is byte-identical to one derived live, so a
// restarted or additional sensor decrypts exactly as the capturing one did.
// It reuses the independent known-answer vector from TestHandshakeKnownAnswer.
func TestLoadHandshake(t *testing.T) {
	const ssid, pass = "netgraph-test", "testpassword"
	ap, sta := "02:00:00:00:aa:00", "02:00:00:00:bb:00"
	anonce := make([]byte, 32)
	snonce := make([]byte, 32)
	for i := range anonce {
		anonce[i] = byte(i)
		snonce[i] = byte(i + 32)
	}

	k := NewKeyring()
	// With no passphrase for the SSID, nothing can be derived: no key, no error.
	if ok, err := k.LoadHandshake(ap, sta, ssid, anonce, snonce, 2); err != nil || ok {
		t.Fatalf("LoadHandshake without a PMK: ok=%v err=%v (want false, nil)", ok, err)
	}
	if k.Keys() != 0 {
		t.Fatalf("installed a key with no PMK: %d", k.Keys())
	}
	if err := k.AddPassphrase(ssid, pass); err != nil {
		t.Fatal(err)
	}
	ok, err := k.LoadHandshake(ap, sta, ssid, anonce, snonce, 2)
	if err != nil || !ok {
		t.Fatalf("LoadHandshake: ok=%v err=%v", ok, err)
	}
	if k.Keys() != 1 {
		t.Fatalf("keys after load = %d, want 1", k.Keys())
	}
	// The recovered key must equal the live-derived PTK exactly.
	pmk, _ := PMK(pass, ssid)
	apMAC, _ := net.ParseMAC(ap)
	staMAC, _ := net.ParseMAC(sta)
	want, _ := DerivePTK(pmk, apMAC, staMAC, anonce, snonce, 384)
	got := k.ptk(ap, sta)
	if got == nil {
		t.Fatal("no key installed under (ap, sta)")
	}
	full := append(append(append([]byte{}, got.KCK...), got.KEK...), got.TK...)
	if !bytes.Equal(full, want) {
		t.Fatal("recovered key differs from the live-derived PTK")
	}
}
