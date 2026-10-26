package wifi

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// amsdu builds an aggregate of LLC payloads, each subframe with its own
// addresses, padded to four bytes between subframes.
func amsdu(subs ...[3][]byte) []byte {
	var b []byte
	for i, s := range subs {
		b = append(b, s[0]...)
		b = append(b, s[1]...)
		b = binary.BigEndian.AppendUint16(b, uint16(len(s[2])))
		b = append(b, s[2]...)
		if i < len(subs)-1 {
			for len(b)%4 != 0 {
				b = append(b, 0)
			}
		}
	}
	return b
}

// An encrypted A-MSDU decrypts like any data frame (the A-MSDU bit is not
// in the CCMP AAD) and each subframe becomes its own Ethernet frame, with
// the subframe's addresses.
func TestProcessorAMSDU(t *testing.T) {
	const ap, sta = "aa:bb:cc:00:00:01", "3c:22:fb:01:02:03"
	k := NewKeyring()
	if err := k.AddPassphrase("home", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	if ok, err := k.LoadHandshake(ap, sta, "home", bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), 2); err != nil || !ok {
		t.Fatalf("LoadHandshake: %v %v", ok, err)
	}
	var got [][]byte
	p := NewProcessor(Config{Keys: k, Data: func(_ time.Time, eth []byte) { got = append(got, append([]byte(nil), eth...)) }})

	staMAC := []byte{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03}
	gw := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	printer := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x77}
	ipv4 := append([]byte{0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00}, make([]byte, 21)...)
	ipv6 := append([]byte{0xaa, 0xaa, 0x03, 0, 0, 0, 0x86, 0xdd}, make([]byte, 40)...)
	plain := amsdu([3][]byte{gw, staMAC, ipv4}, [3][]byte{printer, staMAC, ipv6})

	header := dataHeader(0x4188, false, true) // QoS data, to DS, protected
	header[24] = 0x80                         // A-MSDU present
	body, err := ccmpSeal(header, plain, k.ptk(ap, sta).TK, 9)
	if err != nil {
		t.Fatal(err)
	}
	p.Handle(time.Unix(0, 0), append(append([]byte(nil), header...), body...), false)

	if len(got) != 2 {
		t.Fatalf("got %d Ethernet frames, want 2", len(got))
	}
	for i, want := range []struct {
		dst  []byte
		typ  uint16
		size int
	}{{gw, 0x0800, 21}, {printer, 0x86dd, 40}} {
		eth := got[i]
		if !bytes.Equal(eth[0:6], want.dst) || !bytes.Equal(eth[6:12], staMAC) ||
			binary.BigEndian.Uint16(eth[12:]) != want.typ || len(eth) != 14+want.size {
			t.Errorf("frame %d = %x", i, eth)
		}
	}
}

func TestSplitAMSDURejects(t *testing.T) {
	a := []byte{1, 2, 3, 4, 5, 6}
	for name, b := range map[string][]byte{
		// FragAttacks: a plain frame with the A-MSDU bit flipped.
		"llc as DA": append([]byte{0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00}, make([]byte, 20)...),
		"truncated": append(append(append([]byte{}, a...), a...), 0),
		"overlong":  append(append(append([]byte{}, a...), a...), 0, 50, 1, 2),
	} {
		if _, err := splitAMSDU(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	many := bytes.Repeat(append(append(append([]byte{}, a...), a...), 0, 0, 0, 0), maxAMSDUSubframes+1)
	if _, err := splitAMSDU(many); err == nil {
		t.Error("accepted an aggregate beyond the subframe bound")
	}
}

func FuzzSplitAMSDU(f *testing.F) {
	a := []byte{1, 2, 3, 4, 5, 6}
	f.Add(amsdu([3][]byte{a, a, []byte("hello")}, [3][]byte{a, a, []byte("x")}))
	f.Fuzz(func(t *testing.T, b []byte) {
		subs, err := splitAMSDU(b)
		if err != nil {
			return
		}
		for _, s := range subs {
			if len(s.dst) != 6 || len(s.src) != 6 || len(s.llc) > len(b) {
				t.Fatalf("bad subframe %+v", s)
			}
		}
	})
}
