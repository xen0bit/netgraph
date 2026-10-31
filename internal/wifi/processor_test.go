package wifi

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

func collectEvents() (*Processor, *[]wire.Event) {
	var events []wire.Event
	p := NewProcessor(Config{Emit: func(e wire.Event) { events = append(events, e) }})
	return p, &events
}

func TestProcessorBeaconAndOpenData(t *testing.T) {
	p, events := collectEvents()
	ts := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	ap := []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
	sta := []byte{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03}
	dst := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	beacon := frameBytes(0x0080, ap, ap, ap, "", nil)
	beacon = append(beacon, make([]byte, 12)...)
	beacon = append(beacon, ie(0, []byte("cafe"))...)
	beacon = append(beacon, ie(48, rsnBody(4, 2))...)
	p.Handle(ts, radiotap(2437, -40, 0, beacon), true)
	// A second identical beacon within the dedupe window is suppressed.
	p.Handle(ts.Add(time.Second), radiotap(2437, -40, 0, beacon), true)

	if len(*events) != 1 {
		t.Fatalf("events = %d", len(*events))
	}
	e := (*events)[0].WiFi
	if e == nil || e.Kind != "beacon" || e.SSID != "cafe" || e.Channel != 6 || e.Security != WPA2 || e.Signal != -40 {
		t.Fatalf("beacon event = %+v", e)
	}
	if ssid, sec, ok := p.Keys().Network("aa:bb:cc:00:00:01"); !ok || ssid != "cafe" || sec.Kind != WPA2 {
		t.Errorf("keyring network = %q %+v %v", ssid, sec, ok)
	}

	var gotEther []byte
	p.cfg.Data = func(_ time.Time, b []byte) { gotEther = append([]byte(nil), b...) }
	data := frameBytes(0x0108, ap, sta, dst, string(mustHex(t, "aaaa0300000008004500001c00000000401100000a0000010a000002")), nil)
	p.Handle(ts, data, false)
	if len(gotEther) != 14+20 || binary.BigEndian.Uint16(gotEther[12:]) != 0x0800 ||
		!bytes.Equal(gotEther[:6], dst) || !bytes.Equal(gotEther[6:12], sta) {
		t.Fatalf("rebuilt ethernet = %x", gotEther)
	}
}

func TestProcessorDropsBadFCS(t *testing.T) {
	p, events := collectEvents()
	data := frameBytes(0x0108, []byte{1, 1, 1, 1, 1, 1}, []byte{2, 2, 2, 2, 2, 2}, []byte{3, 3, 3, 3, 3, 3},
		string(mustHex(t, "aaaa03000000080000")), nil)
	// The radiotap FCS is the last four bytes; make it wrong.
	p.Handle(time.Now(), radiotap(2412, 0, 0x10, data), true)
	if len(*events) != 0 {
		t.Fatalf("bad-FCS frame was emitted: %+v", *events)
	}
}

func TestProcessorHandshakeEvent(t *testing.T) {
	p, events := collectEvents()
	ap := []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x03}
	sta := []byte{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x05}
	nonce := bytes.Repeat([]byte{0x11}, 32)
	eapol := ParseTestEAPOL(t, 0x008a, nonce, nil, nil).Raw
	llc := append([]byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e}, eapol...)
	f := frameBytes(0x0108, ap, sta, ap, string(llc), nil)
	p.Handle(time.Now(), f, false)
	if len(*events) != 1 {
		t.Fatalf("events = %d", len(*events))
	}
	w := (*events)[0].WiFi
	if w.Kind != "handshake" || w.EAPOL == nil || w.EAPOL.Message != 1 || w.EAPOL.Version != 2 || w.Client != "3c:22:fb:01:02:05" {
		t.Fatalf("handshake event = %+v", w)
	}
}

func TestProcessorReassemblesFragments(t *testing.T) {
	p, _ := collectEvents()
	ap := []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x07}
	sta := []byte{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x08}
	dst := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	llc := mustHex(t, "aaaa0300000008004500001c00000000401100000a0000010a000002")
	mk := func(frag int, more bool, part []byte) []byte {
		fc := uint16(0x0108)
		if more {
			fc |= 0x0400
		}
		b := frameBytes(fc, ap, sta, dst, string(part), nil)
		binary.LittleEndian.PutUint16(b[22:], uint16(0x1230|frag))
		return b
	}
	var got []byte
	p.cfg.Data = func(_ time.Time, b []byte) { got = append([]byte(nil), b...) }
	p.Handle(time.Now(), mk(0, true, llc[:10]), false)
	if got != nil {
		t.Fatal("first fragment was emitted")
	}
	p.Handle(time.Now(), mk(1, false, llc[10:]), false)
	if len(got) != 14+20 {
		t.Fatalf("reassembled Ethernet = %x", got)
	}
}

func TestProcessorConcurrent(t *testing.T) {
	p, _ := collectEvents()
	ap := []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x04}
	b := frameBytes(0x0080, ap, ap, ap, "", nil)
	b = append(b, make([]byte, 12)...)
	b = append(b, 0, 4, 'w', 'i', 'f', 'i')
	data := radiotap(2412, -30, 0, b)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				p.Handle(time.Now(), data, true)
			}
		}()
	}
	wg.Wait()
}

func FuzzProcessor(f *testing.F) {
	f.Add(radiotap(2412, -50, 0, frameBytes(0x0080, []byte{1, 2, 3, 4, 5, 6}, []byte{1, 2, 3, 4, 5, 6}, []byte{1, 2, 3, 4, 5, 6}, "", nil)))
	f.Add(frameBytes(0x0108, []byte{1, 2, 3, 4, 5, 6}, []byte{7, 8, 9, 10, 11, 12}, []byte{13, 14, 15, 16, 17, 18}, string([]byte{0xaa, 0xaa, 0x03, 0, 0, 0, 8, 0}), nil))
	p := NewProcessor(Config{})
	f.Fuzz(func(t *testing.T, b []byte) {
		p.Handle(time.Unix(0, 0), b, true)
		p.Handle(time.Unix(0, 0), b, false)
	})
}

func frameBytes(fc uint16, a1, a2, a3 []byte, body string, _ []byte) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b, fc)
	copy(b[4:10], a1)
	copy(b[10:16], a2)
	copy(b[16:22], a3)
	return append(b, body...)
}

func radiotap(freq int, signal int, flags byte, frame []byte) []byte {
	rt := make([]byte, 15)
	binary.LittleEndian.PutUint16(rt[2:], 15)
	binary.LittleEndian.PutUint32(rt[4:], 1<<1|1<<3|1<<5)
	rt[8] = flags
	binary.LittleEndian.PutUint16(rt[10:], uint16(freq))
	rt[14] = byte(int8(signal))
	return append(rt, frame...)
}

func TestProcessorEncryptedFragments(t *testing.T) {
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
	llc := mustHex(t, "aaaa0300000008004500001c00000000401100000a0000010a000002")
	tk := k.ptk(ap, sta).TK
	mk := func(frag int, more bool, part []byte) []byte {
		h := dataHeader(0x4188, false, true)
		if more {
			h[1] |= 0x04 // More Fragments
		}
		h[22] = byte(0x30 | frag)
		body, err := ccmpSeal(h, part, tk, uint64(10+frag))
		if err != nil {
			t.Fatal(err)
		}
		return append(append([]byte(nil), h...), body...)
	}
	p.Handle(time.Unix(0, 0), mk(0, true, llc[:11]), false)
	if len(got) != 0 {
		t.Fatal("first encrypted fragment was emitted")
	}
	p.Handle(time.Unix(0, 0), mk(1, false, llc[11:]), false)
	if len(got) != 1 || len(got[0]) != 14+20 {
		t.Fatalf("reassembled encrypted Ethernet = %x", got)
	}
}

func TestProcessorFragmentedAMSDU(t *testing.T) {
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
	tk := k.ptk(ap, sta).TK
	mk := func(frag int, more bool, part []byte) []byte {
		h := dataHeader(0x4188, false, true)
		h[24] = 0x80 // A-MSDU present
		if more {
			h[1] |= 0x04
		}
		h[22] = byte(0x30 | frag)
		body, err := ccmpSeal(h, part, tk, uint64(20+frag))
		if err != nil {
			t.Fatal(err)
		}
		return append(append([]byte(nil), h...), body...)
	}
	p.Handle(time.Unix(0, 0), mk(0, true, plain[:20]), false)
	p.Handle(time.Unix(0, 0), mk(1, false, plain[20:]), false)
	if len(got) != 2 {
		t.Fatalf("got %d Ethernet frames, want 2", len(got))
	}
}

func TestProcessorOutOfOrderFragments(t *testing.T) {
	p, _ := collectEvents()
	ap := []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x09}
	sta := []byte{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x09}
	dst := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	llc := mustHex(t, "aaaa0300000008004500001c00000000401100000a0000010a000002")
	mk := func(frag int, more bool, part []byte) []byte {
		fc := uint16(0x0108)
		if more {
			fc |= 0x0400
		}
		b := frameBytes(fc, ap, sta, dst, string(part), nil)
		binary.LittleEndian.PutUint16(b[22:], uint16(0x1240|frag))
		return b
	}
	var got []byte
	p.cfg.Data = func(_ time.Time, b []byte) { got = append([]byte(nil), b...) }
	p.Handle(time.Now(), mk(1, false, llc[10:]), false)
	if got != nil {
		t.Fatal("final fragment emitted before the first")
	}
	p.Handle(time.Now(), mk(0, true, llc[:10]), false)
	if len(got) != 14+20 {
		t.Fatalf("out-of-order reassembly = %x", got)
	}
}
