package wifi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseBeacon(t *testing.T) {
	ap := []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b, 0x0080) // beacon
	copy(b[4:10], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(b[10:16], ap)
	copy(b[16:22], ap)
	b[22] = 0x10
	fixed := make([]byte, 12)
	binary.LittleEndian.PutUint16(fixed[10:], 0x0011) // ESS + privacy
	b = append(b, fixed...)
	b = append(b, ie(0, []byte("home"))...)
	b = append(b, ie(3, []byte{6})...)
	b = append(b, ie(48, rsnBody(4, 2))...) // CCMP, PSK

	f, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind() != "beacon" || f.SSID != "home" || f.BSSID.String() != "aa:bb:cc:00:00:01" || f.Security.Kind != WPA2 ||
		f.Security.Group != "CCMP" || !f.Security.UsesCCMP() {
		t.Fatalf("frame = %+v", f)
	}
	if f.WireEvent().Security != WPA2 {
		t.Errorf("event = %+v", f.WireEvent())
	}
}

func TestParseHiddenOpenAndWEP(t *testing.T) {
	for _, tc := range []struct {
		name string
		cap  uint16
		ssid []byte
		ies  []byte
		want string
	}{
		{"hidden open", 0x0001, nil, nil, Open},
		{"wep", 0x0011, []byte("old"), nil, WEP},
		{"wpa", 0x0011, []byte("legacy"), ie(221, wpaBody(2, 2)), WPA},
		{"wpa3", 0x0011, []byte("modern"), ie(48, rsnBody(4, 8)), WPA3},
		{"transition", 0x0011, []byte("mixed"), ie(48, rsnBody2(4, 2, 8)), WPA2WPA3},
		{"owe", 0x0011, []byte("open-secure"), ie(48, rsnBody(4, 12)), OWE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &Frame{Type: TypeManagement, Subtype: SubtypeBeacon, Capability: tc.cap}
			ies, err := parseIEs(append(append(ie(0, tc.ssid), ie(3, []byte{1})...), tc.ies...))
			if err != nil {
				t.Fatal(err)
			}
			f.IEs = ies
			f.SSID = ies.SSID()
			f.Security = securityFromIEs(ies, tc.cap)
			if got := f.Security.Kind; got != tc.want {
				t.Errorf("security = %q, want %q (%+v)", got, tc.want, f.Security)
			}
		})
	}
}

func TestRadiotap(t *testing.T) {
	// Flags: FCS + data pad; channel 2437 (channel 6); signal -42.
	present := uint32(1<<1 | 1<<3 | 1<<5)
	rt := make([]byte, 15)
	rt[0] = 0
	binary.LittleEndian.PutUint16(rt[2:], 15)
	binary.LittleEndian.PutUint32(rt[4:], present)
	rt[8] = 0x10 | 0x20
	binary.LittleEndian.PutUint16(rt[10:], 2437)
	binary.LittleEndian.PutUint16(rt[12:], 0)
	rt[14] = 0xd6 // -42
	frame := []byte{1, 2, 3, 4}
	radio, payload, err := ParseRadiotap(append(rt, frame...))
	if err != nil {
		t.Fatal(err)
	}
	if radio.Channel != 6 || radio.Frequency != 2437 || radio.SignalDBM != -42 || !radio.FCS || !radio.DataPad || !radio.HasSignal {
		t.Fatalf("radio = %+v", radio)
	}
	if !bytes.Equal(payload, frame) {
		t.Fatalf("payload = %x", payload)
	}
	if channelForFreq(5180) != 36 || channelForFreq(5955) != 1 || channelForFreq(2484) != 14 {
		t.Error("channel mapping")
	}
}

func TestDataFrameLLC(t *testing.T) {
	llc := mustHex(t, "aaaa0300000008004500001c")
	f := &Frame{Type: TypeData, HeaderLen: 24, Body: llc}
	typ, payload, err := f.LLC()
	if err != nil || typ != 0x0800 || !bytes.Equal(payload, mustHex(t, "4500001c")) {
		t.Fatalf("LLC: %v %04x %x", err, typ, payload)
	}
	f.Protected = true
	if _, _, err := f.LLC(); err == nil {
		t.Fatal("encrypted frame exposed its payload")
	}
}

func TestEthernetRebuild(t *testing.T) {
	f := &Frame{}
	b := f.Ethernet([]byte{1, 2, 3, 4, 5, 6}, []byte{7, 8, 9, 10, 11, 12}, 0x0800, []byte{0xde, 0xad})
	if len(b) != 16 || !bytes.Equal(b[:6], []byte{1, 2, 3, 4, 5, 6}) || !bytes.Equal(b[6:12], []byte{7, 8, 9, 10, 11, 12}) ||
		binary.BigEndian.Uint16(b[12:]) != 0x0800 || !bytes.Equal(b[14:], []byte{0xde, 0xad}) {
		t.Fatalf("ethernet = %x", b)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{0x80, 0})
	f.Add(make([]byte, 24))
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, _ := Parse(b)
		if fr != nil {
			_ = fr.Kind()
			_, _, _ = fr.LLC()
			_ = fr.WireEvent()
		}
		_, _, _ = ParseRadiotap(b)
	})
}

func ie(id byte, body []byte) []byte {
	return append([]byte{id, byte(len(body))}, body...)
}

func rsnBody(pairwise, akm byte) []byte {
	return rsnBody2(pairwise, akm)
}

func rsnBody2(pairwise byte, akms ...byte) []byte {
	b := []byte{1, 0}
	b = append(b, 0x00, 0x0f, 0xac, 0x04) // group CCMP
	b = append(b, 1, 0, 0x00, 0x0f, 0xac, pairwise)
	b = append(b, byte(len(akms)), 0)
	for _, a := range akms {
		b = append(b, 0x00, 0x0f, 0xac, a)
	}
	return append(b, 0, 0)
}

func wpaBody(pairwise, akm byte) []byte {
	b := []byte{0x00, 0x50, 0xf2, 0x01, 1, 0}
	b = append(b, 0x00, 0x50, 0xf2, 0x02) // group TKIP
	b = append(b, 1, 0, 0x00, 0x50, 0xf2, pairwise)
	b = append(b, 1, 0, 0x00, 0x50, 0xf2, akm)
	return append(b, 0, 0)
}
