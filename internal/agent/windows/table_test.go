package windows

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/xen0bit/netgraph/internal/agent"
)

func row4(state uint32, local string, lport uint16, remote string, rport uint16, pid uint32) []byte {
	r := make([]byte, row4Size)
	le := binary.LittleEndian
	le.PutUint32(r[0:], state)
	a := netip.MustParseAddr(local).As4()
	copy(r[4:8], a[:])
	binary.BigEndian.PutUint16(r[8:], lport)
	b := netip.MustParseAddr(remote).As4()
	copy(r[12:16], b[:])
	binary.BigEndian.PutUint16(r[16:], rport)
	le.PutUint32(r[20:], pid)
	return r
}

func row6(state uint32, local string, lport uint16, remote string, rport uint16, pid uint32) []byte {
	r := make([]byte, row6Size)
	le := binary.LittleEndian
	a := netip.MustParseAddr(local).As16()
	copy(r[0:16], a[:])
	binary.BigEndian.PutUint16(r[20:], lport)
	b := netip.MustParseAddr(remote).As16()
	copy(r[24:40], b[:])
	binary.BigEndian.PutUint16(r[44:], rport)
	le.PutUint32(r[48:], state)
	le.PutUint32(r[52:], pid)
	return r
}

func tableOf(rows ...[]byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(len(rows)))
	for _, r := range rows {
		b = append(b, r...)
	}
	return b
}

func TestParseTables(t *testing.T) {
	v4, err := ParseTCP4(tableOf(
		row4(2, "0.0.0.0", 3389, "0.0.0.0", 0, 900),
		row4(5, "10.0.0.2", 3389, "10.0.0.9", 51000, 900),
		row4(5, "10.0.0.2", 50123, "203.0.113.9", 443, 4242),
	))
	if err != nil {
		t.Fatal(err)
	}
	v6, err := ParseTCP6(tableOf(row6(5, "2001:db8::2", 50200, "2001:db8::9", 443, 4242)))
	if err != nil {
		t.Fatal(err)
	}
	if len(v4) != 3 || v4[2].LocalIP != "10.0.0.2" || v4[2].LocalPort != 50123 || v4[2].RemoteIP != "203.0.113.9" ||
		v4[2].RemotePort != 443 || v4[2].PID != 4242 || v4[2].State != "ESTABLISHED" || v4[0].State != "LISTEN" {
		t.Fatalf("v4 = %+v", v4)
	}
	if len(v6) != 1 || v6[0].LocalIP != "2001:db8::2" || v6[0].RemotePort != 443 || v6[0].PID != 4242 {
		t.Fatalf("v6 = %+v", v6)
	}
	procs := map[int]agent.Process{4242: {PID: 4242, Path: `C:\Program Files\Mozilla Firefox\firefox.exe`}, 900: {PID: 900, Path: `C:\Windows\System32\svchost.exe`}}
	conns := Connections(append(v4, v6...), procs, 1)
	if len(conns) != 3 {
		t.Fatalf("connections = %+v", conns)
	}
	if conns[0].Direction != "in" || conns[0].App != "svchost.exe" || conns[1].Direction != "out" || conns[1].App != "firefox.exe" {
		t.Fatalf("connections = %+v", conns)
	}
}

func TestParseTablesBounded(t *testing.T) {
	for _, b := range [][]byte{nil, {1, 0}, {5, 0, 0, 0, 1, 2, 3}, {0xff, 0xff, 0xff, 0xff}} {
		if _, err := ParseTCP4(b); err == nil {
			t.Errorf("ParseTCP4(%x): no error", b)
		}
		if _, err := ParseTCP6(b); err == nil {
			t.Errorf("ParseTCP6(%x): no error", b)
		}
	}
	if s, err := ParseTCP4([]byte{0, 0, 0, 0}); err != nil || len(s) != 0 {
		t.Fatalf("empty = %v %v", s, err)
	}
}

func FuzzParseTCP(f *testing.F) {
	f.Add(tableOf(row4(5, "10.0.0.2", 1, "10.0.0.3", 2, 3)))
	f.Add(tableOf(row6(5, "::1", 1, "::2", 2, 3)))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseTCP4(b)
		_, _ = ParseTCP6(b)
	})
}
