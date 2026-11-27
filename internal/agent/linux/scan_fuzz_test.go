//go:build linux

package linux

import (
	"net/netip"
	"testing"
)

// procSeeds are real /proc shapes: one of each socket table, whitespace,
// truncation, a scoped IPv6 address, and a stat line whose command holds
// parentheses.
var procSeeds = []string{
	"   0: 0100007F:1F90 0900A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 999 1 0 0 0 0\n",
	"   0: 0000000000000000FFFF00000500A8C0:0016 0000000000000000FFFF00000900A8C0:9C40 01 00000000:00000000 00:00000000 00000000     0        0 1000 1 0 0 0 0\n",
	"   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1234 2 0 0 0 0\n",
	"  1:   0200000A:9C40   010200C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 77 1 0 0 0 0   \n",
	"   0: 0100007F:1F90 0900A8C0",
	"   0: fe80::1%eth0:1F90 0000000000000000FFFF00000900A8C0:9C40 01 00000000:00000000 00:00000000 00000000     0        0 1000 1 0 0 0 0\n",
	"1234 (a (b) c) S 1 1234 1234 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0\n",
	"1234 (no closing paren\n",
	"\n",
}

// FuzzParseProc fuzzes the pure /proc parsers: a socket-table line, a hex
// address and the first fields of /proc/<pid>/stat. None may panic, and a
// failed parse leaves its zero value.
func FuzzParseProc(f *testing.F) {
	for _, s := range procSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		line := string(b)
		so, ok := parseSocket(line, "tcp")
		if !ok {
			if so != (socket{}) {
				t.Fatalf("failed parseSocket left %+v", so)
			}
		} else {
			if so.localPort < 0 || so.localPort > 65535 || so.remotePort < 0 || so.remotePort > 65535 {
				t.Fatalf("port out of range: %+v", so)
			}
			if _, err := netip.ParseAddr(so.localIP); err != nil {
				t.Fatalf("local address %q: %v", so.localIP, err)
			}
			if _, err := netip.ParseAddr(so.remoteIP); err != nil {
				t.Fatalf("remote address %q: %v", so.remoteIP, err)
			}
		}

		a, err := parseHexAddr(line)
		if err != nil {
			if a != (hexAddr{}) {
				t.Fatalf("failed parseHexAddr left %+v", a)
			}
		} else {
			if a.Port < 0 || a.Port > 65535 {
				t.Fatalf("port out of range: %+v", a)
			}
			if _, err := netip.ParseAddr(a.Addr); err != nil {
				t.Fatalf("address %q: %v", a.Addr, err)
			}
		}

		ppid, ticks, ok := parseStat(b)
		if !ok && ticks != 0 {
			t.Fatalf("failed parseStat left ticks %d (ppid %d)", ticks, ppid)
		}
	})
}
