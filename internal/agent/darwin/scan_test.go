package darwin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// What lsof -nP -iTCP -iUDP -FpcuftPnT prints: a listener, an established
// IPv4 and IPv6 connection, an unconnected UDP socket.
const lsofOut = `p321
cmDNSResponder
u65
f5
tIPv4
PUDP
n*:5353
p501
csshd
u0
f3
tIPv6
PTCP
n*:22
TST=LISTEN
TQR=0
TQS=0
f4
tIPv4
PTCP
n10.0.0.2:22->10.0.0.9:40000
TST=ESTABLISHED
p777
cGoogle Chrome
u501
f30
tIPv4
PTCP
n10.0.0.2:50123->203.0.113.9:443
TST=ESTABLISHED
f31
tIPv6
PTCP
n[2001:db8::2]:50200->[2001:db8::9]:443
TST=ESTABLISHED
`

func TestParseLsof(t *testing.T) {
	so := ParseLsof([]byte(lsofOut))
	if len(so) != 5 {
		t.Fatalf("sockets = %+v", so)
	}
	if so[1].State != "LISTEN" || so[1].LocalPort != 22 || so[1].Connected() {
		t.Fatalf("listener = %+v", so[1])
	}
	if so[2].PID != 501 || so[2].RemoteIP != "10.0.0.9" || so[2].RemotePort != 40000 || so[2].Proto != "tcp" || so[2].ID != "501/4" {
		t.Fatalf("sshd = %+v", so[2])
	}
	if so[4].LocalIP != "2001:db8::2" || so[4].RemoteIP != "2001:db8::9" || so[4].UID != 501 {
		t.Fatalf("v6 = %+v", so[4])
	}
	if so[0].Connected() {
		t.Fatalf("unconnected UDP = %+v", so[0])
	}
}

func TestParsePsStart(t *testing.T) {
	in := "  501     1     0 Wed Nov 25 10:12:34 2026 /usr/sbin/sshd\n" +
		"  502     1   501 Thu Mar  7 01:02:03 2025 /usr/bin/x\n" +
		"  503     1     0 /usr/bin/no-lstart\n" +
		"  504     1     0 Wed Not 99 99:99:99 2026 /usr/bin/bad-lstart\n"
	got := ParsePs([]byte(in))
	if len(got) != 4 {
		t.Fatalf("processes = %+v", got)
	}
	want := time.Date(2026, time.November, 25, 10, 12, 34, 0, time.Local).UnixMilli()
	if got[501].Start != want || got[501].Path != "/usr/sbin/sshd" {
		t.Fatalf("501 = %+v; want start %d", got[501], want)
	}
	// ps pads a single-digit day with a space; joining fields must not break it.
	want = time.Date(2025, time.March, 7, 1, 2, 3, 0, time.Local).UnixMilli()
	if got[502].Start != want || got[502].Path != "/usr/bin/x" {
		t.Fatalf("502 = %+v; want start %d", got[502], want)
	}
	// Without lstart (or with one that doesn't parse), the whole rest is the
	// command as before, and no start time is claimed.
	if got[503].Start != 0 || got[503].Path != "/usr/bin/no-lstart" {
		t.Fatalf("503 = %+v", got[503])
	}
	if got[504].Start != 0 || !strings.HasSuffix(got[504].Cmdline, "/usr/bin/bad-lstart") {
		t.Fatalf("504 = %+v", got[504])
	}
}

func TestScan(t *testing.T) {
	// ps on macOS prints absolute Unix paths; on another test host the temp
	// dir is whatever it is, so hashing is only checked where it is one.
	exe := filepath.ToSlash(filepath.Join(t.TempDir(), "Google Chrome"))
	if err := os.WriteFile(exe, []byte("chrome"), 0o755); err != nil {
		t.Fatal(err)
	}
	unixPath := strings.HasPrefix(exe, "/")
	if !unixPath {
		exe = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" // nothing to hash, but a macOS path
	}
	ps := "  501     1     0 Wed Nov 25 10:12:34 2026 /usr/sbin/sshd\n  777     1   501 Wed Nov 25 10:13:00 2026 " + exe + "\n"
	args := "  501 /usr/sbin/sshd -D\n  777 " + exe + " --type=renderer --secret=x\n"
	var ran []string
	s := &Scanner{Run: func(_ context.Context, name string, a ...string) ([]byte, error) {
		ran = append(ran, name+" "+strings.Join(a, " "))
		switch {
		case name == "/usr/sbin/lsof":
			return []byte(lsofOut), nil
		case strings.Contains(strings.Join(a, " "), "args="):
			return []byte(args), nil
		default:
			return []byte(ps), nil
		}
	}}
	procs, conns, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 3 {
		t.Fatalf("connections = %+v", conns)
	}
	if conns[0].Direction != "in" || conns[0].App != "sshd" || conns[1].App != "Google Chrome" || conns[1].Direction != "out" || (unixPath && conns[1].SHA256 == "") {
		t.Fatalf("connections = %+v", conns)
	}
	if len(procs) != 2 {
		t.Fatalf("processes = %+v", procs)
	}
	for _, p := range procs {
		if strings.Contains(p.Cmdline, "--secret") {
			t.Fatalf("arguments sent without -cmdlines: %+v", p)
		}
		if p.Start == 0 {
			t.Fatalf("no start time for %+v: PID reuse can't be seen", p)
		}
	}
	if len(ran) != 2 {
		t.Fatalf("ran %q; full command lines need asking for", ran)
	}
	// With -cmdlines the arguments come along.
	s.Cmdlines = true
	procs, _, _ = s.Scan(context.Background())
	found := false
	for _, p := range procs {
		found = found || strings.Contains(p.Cmdline, "--type=renderer")
	}
	if !found {
		t.Fatalf("processes = %+v", procs)
	}
}

// ps -axww -o pid=,ppid=,uid=,lstart=,comm= output: a lstart with a two-digit
// day, one with ps's space-padded single digit, a name with spaces, and lines
// that don't parse.
const psOut = `  501     1     0 Wed Nov 25 10:12:34 2026 /usr/sbin/sshd
  777     1   501 Thu Mar  7 01:02:03 2025 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
  900     1     0 Wed Not 99 99:99:99 2026 /usr/bin/bad
  902     1     0 Wed Nov 1 0:00:00 0000 /usr/bin/year-zero
  901
`

func FuzzParseLsof(f *testing.F) {
	f.Add([]byte(lsofOut))
	f.Add([]byte(psOut))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, s := range ParseLsof(b) {
			if s.LocalPort < 0 || s.LocalPort > 65535 || s.RemotePort < 0 || s.RemotePort > 65535 {
				t.Fatalf("port out of range: %+v", s)
			}
		}
		for pid, p := range ParsePs(b) {
			if pid <= 0 || p.PID != pid {
				t.Fatalf("process %d = %+v", pid, p)
			}
			// Start is Unix milliseconds: a parsed one is plausible, and an
			// unparsed lstart claims none. The upper bound is a year past
			// parseLstart's, so a time zone can't straddle it.
			maxStart := time.Date(2101, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
			if p.Start != 0 && (p.Start < 0 || p.Start > maxStart) {
				t.Fatalf("start out of range: %+v", p)
			}
		}
	})
}
