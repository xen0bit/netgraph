package darwin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	ps := "  501     1     0 /usr/sbin/sshd\n  777     1   501 " + exe + "\n"
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

func FuzzParseLsof(f *testing.F) {
	f.Add([]byte(lsofOut))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, s := range ParseLsof(b) {
			if s.LocalPort < 0 || s.LocalPort > 65535 || s.RemotePort < 0 || s.RemotePort > 65535 {
				t.Fatalf("port out of range: %+v", s)
			}
		}
		_ = ParsePs(b)
	})
}
