package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestNewConnection(t *testing.T) {
	listening := map[Listener]bool{{"tcp", 22}: true}
	p := Process{PID: 7, UID: 1000, Path: "/usr/bin/ssh", Cmdline: "ssh"}
	for _, tc := range []struct {
		s         Socket
		key, dir  string
		local, rm string
	}{
		// A dual-stack socket's view of an IPv4 peer is unmapped, as the
		// sensor records it, and tcp6 is tcp.
		{Socket{Proto: "tcp6", LocalIP: "::ffff:10.0.0.2", LocalPort: 50000, RemoteIP: "::ffff:203.0.113.9", RemotePort: 443, ID: "99"},
			"tcp|10.0.0.2:50000|203.0.113.9:443|99", "out", "10.0.0.2", "203.0.113.9"},
		{Socket{Proto: "tcp", LocalIP: "10.0.0.2", LocalPort: 22, RemoteIP: "10.0.0.9", RemotePort: 40000},
			"tcp|10.0.0.2:22|10.0.0.9:40000", "in", "10.0.0.2", "10.0.0.9"},
		// A connection to itself is keyed by its fixed end and program, not
		// its ephemeral port: a health check is one row, not one a second.
		{Socket{Proto: "tcp6", LocalIP: "::1", LocalPort: 5000, RemoteIP: "::ffff:127.0.0.1", RemotePort: 6000},
			"tcp|self|server|[::1]:5000|ssh", "local", "::1", "127.0.0.1"},
		{Socket{Proto: "tcp", LocalIP: "127.0.0.1", LocalPort: 41062, RemoteIP: "127.0.0.1", RemotePort: 8090, ID: "124483769"},
			"tcp|self|client|127.0.0.1:8090|ssh", "local", "127.0.0.1", "127.0.0.1"},
		{Socket{Proto: "tcp", LocalIP: "10.0.0.2", LocalPort: 41063, RemoteIP: "10.0.0.2", RemotePort: 8090},
			"tcp|self|client|10.0.0.2:8090|ssh", "local", "10.0.0.2", "10.0.0.2"},
	} {
		c := NewConnection(tc.s, listening, p, 1)
		if c.Key != tc.key || c.Direction != tc.dir || c.LocalIP != tc.local || c.RemoteIP != tc.rm || c.Proto != "tcp" || c.App != "ssh" || c.UID != 1000 {
			t.Errorf("%+v: %+v", tc.s, c)
		}
	}
	if (Socket{RemoteIP: "0.0.0.0", RemotePort: 0}).Connected() || (Socket{RemoteIP: "::", RemotePort: 5}).Connected() || !(Socket{RemoteIP: "1.2.3.4", RemotePort: 5}).Connected() {
		t.Fatal("Connected")
	}
}

func TestMergeKeys(t *testing.T) {
	p := Process{PID: 7, Path: "/usr/sbin/haproxy"}
	var conns []Connection
	for i := range 50 { // a health check every scan, each on a new port
		c := NewConnection(Socket{Proto: "tcp", LocalIP: "127.0.0.1", LocalPort: 40000 + i, RemoteIP: "127.0.0.1", RemotePort: 8090, State: "SYN_SENT"}, nil, p, int64(100+i))
		conns = append(conns, c)
	}
	conns = append(conns, NewConnection(Socket{Proto: "tcp", LocalIP: "10.0.0.2", LocalPort: 40000, RemoteIP: "203.0.113.9", RemotePort: 443}, nil, p, 5))
	got := MergeKeys(conns)
	if len(got) != 2 {
		t.Fatalf("got %d connections, want 2: %+v", len(got), got)
	}
	if lo := got[0]; lo.FirstSeen != 100 || lo.LastSeen != 149 || lo.LocalPort != 40049 {
		t.Errorf("merged loopback = %+v", lo)
	}
}

func TestAppName(t *testing.T) {
	for in, want := range map[[2]string]string{
		{"/usr/bin/curl", ""}:                        "curl",
		{`C:\Program Files\Mozilla\firefox.exe`, ""}: "firefox.exe",
		{"", "/usr/sbin/sshd -D"}:                    "sshd",
		{"", "python3 x.py"}:                         "python3",
	} {
		if got := AppName(in[0], in[1]); got != want {
			t.Errorf("AppName%q = %q, want %q", in, got, want)
		}
	}
	if ClipCmdline("curl -u user:secret https://x", false) != "curl" {
		t.Fatal("arguments kept without -cmdlines")
	}
	if got := ClipCmdline("curl -u x", true); got != "curl -u x" {
		t.Fatalf("full = %q", got)
	}
}

func TestHasherCaches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(path, []byte("one"), 0o755); err != nil {
		t.Fatal(err)
	}
	var h Hasher
	a, code := h.Hash(path, path)
	if a == "" || code != "sha256:"+a {
		t.Fatalf("hash = %q %q", a, code)
	}
	// A changed file (size and mtime) is hashed again.
	if err := os.WriteFile(path, []byte("two!"), 0o755); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	_ = os.Chtimes(path, future, future)
	if b, _ := h.Hash(path, path); b == a || b == "" {
		t.Fatalf("hash after change = %q (was %q)", b, a)
	}
	if s, _ := h.Hash("", filepath.Dir(path)); s != "" {
		t.Fatal("hashed a directory")
	}
}

type countScanner struct{ n int }

func (s *countScanner) Capabilities() []string { return []string{"test-scanner"} }

func (s *countScanner) Scan(context.Context) ([]Process, []Connection, error) {
	s.n++
	return nil, []Connection{{Key: "k", RemoteIP: "203.0.113.9", RemotePort: 443, Proto: "tcp", Direction: "out", State: "ESTABLISHED"}}, nil
}

// An open connection that doesn't change is sent again every Refresh, so the
// server's last_seen keeps up with it; between refreshes it isn't.
func TestRunnerRefreshes(t *testing.T) {
	var mu sync.Mutex
	var hello Hello
	var batches []Batch
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/agent/hello":
			_ = json.NewDecoder(r.Body).Decode(&hello)
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/agent/policy":
			_, _ = w.Write([]byte(`{}`))
		case "/api/v1/agent/events":
			var b Batch
			_ = json.NewDecoder(r.Body).Decode(&b)
			batches = append(batches, b)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sc := &countScanner{}
	r := &Runner{Client: &Client{Base: srv.URL, Agent: "laptop", Boot: "b"}, Scanner: sc,
		Interval: 20 * time.Millisecond, Refresh: 200 * time.Millisecond, Hello: Hello{Host: "laptop", Version: "v1"}}
	_ = r.Run(ctx)
	mu.Lock()
	defer mu.Unlock()
	if hello.OS != runtime.GOOS || hello.Arch != runtime.GOARCH || hello.Host != "laptop" || hello.Version != "v1" || !slices.Contains(hello.Capabilities, "test-scanner") {
		t.Fatalf("hello = %+v", hello)
	}
	with := 0
	for _, b := range batches {
		if len(b.Connections) > 0 {
			with++
		}
	}
	// The first batch, then roughly one per refresh: not one every scan.
	if sc.n < 20 || with < 2 || with > sc.n/4 {
		t.Fatalf("%d scans, %d batches, %d with connections", sc.n, len(batches), with)
	}
}
