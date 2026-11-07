// Package agenttest checks a platform scanner against the real system: it
// opens a TCP connection in this process and expects the scanner to report
// it, with this process as its owner. Each scanner's _test file calls it on
// its own platform, where CI runs it (Linux, macOS and Windows runners).
package agenttest

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/agent"
)

// Live dials a listener of its own and scans until both ends show up.
func Live(t *testing.T, s agent.Scanner) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(30 * time.Second)
		}
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	port := c.LocalAddr().(*net.TCPAddr).Port
	srvPort := ln.Addr().(*net.TCPAddr).Port
	exe, _ := os.Executable()
	want := agent.AppName(exe, "")
	var last []agent.Connection
	for range 20 {
		procs, conns, err := s.Scan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		last = conns
		for _, cn := range conns {
			if cn.LocalPort != port || cn.RemotePort != srvPort || cn.RemoteIP != "127.0.0.1" {
				continue
			}
			if cn.PID != os.Getpid() || !strings.EqualFold(cn.App, want) || cn.Proto != "tcp" || cn.Direction != "local" {
				t.Fatalf("our connection = %+v; want pid %d, app %q", cn, os.Getpid(), want)
			}
			for _, p := range procs {
				if p.PID == os.Getpid() {
					if p.Path == "" || p.SHA256 == "" {
						t.Errorf("our process = %+v", p)
					}
					return
				}
			}
			t.Fatalf("our process is missing from %+v", procs)
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("no connection from port %d to %d among %d: %+v", port, srvPort, len(last), first(last, 20))
}

func first(c []agent.Connection, n int) []agent.Connection {
	return c[:min(n, len(c))]
}
