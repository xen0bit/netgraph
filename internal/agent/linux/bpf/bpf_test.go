//go:build linux

package bpf

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

func FuzzParse(f *testing.F) {
	f.Add(make([]byte, eventSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		if e, ok := Parse(b); ok && (!e.Src.IsValid() || e.PID <= 0) {
			t.Fatalf("accepted %+v", e)
		}
	})
}

func TestParse(t *testing.T) {
	b := make([]byte, eventSize)
	ne := binary.NativeEndian
	ne.PutUint64(b[0:], 123e7)
	ne.PutUint64(b[8:], 999)
	ne.PutUint32(b[16:], 42)
	ne.PutUint32(b[20:], 1)
	ne.PutUint16(b[28:], 2)
	b[30], b[31] = 1, KindSend
	ne.PutUint16(b[32:], 6354)
	copy(b[36:], []byte{10, 0, 0, 2})
	copy(b[52:], []byte{9, 9, 9, 9})
	copy(b[68:], "ping")
	e, ok := Parse(b)
	if !ok || e.PID != 42 || e.Proto != 1 || e.SPort != 6354 || e.Src != netip.MustParseAddr("10.0.0.2") ||
		e.Dst != netip.MustParseAddr("9.9.9.9") || e.Comm != "ping" || e.Ino != 999 {
		t.Fatalf("event = %+v (%v)", e, ok)
	}
	if _, ok := Parse(b[:eventSize-1]); ok {
		t.Fatal("short record accepted")
	}
}

// TestLive loads the programs into the running kernel; it needs CAP_BPF and
// CAP_PERFMON, so it runs only with NETGRAPH_BPF_TEST=1 (make bpf-test runs
// it in a privileged container).
func TestLive(t *testing.T) {
	if os.Getenv("NETGRAPH_BPF_TEST") != "1" {
		t.Skip("set NETGRAPH_BPF_TEST=1, with CAP_BPF and CAP_PERFMON")
	}
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/net", &st); err != nil {
		t.Fatal(err)
	}
	r, err := Open(uint32(st.Ino))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if m := r.Missing(); len(m) > 0 {
		t.Fatalf("missing hooks: %v", m)
	}
	got := make(chan Event, 1024)
	go func() {
		for {
			e, err := r.Read()
			if err != nil {
				close(got)
				return
			}
			got <- e
		}
	}()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cport := uint16(c.LocalAddr().(*net.TCPAddr).Port)
	lport := uint16(ln.Addr().(*net.TCPAddr).Port)
	c.Close()
	u, err := net.Dial("udp6", "[::1]:9")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = u.Write([]byte("x"))
	uport := uint16(u.LocalAddr().(*net.UDPAddr).Port)
	u.Close()
	// A ping socket, as unprivileged ping uses (ping_group_range allows it
	// in a container); its echo identifier is the kernel's choice.
	ping, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Close(ping) }()
	echo := []byte{8, 0, 0, 0, 0, 0, 0, 1, 'x'}
	if err := syscall.Sendto(ping, echo, 0, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	sa, _ := syscall.Getsockname(ping)
	ident := uint16(sa.(*syscall.SockaddrInet4).Port)

	want := map[string]bool{"connect": false, "accept": false, "udp": false, "ping": false}
	deadline := time.After(5 * time.Second)
	for {
		done := true
		for _, ok := range want {
			done = done && ok
		}
		if done {
			return
		}
		select {
		case e, ok := <-got:
			if !ok {
				t.Fatal("reader closed")
			}
			if os.Getenv("NETGRAPH_BPF_DEBUG") == "1" {
				t.Logf("%+v", e)
			}
			if e.PID != os.Getpid() {
				continue
			}
			switch {
			case e.Kind == KindConnect && e.SPort == cport && e.DPort == lport && e.Ino != 0:
				want["connect"] = true
			case e.Kind == KindAccept && e.SPort == lport && e.DPort == cport:
				want["accept"] = true
			case e.Kind == KindSend && e.Proto == 17 && e.Family == 10 && e.SPort == uport && e.DPort == 9 && e.Dst == netip.MustParseAddr("::1"):
				want["udp"] = true
			// Unbound: the route picks the source; the agent asks it.
			case e.Kind == KindSend && e.Proto == 1 && e.SPort == ident && e.Src.IsUnspecified() && e.Dst == netip.MustParseAddr("127.0.0.1"):
				want["ping"] = true
			}
			if e.Start == 0 || e.PPID == 0 || e.Comm == "" {
				t.Fatalf("event without its process: %+v", e)
			}
		case <-deadline:
			t.Fatalf("events seen: %v", want)
		}
	}
}
