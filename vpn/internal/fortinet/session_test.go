package fortinet

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/vpn/client"
)

type sessionLog struct {
	mu   sync.Mutex
	seen []client.SessionEvent
}

func (l *sessionLog) hook(ev client.SessionEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = append(l.seen, ev)
}

func (l *sessionLog) events() []client.SessionEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]client.SessionEvent(nil), l.seen...)
}

// A Fortinet session is one user holding one address from login until its
// tunnel ends, with how the login proved them: "password", or
// "password+totp" when a second factor was required and given. If this
// fails, the edge cannot tell a policy that wants a second factor whether
// the user gave one.
func TestAFortinetSessionSaysWhatTheLoginProved(t *testing.T) {
	pool, gateway, err := newTestPool()
	if err != nil {
		t.Fatal(err)
	}
	var hub client.SessionHub
	var log sessionLog
	hub.SetSessionHook(log.hook)
	serverTUN := newFakeTUN()
	srv, err := NewServer(ServerConfig{
		Sessions:    &hub,
		Users:       map[string]string{"alice": "s3cret", "bob": "hunter2"},
		Pool:        pool,
		ServerIP:    gateway,
		TOTPSecrets: map[string]string{"alice": testTOTPSecret},
	}, serverTUN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	go srv.RunTUN()
	ts := httptest.NewTLSServer(srv)
	t.Cleanup(ts.Close)
	newClient := func() *http.Client {
		jar, _ := cookiejar.New(nil)
		return &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test cert
	}

	// bob: password only, then a tunnel that ends.
	cfg, cookie, err := Login(newClient(), ts.URL, "bob", "hunter2", "", nil)
	if err != nil {
		t.Fatalf("bob's login: %v", err)
	}
	evs := log.events()
	if len(evs) != 1 || evs[0].User != "bob" || evs[0].Auth != "password" || !evs[0].Open {
		t.Fatalf("after bob's login: %+v", evs)
	}
	if len(evs[0].Addrs) != 1 || !evs[0].Addrs[0].Addr().Is4() || net.IP(evs[0].Addrs[0].Addr().AsSlice()).String() != cfg.AssignedIP.String() {
		t.Errorf("bob's session addrs %v, want %s/32", evs[0].Addrs, cfg.AssignedIP)
	}
	host := ts.Listener.Addr().String()
	conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test cert
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(TunnelRequest(host, cookie)); err != nil {
		t.Fatal(err)
	}
	c, err := RunClient(conn, cfg, newFakeTUN(), nil)
	if err != nil {
		t.Fatalf("RunClient: %v", err)
	}
	_ = c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for len(log.events()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	evs = log.events()
	if len(evs) != 2 || evs[1].Open || evs[1].ID != evs[0].ID || evs[1].Reason != "disconnected" {
		t.Fatalf("after bob's tunnel ended: %+v, want his session closed", evs)
	}

	// alice: password and a second factor.
	if _, _, err := Login(newClient(), ts.URL, "alice", "s3cret", "", func(Challenge) (string, error) {
		return currentCode(t), nil
	}); err != nil {
		t.Fatalf("alice's login: %v", err)
	}
	evs = log.events()
	if len(evs) != 3 || evs[2].User != "alice" || evs[2].Auth != "password+totp" {
		t.Fatalf("after alice's login: %+v, want her session by password+totp", evs)
	}
}
