package dnsserver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/xen0bit/netgraph/internal/decode"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy/blocklist"
	"github.com/xen0bit/netgraph/internal/wire"
)

// fakeUpstream answers A queries with 203.0.113.<n> (TTL 300), follows a
// CNAME table first, and counts what it was asked.
type fakeUpstream struct {
	name   string
	cnames map[string]string
	big    bool // answer with enough records to need TCP
	fail   bool
	asked  atomic.Int32
}

func (f *fakeUpstream) Name() string { return f.name }

func (f *fakeUpstream) Exchange(_ context.Context, q []byte) ([]byte, error) {
	f.asked.Add(1)
	if f.fail {
		return nil, errors.New("down")
	}
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil, err
	}
	qq, err := p.Question()
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
	_ = b.StartQuestions()
	_ = b.Question(qq)
	_ = b.StartAnswers()
	name := qq.Name
	if t, ok := f.cnames[strings.TrimSuffix(name.String(), ".")]; ok {
		target := dnsmessage.MustNewName(t + ".")
		_ = b.CNAMEResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 300}, dnsmessage.CNAMEResource{CNAME: target})
		name = target
	}
	if qq.Type == dnsmessage.TypeA {
		n := 1
		if f.big {
			n = 120
		}
		for i := range n {
			_ = b.AResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 300}, dnsmessage.AResource{A: [4]byte{203, 0, 113, byte(i + 1)}})
		}
	}
	return b.Finish()
}

func query(t testing.TB, id uint16, name string, typ dnsmessage.Type, edns bool) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	if edns {
		_ = b.StartAdditionals()
		var rh dnsmessage.ResourceHeader
		_ = rh.SetEDNS0(1232, dnsmessage.RCodeSuccess, false)
		_ = b.OPTResource(rh, dnsmessage.OPTResource{})
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func parse(t testing.TB, b []byte) *decode.DNSMsg {
	t.Helper()
	m, err := decode.ParseDNS(b)
	if err != nil {
		t.Fatalf("answer doesn't parse: %v", err)
	}
	return m
}

var (
	lan    = netip.MustParseAddr("192.168.1.20")
	kid    = netip.MustParseAddr("192.168.1.30")
	here   = netip.MustParseAddr("192.168.1.1")
	public = netip.MustParseAddr("198.51.100.7")
)

type recorded struct {
	mu  sync.Mutex
	evs []wire.Event
}

func (r *recorded) add(_ context.Context, evs []wire.Event) {
	r.mu.Lock()
	r.evs = append(r.evs, evs...)
	r.mu.Unlock()
}

func newTestServer(t *testing.T, mode string, ups ...Upstream) (*Server, *recorded) {
	t.Helper()
	rec := &recorded{}
	s, err := New(Config{Listen: "127.0.0.1:0", Upstreams: ups, BlockMode: mode, Record: rec.add,
		Client: func(a netip.Addr) Client {
			switch a {
			case lan:
				return Client{MAC: "02:00:00:00:00:20"}
			case kid:
				return Client{MAC: "02:00:00:00:00:30", Groups: []string{"kids"}}
			}
			return Client{}
		}})
	if err != nil {
		t.Fatal(err)
	}
	s.SetRules(BuildRules(
		[]List{{Name: "ads", Entries: []blocklist.Entry{{Kind: "domain", Value: "ads.example"}, {Kind: "except", Value: "ok.ads.example"}}}},
		[]model.DNSRule{
			{ID: 1, Scope: model.DNSScopeAll, Action: model.DNSBlock, Pattern: "tracker.example"},
			{ID: 2, Scope: model.DNSScopeDevice, ScopeValue: "02:00:00:00:00:20", Action: model.DNSAllow, Pattern: "tracker.example"},
			{ID: 3, Scope: model.DNSScopeGroup, ScopeValue: "kids", Action: model.DNSBlock, Pattern: "games.example"},
			{ID: 4, Scope: model.DNSScopeDevice, ScopeValue: "02:00:00:00:00:99", Action: model.DNSAllow, Pattern: "*"},
		}), nil)
	return s, rec
}

func TestHandleBlocksAndAnswers(t *testing.T) {
	up := &fakeUpstream{name: "fake", cnames: map[string]string{"cloaked.example": "x.ads.example"}}
	s, rec := newTestServer(t, "", up)
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		client netip.Addr
		typ    dnsmessage.Type
		block  string // "" answered, else what blocked it
	}{
		{"www.example.", lan, dnsmessage.TypeA, ""},
		{"x.ads.example.", lan, dnsmessage.TypeA, "list:ads"},
		{"ADS.Example.", lan, dnsmessage.TypeAAAA, "list:ads"}, // case doesn't matter
		{"ok.ads.example.", lan, dnsmessage.TypeA, ""},         // the list's own exception
		{"tracker.example.", kid, dnsmessage.TypeA, "rule:1"},
		{"tracker.example.", lan, dnsmessage.TypeA, ""}, // this device is allowed it
		{"games.example.", kid, dnsmessage.TypeA, "rule:3"},
		{"games.example.", lan, dnsmessage.TypeA, ""},
		{"cloaked.example.", lan, dnsmessage.TypeA, "list:ads"}, // a CNAME to a blocked name
	} {
		out := s.Handle(ctx, query(t, 7, tc.name, tc.typ, false), tc.client, here, "udp")
		m := parse(t, out)
		if m.ID != 7 || !m.Response || len(m.Questions) != 1 {
			t.Fatalf("%s: bad answer %+v", tc.name, m)
		}
		var addr string
		for _, a := range m.Answers {
			if a.Addr.IsValid() {
				addr = a.Addr.String()
			}
		}
		switch {
		case tc.block != "" && tc.typ == dnsmessage.TypeA && addr != "0.0.0.0":
			t.Errorf("%s from %s: answered %q, want 0.0.0.0", tc.name, tc.client, addr)
		case tc.block != "" && tc.typ == dnsmessage.TypeAAAA && addr != "::":
			t.Errorf("%s: answered %q, want ::", tc.name, addr)
		case tc.block == "" && !strings.HasPrefix(addr, "203.0.113."):
			t.Errorf("%s from %s: answered %q, want the upstream's", tc.name, tc.client, addr)
		}
	}
	// Every lookup is recorded, with what blocked it.
	time.Sleep(10 * time.Millisecond)
	ctx2, cancel := context.WithCancel(ctx)
	cancel()
	s.recorder(ctx2) // flushes what's queued
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.evs) != 9 {
		t.Fatalf("recorded %d lookups, want 9", len(rec.evs))
	}
	if d := rec.evs[1].DNS; d.RCode != "BLOCKED" || d.BlockedBy != "list:ads" || d.QName != "x.ads.example" || d.Client != lan {
		t.Errorf("blocked lookup recorded as %+v", d)
	}
	if d := rec.evs[0].DNS; d.RCode != "NOERROR" || len(d.Answers) != 1 || d.Answers[0].Data != "203.0.113.1" || d.QType != "A" {
		t.Errorf("answered lookup recorded as %+v", d)
	}
}

func TestBlockModes(t *testing.T) {
	for mode, want := range map[string]uint8{BlockNXDomain: 3, BlockRefused: 5} {
		s, _ := newTestServer(t, mode, &fakeUpstream{name: "fake"})
		m := parse(t, s.Handle(context.Background(), query(t, 1, "ads.example.", dnsmessage.TypeA, false), lan, here, "udp"))
		if m.RCode != want || len(m.Answers) != 0 {
			t.Errorf("%s: rcode %d with %d answers", mode, m.RCode, len(m.Answers))
		}
	}
	if _, err := New(Config{Upstreams: []Upstream{&fakeUpstream{}}, BlockMode: "drop"}); err == nil {
		t.Error("an unknown block mode was accepted")
	}
}

// Outside the allow-list the answer is REFUSED, and only so many a second: it
// must not be an open resolver, or a reflector.
func TestRefusesStrangers(t *testing.T) {
	up := &fakeUpstream{name: "fake"}
	s, _ := newTestServer(t, "", up)
	answered := 0
	for range 100 {
		out := s.Handle(context.Background(), query(t, 2, "www.example.", dnsmessage.TypeA, false), public, here, "udp")
		if out == nil {
			continue
		}
		answered++
		if m := parse(t, out); m.RCode != 5 || len(m.Answers) != 0 {
			t.Fatalf("a stranger got rcode %d, %d answers", m.RCode, len(m.Answers))
		}
	}
	if up.asked.Load() != 0 {
		t.Error("a stranger's question was forwarded")
	}
	// Garbage from a stranger is refused too (or ignored), never answered
	// with anything that says more.
	s.limiter = limiter{per: refusedPerSecond}
	garbage := []byte{9, 9, 1, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0xff}
	if out := s.Handle(context.Background(), garbage, public, here, "udp"); out != nil {
		if m := parse(t, out); m.RCode != 5 {
			t.Errorf("a stranger's garbage got rcode %d", m.RCode)
		}
	}
	if answered > refusedPerSecond {
		t.Errorf("%d refusals in a burst, want at most %d", answered, refusedPerSecond)
	}
}

func TestCacheAndTruncation(t *testing.T) {
	up := &fakeUpstream{name: "fake"}
	s, _ := newTestServer(t, "", up)
	now := time.Now()
	s.cache.now = func() time.Time { return now }
	ctx := context.Background()
	s.Handle(ctx, query(t, 1, "www.example.", dnsmessage.TypeA, false), lan, here, "udp")
	now = now.Add(100 * time.Second)
	m := parse(t, s.Handle(ctx, query(t, 9, "WWW.example.", dnsmessage.TypeA, false), lan, here, "udp"))
	if up.asked.Load() != 1 {
		t.Errorf("asked upstream %d times, want 1", up.asked.Load())
	}
	if m.ID != 9 || len(m.Answers) != 1 || m.Answers[0].TTL != 200 {
		t.Errorf("cached answer: id %d, %+v", m.ID, m.Answers)
	}
	// Past its TTL, it's asked again.
	now = now.Add(201 * time.Second)
	s.Handle(ctx, query(t, 1, "www.example.", dnsmessage.TypeA, false), lan, here, "udp")
	if up.asked.Load() != 2 {
		t.Errorf("an expired answer was used")
	}

	big := &fakeUpstream{name: "big", big: true}
	s2, _ := newTestServer(t, "", big)
	out := s2.Handle(ctx, query(t, 3, "many.example.", dnsmessage.TypeA, true), lan, here, "udp")
	if m := parse(t, out); !m.Truncated || len(m.Answers) != 0 || len(out) > maxUDP {
		t.Errorf("an answer too big for UDP: truncated %v, %d answers, %d bytes", m.Truncated, len(m.Answers), len(out))
	}
	if m := parse(t, s2.Handle(ctx, query(t, 3, "many.example.", dnsmessage.TypeA, true), lan, here, "tcp")); m.Truncated || len(m.Answers) != 120 {
		t.Errorf("over TCP: truncated %v, %d answers", m.Truncated, len(m.Answers))
	}
}

func TestFailover(t *testing.T) {
	down, up := &fakeUpstream{name: "down", fail: true}, &fakeUpstream{name: "up"}
	s, _ := newTestServer(t, "", down, up)
	ctx := context.Background()
	if m := parse(t, s.Handle(ctx, query(t, 1, "a.example.", dnsmessage.TypeA, false), lan, here, "udp")); m.RCode != 0 || len(m.Answers) != 1 {
		t.Fatalf("failover answer: %+v", m)
	}
	// The failed one is skipped while it's in backoff.
	s.Handle(ctx, query(t, 1, "b.example.", dnsmessage.TypeA, false), lan, here, "udp")
	if down.asked.Load() != 1 || up.asked.Load() != 2 {
		t.Errorf("asked down %d, up %d times", down.asked.Load(), up.asked.Load())
	}
	st := s.Status()
	if st.Upstreams[0].Healthy || !st.Upstreams[1].Healthy || st.Upstreams[1].Answered != 2 {
		t.Errorf("status = %+v", st.Upstreams)
	}
	// With none answering, SERVFAIL.
	up.fail = true
	if m := parse(t, s.Handle(ctx, query(t, 1, "c.example.", dnsmessage.TypeA, false), lan, here, "udp")); m.RCode != 2 {
		t.Errorf("rcode %d with every upstream down, want SERVFAIL", m.RCode)
	}
}

func TestMalformed(t *testing.T) {
	s, _ := newTestServer(t, "", &fakeUpstream{name: "fake"})
	ctx := context.Background()
	if out := s.Handle(ctx, []byte{1, 2, 3}, lan, here, "udp"); out != nil {
		t.Error("answered a runt")
	}
	q := query(t, 5, "a.example.", dnsmessage.TypeA, false)
	q[2] |= 0x80 // a response
	if out := s.Handle(ctx, q, lan, here, "udp"); out != nil {
		t.Error("answered a response")
	}
	bad := append(query(t, 5, "a.example.", dnsmessage.TypeA, false)[:12], 0xc0, 0x0c) // a pointer to itself
	bad[5] = 1
	if m := parse(t, s.Handle(ctx, bad, lan, here, "udp")); m.RCode != 1 {
		t.Errorf("a broken question got rcode %d, want FORMERR", m.RCode)
	}
}

// Over real sockets: UDP and TCP on loopback.
func TestRunServes(t *testing.T) {
	s, _ := newTestServer(t, "", &fakeUpstream{name: "fake"})
	s.idle = 300 * time.Millisecond
	s.cfg.Allow = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	s.cfg.Listen = ":0" // a wildcard: the address a lookup came to is worked out
	rec := &recorded{}
	s.cfg.Record = rec.add
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- s.Run(ctx) }()
	var addrs []string
	for i := 0; i < 200 && len(addrs) < 2; i++ {
		time.Sleep(5 * time.Millisecond)
		addrs = s.Addrs()
	}
	if len(addrs) < 2 {
		t.Fatal("not listening")
	}
	port := func(a string) string { _, p, _ := net.SplitHostPort(a[4:]); return p }
	udp, tcp := "127.0.0.1:"+port(addrs[0]), "127.0.0.1:"+port(addrs[1])
	c, err := net.Dial("udp", udp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(query(t, 11, "ads.example.", dnsmessage.TypeA, false)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if m := parse(t, buf[:n]); m.ID != 11 || len(m.Answers) != 1 || m.Answers[0].Addr.String() != "0.0.0.0" {
		t.Errorf("udp: %+v", m)
	}
	tc, err := net.Dial("tcp", tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	a, err := exchangeStream(tc, query(t, 12, "www.example.", dnsmessage.TypeA, false))
	if err != nil {
		t.Fatal(err)
	}
	if m := parse(t, a); m.ID != 12 || len(m.Answers) != 1 {
		t.Errorf("tcp: %+v", m)
	}
	// A length that lies is the end of the connection, not a hang.
	_, _ = tc.Write([]byte{0, 200, 1, 2})
	_ = tc.SetDeadline(time.Now().Add(s.idle + 2*time.Second))
	if _, err := io.ReadAll(tc); err != nil && !errors.Is(err, io.EOF) {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Error("a short TCP message held the connection open past the idle time")
		}
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // the recorder's last flush
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, ev := range rec.evs {
		if ev.DNS.Server != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("%s over %s recorded as asked of %s", ev.DNS.QName, ev.DNS.Proto, ev.DNS.Server)
		}
	}
	if len(rec.evs) != 2 {
		t.Errorf("recorded %d lookups, want 2", len(rec.evs))
	}
}

func TestParseUpstreams(t *testing.T) {
	ups, err := ParseUpstreams(`# resolvers
1.1.1.1
tls://9.9.9.9#dns.quad9.net   # Quad9 over TLS
https://dns.nextdns.io/abc123secret
tcp://[2606:4700:4700::1111]:53, udp://8.8.8.8:5353
`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, u := range ups {
		names = append(names, u.Name())
	}
	want := "udp://1.1.1.1:53 tls://9.9.9.9:853 https://dns.nextdns.io tcp://[2606:4700:4700::1111]:53 udp://8.8.8.8:5353"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("names = %s\nwant    %s", got, want)
	}
	if ups[1].(*streamUpstream).tls.ServerName != "dns.quad9.net" {
		t.Error("tls server name not read after #")
	}
	for _, bad := range []string{"ftp://x", "tls://", "", "# only a comment"} {
		if _, err := ParseUpstreams(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// DoH speaks RFC 8484, and an error never repeats the URL's path, which can
// hold an account's ID.
func TestDoH(t *testing.T) {
	fake := &fakeUpstream{name: "fake"}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" || r.URL.Path != "/secret-id/dns-query" {
			http.Error(w, "no", http.StatusBadRequest)
			return
		}
		q, _ := io.ReadAll(r.Body)
		if binary.BigEndian.Uint16(q) != 0 {
			http.Error(w, "id not 0", http.StatusBadRequest)
			return
		}
		a, _ := fake.Exchange(r.Context(), q)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(a)
	}))
	defer srv.Close()
	u, err := ParseUpstream(srv.URL + "/secret-id/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	u.(*dohUpstream).client = srv.Client()
	a, err := u.Exchange(context.Background(), query(t, 77, "www.example.", dnsmessage.TypeA, false))
	if err != nil {
		t.Fatal(err)
	}
	if m := parse(t, a); m.ID != 77 || len(m.Answers) != 1 {
		t.Errorf("doh answer %+v", m)
	}
	if strings.Contains(u.Name(), "secret") {
		t.Errorf("name %q shows the path", u.Name())
	}
	srv.Close()
	_, err = u.Exchange(context.Background(), query(t, 1, "www.example.", dnsmessage.TypeA, false))
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("error %v", err)
	}
}

func FuzzHandle(f *testing.F) {
	f.Add(query(f, 1, "www.example.", dnsmessage.TypeA, true), true)
	f.Add(query(f, 2, "ads.example.", dnsmessage.TypeAAAA, false), false)
	f.Add([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1}, true)
	up := &fakeUpstream{name: "fake", cnames: map[string]string{"c.example": "ads.example"}}
	s, err := New(Config{Upstreams: []Upstream{up}})
	if err != nil {
		f.Fatal(err)
	}
	s.SetRules(BuildRules([]List{{Name: "ads", Entries: []blocklist.Entry{{Kind: "domain", Value: "ads.example"}}}}, nil), nil)
	f.Fuzz(func(t *testing.T, b []byte, udp bool) {
		proto := "tcp"
		if udp {
			proto = "udp"
		}
		out := s.Handle(context.Background(), b, lan, here, proto)
		if out == nil {
			return
		}
		if len(out) > maxMessage || udp && len(out) > maxUDP && len(b) <= maxUDP {
			// An upstream's answer is passed on; ours are small.
			if _, err := decode.ParseDNS(out); err != nil {
				t.Fatalf("sent %d bytes that don't parse", len(out))
			}
		}
		if len(b) >= 2 && (out[0] != b[0] || out[1] != b[1]) {
			t.Fatalf("answer ID %x%x, query %x%x", out[0], out[1], b[0], b[1])
		}
	})
}
