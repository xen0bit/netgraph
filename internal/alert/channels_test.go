package alert

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

type seen struct {
	mu     sync.Mutex
	reqs   []*http.Request
	bodies []map[string]any
	status int
}

func (s *seen) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	s.mu.Lock()
	s.reqs = append(s.reqs, r)
	s.bodies = append(s.bodies, m)
	st := s.status
	s.mu.Unlock()
	if st != 0 {
		w.WriteHeader(st)
	}
}

func channelServer(t *testing.T) (*seen, string) {
	t.Helper()
	s := &seen{}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return s, strings.TrimPrefix(srv.URL, "http://")
}

func anomalyOf(sev string) Payload {
	return NewAnomalyPayload(model.Anomaly{Kind: model.AnomalyScan, Severity: sev, Summary: "a <b>scan</b>"})
}

func TestChannelsSpeakTheirProtocols(t *testing.T) {
	ctx := context.Background()
	s, host := channelServer(t)

	r, err := ParseChannel("ntfy+http://"+host+"/alerts?token=tok&min=high&quiet=22:00-07:00&kinds=scan,beacon", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Min != model.SeverityHigh || r.Quiet == nil || len(r.Kinds) != 2 {
		t.Errorf("route %+v", r)
	}
	if err := r.Send(ctx, anomalyOf(model.SeverityHigh)); err != nil {
		t.Fatal(err)
	}
	b := s.bodies[0]
	if b["topic"] != "alerts" || b["priority"] != float64(4) || b["title"] != "netgraph: scan" || s.reqs[0].Header.Get("Authorization") != "Bearer tok" {
		t.Errorf("ntfy: %v, %v", b, s.reqs[0].Header)
	}

	r, err = ParseChannel("gotify+http://"+host+"/?token=apptok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Send(ctx, anomalyOf(model.SeverityLow)); err != nil {
		t.Fatal(err)
	}
	if s.reqs[1].URL.Path != "/message" || s.reqs[1].Header.Get("X-Gotify-Key") != "apptok" || s.bodies[1]["priority"] != float64(2) {
		t.Errorf("gotify: %s %v %v", s.reqs[1].URL, s.reqs[1].Header, s.bodies[1])
	}

	r, err = ParseChannel("telegram://123:SECRET@-100200", nil)
	if err != nil {
		t.Fatal(err)
	}
	tg := r.Channel.(*telegramChannel)
	if tg.token != "123:SECRET" || tg.chat != "-100200" {
		t.Errorf("telegram %+v", tg)
	}
	tg.base = "http://" + host
	if err := r.Send(ctx, anomalyOf(model.SeverityMedium)); err != nil {
		t.Fatal(err)
	}
	if s.reqs[2].URL.Path != "/bot123:SECRET/sendMessage" || s.bodies[2]["chat_id"] != "-100200" || s.bodies[2]["parse_mode"] != nil {
		t.Errorf("telegram: %s %v", s.reqs[2].URL, s.bodies[2])
	}
}

// Secrets stay out of names, parse errors and delivery errors: all of those reach logs.
func TestSecretsStayOutOfWhatIsLogged(t *testing.T) {
	for _, raw := range []string{"telegram://123:SECRET@42", "ntfy://h/t?token=SECRET", "gotify://h/?token=SECRET", "smtp://u:SECRET@h:25/?from=a@b.c&to=d@e.f", "https://h/SECRET"} {
		r, err := ParseChannel(raw, nil)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if strings.Contains(r.Name(), "SECRET") {
			t.Errorf("the name %q holds a secret", r.Name())
		}
	}
	for _, raw := range []string{"telegram://SECRET@h", "ht!tp://SECRET", "smtp://u:SECRET@h", "bad://SECRET", "ntfy://SECRET", "http://h:SECRET/"} {
		if _, err := ParseChannel(raw, nil); err == nil {
			t.Errorf("%s was accepted", raw)
		} else if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("the error repeats the secret: %v", err)
		}
	}
	// A connection failure's error quotes the URL, and Telegram's holds the token.
	r, err := ParseChannel("telegram://123:SECRET@42", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Channel.(*telegramChannel).base = "http://127.0.0.1:1"
	err = r.Send(context.Background(), anomalyOf(model.SeverityHigh))
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("delivery error: %v", err)
	}
}

func TestParseChannelRejects(t *testing.T) {
	for _, bad := range []string{"", "nothing", "ntfy://host", "ntfy://host/a/b", "gotify://host", "telegram://host", "smtp://h:25", "smtp://h:25/?from=a@b.c", "https://h/?min=urgent", "https://h/?quiet=noon", "https://h/?quiet=10:00-10:00"} {
		if _, err := ParseChannel(bad, nil); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestQuietOverMidnight(t *testing.T) {
	q, err := parseQuiet("22:00-07:00")
	if err != nil {
		t.Fatal(err)
	}
	at := func(h int) time.Time { return time.Date(2026, 1, 1, h, 0, 0, 0, time.UTC) }
	for h, want := range map[int]bool{21: false, 22: true, 23: true, 0: true, 6: true, 7: false, 12: false} {
		if q.In(at(h)) != want {
			t.Errorf("hour %d: %v", h, !want)
		}
	}
	day, _ := parseQuiet("09:00-17:00")
	if !day.In(at(12)) || day.In(at(18)) || q.String() != "22:00-07:00" {
		t.Errorf("day %v, string %s", day, q)
	}
}

type memChannel struct {
	mu   sync.Mutex
	got  []Payload
	fail bool
	name string
}

func (c *memChannel) Name() string { return c.name }
func (c *memChannel) Send(_ context.Context, p Payload) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return errPermanent
	}
	c.got = append(c.got, p)
	return nil
}
func (c *memChannel) texts() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, p := range c.got {
		out = append(out, p.Text)
	}
	return out
}

func waitChan(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out: %s", what)
}

// Each channel takes what it asked for, and one that's down holds up nothing.
func TestRoutesFilterAndDontBlockEachOther(t *testing.T) {
	all, high, dead := &memChannel{name: "all"}, &memChannel{name: "high"}, &memChannel{name: "dead", fail: true}
	scans := &memChannel{name: "scans"}
	n := New(Config{Routes: []Route{{Channel: dead}, {Channel: all}, {Channel: high, Min: model.SeverityHigh}, {Channel: scans, Kinds: []string{model.AnomalyScan}}}, AnomalyMin: model.SeverityLow, Logger: slog.New(slog.DiscardHandler)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	n.NotifyAnomaly(model.Anomaly{Kind: model.AnomalyBeacon, Severity: model.SeverityMedium, Summary: "beacon"})
	n.NotifyAnomaly(model.Anomaly{Kind: model.AnomalyScan, Severity: model.SeverityHigh, Summary: "scan"})
	waitChan(t, "delivery", func() bool { return len(all.texts()) == 2 && len(high.texts()) == 1 && len(scans.texts()) == 1 })
	if !strings.Contains(high.texts()[0], "scan") || !strings.Contains(scans.texts()[0], "scan") {
		t.Errorf("high %v, scans %v", high.texts(), scans.texts())
	}
	if s := n.Stats(); s.Failed != 2 {
		t.Errorf("stats %+v", s)
	}
	if got := n.Channels(); len(got) != 4 || got[2].Min != model.SeverityHigh {
		t.Errorf("channels %+v", got)
	}
	if err := n.Test(ctx, "high"); err != nil {
		t.Fatal(err)
	}
	waitChan(t, "the test message", func() bool { return len(high.texts()) == 2 })
	if err := n.Test(ctx, "nobody"); err != ErrNoChannel {
		t.Errorf("unknown channel: %v", err)
	}
}

// Quiet hours hold back all but high severity, then deliver one summary.
func TestQuietHoursHoldThenSummarise(t *testing.T) {
	c := &memChannel{name: "c"}
	q, _ := parseQuiet("22:00-07:00")
	n := New(Config{Routes: []Route{{Channel: c, Quiet: q}}, AnomalyMin: model.SeverityLow, Logger: slog.New(slog.DiscardHandler)})
	var mu sync.Mutex
	now := time.Date(2026, 1, 1, 23, 0, 0, 0, time.UTC)
	n.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	n.NotifyAnomaly(model.Anomaly{Kind: model.AnomalyBeacon, Severity: model.SeverityMedium, Summary: "beacon one"})
	n.NotifyAnomaly(model.Anomaly{Kind: model.AnomalyDNSFailures, Severity: model.SeverityLow, Summary: "dns two"})
	n.NotifyAnomaly(model.Anomaly{Kind: model.AnomalyScan, Severity: model.SeverityHigh, Summary: "wake me"})
	waitChan(t, "high severity through", func() bool { return len(c.texts()) == 1 })
	if !strings.Contains(c.texts()[0], "wake me") {
		t.Errorf("got %v", c.texts())
	}
	mu.Lock()
	now = time.Date(2026, 1, 2, 8, 0, 0, 0, time.UTC)
	mu.Unlock()
	n.routes[0].in <- work{p: NewReportPayload("morning report")}
	waitChan(t, "the summary", func() bool { return len(c.texts()) == 3 })
	got := c.texts()
	if !strings.Contains(got[1], "2 alerts during quiet hours") || !strings.Contains(got[1], "beacon one") || !strings.Contains(got[1], "dns two") || got[2] != "morning report" {
		t.Errorf("got %q", got)
	}
}

func TestHeldDigestCounts(t *testing.T) {
	d := heldDigest([]Payload{{Text: "x"}}, 3)
	if !strings.Contains(d.Text, "4 alerts") || !strings.Contains(d.Text, "and 3 more") {
		t.Errorf("%q", d.Text)
	}
}

// fakeSMTP speaks just enough, and returns what it was told.
func fakeSMTP(t *testing.T, auth bool) (string, <-chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	out := make(chan string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		w := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
		w("220 test")
		var msg strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				out <- msg.String()
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					w("250 queued")
					continue
				}
				msg.WriteString(line)
				continue
			}
			u := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(u, "EHLO"):
				if auth {
					w("250-test")
					w("250 AUTH PLAIN")
				} else {
					w("250 test")
				}
			case strings.HasPrefix(u, "DATA"):
				w("354 go")
				inData = true
			case strings.HasPrefix(u, "QUIT"):
				w("221 bye")
				out <- msg.String()
				return
			case strings.HasPrefix(u, "AUTH"):
				msg.WriteString("AUTHED\r\n")
				w("235 ok")
			default:
				w("250 ok")
			}
		}
	}()
	return l.Addr().String(), out
}

func TestEmail(t *testing.T) {
	addr, got := fakeSMTP(t, true)
	r, err := ParseChannel("smtp://me:pw@"+addr+"/?from=net@example.com&to=a@example.com,b@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	// A name off the network tries to add a header and end the message early.
	p := NewAnomalyPayload(model.Anomaly{Kind: "x\r\nBcc: evil@example.com", Severity: model.SeverityHigh, Summary: "line\n.\nafter"})
	if err := r.Send(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	msg := <-got
	if !strings.Contains(msg, "AUTHED") || !strings.Contains(msg, "To: a@example.com, b@example.com") || !strings.Contains(msg, "after") {
		t.Errorf("message: %q", msg)
	}
	if strings.Contains(msg, "\r\nBcc:") {
		t.Errorf("a header was injected: %q", msg)
	}
}

// With no TLS on offer, a password isn't sent to anywhere but this machine.
func TestEmailWontSendAPasswordInTheClear(t *testing.T) {
	for _, c := range []struct {
		secure bool
		host   string
		want   bool
	}{{false, "mail.example.com", false}, {false, "192.168.1.9", false}, {true, "mail.example.com", true}, {false, "localhost", true}, {false, "127.0.0.1", true}} {
		if got := mayAuthenticate(c.secure, c.host); got != c.want {
			t.Errorf("secure %v, %s: %v", c.secure, c.host, got)
		}
	}
}
