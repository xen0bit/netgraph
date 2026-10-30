package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/store"
)

type receiver struct {
	mu    sync.Mutex
	fails int // respond 500 this many times first
	got   []Payload
	done  chan struct{}
}

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fails > 0 {
		r.fails--
		http.Error(w, "busy", http.StatusInternalServerError)
		return
	}
	var p Payload
	if req.Header.Get("Content-Type") != "application/json" || json.NewDecoder(req.Body).Decode(&p) != nil {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	r.got = append(r.got, p)
	r.done <- struct{}{}
}

func start(t *testing.T, r *receiver, learn time.Duration, since time.Time) *Notifier {
	t.Helper()
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	n := New(Config{URL: srv.URL, Learn: learn, Since: func(context.Context) (time.Time, error) { return since, nil }})
	n.backoff = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go n.Run(ctx)
	return n
}

func device(label string, ts time.Time) store.NewDevice {
	return store.NewDevice{ID: "device:3c:22:fb:01:02:03", MAC: "3c:22:fb:01:02:03", Label: label, Vendor: "Apple, Inc.",
		IP: netip.MustParseAddr("192.168.1.23"), Sensor: "router", TS: ts}
}

func TestDeliverAndRetry(t *testing.T) {
	r := &receiver{fails: 2, done: make(chan struct{}, 4)}
	n := start(t, r, 0, time.Time{})
	n.Notify(device("alice-iphone", time.Now()))
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatal("no alert delivered")
	}
	p := r.got[0]
	want := "New device on the network: alice-iphone (192.168.1.23, 3c:22:fb:01:02:03, Apple, Inc.)"
	if p.Event != "new_device" || p.Text != want || p.Content != want || p.Device.MAC != "3c:22:fb:01:02:03" {
		t.Fatalf("payload = %+v", p)
	}
}

func TestAnomalyAlertAndCooldown(t *testing.T) {
	r := &receiver{done: make(chan struct{}, 4)}
	srv := httptest.NewServer(r)
	defer srv.Close()
	n := New(Config{URL: srv.URL, AnomalyMin: model.SeverityMedium, AnomalyCooldown: time.Hour})
	n.backoff = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	a := model.Anomaly{Kind: model.AnomalyScan, Severity: model.SeverityMedium, Device: "device:aa", Summary: "scan"}
	n.NotifyAnomaly(a)
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatal("anomaly alert not delivered")
	}
	n.NotifyAnomaly(a)
	select {
	case <-r.done:
		t.Fatal("duplicate anomaly delivered during cooldown")
	case <-time.After(50 * time.Millisecond):
	}
	r.mu.Lock()
	p := r.got[0]
	r.mu.Unlock()
	if p.Event != "anomaly" || p.Anomaly == nil || p.Device != nil {
		t.Fatalf("payload = %+v", p)
	}
}

// A name from the LAN cannot ping a channel or inject chat markup.
func TestPayloadIsInert(t *testing.T) {
	p := NewPayload(device("<!channel> @everyone\nhi", time.Now()))
	if strings.ContainsAny(p.Text, "<>\n") || strings.Contains(p.Text, "@everyone") {
		t.Fatalf("text = %q", p.Text)
	}
	b, _ := json.Marshal(p)
	if !strings.Contains(string(b), `"allowed_mentions":{"parse":[]}`) {
		t.Fatalf("payload = %s", b)
	}
	if long := NewPayload(device(strings.Repeat("x", 500), time.Now())); len(long.Text) > 200 {
		t.Fatalf("long label not bounded: %d", len(long.Text))
	}
}

// During the learning period nothing is sent; afterwards it is.
func TestLearningPeriod(t *testing.T) {
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	r := &receiver{done: make(chan struct{}, 4)}
	n := start(t, r, 24*time.Hour, since)
	n.Notify(device("early", since.Add(time.Hour)))
	n.Notify(device("late", since.Add(25*time.Hour)))
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatal("no alert after the learning period")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.got) != 1 || r.got[0].Device.Label != "late" {
		t.Fatalf("got %+v", r.got)
	}
}
