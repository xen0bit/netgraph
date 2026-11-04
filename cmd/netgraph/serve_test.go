package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/alert"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/store"
)

// A scan's news reaches the alert channels, severity floor and all.
func TestFindingsReachAlerts(t *testing.T) {
	got := make(chan alert.Payload, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var p alert.Payload
		_ = json.Unmarshal(b, &p)
		got <- p
	}))
	defer srv.Close()
	n := alert.New(alert.Config{URL: srv.URL, AnomalyMin: model.SeverityMedium, Logger: slog.New(slog.DiscardHandler)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	finding := func(sev, summary string) store.FindingEvent {
		return store.FindingEvent{Type: store.FindingNew, Finding: model.Finding{Anomaly: model.Anomaly{Kind: model.AnomalyScan, Severity: sev, Summary: summary, Entity: summary}}}
	}
	announceFindings([]store.FindingEvent{finding(model.SeverityLow, "too small"), finding(model.SeverityHigh, "loud")}, n, nil)
	select {
	case p := <-got:
		if !strings.Contains(p.Text, "loud") {
			t.Errorf("got %q", p.Text)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no alert")
	}
	select {
	case p := <-got:
		t.Errorf("under the floor: %q", p.Text)
	case <-time.After(50 * time.Millisecond):
	}
	// Nobody listening is fine.
	announceFindings([]store.FindingEvent{finding(model.SeverityHigh, "x")}, nil, nil)
}

func TestReadChannels(t *testing.T) {
	file := filepath.Join(t.TempDir(), "channels")
	body := "# my phone\nntfy://ntfy.sh/alerts?token=SECRET\n\ntelegram://1:SECRET@2?min=high\n"
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	routes, err := readChannels(file)
	if err != nil || len(routes) != 2 || routes[1].Min != model.SeverityHigh {
		t.Fatalf("%+v, %v", routes, err)
	}
	// A bad line is named by number, and its token isn't repeated.
	if err := os.WriteFile(file, []byte("https://ok.example/\nbad://SECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = readChannels(file)
	if err == nil || !strings.Contains(err.Error(), "line 2") || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("got %v", err)
	}
	if routes, err := readChannels(""); err != nil || len(routes) != 0 {
		t.Errorf("none set: %v, %v", routes, err)
	}
}

func TestReadBridge(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	if c, err := readBridge("", log); err != nil || c != nil {
		t.Errorf("none set: %+v, %v", c, err)
	}
	t.Setenv("NETGRAPH_MQTT", "mqtt://u:p@broker.lan/home")
	c, err := readBridge("", log)
	if err != nil || c.Prefix != "home" || c.Options.Password != "p" {
		t.Errorf("%+v, %v", c, err)
	}
	t.Setenv("NETGRAPH_MQTT", "ftp://u:SECRET@h")
	if _, err := readBridge("", log); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("got %v", err)
	}
}
