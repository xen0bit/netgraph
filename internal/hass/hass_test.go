package hass

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/mqtt"
)

type retainBroker struct {
	l       net.Listener
	mu      sync.Mutex
	topics  map[string]string
	events  []string
	conns   int
	connect []string
	drop    chan struct{}
}

func newBroker(t *testing.T) *retainBroker {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &retainBroker{l: l, topics: map[string]string{}, drop: make(chan struct{}, 4)}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go b.serve(c)
		}
	}()
	return b
}

func (b *retainBroker) serve(c net.Conn) {
	defer c.Close()
	go func() {
		<-b.drop
		c.Close()
	}()
	r := bufio.NewReader(c)
	for {
		typ, flags, body, err := mqtt.ReadPacket(r)
		if err != nil {
			return
		}
		switch typ {
		case 1:
			b.mu.Lock()
			b.conns++
			b.connect = append(b.connect, string(body))
			b.mu.Unlock()
			_, _ = c.Write([]byte{2 << 4, 2, 0, 0})
		case 3:
			n := int(body[0])<<8 | int(body[1])
			topic, msg := string(body[2:2+n]), string(body[2+n:])
			b.mu.Lock()
			if flags&1 == 1 {
				if msg == "" {
					delete(b.topics, topic)
				} else {
					b.topics[topic] = msg
				}
			} else {
				b.events = append(b.events, msg)
			}
			b.mu.Unlock()
		case 12:
			_, _ = c.Write([]byte{13 << 4, 0})
		}
	}
}

func (b *retainBroker) get(topic string) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.topics[topic]
	return v, ok
}

type fakeSource struct {
	mu   sync.Mutex
	devs []model.Device
	err  error
	open int
}

func (s *fakeSource) Devices(context.Context, model.Filter) ([]model.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.devs, s.err
}

func (s *fakeSource) Findings(context.Context, model.FindingQuery) (*model.FindingList, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &model.FindingList{Counts: map[string]int{model.FindingNew: s.open}}, nil
}

func (s *fakeSource) set(d []model.Device) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devs = d
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

const macA, objA = "aa:bb:cc:00:00:01", "aabbcc000001"

func TestDevicesAppearAndLeave(t *testing.T) {
	broker := newBroker(t)
	now := time.UnixMilli(10_000_000_000)
	src := &fakeSource{open: 3, devs: []model.Device{
		{MAC: macA, Label: `Alice's "phone"`, Owner: "Alice", UserLabel: true, ActiveTo: now.UnixMilli() - 1000, Vendor: "Apple"},
		{MAC: "aa:bb:cc:00:00:02", Label: "named, asleep", UserLabel: true, ActiveTo: now.Add(-time.Hour).UnixMilli()},
		{MAC: "da:00:00:00:00:03", Label: "private 00:03", ActiveTo: now.UnixMilli()},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	br := New(Config{Options: mqtt.Options{Addr: broker.l.Addr().String()}, Every: 10 * time.Millisecond, Now: func() time.Time { return now }}, src)
	go br.Run(ctx)
	cfgTopic := discoveryTopic("device_tracker", objA)
	waitFor(t, "discovery", func() bool { _, ok := broker.get(cfgTopic); return ok })
	raw, _ := broker.get(cfgTopic)
	var cfg struct {
		UniqueID   string `json:"unique_id"`
		StateTopic string `json:"state_topic"`
		Device     struct {
			Name        string     `json:"name"`
			Connections [][]string `json:"connections"`
		} `json:"device"`
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	if cfg.UniqueID != "netgraph_"+objA || cfg.Device.Name != `Alice's "phone"` || cfg.Device.Connections[0][1] != macA || cfg.StateTopic != "netgraph/device/"+objA+"/state" {
		t.Errorf("config: %+v", cfg)
	}
	waitFor(t, "states", func() bool {
		a, _ := broker.get("netgraph/device/" + objA + "/state")
		b, _ := broker.get("netgraph/device/aabbcc000002/state")
		return a == "home" && b == "not_home"
	})
	// A device nobody named stays private by default.
	if _, ok := broker.get(discoveryTopic("device_tracker", "da0000000003")); ok {
		t.Error("an unnamed device was published")
	}
	waitFor(t, "the count", func() bool { v, _ := broker.get("netgraph/findings/state"); return v == "3" })
	if v, _ := broker.get("netgraph/status"); v != "online" {
		t.Errorf("status %q", v)
	}
	if _, ok := broker.get(discoveryTopic("sensor", "open_findings")); !ok {
		t.Error("no findings sensor")
	}
	// db forget, or no longer named: retained messages are taken back.
	src.set(src.devs[1:])
	waitFor(t, "it to leave", func() bool {
		_, a := broker.get(cfgTopic)
		_, b := broker.get("netgraph/device/" + objA + "/state")
		return !a && !b
	})
	br.Finding(FindingEventNew, model.Finding{Anomaly: model.Anomaly{Kind: "scan", Severity: "high", Summary: "x"}})
	waitFor(t, "the event", func() bool {
		broker.mu.Lock()
		defer broker.mu.Unlock()
		return len(broker.events) == 1 && strings.Contains(broker.events[0], `"event_type":"new"`)
	})
}

func TestReconnects(t *testing.T) {
	broker := newBroker(t)
	src := &fakeSource{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	br := New(Config{Options: mqtt.Options{Addr: broker.l.Addr().String()}, Every: time.Hour}, src)
	go br.Run(ctx)
	waitFor(t, "connected", func() bool { _, ok := broker.get("netgraph/status"); return ok })
	broker.drop <- struct{}{}
	waitFor(t, "reconnected", func() bool {
		broker.mu.Lock()
		defer broker.mu.Unlock()
		return broker.conns >= 2
	})
}

// A store error isn't the broker's fault, and mustn't end the connection or take
// devices back.
func TestReadErrorKeepsWhatItPublished(t *testing.T) {
	broker := newBroker(t)
	now := time.Now()
	src := &fakeSource{devs: []model.Device{{MAC: macA, Label: "a", UserLabel: true}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	br := New(Config{Options: mqtt.Options{Addr: broker.l.Addr().String()}, Every: 5 * time.Millisecond, Now: func() time.Time { return now }}, src)
	go br.Run(ctx)
	waitFor(t, "discovery", func() bool { _, ok := broker.get(discoveryTopic("device_tracker", objA)); return ok })
	src.mu.Lock()
	src.err = errors.New("database busy")
	src.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	if _, ok := broker.get(discoveryTopic("device_tracker", objA)); !ok {
		t.Error("an error took the device back")
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if broker.conns != 1 {
		t.Errorf("%d connections", broker.conns)
	}
}

func TestParseURL(t *testing.T) {
	c, err := ParseURL("mqtts://u:p%40ss@broker.lan/home/net?devices=all")
	if err != nil {
		t.Fatal(err)
	}
	if c.Options.Addr != "broker.lan:8883" || c.Options.Username != "u" || c.Options.Password != "p@ss" || c.Prefix != "home/net" || !c.AllDevs || c.Options.TLS == nil {
		t.Errorf("%+v", c)
	}
	if c, err = ParseURL("mqtt://[::1]:1884"); err != nil || c.Options.Addr != "[::1]:1884" || c.Options.TLS != nil || c.Prefix != "" {
		t.Errorf("%+v, %v", c, err)
	}
	for _, bad := range []string{"http://x", "mqtt://", "mqtt://h/a+b", "mqtt://h?devices=some", "mqtt://u:se cret@h:bad"} {
		if _, err := ParseURL(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		} else if strings.Contains(err.Error(), "cret") {
			t.Errorf("the error repeats the password: %v", err)
		}
	}
}
