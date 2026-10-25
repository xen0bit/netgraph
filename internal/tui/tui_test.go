package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"

	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/sensor"
	"github.com/xen0bit/netgraph/internal/store"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

type sink struct{ events []wire.Event }

func (s *sink) Emit(ev wire.Event) {
	ev.Seq = uint64(len(s.events) + 1)
	s.events = append(s.events, ev)
}

func homeBackend(t *testing.T) *store.Store {
	t.Helper()
	src, err := capture.OpenFile(testutil.Home(t).WriteFile())
	if err != nil {
		t.Fatal(err)
	}
	var out sink
	r := &sensor.Runner{Processor: sensor.NewProcessor(sensor.Config{}, &out), Out: &out}
	if err := r.RunFile(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "ng.db"), store.Config{Now: func() time.Time { return testutil.Base.Add(10 * time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.Ingest(context.Background(), "router", "b", out.events); err != nil {
		t.Fatal(err)
	}
	return st
}

// driver runs a model the way bubbletea would, executing commands inline.
type driver struct {
	t *testing.T
	m Model
}

func (d *driver) run(cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	switch msg := cmd().(type) {
	case nil:
	case tea.BatchMsg:
		for _, c := range msg {
			d.run(c)
		}
	case liveMsg:
		// Do not recurse into the next tick.
		nm, _ := d.m.Update(msg)
		d.m = nm.(Model)
	default:
		nm, next := d.m.Update(msg)
		d.m = nm.(Model)
		d.run(next)
	}
}

func (d *driver) send(msg tea.Msg) {
	nm, cmd := d.m.Update(msg)
	d.m = nm.(Model)
	d.run(cmd)
}

func (d *driver) keys(ks ...string) {
	for _, k := range ks {
		var msg tea.KeyMsg
		switch k {
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		case "tab":
			msg = tea.KeyMsg{Type: tea.KeyTab}
		case "down":
			msg = tea.KeyMsg{Type: tea.KeyDown}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		d.send(msg)
	}
}

func (d *driver) screen() string { return ansi.Strip(d.m.View()) }

func (d *driver) want(subs ...string) {
	d.t.Helper()
	s := d.screen()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			d.t.Fatalf("screen lacks %q:\n%s", sub, s)
		}
	}
}

func newDriver(t *testing.T) *driver {
	r := lipgloss.NewRenderer(os.Stdout)
	r.SetColorProfile(termenv.Ascii)
	now := testutil.Base.Add(10 * time.Minute)
	m := New(Options{
		Backend: homeBackend(t), Source: "test.db", Now: func() time.Time { return now },
		Filter: model.Filter{From: testutil.Base.Add(-time.Minute), To: testutil.Base.Add(5 * time.Minute)}, SaveDir: t.TempDir(),
	}, newStyles(r, false))
	d := &driver{t: t, m: m}
	d.send(tea.WindowSizeMsg{Width: 200, Height: 50})
	d.run(d.m.Init())
	return d
}

func TestTabs(t *testing.T) {
	d := newDriver(t)
	d.want("netgraph", "test.db", "devices", "lookups", "alice-iphone", "busiest devices", "traffic")
	d.keys("2")
	d.want("DEVICE", "alice-iphone", "BRN001BA9", "Office Printer", "desktop-1", "core-switch")
	d.keys("3")
	d.want("www.example.com", "quic.example.org", "plain.example.net", "opened/fin")
	d.keys("4")
	d.want("nope.invalid", "NXDOMAIN", "lost.example.com", "TIMEOUT", "93.184.216.34 (300s)")
	d.keys("5")
	d.want("resolves_to", "has_ip", "hostname", "announces")
	d.keys("?")
	d.want("keys", "collapse addresses into names")
	d.keys("q") // closes help, does not quit
	d.want("REL")
}

func TestFilterAndDetail(t *testing.T) {
	d := newDriver(t)
	d.keys("3", "/")
	for _, r := range "app:quic" {
		d.send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	d.keys("enter")
	d.want("filter: app:quic", "quic.example.org")
	if strings.Contains(d.screen(), "www.example.com") {
		t.Fatal("filter did not apply")
	}
	d.keys("x")
	if strings.Contains(d.screen(), "filter: app:quic") {
		t.Fatal("x did not clear the filter")
	}
	d.keys("2", "enter")
	d.want("alice-iphone", "device:3c:22:fb:01:02:03", "Relationships in this window", "Timeline", "dhcp")
	d.keys("esc")
	d.want("DEVICE")
}

func TestGraphAndWindow(t *testing.T) {
	d := newDriver(t)
	d.keys("6")
	d.want("collapse", "top 15", "Google aa:bb:cc", "plain.example.net")
	d.keys("o")
	d.want("connects www.example.com", "queried")
	d.keys("down", "enter")
	d.want("Relationships in this window")
	d.keys("esc", "s")
	if !strings.Contains(d.m.status, "saved") {
		t.Fatalf("save: %q", d.m.status)
	}
	before := d.m.to
	d.keys("[")
	if d.m.to != before.Add(-d.m.span/2) {
		t.Fatalf("[ moved the window to %v", d.m.to)
	}
	span := d.m.span
	d.keys("-")
	if d.m.span != 2*span {
		t.Fatalf("- zoomed to %v", d.m.span)
	}
	// Far in the past: nothing.
	d.keys("{", "{", "{", "{", "{", "{", "{", "{")
	d.want("No activity in this window.")
}

func TestLive(t *testing.T) {
	liveEvery = time.Millisecond
	d := newDriver(t)
	d.keys("l")
	if !d.m.live || !d.m.to.Equal(testutil.Base.Add(10*time.Minute)) {
		t.Fatalf("live: %v %v", d.m.live, d.m.to)
	}
	d.want("● live")
	d.keys("[")
	if d.m.live {
		t.Fatal("shifting back should leave live mode")
	}
}

func TestParseFilter(t *testing.T) {
	f, err := parseFilter("device:alice-* ip:10.0.0.0/8 port:443 proto:udp app:quic *.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if f.Device != "alice-*" || f.IP != "10.0.0.0/8" || f.Port != 443 || f.Proto != "udp" || f.App != "quic" || f.Domain != "*.example.com" {
		t.Fatalf("%+v", f)
	}
	if got := filterString(f); got != "device:alice-* ip:10.0.0.0/8 domain:*.example.com port:443 proto:udp app:quic" {
		t.Fatalf("filterString = %q", got)
	}
	if f, _ := parseFilter("fd00::50"); f.IP != "fd00::50" {
		t.Fatalf("bare v6: %+v", f)
	}
	if f, _ := parseFilter("3c:22:fb:01:02:03"); f.Device != "3c:22:fb:01:02:03" {
		t.Fatalf("bare mac: %+v", f)
	}
	if _, err := parseFilter("bogus:1"); err == nil {
		t.Fatal("unknown key accepted")
	}
	if _, err := parseFilter("port:x"); err == nil {
		t.Fatal("bad port accepted")
	}
}
