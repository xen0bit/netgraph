package store

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/wire"
)

// TestScale ingests a busy home's day and times the queries the UIs make.
// It takes a minute or two, so it runs only with NETGRAPH_SCALE=1:
//
//	NETGRAPH_SCALE=1 go test -run TestScale -v ./internal/store/
func TestScale(t *testing.T) {
	if os.Getenv("NETGRAPH_SCALE") == "" {
		t.Skip("set NETGRAPH_SCALE=1")
	}
	const (
		devices        = 40
		flowsPerDevice = 3000 // a day
		domains        = 2000
	)
	day := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	// NETGRAPH_SCALE_DB keeps the database between runs: an existing file
	// skips the minute of ingest.
	path := os.Getenv("NETGRAPH_SCALE_DB")
	if path == "" {
		path = filepath.Join(t.TempDir(), "scale.db")
	}
	_, statErr := os.Stat(path)
	reuse := statErr == nil
	st, err := Open(path, Config{Now: func() time.Time { return day.Add(25 * time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rng := rand.New(rand.NewPCG(1, 2))

	type ev struct {
		at time.Time
		e  wire.Event
	}
	var evs []ev
	var nflows, ndns int
	for d := range devices {
		mac := fmt.Sprintf("3c:22:fb:00:%02x:%02x", d/256, d%256)
		ip := netip.AddrFrom4([4]byte{192, 168, 1, byte(10 + d)})
		evs = append(evs, ev{day, wire.Event{Type: wire.TypeDHCP, TS: day, DHCP: &wire.DHCP{Version: 4, MsgType: "ACK", MAC: mac, YourIP: ip, Hostname: fmt.Sprintf("device-%d", d), LeaseSecs: 86400}}})
		for i := range flowsPerDevice {
			start := day.Add(time.Duration(rng.Int64N(int64(24 * time.Hour))))
			dom := fmt.Sprintf("svc%d.example%d.com", rng.IntN(domains), rng.IntN(50))
			remote := netip.AddrFrom4([4]byte{93, byte(rng.IntN(256)), byte(rng.IntN(256)), byte(1 + rng.IntN(250))})
			evs = append(evs, ev{start.Add(-20 * time.Millisecond), wire.Event{Type: wire.TypeDNS, TS: start.Add(-20 * time.Millisecond), DNS: &wire.DNS{
				Client: ip, ClientMAC: mac, Server: netip.MustParseAddr("192.168.1.1"), QName: dom, QType: "A", RCode: "NOERROR",
				Answers: []wire.Answer{{Name: dom, Type: "A", TTL: 300, Data: remote.String()}}}}})
			ndns++
			// Most connections are short; a few are long-lived.
			dur := time.Duration(rng.ExpFloat64() * float64(20*time.Second))
			if rng.IntN(50) == 0 {
				dur = time.Duration(rng.Int64N(int64(2 * time.Hour)))
			}
			id := uint64(d*flowsPerDevice + i)
			for s := start; ; s = s.Add(30 * time.Second) {
				e := s.Add(30 * time.Second)
				if end := start.Add(dur); end.Before(e) {
					e = end
				}
				final := !e.Before(start.Add(dur))
				evs = append(evs, ev{e, wire.Event{Type: wire.TypeFlow, TS: e, Flow: &wire.Flow{
					ID: id, Proto: 6, Src: ip, SrcPort: uint16(30000 + i%30000), Dst: remote, DstPort: 443, SrcMAC: mac,
					FirstSeen: start, Start: s, End: e, BytesOut: uint64(rng.IntN(20000)), BytesIn: uint64(rng.IntN(500000)),
					PktsOut: 10, PktsIn: 40, App: "tls", SNI: dom, Final: final, EndReason: "fin"}}})
				nflows++
				if final {
					break
				}
			}
		}
	}
	// Sensors deliver in time order.
	slices.SortStableFunc(evs, func(a, b ev) int { return a.at.Compare(b.at) })
	batch := make([]wire.Event, 0, 2000)
	began := time.Now()
	if reuse {
		evs = nil
	}
	for i, e := range evs {
		e.e.Seq = uint64(i + 1)
		batch = append(batch, e.e)
		if len(batch) == cap(batch) || i == len(evs)-1 {
			if _, err := st.Ingest(context.Background(), "scale", "b", batch); err != nil {
				t.Fatal(err)
			}
			batch = batch[:0]
		}
	}
	took := time.Since(began)
	fi, _ := os.Stat(path)
	t.Logf("ingested %d events (%d flow records, %d lookups) in %s: %.0f events/s; database %.1f MB",
		len(evs), nflows, ndns, took.Round(time.Millisecond), float64(len(evs))/took.Seconds(), float64(fi.Size())/1e6)

	ctx := context.Background()
	for _, w := range []struct {
		name string
		f    model.Filter
	}{
		{"1h", model.Filter{From: day.Add(12 * time.Hour), To: day.Add(13 * time.Hour)}},
		{"24h", model.Filter{From: day, To: day.Add(24 * time.Hour)}},
		{"1h device", model.Filter{From: day.Add(12 * time.Hour), To: day.Add(13 * time.Hour), Device: "device-7"}},
	} {
		time1 := func(what string, fn func() (int, error)) {
			t0 := time.Now()
			n, err := fn()
			if err != nil {
				t.Fatalf("%s %s: %v", w.name, what, err)
			}
			t.Logf("  %-10s %-10s %6d rows  %s", w.name, what, n, time.Since(t0).Round(time.Millisecond))
		}
		time1("summary", func() (int, error) {
			s, err := st.Summary(ctx, w.f)
			if err != nil {
				return 0, err
			}
			return s.Flows, nil
		})
		time1("devices", func() (int, error) { d, err := st.Devices(ctx, w.f); return len(d), err })
		time1("flows", func() (int, error) { f, err := st.Flows(ctx, w.f); return len(f), err })
		time1("dns", func() (int, error) { d, err := st.DNS(ctx, w.f); return len(d), err })
		time1("timeseries", func() (int, error) {
			s, err := st.Timeseries(ctx, w.f, 0)
			if err != nil {
				return 0, err
			}
			return len(s.Buckets), nil
		})
		graph := func(o model.GraphOptions) func() (int, error) {
			return func() (int, error) {
				g, err := st.Graph(ctx, w.f, o)
				if err != nil {
					return 0, err
				}
				return len(g.Edges), nil
			}
		}
		time1("graph", graph(model.DefaultGraphOptions))
		all := model.DefaultGraphOptions
		all.TopN = -1
		time1("graph all", graph(all))
	}
}
