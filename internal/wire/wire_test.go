package wire

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func sampleEvents(n int) []Event {
	ts := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	out := make([]Event, n)
	for i := range out {
		out[i] = Event{Seq: uint64(i + 1), Type: TypeFlow, TS: ts, Flow: &Flow{
			ID: uint64(i), Proto: 6,
			Src: netip.MustParseAddr("192.168.1.10"), SrcPort: 50000,
			Dst: netip.MustParseAddr("2001:db8::1"), DstPort: 443,
			FirstSeen: ts, Start: ts, End: ts.Add(time.Second), BytesOut: 100, SNI: "example.com",
		}}
	}
	return out
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := sampleEvents(50)
	body, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(in) {
		t.Fatalf("got %d events, want %d", len(out), len(in))
	}
	got, want := out[7].Flow, in[7].Flow
	if got.Dst != want.Dst || got.SNI != want.SNI || !got.Start.Equal(want.Start) || got.BytesOut != want.BytesOut {
		t.Errorf("round trip mismatch: %+v vs %+v", got, want)
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := Decode([]byte("not zstd")); err == nil {
		t.Fatal("expected an error")
	}
}

// The shipper must deliver every event in order across a server outage.
func TestShipperRetriesInOrder(t *testing.T) {
	var mu sync.Mutex
	var got []uint64
	fail := 2
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get(HeaderSensor) != "s1" {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if fail > 0 {
			fail--
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		evs, err := Decode(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, e := range evs {
			got = append(got, e.Seq)
		}
	}))
	defer srv.Close()

	s := NewShipper(ShipperConfig{URL: srv.URL, Token: "tok", Sensor: "s1", MaxEvents: 10, FlushInterval: 10 * time.Millisecond})
	for _, ev := range sampleEvents(35) {
		s.Emit(ev)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for {
		if err := s.Flush(ctx); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("never delivered")
		case <-time.After(5 * time.Millisecond):
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 35 {
		t.Fatalf("delivered %d events, want 35", len(got))
	}
	for i, seq := range got {
		if seq != uint64(i+1) {
			t.Fatalf("event %d has seq %d: out of order", i, seq)
		}
	}
}

func TestShipperSpoolBound(t *testing.T) {
	s := NewShipper(ShipperConfig{URL: "http://127.0.0.1:1", MaxEvents: 5, SpoolBytes: 1})
	for _, ev := range sampleEvents(50) {
		s.Emit(ev)
	}
	st := s.Stats()
	// Every sealed batch but the newest must have been dropped.
	if st.EventsDropped != 45 || st.Queued != 5 {
		t.Fatalf("dropped=%d queued=%d, want 45 and 5", st.EventsDropped, st.Queued)
	}
}
