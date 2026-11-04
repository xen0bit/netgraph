package store

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

type qualityNet struct {
	t    *testing.T
	st   *Store
	now  time.Time
	seq  uint64
	flow uint64
}

const qualityPhone = "3c:22:fb:01:02:03"

func newQualityNet(t *testing.T) *qualityNet {
	t.Helper()
	q := &qualityNet{t: t, now: testutil.Base.Add(30 * 24 * time.Hour)}
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return q.now }, RawRetention: 90 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	q.st = st
	q.send(wire.Event{Type: wire.TypeHello, TS: q.now, Hello: &wire.Hello{Name: "router", Version: "t",
		Interfaces: []wire.Interface{{Name: "br-lan", MAC: "02:00:5e:00:00:01", Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.1/24")}}}}})
	return q
}

func (q *qualityNet) send(evs ...wire.Event) {
	q.t.Helper()
	for i := range evs {
		q.seq++
		evs[i].Seq = q.seq
	}
	if _, err := q.st.Ingest(context.Background(), "router", "b", evs); err != nil {
		q.t.Fatal(err)
	}
}

// conn records one outward connection at at, with its handshake's legs in ms.
func (q *qualityNet) conn(at time.Time, serverMS, clientMS float64, answered bool, retrans uint32) {
	q.t.Helper()
	q.flow++
	in, pkts := uint64(1000), uint64(100)
	if !answered {
		in, pkts = 0, 0
	}
	q.send(wire.Event{Type: wire.TypeFlow, TS: at, Flow: &wire.Flow{
		ID: q.flow, Proto: 6, Src: netip.MustParseAddr("192.168.1.23"), SrcPort: uint16(40000 + q.flow%20000), Dst: netip.MustParseAddr("93.184.216.34"), DstPort: 443,
		SrcMAC: qualityPhone, DstMAC: "02:00:5e:00:00:01", FirstSeen: at, Start: at, End: at.Add(time.Second), BytesOut: 100, BytesIn: in, PktsOut: 100, PktsIn: pkts, Final: true, EndReason: "fin",
		RTTServerUS: uint32(serverMS * 1000), RTTClientUS: uint32(clientMS * 1000), Retrans: retrans,
	}})
}

// many records n connections spread over the hour before end.
func (q *qualityNet) many(end time.Time, n int, serverMS, clientMS float64, retrans uint32) {
	q.t.Helper()
	for i := range n {
		q.conn(end.Add(-time.Hour+time.Duration(i)*time.Hour/time.Duration(n)), serverMS, clientMS, true, retrans)
	}
}

func (q *qualityNet) quality() *model.Quality {
	q.t.Helper()
	r, err := q.st.Quality(context.Background(), model.Filter{From: q.now.Add(-time.Hour), To: q.now})
	if err != nil {
		q.t.Fatal(err)
	}
	return r
}

func TestQualitySaysWhereTroubleIs(t *testing.T) {
	usual := func(q *qualityNet) { q.many(q.now.Add(-24*time.Hour), 20, 20, 2, 0) }
	for _, c := range []struct {
		name           string
		serverMS, cMS  float64
		retrans        uint32
		verdict, words string
	}{
		{"all fine", 22, 2, 0, model.QualityGood, "Nothing looks wrong"},
		{"a slow upstream, with a healthy LAN", 200, 2, 0, model.QualitySlowUpstream, "upstream"},
		{"slow Wi-Fi, with a healthy upstream", 20, 80, 0, model.QualitySlowLocal, "your own network"},
		{"both slow: the near end is what's fixable", 200, 80, 0, model.QualitySlowLocal, "your own network"},
		{"losing packets", 20, 2, 20, model.QualityLossy, "lost"},
	} {
		t.Run(c.name, func(t *testing.T) {
			q := newQualityNet(t)
			usual(q)
			q.many(q.now, 20, c.serverMS, c.cMS, c.retrans)
			r := q.quality()
			if r.Verdict != c.verdict || !strings.Contains(r.Summary, c.words) {
				t.Errorf("%s: %s", r.Verdict, r.Summary)
			}
			if r.WAN.Samples != 20 || r.LAN.Samples != 20 || r.Usual.Samples != 20 {
				t.Errorf("samples: %+v %+v %+v", r.WAN, r.LAN, r.Usual)
			}
			if len(r.Devices) != 1 || r.Devices[0].ID != "device:"+qualityPhone || len(r.Series) == 0 {
				t.Errorf("devices %+v, series %d", r.Devices, len(r.Series))
			}
		})
	}
}

func TestQualityWontGuessFromTooLittle(t *testing.T) {
	q := newQualityNet(t)
	q.many(q.now, 2, 500, 500, 0)
	if r := q.quality(); r.Verdict != model.QualityUnknown {
		t.Errorf("%s: %s", r.Verdict, r.Summary)
	}
	// With no history, a high number can't be called worse than usual.
	q = newQualityNet(t)
	q.many(q.now, 20, 200, 2, 0)
	if r := q.quality(); r.Verdict != model.QualityGood || !strings.Contains(r.Summary, "history") {
		t.Errorf("%s: %s", r.Verdict, r.Summary)
	}
}

func TestQualityFindsOutages(t *testing.T) {
	q := newQualityNet(t)
	start := q.now.Add(-30 * time.Minute).Truncate(time.Minute)
	q.many(start.Add(-time.Minute), 20, 20, 2, 0) // healthy, until then
	for m := range 4 {
		for i := range 5 {
			q.conn(start.Add(time.Duration(m)*time.Minute+time.Duration(i)*time.Second), 0, 0, false, 0)
		}
	}
	r := q.quality()
	if r.Verdict != model.QualityOutage || r.Unanswered != 20 {
		t.Fatalf("%s: %s, unanswered %d", r.Verdict, r.Summary, r.Unanswered)
	}
	if len(r.Outages) != 1 || r.Outages[0].FromMS != start.UnixMilli() || r.Outages[0].Attempts != 20 {
		t.Errorf("outages %+v, want from %d", r.Outages, start.UnixMilli())
	}
}

func TestFindOutages(t *testing.T) {
	const m = int64(time.Minute / time.Millisecond)
	dead := func(i int64) minuteCount { return minuteCount{i * m, 5, 0} }
	for name, c := range map[string]struct {
		in   []minuteCount
		want int
	}{
		"one bad minute is a blip":  {[]minuteCount{dead(1)}, 0},
		"two in a row":              {[]minuteCount{dead(1), dead(2)}, 1},
		"an answer splits them":     {[]minuteCount{dead(1), dead(2), {3 * m, 5, 1}, dead(4), dead(5)}, 2},
		"too few attempts to judge": {[]minuteCount{{m, 1, 0}, {2 * m, 2, 0}}, 0},
		"a long silence splits":     {[]minuteCount{dead(1), dead(2), dead(30), dead(31)}, 2},
		"a quiet night is nothing":  {nil, 0},
	} {
		if got := findOutages(c.in); len(got) != c.want {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

// A device filter narrows everything, and a backwards window is refused.
func TestQualityFilterAndBounds(t *testing.T) {
	q := newQualityNet(t)
	q.many(q.now, 10, 20, 2, 0)
	f := model.Filter{From: q.now.Add(-time.Hour), To: q.now, Device: "no-such-device"}
	r, err := q.st.Quality(context.Background(), f)
	if err != nil || r.WAN.Samples != 0 || r.Verdict != model.QualityUnknown {
		t.Fatalf("%+v, %v", r, err)
	}
	f.Device = qualityPhone
	if r, err = q.st.Quality(context.Background(), f); err != nil || r.WAN.Samples != 10 {
		t.Fatalf("%+v, %v", r, err)
	}
	if _, err := q.st.Quality(context.Background(), model.Filter{From: q.now, To: q.now.Add(-time.Hour)}); err == nil {
		t.Error("a backwards window")
	}
	r, err = q.st.Quality(context.Background(), model.Filter{From: q.now.Add(-30 * 24 * time.Hour), To: q.now})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fmt.Sprint(r.Gaps), "7 days") || r.FromMS != q.now.Add(-7*24*time.Hour).UnixMilli() {
		t.Errorf("a long window: from %d, gaps %v", r.FromMS, r.Gaps)
	}
}

// A connection's legs arrive once, and later records of it mustn't erase them.
func TestLegsSurviveLaterRecords(t *testing.T) {
	q := newQualityNet(t)
	at := q.now.Add(-10 * time.Minute)
	base := wire.Flow{ID: 7, Proto: 6, Src: netip.MustParseAddr("192.168.1.23"), SrcPort: 5000, Dst: netip.MustParseAddr("93.184.216.34"), DstPort: 443, SrcMAC: qualityPhone, FirstSeen: at, Start: at, End: at.Add(time.Second), PktsOut: 10, PktsIn: 10}
	first, second := base, base
	first.RTTServerUS, first.RTTClientUS, first.Retrans = 20_000, 2_000, 1
	second.Start, second.End, second.Retrans = at.Add(time.Second), at.Add(2*time.Second), 2
	q.send(wire.Event{Type: wire.TypeFlow, TS: at, Flow: &first}, wire.Event{Type: wire.TypeFlow, TS: at, Flow: &second})
	var server, client, retrans int
	if err := q.st.r.QueryRow(`SELECT rtt_server_us, rtt_client_us, retrans FROM connections`).Scan(&server, &client, &retrans); err != nil {
		t.Fatal(err)
	}
	if server != 20_000 || client != 2_000 || retrans != 3 {
		t.Errorf("%d %d %d", server, client, retrans)
	}
}

// A lookup nobody answered has no latency at all: real captures have them.
func TestQualityOnARealCapture(t *testing.T) {
	st, _, _ := homeStore(t)
	r, err := st.Quality(context.Background(), win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if r.WAN.Samples == 0 || r.DNSQueries == 0 || r.DNS.Samples == 0 {
		t.Errorf("wan %+v, dns %+v of %d", r.WAN, r.DNS, r.DNSQueries)
	}
	if r.DNSTimeouts+r.DNS.Samples > r.DNSQueries {
		t.Errorf("%d timeouts and %d answered of %d", r.DNSTimeouts, r.DNS.Samples, r.DNSQueries)
	}
}
