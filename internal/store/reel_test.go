package store

import (
	"context"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
)

// reelNet is a device talking to two names at known times.
func reelNet(t *testing.T) (*Store, time.Time) {
	t.Helper()
	base := testutil.Base.Truncate(time.Hour)
	n := &anomalyNet{t: t}
	for i := range 6 {
		n.flow(laptop, base.Add(time.Duration(i)*10*time.Minute+time.Second), "www.example.com", "93.184.216.34", 443, 100_000)
	}
	n.flow(laptop, base.Add(35*time.Minute), "api.other.net", "198.51.100.9", 443, 50_000)
	return n.store(base), base
}

func edgeTotals(r *model.Reel) map[int][2]uint64 {
	out := map[int][2]uint64{}
	for _, s := range r.Series {
		var t [2]uint64
		for _, p := range s.Points {
			if int(p[0]) >= r.Steps {
				continue
			}
			t[0] += p[1]
			t[1] += p[2]
		}
		out[s.Edge] = t
	}
	return out
}

// A reel's steps add up to the graph it carries, from whichever source: its
// timeline and its picture must not disagree.
func TestReelAddsUpToItsGraph(t *testing.T) {
	st, base := reelNet(t)
	ctx := context.Background()
	f := model.Filter{From: base, To: base.Add(time.Hour)}
	for _, tc := range []struct {
		name string
		step time.Duration
		src  string
	}{{"raw", 0, model.PrecisionExact}} {
		r, err := st.Reel(ctx, f, model.DefaultGraphOptions, tc.step)
		if err != nil {
			t.Fatal(err)
		}
		if r.Precision != tc.src {
			t.Errorf("%s: precision %q", tc.name, r.Precision)
		}
		if r.Steps == 0 || r.Steps > maxReelSteps || r.StepMS <= 0 {
			t.Errorf("%s: %d steps of %d ms", tc.name, r.Steps, r.StepMS)
		}
		if r.Unassigned != 0 {
			t.Errorf("%s: %d bytes on no edge", tc.name, r.Unassigned)
		}
		totals := edgeTotals(r)
		if len(totals) == 0 {
			t.Fatalf("%s: no series", tc.name)
		}
		for i, e := range r.Graph.Edges {
			if e.Rel != model.RelConnects {
				continue
			}
			got, want := totals[i], [2]uint64{e.BytesOut, e.BytesIn}
			if diff := int64(got[0]) - int64(want[0]); diff < -8 || diff > 8 {
				t.Errorf("%s: edge %s→%s up %d, graph says %d", tc.name, e.From, e.To, got[0], want[0])
			}
		}
	}
}

// A long window reads minutes, a very old one hours, and the same bytes arrive.
func TestReelSources(t *testing.T) {
	st, base := reelNet(t)
	ctx := context.Background()
	long := model.Filter{From: base.Add(-3 * time.Hour), To: base.Add(3 * time.Hour)}
	r, err := st.Reel(ctx, long, model.DefaultGraphOptions, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Precision != precisionMinute {
		t.Errorf("a six-hour window read %q", r.Precision)
	}
	if r.StepMS < minuteMS {
		t.Errorf("minutes at a step of %d ms", r.StepMS)
	}
	var up uint64
	for _, tot := range edgeTotals(r) {
		up += tot[0]
	}
	if up < 650_000 {
		t.Errorf("minutes carried %d bytes up, want the 650000 sent", up)
	}
	if r.Unassigned != 0 {
		t.Errorf("%d bytes on no edge", r.Unassigned)
	}
}

// Top N folds what it left out into one node, and its traffic goes there.
func TestReelFollowsTopN(t *testing.T) {
	st, base := reelNet(t)
	o := model.DefaultGraphOptions
	o.TopN = 1
	r, err := st.Reel(context.Background(), model.Filter{From: base, To: base.Add(time.Hour)}, o, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Unassigned != 0 {
		t.Errorf("%d bytes on no edge with Top N", r.Unassigned)
	}
	var other bool
	for _, s := range r.Series {
		if e := r.Graph.Edges[s.Edge]; len(e.To) > 6 && e.To[:6] == "other:" {
			other = true
		}
	}
	if !other {
		t.Error("nothing reached the node of what Top N left out")
	}
}

func TestMinuteTierIsErased(t *testing.T) {
	st, base := reelNet(t)
	ctx := context.Background()
	count := func() int {
		var n int
		if err := st.r.QueryRowContext(ctx, `SELECT count(*) FROM traffic_minute`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count() == 0 {
		t.Fatal("ingest wrote no minutes")
	}
	if _, err := st.ForgetDevice(ctx, laptop.mac); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 0 {
		t.Errorf("forgetting the only device left %d minutes", n)
	}
	st2, _ := reelNet(t)
	if _, err := st2.PurgeBefore(ctx, base.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st2.r.QueryRowContext(ctx, `SELECT count(*) FROM traffic_minute`).Scan(&n); err != nil || n != 0 {
		t.Errorf("a purge left %d minutes, %v", n, err)
	}
}

// A week's timeline reads minutes, and agrees with its records.
func TestTimeseriesReadsMinutesForLongWindows(t *testing.T) {
	st, base := reelNet(t)
	ctx := context.Background()
	f := model.Filter{From: base.Add(-12 * time.Hour), To: base.Add(12 * time.Hour)}
	ts, err := st.Timeseries(ctx, f, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ts.Precision != precisionMinute {
		t.Fatalf("read %q", ts.Precision)
	}
	var up uint64
	var flows int
	for _, b := range ts.Buckets {
		up += b.BytesOut
		flows += b.FlowsNew
	}
	if up != 650_000 || flows != 7 {
		t.Errorf("%d bytes up and %d connections, want 650000 and 7", up, flows)
	}
}
