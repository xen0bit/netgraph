package store

import (
	"context"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
)

func TestFrameMatchesWindow(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	f := win(0, 10*time.Minute)
	fr, err := st.Frame(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	if fr.AtMS != f.To.UnixMilli() || fr.FromMS != f.From.UnixMilli() {
		t.Fatalf("frame bounds = %+v", fr)
	}
	if fr.Summary == nil || fr.Summary.Devices == 0 || len(fr.Devices) == 0 {
		t.Fatalf("empty frame: %+v", fr)
	}
	if fr.Precision != model.PrecisionExact {
		t.Fatalf("precision = %q", fr.Precision)
	}
	if fr.Graph == nil || len(fr.Graph.Nodes) == 0 {
		t.Fatalf("frame graph missing")
	}
}

func TestTimelinePagingAndEntityFilter(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	page, err := st.Timeline(ctx, win(0, time.Hour), model.TimelineQuery{Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 3 || page.Next == "" {
		t.Fatalf("timeline page = %+v", page)
	}
	next, err := st.Timeline(ctx, win(0, time.Hour), model.TimelineQuery{Limit: 3, Cursor: page.Next})
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Events) == 0 {
		t.Fatal("cursor returned no events")
	}
	mac := "3c:22:fb:01:02:03"
	entity, err := st.Timeline(ctx, win(0, time.Hour), model.TimelineQuery{Entity: model.EntityID(model.KindDevice, mac), Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entity.Events {
		if e.Entity != model.EntityID(model.KindDevice, mac) && e.Related != model.EntityID(model.KindDevice, mac) {
			t.Fatalf("entity filter leaked %+v", e)
		}
	}
}

func TestStoryForDevice(t *testing.T) {
	st, _, _ := homeStore(t)
	story, err := st.Story(context.Background(), model.EntityID(model.KindDevice, "3c:22:fb:01:02:03"), win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if story.Label == "" || len(story.Segments) == 0 {
		t.Fatalf("story = %+v", story)
	}
	if story.Segments[0].FromMS > story.Segments[len(story.Segments)-1].FromMS {
		t.Fatal("story segments are not sorted")
	}
}

func TestDiffFrames(t *testing.T) {
	st, _, _ := homeStore(t)
	a := win(0, 5*time.Minute)
	b := win(5*time.Minute, 10*time.Minute)
	d, err := st.Diff(context.Background(), a, b, "")
	if err != nil {
		t.Fatal(err)
	}
	if d.FromMS != a.To.UnixMilli() || d.ToMS != b.To.UnixMilli() {
		t.Fatalf("diff bounds = %+v", d)
	}
	// The lab capture has DNS and connections in both halves; an empty
	// diff is possible, but the result must still be deterministic.
	if d.Added == nil && d.Removed == nil && d.Changed == nil && len(d.Gaps) == 0 {
		t.Fatal("diff has no result and no gap")
	}
	_ = testutil.Base
}

func TestBackfillTimeline(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	if _, err := st.w.ExecContext(ctx, `DELETE FROM timeline_events`); err != nil {
		t.Fatal(err)
	}
	n, err := st.BackfillTimeline(ctx, testutil.Base)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("backfill wrote nothing")
	}
	page, err := st.Timeline(ctx, win(0, time.Hour), model.TimelineQuery{Limit: 10})
	if err != nil || len(page.Events) == 0 {
		t.Fatalf("timeline after backfill = %+v %v", page, err)
	}
}
