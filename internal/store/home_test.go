package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
)

func TestHomeWithNothing(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return testutil.Base }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h, err := st.Home(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if h.State != model.HomeNoData || h.AsOfMS != 0 || h.Active == nil || h.Sensors == nil {
		t.Errorf("empty store: %+v", h)
	}
}

func TestHomeAnswersAsOfTheNewestData(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	rng, err := st.DataRange(ctx)
	if err != nil || rng.LastMS == 0 {
		t.Fatalf("range %+v, %v", rng, err)
	}
	h, err := st.Home(ctx, time.UnixMilli(rng.FirstMS-1000))
	if err != nil {
		t.Fatal(err)
	}
	if h.AsOfMS != rng.LastMS {
		t.Errorf("as of %d, newest data %d", h.AsOfMS, rng.LastMS)
	}
	if len(h.Active) == 0 || len(h.TopTalkers) == 0 || len(h.TopTalkers) > 5 {
		t.Errorf("active %d, talkers %d", len(h.Active), len(h.TopTalkers))
	}
	for i := 1; i < len(h.TopTalkers); i++ {
		a, b := h.TopTalkers[i-1], h.TopTalkers[i]
		if a.BytesIn+a.BytesOut < b.BytesIn+b.BytesOut {
			t.Errorf("talkers out of order: %+v", h.TopTalkers)
		}
	}
	if len(h.NewDevices) == 0 || h.Since == nil || h.Traffic == nil {
		t.Errorf("since before everything: new %d, summary %v, traffic %v", len(h.NewDevices), h.Since, h.Traffic)
	}
	// Coming back after the newest record, nothing is new.
	later, err := st.Home(ctx, time.UnixMilli(rng.LastMS+1))
	if err != nil {
		t.Fatal(err)
	}
	if len(later.NewDevices) != 0 {
		t.Errorf("new since the end of the data: %+v", later.NewDevices)
	}
}

func TestHomeClampsALongAbsence(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	rng, _ := st.DataRange(ctx)
	h, err := st.Home(ctx, time.UnixMilli(rng.LastMS).Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !h.SinceClamped || h.SinceMS < rng.LastMS-homeMaxSince.Milliseconds() {
		t.Errorf("clamped %v, since %d, last %d", h.SinceClamped, h.SinceMS, rng.LastMS)
	}
}

func TestHomeSaysWhenSensorsGoQuiet(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	h, err := st.Home(ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Sensors) == 0 {
		t.Skip("the home capture reports no sensor")
	}
	last := h.Sensors[0].LastSeen
	st.cfg.Now = func() time.Time { return time.UnixMilli(last).Add(homeQuiet + time.Second) }
	h, err = st.Home(ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if h.State != model.HomeQuiet || !h.Sensors[0].Quiet {
		t.Errorf("state %q, sensors %+v", h.State, h.Sensors)
	}
}
