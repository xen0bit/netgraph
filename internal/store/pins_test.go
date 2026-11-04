package store

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
)

func TestMapPins(t *testing.T) {
	now := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	dev := "device:aa:bb:cc:00:00:01"
	if err := st.SetMapPins(ctx, []model.MapPin{{ID: dev, X: 1, Y: 2}, {ID: "site:example.com", X: 3, Y: 4}}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMapPins(ctx, []model.MapPin{{ID: dev, X: 5, Y: 6}}); err != nil {
		t.Fatal(err)
	}
	pins, err := st.MapPins(ctx)
	if err != nil || len(pins) != 2 || pins[0].ID != dev || pins[0].X != 5 {
		t.Fatalf("pins: %+v, %v", pins, err)
	}
	for _, bad := range []model.MapPin{{ID: "", X: 1}, {ID: "noprefix", X: 1}, {ID: dev, X: math.NaN()}, {ID: dev, Y: math.Inf(1)}} {
		if err := st.SetMapPins(ctx, []model.MapPin{bad}); !errors.Is(err, ErrInvalid) {
			t.Errorf("pin %+v: %v", bad, err)
		}
	}
	if err := st.DeleteMapPins(ctx, []string{"site:example.com"}); err != nil {
		t.Fatal(err)
	}
	if pins, _ := st.MapPins(ctx); len(pins) != 1 {
		t.Errorf("after delete: %+v", pins)
	}
	// A purge takes what has not been touched since its cutoff.
	if _, err := st.PurgeBefore(ctx, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if pins, _ := st.MapPins(ctx); len(pins) != 0 {
		t.Errorf("a purge left %+v", pins)
	}
}

func TestMapPinsAreCapped(t *testing.T) {
	now := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	too := make([]model.MapPin, maxPins+1)
	for i := range too {
		too[i] = model.MapPin{ID: "ip:x"}
	}
	if err := st.SetMapPins(context.Background(), too); !errors.Is(err, ErrInvalid) {
		t.Errorf("too many pins: %v", err)
	}
}

// Forgetting a device takes its pin, and the pins of what it alone used.
func TestForgetRemovesPins(t *testing.T) {
	now := testutil.Base
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	mac := "aa:bb:cc:00:00:09"
	if _, err := st.w.ExecContext(ctx, `INSERT INTO entities (kind, key, first_seen, last_seen) VALUES ('device', ?, 1, 1)`, mac); err != nil {
		t.Fatal(err)
	}
	if err := st.SetMapPins(ctx, []model.MapPin{{ID: "device:" + mac}, {ID: "other:device:" + mac}, {ID: "site:example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ForgetDevice(ctx, mac); err != nil {
		t.Fatal(err)
	}
	pins, err := st.MapPins(ctx)
	if err != nil || len(pins) != 1 || pins[0].ID != "site:example.com" {
		t.Errorf("after forgetting: %+v, %v", pins, err)
	}
}
