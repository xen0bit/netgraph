package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/testutil"
)

func TestPassport(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	devs, err := st.Devices(ctx, win(0, time.Hour))
	if err != nil || len(devs) == 0 {
		t.Fatalf("devices: %v, %v", devs, err)
	}
	busiest := devs[0]
	for _, d := range devs {
		if d.BytesIn+d.BytesOut > busiest.BytesIn+busiest.BytesOut {
			busiest = d
		}
	}
	p, err := st.Passport(ctx, busiest.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.Device == nil || p.Device.ID != busiest.ID || len(p.Hours) != 24 {
		t.Fatalf("passport: %+v", p)
	}
	var hours uint64
	for _, h := range p.Hours {
		hours += h
	}
	if want := p.ThisWeek.BytesIn + p.ThisWeek.BytesOut; hours != want || want == 0 {
		t.Errorf("hours add to %d, the week to %d", hours, want)
	}
	if p.ThisWeek.Destinations == 0 || len(p.Destinations) == 0 || len(p.Days) == 0 {
		t.Errorf("week %+v, destinations %d, days %d", p.ThisWeek, len(p.Destinations), len(p.Days))
	}
	// First seen this week: it can't be called new against a week it wasn't here.
	if p.HasLastWeek || p.NewDestinations != 0 {
		t.Errorf("no history, yet last week %v, new %d", p.HasLastWeek, p.NewDestinations)
	}
}

// The hours move with the reader's timezone; nothing is lost or gained.
func TestPassportTimezone(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	devs, _ := st.Devices(ctx, win(0, time.Hour))
	var id string
	for _, d := range devs {
		if d.BytesIn+d.BytesOut > 0 {
			id = d.ID
			break
		}
	}
	utc, err := st.Passport(ctx, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	east, err := st.Passport(ctx, id, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for h := range 24 {
		if utc.Hours[h] != east.Hours[(h+2)%24] {
			t.Errorf("hour %d: %d, shifted %d", h, utc.Hours[h], east.Hours[(h+2)%24])
		}
	}
	hour := testutil.Base.UTC().Hour()
	if utc.Hours[hour] == 0 {
		t.Errorf("the capture's hour %d has no traffic: %v", hour, utc.Hours)
	}
}

func TestPassportRejects(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	if _, err := st.Passport(ctx, "domain:example.com", 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("a domain: %v", err)
	}
	if _, err := st.Passport(ctx, "device:00:00:00:00:00:99", 0); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown device: %v", err)
	}
}

// A connected UI gets each event with the device it is about.
func TestLiveEventsNameTheirDevice(t *testing.T) {
	st, _, events := homeStore(t)
	ch, cancel := st.Subscribe()
	defer cancel()
	if _, err := st.Ingest(context.Background(), "router", "boot2", events); err != nil {
		t.Fatal(err)
	}
	devs, err := st.Devices(context.Background(), win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{}
	for _, d := range devs {
		labels[d.ID] = d.Label
	}
	named := 0
	for {
		select {
		case evs := <-ch:
			for _, e := range evs {
				if e.Entity != "" && e.Label != "" {
					named++
					// The name everything else calls it, not the raw entity label.
					if want, ok := labels[e.Entity]; ok && e.Label != want {
						t.Errorf("%s is %q in the feed and %q elsewhere", e.Entity, e.Label, want)
					}
				}
			}
			continue
		default:
		}
		break
	}
	if named == 0 {
		t.Error("no live event named its device")
	}
}

// A window's rows can be sorted before the limit, so "oldest" means the oldest
// of all of them rather than of the busiest thousand.
func TestFlowsSortBeforeTheLimit(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	f := win(0, time.Hour)
	all, err := st.Flows(ctx, f)
	if err != nil || len(all) < 3 {
		t.Fatalf("flows: %d, %v", len(all), err)
	}
	oldest := all[0].FirstSeen
	for _, x := range all {
		oldest = min(oldest, x.FirstSeen)
	}
	f.Sort, f.Limit = "first_seen", 1
	got, err := st.Flows(ctx, f)
	if err != nil || len(got) != 1 || got[0].FirstSeen != oldest {
		t.Errorf("oldest: %+v, %v, want first seen %d", got, err, oldest)
	}
	f.Sort, f.Limit = "-bytes_out", 0
	got, err = st.Flows(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].BytesOut < got[i].BytesOut {
			t.Fatalf("not sorted by sent: %d then %d", got[i-1].BytesOut, got[i].BytesOut)
		}
	}
}
