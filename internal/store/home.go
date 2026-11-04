package store

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

const (
	// homeActive is how recently a device must have been seen to count as here.
	homeActive = 10 * time.Minute
	// homeTalkers is the window the busiest devices are ranked over.
	homeTalkers = time.Hour
	// homeQuiet is how long a sensor can go unheard before Home says so. A
	// healthy sensor reports every few seconds.
	homeQuiet = 2 * time.Minute
	// homeMaxSince bounds "since you were last here": past it, the page says it
	// covers less than the whole absence.
	homeMaxSince = 7 * 24 * time.Hour
)

// Home is the landing page's answer: is everything reporting, what is new
// since since, who is here and who is busy. "Now" means the newest data held,
// so a server holding an import or a stopped sensor's data still shows what it
// knows, and AsOfMS says when that was.
func (s *Store) Home(ctx context.Context, since time.Time) (*model.Home, error) {
	now := s.cfg.Now()
	rng, err := s.DataRange(ctx)
	if err != nil {
		return nil, err
	}
	out := &model.Home{
		NowMS: ms(now), AsOfMS: rng.LastMS,
		Sensors: []model.HomeSensor{}, Active: []model.Device{}, NewDevices: []model.Device{}, TopTalkers: []model.Device{},
	}
	sensors, err := s.Sensors(ctx)
	if err != nil {
		return nil, err
	}
	for _, sn := range sensors {
		out.Sensors = append(out.Sensors, model.HomeSensor{
			Name: sn.Name, Version: sn.Version, LastSeen: sn.LastSeen, Interfaces: sn.Interfaces,
			Quiet: now.Sub(time.UnixMilli(sn.LastSeen)) > homeQuiet,
		})
	}
	if rng.LastMS == 0 {
		out.State = model.HomeNoData
		return out, nil
	}
	out.State = model.HomeOK
	if len(out.Sensors) > 0 && !slices.ContainsFunc(out.Sensors, func(h model.HomeSensor) bool { return !h.Quiet }) {
		out.State = model.HomeQuiet
	} else if len(out.Sensors) == 0 {
		// Imported captures have no sensor reporting: the data simply ends.
		out.State = model.HomeImported
	}
	// A window is half-open, so the newest record needs the millisecond after it.
	end := time.UnixMilli(rng.LastMS + 1)
	if end.After(now) {
		end = now
	}
	sinceFloor := end.Add(-homeMaxSince)
	if since.IsZero() {
		since = end.Add(-24 * time.Hour)
	}
	if since.Before(sinceFloor) {
		since = sinceFloor
		out.SinceClamped = true
	}
	if since.After(end) {
		since = end
	}
	out.SinceMS = ms(since)

	recent, err := s.Devices(ctx, model.Filter{From: end.Add(-homeTalkers), To: end})
	if err != nil {
		return nil, err
	}
	activeFrom := ms(end.Add(-homeActive))
	for _, d := range recent {
		if d.ActiveTo >= activeFrom {
			out.Active = append(out.Active, d)
		}
	}
	slices.SortFunc(out.Active, func(a, b model.Device) int { return cmp.Compare(a.Label, b.Label) })
	talkers := slices.Clone(recent)
	slices.SortFunc(talkers, func(a, b model.Device) int {
		return cmp.Or(cmp.Compare(b.BytesIn+b.BytesOut, a.BytesIn+a.BytesOut), cmp.Compare(a.Label, b.Label))
	})
	for _, d := range firstN(talkers, 5) {
		if d.BytesIn+d.BytesOut > 0 {
			out.TopTalkers = append(out.TopTalkers, d)
		}
	}

	if since.Before(end) {
		f := model.Filter{From: since, To: end}
		if out.Since, err = s.Summary(ctx, f); err != nil {
			return nil, err
		}
		seen, err := s.Devices(ctx, f)
		if err != nil {
			return nil, err
		}
		for _, d := range seen {
			if d.FirstSeen >= ms(since) {
				out.NewDevices = append(out.NewDevices, d)
			}
		}
		slices.SortFunc(out.NewDevices, func(a, b model.Device) int {
			return cmp.Or(cmp.Compare(b.FirstSeen, a.FirstSeen), cmp.Compare(a.Label, b.Label))
		})
	}
	if out.Traffic, err = s.Timeseries(ctx, model.Filter{From: end.Add(-24 * time.Hour), To: end}, 15*time.Minute); err != nil {
		return nil, err
	}
	return out, nil
}
