package store

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

const (
	passportWeek = 7 * 24 * time.Hour
	passportTop  = 10
)

// Passport is one device's profile: who it is, when it is usually busy, and how
// this week compares with the last. It reads the hourly rollups, which outlive
// raw retention, so every figure is at hour precision. The weeks end at the
// newest data held. tzOffset moves the hours of the day into the reader's
// timezone.
func (s *Store) Passport(ctx context.Context, id string, tzOffset time.Duration) (*model.Passport, error) {
	kind, key, ok := strings.Cut(id, ":")
	if !ok || kind != "device" || key == "" {
		return nil, fmt.Errorf("%w: a passport is for a device: %q", ErrInvalid, id)
	}
	rng, err := s.DataRange(ctx)
	if err != nil {
		return nil, err
	}
	var eid int64
	if err := s.r.QueryRowContext(ctx, `SELECT id FROM entities WHERE kind = 'device' AND key = ?`, key).Scan(&eid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	// One past the newest hour, so that hour counts as this week's.
	endMS := min(hourOf(rng.LastMS)+time.Hour.Milliseconds(), hourOf(ms(s.cfg.Now()))+time.Hour.Milliseconds())
	end := time.UnixMilli(endMS)
	week := end.Add(-passportWeek)
	lastWeek := week.Add(-passportWeek)
	out := &model.Passport{
		ID: id, AsOfMS: rng.LastMS, WeekFromMS: ms(week), LastWeekFromMS: ms(lastWeek),
		Hours: make([]uint64, 24), Days: []model.PassportDay{}, Destinations: []model.PassportDest{},
	}
	if out.Device, err = s.passportDevice(ctx, key, end); err != nil {
		return nil, err
	}
	if out.Device == nil {
		return nil, ErrNotFound
	}
	if out.Story, err = s.Story(ctx, id, model.Filter{From: end.Add(-24 * time.Hour), To: end}); err != nil {
		return nil, err
	}

	rows, err := s.r.QueryContext(ctx, `SELECT bucket, sum(flows), sum(bytes_out), sum(bytes_in) FROM traffic_hourly
		WHERE client_device = ? AND multicast = 0 AND bucket >= ? AND bucket < ? GROUP BY bucket ORDER BY bucket`, eid, ms(lastWeek), endMS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	dayMS := (24 * time.Hour).Milliseconds()
	offset := tzOffset.Milliseconds()
	days := map[int64]*model.PassportDay{}
	for rows.Next() {
		var bucket int64
		var flows int
		var bo, bi uint64
		if err := rows.Scan(&bucket, &flows, &bo, &bi); err != nil {
			return nil, err
		}
		local := bucket + offset
		dayStart := local - pmod(local, dayMS) - offset
		d := days[dayStart]
		if d == nil {
			d = &model.PassportDay{TS: dayStart}
			days[dayStart] = d
		}
		d.Flows += flows
		d.BytesOut += bo
		d.BytesIn += bi
		w := &out.LastWeek
		if bucket >= ms(week) {
			w = &out.ThisWeek
			out.Hours[pmod(local, dayMS)/time.Hour.Milliseconds()] += bo + bi
		}
		w.Flows += flows
		w.BytesOut += bo
		w.BytesIn += bi
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, d := range days {
		out.Days = append(out.Days, *d)
	}
	slices.SortFunc(out.Days, func(a, b model.PassportDay) int { return cmp.Compare(a.TS, b.TS) })

	dests, err := s.r.QueryContext(ctx, `SELECT coalesce(nullif(name, ''), remote_ip) AS k, direction,
			sum(CASE WHEN bucket >= ?1 THEN flows ELSE 0 END),
			sum(CASE WHEN bucket >= ?1 THEN bytes_out ELSE 0 END),
			sum(CASE WHEN bucket >= ?1 THEN bytes_in ELSE 0 END),
			max(CASE WHEN bucket >= ?1 THEN 1 ELSE 0 END),
			max(CASE WHEN bucket < ?1 THEN 1 ELSE 0 END)
		FROM traffic_hourly WHERE client_device = ?2 AND multicast = 0 AND bucket >= ?3 AND bucket < ?4
		GROUP BY k, direction`, ms(week), eid, ms(lastWeek), endMS)
	if err != nil {
		return nil, err
	}
	defer dests.Close()
	seen := map[string]bool{}
	seenBefore := map[string]bool{}
	for dests.Next() {
		var d model.PassportDest
		var now, before bool
		if err := dests.Scan(&d.Key, &d.Direction, &d.Flows, &d.BytesOut, &d.BytesIn, &now, &before); err != nil {
			return nil, err
		}
		if before {
			seenBefore[d.Key] = true
		}
		if now {
			seen[d.Key] = true
			out.Destinations = append(out.Destinations, d)
		}
	}
	if err := dests.Err(); err != nil {
		return nil, err
	}
	out.ThisWeek.Destinations = len(seen)
	out.LastWeek.Destinations = len(seenBefore)
	// Nothing is "new" without a week to compare it with.
	out.HasLastWeek = out.Device.FirstSeen < ms(week)
	for i := range out.Destinations {
		out.Destinations[i].New = out.HasLastWeek && !seenBefore[out.Destinations[i].Key]
		if out.Destinations[i].New {
			out.NewDestinations++
		}
	}
	slices.SortFunc(out.Destinations, func(a, b model.PassportDest) int {
		return cmp.Or(cmp.Compare(b.BytesIn+b.BytesOut, a.BytesIn+a.BytesOut), cmp.Compare(a.Key, b.Key), cmp.Compare(a.Direction, b.Direction))
	})
	out.Destinations = firstN(out.Destinations, passportTop)
	return out, nil
}

// passportDevice is the device as Devices describes it over the last week, or,
// when it has been silent that long, with no window's activity at all.
func (s *Store) passportDevice(ctx context.Context, key string, end time.Time) (*model.Device, error) {
	list, err := s.Devices(ctx, model.Filter{From: end.Add(-passportWeek), To: end, Device: key})
	if err != nil {
		return nil, err
	}
	if i := slices.IndexFunc(list, func(d model.Device) bool { return d.MAC == key }); i >= 0 {
		return &list[i], nil
	}
	// Quiet for a week: the entity is still known, with no activity to report.
	d, err := s.Entity(ctx, "device:"+key, model.Filter{From: end.Add(-time.Minute), To: end})
	if err != nil {
		return nil, err
	}
	if d.Device != nil {
		return d.Device, nil
	}
	return &model.Device{ID: "device:" + key, MAC: key, Label: d.Label, FirstSeen: d.FirstSeen, LastSeen: d.LastSeen}, nil
}

// pmod is the remainder that is never negative, for times before an offset.
func pmod(a, b int64) int64 { return ((a % b) + b) % b }
