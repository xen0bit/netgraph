package store

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"github.com/xen0bit/netgraph/internal/model"
	"slices"
	"strconv"
	"strings"
)

// Frame builds a recorded moment: a short lookback ending at the filter's
// To. It is intentionally built from the same query functions as the rest of
// the API, so a frame can never disagree with a window query.
func (s *Store) Frame(ctx context.Context, f model.Filter) (*model.Frame, error) {
	return s.frame(ctx, f, true)
}

func (s *Store) frame(ctx context.Context, f model.Filter, full bool) (*model.Frame, error) {
	from, to := s.window(f)
	out := &model.Frame{
		AtMS: to, FromMS: from, ToMS: to, LookbackMS: to - from,
		Precision: s.precision(from, to), Scope: f.Device,
	}
	sum, err := s.Summary(ctx, f)
	if err != nil {
		return nil, err
	}
	out.Summary = sum
	if out.Devices, err = s.Devices(ctx, f); err != nil {
		return nil, err
	}
	if out.Destinations, err = s.Destinations(ctx, f); err != nil {
		return nil, err
	}
	if out.Flows, err = s.Flows(ctx, f); err != nil {
		return nil, err
	}
	if out.DNS, err = s.DNS(ctx, f); err != nil {
		return nil, err
	}
	if out.WiFi, err = s.WiFi(ctx, f); err != nil {
		return nil, err
	}
	if out.Sensors, err = s.Sensors(ctx); err != nil {
		return nil, err
	}
	if full {
		if rep, err := s.Anomalies(ctx, f); err == nil {
			out.Anomalies = rep.Anomalies
		}
		if g, err := s.Graph(ctx, f, model.DefaultGraphOptions); err == nil {
			out.Graph = g
		}
	}
	// Tell the UI when a layer was cut rather than silently returning a
	// misleadingly complete frame.
	if f.Limit > 0 {
		if len(out.Devices) >= f.Limit {
			out.Truncated = append(out.Truncated, "devices")
		}
		if len(out.Flows) >= f.Limit {
			out.Truncated = append(out.Truncated, "flows")
		}
		if len(out.DNS) >= f.Limit {
			out.Truncated = append(out.Truncated, "dns")
		}
		if len(out.Destinations) >= f.Limit {
			out.Truncated = append(out.Truncated, "destinations")
		}
	}
	return out, nil
}

// Story turns an entity's recorded facts, connections, lookups and
// observations into intervals and milestones. It is the backend for the
// Flight Recorder's follow camera and the CLI's story view.
func (s *Store) Story(ctx context.Context, id string, f model.Filter) (*model.Story, error) {
	d, err := s.Entity(ctx, id, f)
	if err != nil {
		return nil, err
	}
	from, to := s.window(f)
	out := &model.Story{Entity: id, Label: d.Label, FromMS: from, ToMS: to}
	evidence := map[string]model.EvidenceRef{}
	addEvidence := func(e model.EvidenceRef) {
		if e.ID == "" {
			return
		}
		evidence[e.Kind+":"+e.ID] = e
		out.Evidence = append(out.Evidence, e)
	}
	if d.Device != nil {
		start, end := max(d.FirstSeen, from), min(d.LastSeen, to)
		if end >= start {
			out.Segments = append(out.Segments, model.StorySegment{
				Kind: "presence", FromMS: start, ToMS: end, Entity: id, Label: d.Label,
				Evidence: []model.EvidenceRef{{Kind: "entity", ID: id, TS: start, Text: "device was present"}},
			})
		}
	}
	for _, fact := range d.Facts {
		other, label := fact.Dst, fact.DstLabel
		if fact.Dst == id {
			other, label = fact.Src, fact.SrcLabel
		}
		if other == "" {
			other = id
		}
		ev := model.EvidenceRef{Kind: "fact", ID: fmt.Sprintf("%s:%s:%s:%d", fact.Rel, fact.Src, fact.Dst, fact.FirstSeen), TS: fact.FirstSeen, Text: fact.Rel}
		addEvidence(ev)
		out.Segments = append(out.Segments, model.StorySegment{
			Kind: fact.Rel, FromMS: fact.FirstSeen, ToMS: fact.LastSeen, Entity: other, Label: label, Count: fact.Count, Evidence: []model.EvidenceRef{ev},
		})
	}
	for _, fl := range d.Flows {
		other := model.EntityID(model.KindIP, fl.RemoteIP)
		label := fl.RemoteIP
		if fl.Name != "" {
			other = model.EntityID(model.KindDomain, fl.Name)
			label = fl.Name
		}
		ev := model.EvidenceRef{Kind: "flow", ID: fl.Key, TS: fl.FirstSeen, Text: fl.Name}
		addEvidence(ev)
		out.Segments = append(out.Segments, model.StorySegment{
			Kind: "connection", FromMS: fl.FirstSeen, ToMS: fl.LastSeen, Entity: other, Label: label,
			BytesOut: fl.BytesOut, BytesIn: fl.BytesIn, Count: 1, Evidence: []model.EvidenceRef{ev},
		})
	}
	for _, q := range d.DNS {
		ev := model.EvidenceRef{Kind: "dns", ID: fmt.Sprintf("%d:%s:%s", q.TS, q.QName, q.ClientIP), TS: q.TS, Text: q.QName}
		addEvidence(ev)
		out.Milestones = append(out.Milestones, model.TimelineEntry{
			TS: q.TS, Kind: "dns", Title: q.QName + " " + q.RCode, Ref: "dns:" + ev.ID,
		})
	}
	for _, ev := range d.Timeline {
		out.Milestones = append(out.Milestones, model.TimelineEntry{TS: ev.TS, Kind: ev.Type, Title: ev.Detail})
	}
	slices.SortFunc(out.Segments, func(a, b model.StorySegment) int {
		return cmp.Or(cmp.Compare(a.FromMS, b.FromMS), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Entity, b.Entity))
	})
	slices.SortFunc(out.Milestones, func(a, b model.TimelineEntry) int {
		return cmp.Or(cmp.Compare(a.TS, b.TS), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Title, b.Title))
	})
	if len(out.Segments) == 0 {
		out.Gaps = append(out.Gaps, "no recorded activity in this window")
	}
	if d.Device == nil && d.Kind == model.KindDevice {
		out.Gaps = append(out.Gaps, "device metadata was not loaded")
	}
	return out, nil
}

// Timeline returns a stable page of rail events.
func (s *Store) Timeline(ctx context.Context, f model.Filter, q model.TimelineQuery) (*model.TimelinePage, error) {
	from, to := s.window(f)
	limit := q.Limit
	if limit <= 0 {
		limit = 500
	}
	if limit > 5000 {
		limit = 5000
	}
	var where []string
	args := []any{from, to}
	where = append(where, "t.ts >= ?", "t.ts < ?")
	if e := strings.TrimSpace(q.Entity); e != "" {
		where = append(where, "(t.entity_key = ? OR t.related_key = ?)")
		args = append(args, e, e)
	}
	if len(q.Kinds) > 0 {
		ph := make([]string, len(q.Kinds))
		for i, k := range q.Kinds {
			ph[i] = "?"
			args = append(args, k)
		}
		where = append(where, "t.kind IN ("+strings.Join(ph, ",")+")")
	}
	if q.Cursor != "" {
		a, b, ok := strings.Cut(q.Cursor, "|")
		if !ok {
			return nil, fmt.Errorf("%w: bad timeline cursor", ErrInvalid)
		}
		ts, err1 := strconv.ParseInt(a, 10, 64)
		id, err2 := strconv.ParseInt(b, 10, 64)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("%w: bad timeline cursor", ErrInvalid)
		}
		where = append(where, "(t.ts < ? OR (t.ts = ? AND t.id < ?))")
		args = append(args, ts, ts, id)
	}
	sqlq := `SELECT t.id, t.ts, t.kind,
		coalesce(nullif(t.entity_key,''), e.kind || ':' || e.key, ''),
		coalesce(nullif(t.related_key,''), r.kind || ':' || r.key, ''),
		t.severity, t.title, t.ref_table, t.ref_key, t.attrs
		FROM timeline_events t
		LEFT JOIN entities e ON e.id = t.entity_id
		LEFT JOIN entities r ON r.id = t.related_id
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY t.ts DESC, t.id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.r.QueryContext(ctx, sqlq, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &model.TimelinePage{Events: []model.TimelineEntry{}, Precision: s.precision(from, to)}
	for rows.Next() {
		var e model.TimelineEntry
		var refTable, refKey, attrs string
		if err := rows.Scan(&e.ID, &e.TS, &e.Kind, &e.Entity, &e.Related, &e.Severity, &e.Title, &refTable, &refKey, &attrs); err != nil {
			return nil, err
		}
		e.Ref = refTable + ":" + refKey
		_ = json.Unmarshal([]byte(attrs), &e.Attrs)
		page.Events = append(page.Events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(page.Events) > limit {
		page.Events = page.Events[:limit]
		last := page.Events[len(page.Events)-1]
		page.Next = strconv.FormatInt(last.TS, 10) + "|" + strconv.FormatInt(last.ID, 10)
	}
	return page, nil
}

// Diff compares the network at two recorded moments.
func (s *Store) Diff(ctx context.Context, a, b model.Filter, scope string) (*model.Diff, error) {
	fa, err := s.frame(ctx, a, false)
	if err != nil {
		return nil, err
	}
	fb, err := s.frame(ctx, b, false)
	if err != nil {
		return nil, err
	}
	out := &model.Diff{FromMS: fa.AtMS, ToMS: fb.AtMS}
	if scope != "" {
		out.Gaps = append(out.Gaps, "scope "+scope+" is applied by the caller filter")
	}
	if fa.Precision != model.PrecisionExact || fb.Precision != model.PrecisionExact {
		out.Gaps = append(out.Gaps, "one or both moments are hourly rollups")
	}
	ev := func(frame *model.Frame, text string) model.EvidenceRef {
		return model.EvidenceRef{Kind: "frame", ID: fmt.Sprintf("%d", frame.AtMS), TS: frame.AtMS, Text: text}
	}
	type keyed struct {
		label string
		value string
		ev    model.EvidenceRef
	}
	devices := func(f *model.Frame) map[string]keyed {
		m := map[string]keyed{}
		for _, d := range f.Devices {
			m[d.ID] = keyed{label: d.Label, value: d.Vendor, ev: ev(f, "device "+d.Label)}
		}
		return m
	}
	dests := func(f *model.Frame) map[string]keyed {
		m := map[string]keyed{}
		for _, d := range f.Destinations {
			m[d.Key] = keyed{label: d.Label, value: fmt.Sprintf("%d/%d", d.BytesOut, d.BytesIn), ev: ev(f, "destination "+d.Label)}
		}
		return m
	}
	wifi := func(f *model.Frame) map[string]keyed {
		m := map[string]keyed{}
		for _, w := range f.WiFi {
			m[w.BSSID] = keyed{label: w.SSID, value: fmt.Sprintf("%s ch%d", w.Security, w.Channel), ev: ev(f, "Wi-Fi "+w.SSID)}
		}
		return m
	}
	sensors := func(f *model.Frame) map[string]keyed {
		m := map[string]keyed{}
		for _, sn := range f.Sensors {
			m[sn.Name] = keyed{label: sn.Name, value: sn.Version, ev: ev(f, "sensor "+sn.Name)}
		}
		return m
	}
	dns := func(f *model.Frame) map[string]keyed {
		m := map[string]keyed{}
		for _, q := range f.DNS {
			m[q.QName] = keyed{label: q.QName, value: q.RCode, ev: ev(f, "lookup "+q.QName)}
		}
		return m
	}
	anomalies := func(f *model.Frame) map[string]keyed {
		m := map[string]keyed{}
		for _, an := range f.Anomalies {
			m[an.Kind+"|"+an.Device+"|"+an.Entity] = keyed{label: an.Summary, value: an.Severity, ev: ev(f, "anomaly "+an.Kind)}
		}
		return m
	}
	compare := func(kind string, am, bm map[string]keyed) {
		for k, av := range am {
			bv, ok := bm[k]
			if !ok {
				out.Removed = append(out.Removed, model.DiffItem{Kind: kind, Key: k, Label: av.label, Before: av.value, Evidence: []model.EvidenceRef{av.ev}})
				continue
			}
			if av.value != bv.value || av.label != bv.label {
				out.Changed = append(out.Changed, model.DiffItem{Kind: kind, Key: k, Label: bv.label, Before: av.value, After: bv.value, Evidence: []model.EvidenceRef{av.ev, bv.ev}})
			}
		}
		for k, bv := range bm {
			if _, ok := am[k]; !ok {
				out.Added = append(out.Added, model.DiffItem{Kind: kind, Key: k, Label: bv.label, After: bv.value, Evidence: []model.EvidenceRef{bv.ev}})
			}
		}
	}
	compare("device", devices(fa), devices(fb))
	compare("destination", dests(fa), dests(fb))
	compare("wifi", wifi(fa), wifi(fb))
	compare("sensor", sensors(fa), sensors(fb))
	compare("dns", dns(fa), dns(fb))
	compare("anomaly", anomalies(fa), anomalies(fb))
	sortDiff := func(items []model.DiffItem) {
		slices.SortFunc(items, func(a, b model.DiffItem) int {
			return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Key, b.Key))
		})
	}
	sortDiff(out.Added)
	sortDiff(out.Removed)
	sortDiff(out.Changed)
	if len(out.Added)+len(out.Removed)+len(out.Changed) == 0 {
		out.Gaps = append(out.Gaps, "no differences in the selected layers")
	}
	return out, nil
}
