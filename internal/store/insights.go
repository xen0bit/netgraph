package store

import (
	"cmp"
	"context"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

// Exposure builds a read-only inventory of reachable or weak things. It is
// deliberately explainable: every finding is backed by the same records as
// the rest of the API, and it is not a vulnerability scan.
func (s *Store) Exposure(ctx context.Context, f model.Filter) (*model.ExposureReport, error) {
	from, to := s.window(f)
	out := &model.ExposureReport{FromMS: from, ToMS: to, Findings: []model.ExposureFinding{}}
	seen := map[string]bool{}
	add := func(x model.ExposureFinding) {
		k := x.Kind + "|" + x.Entity + "|" + x.Summary
		if seen[k] {
			return
		}
		seen[k] = true
		out.Findings = append(out.Findings, x)
	}
	if rep, err := s.Anomalies(ctx, f); err == nil {
		for _, a := range rep.Anomalies {
			if model.SeverityRank(a.Severity) < model.SeverityRank(model.SeverityMedium) {
				continue
			}
			ev := []model.EvidenceRef{{Kind: "anomaly", ID: a.Kind + ":" + time.UnixMilli(a.TS).UTC().Format(time.RFC3339), TS: a.TS, Text: a.Summary}}
			add(model.ExposureFinding{Kind: a.Kind, Severity: a.Severity, Entity: a.Entity, Label: a.DeviceName, Summary: a.Summary, Evidence: ev})
		}
	}
	if wifi, err := s.WiFi(ctx, f); err == nil {
		for _, n := range wifi {
			sec := strings.ToUpper(n.Security)
			if n.Security == "" || strings.Contains(sec, "WEP") || strings.Contains(sec, "TKIP") {
				sev := model.SeverityMedium
				if strings.Contains(sec, "WEP") || n.Security == "" {
					sev = model.SeverityHigh
				}
				add(model.ExposureFinding{
					Kind: "wifi_weak_security", Severity: sev, Entity: model.EntityID(model.KindSSID, strings.ToLower(n.SSID)),
					Label: n.SSID, Summary: n.SSID + " uses " + firstNonEmpty(n.Security, "open") + " security",
					Evidence: []model.EvidenceRef{{Kind: "wifi", ID: n.BSSID, TS: n.LastSeen, Text: n.SSID}},
				})
			}
		}
	}
	if devs, err := s.Devices(ctx, f); err == nil {
		for _, d := range devs {
			if len(d.Serves) > 0 {
				add(model.ExposureFinding{
					Kind: "inbound_service", Severity: model.SeverityMedium, Entity: d.ID, Label: d.Label,
					Summary:  d.Label + " serves " + strings.Join(d.Serves, ", ") + " to clients",
					Evidence: []model.EvidenceRef{{Kind: "entity", ID: d.ID, TS: d.LastSeen, Text: d.Label}},
				})
			}
			if d.Randomized && d.Inbound > 0 {
				add(model.ExposureFinding{
					Kind: "inbound_to_private_address", Severity: model.SeverityLow, Entity: d.ID, Label: d.Label,
					Summary:  d.Label + " has a randomized address and accepts inbound connections",
					Evidence: []model.EvidenceRef{{Kind: "entity", ID: d.ID, TS: d.LastSeen, Text: d.Label}},
				})
			}
		}
	}
	now := s.cfg.Now().UnixMilli()
	if sensors, err := s.Sensors(ctx); err == nil {
		for _, sn := range sensors {
			if now-sn.LastSeen > 5*60_000 {
				add(model.ExposureFinding{
					Kind: model.AnomalySensorSilent, Severity: model.SeverityMedium, Entity: model.EntityID(model.KindSensor, sn.Name),
					Label: sn.Name, Summary: "sensor " + sn.Name + " has not reported recently",
					Evidence: []model.EvidenceRef{{Kind: "sensor", ID: sn.Name, TS: sn.LastSeen, Text: sn.Name}},
				})
			}
		}
	}
	slices.SortFunc(out.Findings, func(a, b model.ExposureFinding) int {
		return cmp.Or(cmp.Compare(model.SeverityRank(b.Severity), model.SeverityRank(a.Severity)),
			cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Entity, b.Entity), cmp.Compare(a.Summary, b.Summary))
	})
	out.Gaps = append(out.Gaps,
		"passive observation only: this is not a vulnerability scan",
		"encrypted DNS and blocked probes are invisible",
	)
	return out, nil
}

// Coverage reports which sensors saw which devices, and where a devicemay be
// hidden by a blind spot.
func (s *Store) Coverage(ctx context.Context, f model.Filter) (*model.CoverageReport, error) {
	from, to := s.window(f)
	out := &model.CoverageReport{FromMS: from, ToMS: to, Sensors: []model.CoverageSensor{}, Devices: []model.CoverageDevice{}}
	names := map[int64]string{}
	if rows, err := s.r.QueryContext(ctx, `SELECT id, name FROM sensors`); err == nil {
		for rows.Next() {
			var id int64
			var name string
			if rows.Scan(&id, &name) == nil {
				names[id] = name
			}
		}
		rows.Close()
	}
	type dev struct {
		key, label string
		sensors    map[string]bool
		flows      int
	}
	devs := map[int64]*dev{}
	if rows, err := s.r.QueryContext(ctx, `SELECT id, key, coalesce(nullif(label,''), key) FROM entities WHERE kind = 'device'`); err == nil {
		for rows.Next() {
			var id int64
			var key, label string
			if rows.Scan(&id, &key, &label) == nil {
				devs[id] = &dev{key: key, label: label, sensors: map[string]bool{}}
			}
		}
		rows.Close()
	}
	if rows, err := s.r.QueryContext(ctx, `SELECT client_device, sensor_id, count(*) FROM connections
		WHERE client_device != 0 AND first_seen < ? AND last_seen >= ? GROUP BY client_device, sensor_id`, to, from); err == nil {
		for rows.Next() {
			var id, sid int64
			var n int
			if rows.Scan(&id, &sid, &n) != nil {
				continue
			}
			d := devs[id]
			if d == nil {
				continue
			}
			if name := names[sid]; name != "" {
				d.sensors[name] = true
			}
			d.flows += n
		}
		rows.Close()
	}
	for _, d := range devs {
		ss := make([]string, 0, len(d.sensors))
		for name := range d.sensors {
			ss = append(ss, name)
		}
		slices.Sort(ss)
		if len(ss) == 0 {
			continue
		}
		out.Devices = append(out.Devices, model.CoverageDevice{
			Device: model.EntityID(model.KindDevice, d.key), Label: d.label, Sensors: ss, OnlyOne: len(ss) == 1,
		})
	}
	slices.SortFunc(out.Devices, func(a, b model.CoverageDevice) int { return cmp.Compare(a.Label, b.Label) })
	if sensors, err := s.Sensors(ctx); err == nil {
		for _, sn := range sensors {
			cs := model.CoverageSensor{Name: sn.Name, LastSeen: sn.LastSeen, Version: sn.Version, Interfaces: sn.Interfaces}
			for _, d := range out.Devices {
				for _, name := range d.Sensors {
					if name == sn.Name {
						cs.Devices++
						if d.OnlyOne {
							cs.OnlyDevice++
						}
					}
				}
			}
			out.Sensors = append(out.Sensors, cs)
		}
	}
	out.Gaps = append(out.Gaps,
		"coverage is where traffic was observed, not an RF survey",
		"a device with one sensor may simply have been quiet elsewhere",
	)
	return out, nil
}

// Airspace is the time-aware Wi-Fi view: APs, clients, channels and rogue
// flags from the same Wi-Fi facts the rest of netgraph uses.
func (s *Store) Airspace(ctx context.Context, f model.Filter) (*model.AirspaceReport, error) {
	from, to := s.window(f)
	out := &model.AirspaceReport{FromMS: from, ToMS: to, Networks: []model.AirspaceNetwork{}}
	wifi, err := s.WiFi(ctx, f)
	if err != nil {
		return nil, err
	}
	rogue := map[string]bool{}
	if rep, err := s.Anomalies(ctx, f); err == nil {
		for _, a := range rep.Anomalies {
			if a.Kind == model.AnomalyRogueAP {
				rogue[a.Summary] = true
			}
		}
	}
	for _, n := range wifi {
		an := model.AirspaceNetwork{BSSID: n.BSSID, SSID: n.SSID, Security: n.Security, Channel: n.Channel, FirstSeen: n.FirstSeen, LastSeen: n.LastSeen}
		rows, err := s.r.QueryContext(ctx, `SELECT d.key, coalesce(nullif(d.label,''), d.key)
			FROM facts a JOIN entities d ON d.id = a.src
			WHERE a.rel = 'associates' AND a.dst = (SELECT id FROM entities WHERE kind = 'device' AND key = ?)
			  AND a.first_seen < ? AND a.last_seen >= ?`, n.BSSID, to, from)
		if err == nil {
			for rows.Next() {
				var key, label string
				if rows.Scan(&key, &label) == nil {
					an.Clients = append(an.Clients, label)
				}
			}
			rows.Close()
		}
		for summary := range rogue {
			if strings.Contains(summary, n.SSID) || strings.Contains(summary, n.BSSID) {
				an.Rogue = true
			}
		}
		out.Networks = append(out.Networks, an)
	}
	slices.SortFunc(out.Networks, func(a, b model.AirspaceNetwork) int {
		return cmp.Or(cmp.Compare(a.Channel, b.Channel), cmp.Compare(a.SSID, b.SSID), cmp.Compare(a.BSSID, b.BSSID))
	})
	out.Gaps = append(out.Gaps, "only channels covered by a monitor-mode sensor are visible")
	return out, nil
}

// Weather is a simple, explainable traffic forecast: a moving mean and a
// band over the observed buckets, never a claim about unseen traffic.
func (s *Store) Weather(ctx context.Context, f model.Filter) (*model.WeatherReport, error) {
	from, to := s.window(f)
	span := time.Duration(to-from) * time.Millisecond
	step := span / 60
	if step < time.Minute {
		step = time.Minute
	}
	if step > time.Hour {
		step = time.Hour
	}
	series, err := s.Timeseries(ctx, f, step)
	if err != nil {
		return nil, err
	}
	out := &model.WeatherReport{FromMS: from, ToMS: to, StepMS: step.Milliseconds(), Points: []model.WeatherPoint{}}
	for _, b := range series.Buckets {
		out.Points = append(out.Points, model.WeatherPoint{TS: b.TS, BytesOut: b.BytesOut, BytesIn: b.BytesIn, Flows: b.FlowsNew, DNS: b.DNSQueries, Devices: b.Devices})
	}
	// Last up to 24 observed buckets, then six forecast buckets.
	obs := out.Points
	n := min(24, len(obs))
	if n > 0 {
		var sum, sum2 float64
		for _, p := range obs[len(obs)-n:] {
			v := float64(p.BytesOut + p.BytesIn)
			sum += v
			sum2 += v * v
		}
		mean := sum / float64(n)
		sd := math.Sqrt(max(0, sum2/float64(n)-mean*mean))
		for i := 1; i <= 6; i++ {
			out.Points = append(out.Points, model.WeatherPoint{
				TS: to + int64(i)*step.Milliseconds(), Lower: uint64(max(0, mean-sd)), Upper: uint64(mean + sd), Forecast: true,
			})
		}
	} else {
		out.Gaps = append(out.Gaps, "no observed buckets to forecast from")
	}
	if series.Precision != model.PrecisionExact {
		out.Gaps = append(out.Gaps, "the window is answered from hourly rollups")
	}
	out.Gaps = append(out.Gaps, "forecast is a moving mean over observed buckets, not a seasonal model")
	return out, nil
}
