package store

import (
	"cmp"
	"context"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	wifipkg "github.com/xen0bit/netgraph/internal/wifi"
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
	rep, err := s.Anomalies(ctx, f)
	if err != nil {
		return nil, err
	}
	for _, a := range rep.Anomalies {
		if model.SeverityRank(a.Severity) < model.SeverityRank(model.SeverityMedium) {
			continue
		}
		ev := []model.EvidenceRef{{Kind: "anomaly", ID: a.Kind + ":" + time.UnixMilli(a.TS).UTC().Format(time.RFC3339), TS: a.TS, Text: a.Summary}}
		add(model.ExposureFinding{Kind: a.Kind, Severity: a.Severity, Entity: firstNonEmpty(a.Device, a.Entity), Label: a.DeviceName, Summary: a.Summary, Evidence: ev})
	}
	wifi, err := s.WiFi(ctx, f)
	if err != nil {
		return nil, err
	}
	for _, n := range wifi {
		// An empty security is a network only heard through its clients, not
		// an open one: the sensor has not seen its beacon.
		var sev string
		switch n.Security {
		case wifipkg.Open, wifipkg.WEP:
			sev = model.SeverityHigh
		case wifipkg.WPA:
			sev = model.SeverityMedium
		default:
			continue
		}
		add(model.ExposureFinding{
			Kind: "wifi_weak_security", Severity: sev, Entity: model.EntityID(model.KindSSID, strings.ToLower(n.SSID)),
			Label: n.SSID, Summary: firstNonEmpty(n.SSID, n.BSSID) + " uses " + n.Security + " security",
			Evidence: []model.EvidenceRef{{Kind: "wifi", ID: n.BSSID, TS: n.LastSeen, Text: n.SSID}},
		})
	}
	devs, err := s.Devices(ctx, f)
	if err != nil {
		return nil, err
	}
	for _, d := range devs {
		ev := []model.EvidenceRef{{Kind: "entity", ID: d.ID, TS: d.LastSeen, Text: d.Label}}
		// Reachable from outside is exposure; a printer serving the LAN is
		// only inventory.
		switch {
		case len(d.Serves) > 0 && d.Inbound > 0:
			add(model.ExposureFinding{Kind: "inbound_service", Severity: model.SeverityMedium, Entity: d.ID, Label: d.Label,
				Summary: d.Label + " serves " + strings.Join(d.Serves, ", ") + " to clients outside", Evidence: ev})
		case len(d.Serves) > 0:
			add(model.ExposureFinding{Kind: "local_service", Severity: model.SeverityLow, Entity: d.ID, Label: d.Label,
				Summary: d.Label + " serves " + strings.Join(d.Serves, ", ") + " on the network", Evidence: ev})
		}
		if d.Randomized && d.Inbound > 0 {
			add(model.ExposureFinding{Kind: "inbound_to_private_address", Severity: model.SeverityLow, Entity: d.ID, Label: d.Label,
				Summary: d.Label + " has a randomized address and accepts inbound connections", Evidence: ev})
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

// Coverage reports which sensors saw which devices, and where a device may be
// hidden by a blind spot.
func (s *Store) Coverage(ctx context.Context, f model.Filter) (*model.CoverageReport, error) {
	from, to := s.window(f)
	out := &model.CoverageReport{FromMS: from, ToMS: to, Sensors: []model.CoverageSensor{}, Devices: []model.CoverageDevice{}}
	type dev struct {
		key, label string
		sensors    map[string]bool
	}
	devs := map[int64]*dev{}
	rows, err := s.r.QueryContext(ctx, `SELECT c.client_device, e.key, coalesce(nullif(e.label,''), e.key), n.name
		FROM connections c
		JOIN entities e ON e.id = c.client_device AND e.kind = 'device'
		JOIN sensors n ON n.id = c.sensor_id
		WHERE c.first_seen < ? AND c.last_seen >= ?
		GROUP BY c.client_device, c.sensor_id`, to, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var key, label, sensor string
		if err := rows.Scan(&id, &key, &label, &sensor); err != nil {
			return nil, err
		}
		d := devs[id]
		if d == nil {
			d = &dev{key: key, label: label, sensors: map[string]bool{}}
			devs[id] = d
		}
		d.sensors[sensor] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	for _, d := range devs {
		ss := make([]string, 0, len(d.sensors))
		for name := range d.sensors {
			ss = append(ss, name)
		}
		slices.Sort(ss)
		out.Devices = append(out.Devices, model.CoverageDevice{
			Device: model.EntityID(model.KindDevice, d.key), Label: d.label, Sensors: ss, OnlyOne: len(ss) == 1,
		})
	}
	slices.SortFunc(out.Devices, func(a, b model.CoverageDevice) int {
		return cmp.Or(cmp.Compare(a.Label, b.Label), cmp.Compare(a.Device, b.Device))
	})
	sensors, err := s.Sensors(ctx)
	if err != nil {
		return nil, err
	}
	for _, sn := range sensors {
		cs := model.CoverageSensor{Name: sn.Name, LastSeen: sn.LastSeen, Version: sn.Version, Interfaces: sn.Interfaces}
		for _, d := range out.Devices {
			if slices.Contains(d.Sensors, sn.Name) {
				cs.Devices++
				if d.OnlyOne {
					cs.OnlyDevice++
				}
			}
		}
		out.Sensors = append(out.Sensors, cs)
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
	// The anomaly engine names a new access point by BSSID. An open twin is
	// named only by SSID, and of that SSID's radios it is the open ones.
	rep, err := s.Anomalies(ctx, f)
	if err != nil {
		return nil, err
	}
	rogueBSSID, rogueSSID := map[string]bool{}, map[string]bool{}
	for _, a := range rep.Anomalies {
		switch {
		case a.Kind != model.AnomalyRogueAP:
		case a.Device != "":
			rogueBSSID[strings.TrimPrefix(a.Device, model.KindDevice+":")] = true
		case a.Severity == model.SeverityHigh:
			rogueSSID[a.Entity] = true
		}
	}
	for _, n := range wifi {
		an := model.AirspaceNetwork{BSSID: n.BSSID, SSID: n.SSID, Security: n.Security, Channel: n.Channel, FirstSeen: n.FirstSeen, LastSeen: n.LastSeen}
		an.Rogue = rogueBSSID[n.BSSID] || (n.Security == wifipkg.Open && rogueSSID[model.EntityID(model.KindSSID, strings.ToLower(n.SSID))])
		rows, err := s.r.QueryContext(ctx, `SELECT coalesce(nullif(d.label,''), d.key)
			FROM facts a JOIN entities d ON d.id = a.src
			WHERE a.rel = 'associates' AND a.dst = (SELECT id FROM entities WHERE kind = 'device' AND key = ?)
			  AND a.first_seen < ? AND a.last_seen >= ?
			GROUP BY d.id ORDER BY 1`, n.BSSID, to, from)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var label string
			if err := rows.Scan(&label); err != nil {
				rows.Close()
				return nil, err
			}
			an.Clients = append(an.Clients, label)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
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
	// Timeseries picks a round step, and may widen it to what the data at
	// this age can answer, so the step reported is the one it used.
	series, err := s.Timeseries(ctx, f, 0)
	if err != nil {
		return nil, err
	}
	step := series.StepMS
	out := &model.WeatherReport{FromMS: from, ToMS: to, StepMS: step, Points: []model.WeatherPoint{}}
	var whole []float64
	for _, b := range series.Buckets {
		out.Points = append(out.Points, model.WeatherPoint{TS: b.TS, BytesOut: b.BytesOut, BytesIn: b.BytesIn, Flows: b.FlowsNew, DNS: b.DNSQueries, Devices: b.Devices})
		// A bucket the window cuts through holds part of a step's traffic
		// and would drag the mean down.
		if b.TS >= from && b.TS+step <= to {
			whole = append(whole, float64(b.BytesOut+b.BytesIn))
		}
	}
	// Up to the last 24 whole buckets, then six forecast buckets.
	if n := min(24, len(whole)); n > 0 {
		var sum, sum2 float64
		for _, v := range whole[len(whole)-n:] {
			sum += v
			sum2 += v * v
		}
		mean := sum / float64(n)
		sd := math.Sqrt(max(0, sum2/float64(n)-mean*mean))
		next := series.Buckets[len(series.Buckets)-1].TS + step
		for i := range int64(6) {
			out.Points = append(out.Points, model.WeatherPoint{
				TS: next + i*step, Lower: uint64(max(0, mean-sd)), Upper: uint64(mean + sd), Forecast: true,
			})
		}
	} else {
		out.Gaps = append(out.Gaps, "no whole bucket to forecast from")
	}
	if series.Precision != model.PrecisionExact {
		out.Gaps = append(out.Gaps, "the window is answered from hourly rollups")
	}
	out.Gaps = append(out.Gaps, "forecast is a moving mean over observed buckets, not a seasonal model")
	return out, nil
}
