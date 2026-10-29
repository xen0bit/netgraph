package store

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/anomaly"
	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/oui"
)

const (
	// AnomalyHistory is how much history the checks that compare with it
	// need before a window: until the network has been watched this long
	// everything is new.
	AnomalyHistory = 24 * time.Hour
	// anomalyBaseline is how far back "never before" and "its busiest
	// hour" look.
	anomalyBaseline = 7 * 24 * time.Hour
	// A device that reached at most this many destinations in the baseline
	// is predictable (a plug, a camera): anything new from it stands out.
	stableDestinations = 30
	// Per device, at most this many new destinations are reported one by
	// one; the rest are summed up.
	maxNewPerDevice = 10
)

type anomalyDevice struct {
	id, mac, name, role string
	first, joined       int64
	randomized          bool
	vendor              string
}

// Anomalies runs the anomaly checks over a window. Without a day of history
// before the window (Learning) it runs only those that need none: beacons,
// failed lookups, DNS tunnels and access points disagreeing on security.
// A device filter keeps that device's anomalies; other filters are ignored.
func (s *Store) Anomalies(ctx context.Context, f model.Filter) (*model.AnomalyReport, error) {
	from, to := s.window(f)
	rep := &model.AnomalyReport{FromMS: from, ToMS: to, Anomalies: []model.Anomaly{}}
	since, err := s.FirstSensorSeen(ctx)
	if err != nil {
		return nil, err
	}
	if !since.IsZero() {
		rep.SinceMS = since.UnixMilli()
	}
	history := rep.SinceMS != 0 && from-rep.SinceMS >= AnomalyHistory.Milliseconds()
	rep.Learning = !history
	a := &anomalies{s: s, from: from, to: to, since: rep.SinceMS, devs: map[int64]*anomalyDevice{}}
	checks := []func(context.Context) error{a.newDevices, a.beacons, a.dns, a.accessPoints, a.scans, a.bruteForce}
	if history {
		checks = append(checks, a.newDestinations, a.uploadSpikes, a.newServices, a.inboundSurges)
	}
	for _, check := range checks {
		if err := check(ctx); err != nil {
			return nil, err
		}
	}
	out := a.out
	if f.Device != "" {
		ids, err := s.deviceIDs(ctx, f.Device)
		if err != nil {
			return nil, err
		}
		devs, err := a.devices(ctx, ids)
		if err != nil {
			return nil, err
		}
		keep := map[string]bool{}
		for _, d := range devs {
			keep[d.id] = true
		}
		out = slices.DeleteFunc(out, func(x model.Anomaly) bool { return !keep[x.Device] })
	}
	slices.SortFunc(out, func(x, y model.Anomaly) int {
		if c := cmp.Compare(model.SeverityRank(y.Severity), model.SeverityRank(x.Severity)); c != 0 {
			return c
		}
		return cmp.Or(cmp.Compare(x.TS, y.TS), cmp.Compare(x.Kind, y.Kind), cmp.Compare(x.Device, y.Device), cmp.Compare(x.Entity, y.Entity))
	})
	rep.Anomalies = append(rep.Anomalies, out...)
	return rep, nil
}

type anomalies struct {
	s        *Store
	from, to int64
	since    int64
	devs     map[int64]*anomalyDevice
	out      []model.Anomaly
}

func (a *anomalies) add(x model.Anomaly) { a.out = append(a.out, x) }

// devices loads the named device entities, cached across checks.
func (a *anomalies) devices(ctx context.Context, ids []int64) (map[int64]*anomalyDevice, error) {
	var missing []int64
	for _, id := range ids {
		if _, ok := a.devs[id]; !ok && id != 0 {
			missing = append(missing, id)
		}
	}
	for chunk := range slices.Chunk(missing, 500) {
		rows, err := a.s.r.QueryContext(ctx, `SELECT id, key, label, first_seen, attrs FROM entities WHERE kind = 'device' AND id IN (`+idList(chunk)+`)`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, first int64
			var mac, label, attrs string
			if err := rows.Scan(&id, &mac, &label, &first, &attrs); err != nil {
				rows.Close()
				return nil, err
			}
			a.devs[id] = newAnomalyDevice(mac, label, first, attrs)
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	out := map[int64]*anomalyDevice{}
	for _, id := range ids {
		if d := a.devs[id]; d != nil {
			out[id] = d
		}
	}
	return out, nil
}

func newAnomalyDevice(mac, label string, first int64, attrs string) *anomalyDevice {
	var m map[string]string
	_ = json.Unmarshal([]byte(attrs), &m)
	d := &anomalyDevice{id: model.EntityID(model.KindDevice, mac), mac: mac, name: deviceLabel(mac, label, m), role: m["role"], first: first, vendor: m["vendor"]}
	d.joined, _ = strconv.ParseInt(m["joined"], 10, 64)
	if d.vendor == oui.Randomized {
		d.vendor, d.randomized = "", true
	}
	return d
}

// who is the device a row belongs to: its entity, else its address.
func (a *anomalies) who(devs map[int64]*anomalyDevice, dev int64, ip string) (id, name string) {
	if d := devs[dev]; d != nil {
		return d.id, d.name
	}
	return "", ip
}

// newDevices: a device used an address on the LAN for the first time in the
// window, the same event as a new-device alert, after the same day of
// learning.
func (a *anomalies) newDevices(ctx context.Context) error {
	rows, err := a.s.r.QueryContext(ctx, `SELECT key, label, first_seen, attrs FROM entities
		WHERE kind = 'device' AND json_valid(attrs)
		AND CAST(json_extract(attrs, '$.joined') AS INTEGER) >= ? AND CAST(json_extract(attrs, '$.joined') AS INTEGER) < ?`, a.from, a.to)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var mac, label, attrs string
		var first int64
		if err := rows.Scan(&mac, &label, &first, &attrs); err != nil {
			return err
		}
		d := newAnomalyDevice(mac, label, first, attrs)
		if d.role == "router" || a.since == 0 || d.joined-a.since < AnomalyHistory.Milliseconds() {
			continue
		}
		sev, who := model.SeverityMedium, d.vendor
		if d.randomized {
			// Phones join each network with a private MAC, and some
			// rotate it: a new one is weaker evidence.
			sev, who = model.SeverityLow, "private MAC"
		}
		ev := map[string]string{"mac": d.mac, "joined": strconv.FormatInt(d.joined, 10)}
		if d.vendor != "" {
			ev["vendor"] = d.vendor
		}
		a.add(model.Anomaly{Kind: model.AnomalyNewDevice, Severity: sev, TS: d.joined, Device: d.id, DeviceName: d.name,
			Summary: strings.TrimSpace(fmt.Sprintf("%s joined the network (%s)", d.name, cmp.Or(who, d.mac))), Evidence: ev})
	}
	return rows.Err()
}

// destKey is how the destination checks name where a connection went: its
// site when it was reached by name, else its address.
func destKey(name, ip string) string {
	if name != "" {
		return model.EntityID(model.KindSite, graph.Site(name))
	}
	return model.EntityID(model.KindIP, ip)
}

const connName = `coalesce(nullif(c.sni, ''), nullif(c.http_host, ''), nullif(c.qname, ''), '')`

// newDestinations: a device with history reached a site (or an unnamed
// address) it had not in the last week. From a predictable device anything
// new counts; from a busy one (a laptop browsing) only what it uploaded
// real data to.
func (a *anomalies) newDestinations(ctx context.Context) error {
	type dest struct {
		key      string
		names    map[string]bool
		up       float64
		conns    int
		first    int64
		dev      int64
		clientIP string
	}
	rows, err := a.s.r.QueryContext(ctx, `SELECT c.client_device, c.client_ip, `+connName+`, c.remote_ip, sum(`+connBytes("bytes_out", a.from, a.to)+`), count(*), min(c.first_seen)
		FROM connections c WHERE c.last_seen >= ? AND c.first_seen < ? AND c.client_device != 0 AND c.direction = 'out' AND c.multicast = 0
		GROUP BY 1, 2, 3, 4`, a.from, a.to)
	if err != nil {
		return err
	}
	window := map[int64]map[string]*dest{}
	for rows.Next() {
		var dev, n, first int64
		var cip, name, rip string
		var up float64
		if err := rows.Scan(&dev, &cip, &name, &rip, &up, &n, &first); err != nil {
			rows.Close()
			return err
		}
		k := destKey(name, rip)
		if window[dev] == nil {
			window[dev] = map[string]*dest{}
		}
		d := window[dev][k]
		if d == nil {
			d = &dest{key: k, names: map[string]bool{}, first: first, dev: dev, clientIP: cip}
			window[dev][k] = d
		}
		if name != "" {
			d.names[name] = true
		}
		d.up += up
		d.conns += int(n)
		d.first = min(d.first, first)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(window) == 0 {
		return nil
	}
	// Where each device, and the network, went before the window: whole
	// hours from the rollups, and the raw connections of the hours the
	// window cuts into.
	base := a.from - anomalyBaseline.Milliseconds()
	seen := map[int64]map[string]bool{}
	network := map[string]bool{}
	note := func(dev int64, k string) {
		if seen[dev] == nil {
			seen[dev] = map[string]bool{}
		}
		seen[dev][k] = true
		network[k] = true
	}
	rows, err = a.s.r.QueryContext(ctx, `SELECT client_device, name, remote_ip FROM traffic_hourly
		WHERE bucket >= ? AND bucket + 3600000 <= ? AND multicast = 0 AND direction != 'in' GROUP BY 1, 2, 3`, base, a.from)
	if err != nil {
		return err
	}
	for rows.Next() {
		var dev int64
		var name, rip string
		if err := rows.Scan(&dev, &name, &rip); err != nil {
			rows.Close()
			return err
		}
		note(dev, destKey(name, rip))
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = a.s.r.QueryContext(ctx, `SELECT c.client_device, `+connName+`, c.remote_ip FROM connections c
		WHERE c.first_seen < ? AND c.last_seen >= ? AND c.multicast = 0 AND c.direction != 'in' GROUP BY 1, 2, 3`, a.from, a.from-2*time.Hour.Milliseconds())
	if err != nil {
		return err
	}
	for rows.Next() {
		var dev int64
		var name, rip string
		if err := rows.Scan(&dev, &name, &rip); err != nil {
			rows.Close()
			return err
		}
		note(dev, destKey(name, rip))
	}
	if err := rows.Close(); err != nil {
		return err
	}

	devs, err := a.devices(ctx, slices.Collect(maps.Keys(window)))
	if err != nil {
		return err
	}
	for _, dev := range slices.Sorted(maps.Keys(window)) {
		d := devs[dev]
		if d == nil || a.from-d.first < AnomalyHistory.Milliseconds() {
			continue // a device without history: everything is new
		}
		known := len(seen[dev])
		stable := known <= stableDestinations
		var found []model.Anomaly
		for _, k := range slices.Sorted(maps.Keys(window[dev])) {
			x := window[dev][k]
			if seen[dev][k] {
				continue
			}
			fresh := !network[k]
			var sev string
			switch {
			case stable && fresh && x.up >= 10<<20:
				sev = model.SeverityHigh
			case stable:
				sev = model.SeverityMedium
			case fresh && x.up >= 50<<20:
				sev = model.SeverityMedium
			case x.up >= 1<<20:
				sev = model.SeverityLow
			default:
				continue
			}
			_, label, _ := model.SplitEntityID(k)
			names := slices.Sorted(maps.Keys(x.names))
			if len(names) == 1 {
				label = names[0]
			}
			where := "for the first time"
			if fresh {
				where = "for the first time on this network"
			}
			ev := map[string]string{"uploaded": model.FormatBytes(uint64(x.up)), "connections": strconv.Itoa(x.conns),
				"history": fmt.Sprintf("%d destinations in the last 7 days", known)}
			if len(names) > 0 {
				ev["names"] = strings.Join(names[:min(len(names), 5)], ",")
			}
			if fresh {
				ev["network"] = "new"
			}
			found = append(found, model.Anomaly{Kind: model.AnomalyNewDestination, Severity: sev, TS: max(x.first, a.from), Device: d.id, DeviceName: d.name, Entity: k,
				Summary: fmt.Sprintf("%s reached %s %s (%s up)", d.name, label, where, model.FormatBytes(uint64(x.up))), Evidence: ev})
		}
		slices.SortStableFunc(found, func(x, y model.Anomaly) int {
			return cmp.Compare(model.SeverityRank(y.Severity), model.SeverityRank(x.Severity))
		})
		if len(found) > maxNewPerDevice {
			rest := found[maxNewPerDevice:]
			var keys []string
			for _, x := range rest {
				keys = append(keys, x.Entity)
			}
			found = append(found[:maxNewPerDevice], model.Anomaly{Kind: model.AnomalyNewDestination, Severity: model.SeverityLow, TS: rest[0].TS,
				Device: d.id, DeviceName: d.name, Summary: fmt.Sprintf("%s reached %d more destinations for the first time", d.name, len(rest)),
				Evidence: map[string]string{"destinations": strings.Join(keys[:min(len(keys), 10)], ",")}})
		}
		a.out = append(a.out, found...)
	}
	return nil
}

// uploadSpikes: a device sent more in the window, per hour, than in any
// hour of its last week and several times its usual hour. Only connections
// the device opened count: a server answering its clients is not uploading.
func (a *anomalies) uploadSpikes(ctx context.Context) error {
	rows, err := a.s.r.QueryContext(ctx, `SELECT c.client_device, sum(`+connBytes("bytes_out", a.from, a.to)+`), min(c.first_seen)
		FROM connections c WHERE c.last_seen >= ? AND c.first_seen < ? AND c.client_device != 0 AND c.multicast = 0 AND c.direction != 'in' GROUP BY 1`, a.from, a.to)
	if err != nil {
		return err
	}
	up := map[int64]float64{}
	first := map[int64]int64{}
	for rows.Next() {
		var dev, ts int64
		var b float64
		if err := rows.Scan(&dev, &b, &ts); err != nil {
			rows.Close()
			return err
		}
		up[dev], first[dev] = b, ts
	}
	if err := rows.Close(); err != nil {
		return err
	}
	hours := map[int64][]float64{}
	rows, err = a.s.r.QueryContext(ctx, `SELECT client_device, sum(bytes_out) FROM traffic_hourly
		WHERE bucket >= ? AND bucket + 3600000 <= ? AND multicast = 0 AND client_device != 0 AND direction != 'in' GROUP BY client_device, bucket HAVING sum(bytes_out) > 0`,
		a.from-anomalyBaseline.Milliseconds(), a.from)
	if err != nil {
		return err
	}
	for rows.Next() {
		var dev int64
		var b float64
		if err := rows.Scan(&dev, &b); err != nil {
			rows.Close()
			return err
		}
		hours[dev] = append(hours[dev], b)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	devs, err := a.devices(ctx, slices.Collect(maps.Keys(up)))
	if err != nil {
		return err
	}
	// A window shorter than an hour is compared as it is: its total is a
	// lower bound on that hour's.
	span := max(float64(a.to-a.from)/float64(time.Hour.Milliseconds()), 1)
	for _, dev := range slices.Sorted(maps.Keys(up)) {
		d := devs[dev]
		if d == nil {
			continue
		}
		rate := up[dev] / span
		spike, high, median, peak := anomaly.Spike(rate, hours[dev])
		if !spike {
			continue
		}
		sev := model.SeverityMedium
		if high {
			sev = model.SeverityHigh
		}
		a.add(model.Anomaly{Kind: model.AnomalyUploadSpike, Severity: sev, TS: max(first[dev], a.from), Device: d.id, DeviceName: d.name,
			Summary: fmt.Sprintf("%s sent %s (%s an hour); its busiest hour in the last 7 days was %s, a typical one %s", d.name,
				model.FormatBytes(uint64(up[dev])), model.FormatBytes(uint64(rate)), model.FormatBytes(uint64(peak)), model.FormatBytes(uint64(median))),
			Evidence: map[string]string{"uploaded": model.FormatBytes(uint64(up[dev])), "per_hour": model.FormatBytes(uint64(rate)),
				"busiest_hour": model.FormatBytes(uint64(peak)), "typical_hour": model.FormatBytes(uint64(median)), "hours": strconv.Itoa(len(hours[dev]))}})
	}
	return nil
}

// beacons: connections from a device to one destination opening on a fixed
// period. Names, NTP and DNS are excluded; a period to an unnamed address is
// the classic shape of malware calling home.
func (a *anomalies) beacons(ctx context.Context) error {
	if a.to-a.from < 5*time.Minute.Milliseconds() {
		return nil
	}
	rows, err := a.s.r.QueryContext(ctx, `SELECT c.client_device, c.client_ip, `+connName+`, c.remote_ip, c.remote_port, c.proto, c.first_seen
		FROM connections c WHERE c.first_seen >= ? AND c.first_seen < ? AND c.direction = 'out' AND c.multicast = 0
		AND c.remote_port NOT IN (53, 123, 853, 5353) LIMIT 200000`, a.from, a.to)
	if err != nil {
		return err
	}
	type series struct {
		dev     int64
		ip, key string
		name    string
		port    int
		proto   int
		starts  []int64
	}
	all := map[string]*series{}
	for rows.Next() {
		var dev, ts int64
		var cip, name, rip string
		var port, proto int
		if err := rows.Scan(&dev, &cip, &name, &rip, &port, &proto, &ts); err != nil {
			rows.Close()
			return err
		}
		k := destKey(name, rip)
		id := fmt.Sprintf("%d|%s|%s", dev, cip, k)
		if dev != 0 {
			id = fmt.Sprintf("%d||%s", dev, k)
		}
		sr := all[id]
		if sr == nil {
			sr = &series{dev: dev, ip: cip, key: k, name: name, port: port, proto: proto}
			all[id] = sr
		}
		sr.starts = append(sr.starts, ts)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var ids []int64
	for _, sr := range all {
		ids = append(ids, sr.dev)
	}
	devs, err := a.devices(ctx, ids)
	if err != nil {
		return err
	}
	for _, id := range slices.Sorted(maps.Keys(all)) {
		sr := all[id]
		p, ok := anomaly.Beacon(sr.starts)
		if !ok {
			continue
		}
		devID, name := a.who(devs, sr.dev, sr.ip)
		_, label, _ := model.SplitEntityID(sr.key)
		sev := model.SeverityLow
		if sr.name == "" {
			sev = model.SeverityMedium
			label = fmt.Sprintf("%s port %d", label, sr.port)
		} else {
			label = sr.name
		}
		period := time.Duration(p.Period) * time.Millisecond
		a.add(model.Anomaly{Kind: model.AnomalyBeacon, Severity: sev, TS: slices.Min(sr.starts), Device: devID, DeviceName: name, Entity: sr.key,
			Summary: fmt.Sprintf("%s connects to %s every %s (±%.0f%%), %d times", name, label, period.Round(time.Second), p.Jitter*100, p.Events),
			Evidence: map[string]string{"period": period.Round(time.Second).String(), "jitter": fmt.Sprintf("%.1f%%", p.Jitter*100),
				"events": strconv.Itoa(p.Events), "port": fmt.Sprintf("%d/%s", sr.port, protoName(sr.proto))}})
	}
	return nil
}

// dns: per device, many lookups of names that do not exist (the shape of
// malware generating domain names, or a broken device), and many long,
// unique names under one site (data smuggled out in the names).
func (a *anomalies) dns(ctx context.Context) error {
	rows, err := a.s.r.QueryContext(ctx, `SELECT client_device, client_ip, qname, rcode, min(ts) FROM dns
		WHERE ts >= ? AND ts < ? GROUP BY 1, 2, 3, 4 LIMIT 500000`, a.from, a.to)
	if err != nil {
		return err
	}
	type client struct {
		dev       int64
		ip        string
		names     map[string]bool
		nx        map[string]int64 // name -> first failure
		perSite   map[string]map[string]bool
		firstSite map[string]int64
	}
	all := map[string]*client{}
	for rows.Next() {
		var dev, ts int64
		var ip, name, rcode string
		if err := rows.Scan(&dev, &ip, &name, &rcode, &ts); err != nil {
			rows.Close()
			return err
		}
		name = strings.TrimSuffix(strings.ToLower(name), ".")
		if anomaly.LocalName(name) {
			continue
		}
		k := ip
		if dev != 0 {
			k = strconv.FormatInt(dev, 10)
		}
		c := all[k]
		if c == nil {
			c = &client{dev: dev, ip: ip, names: map[string]bool{}, nx: map[string]int64{}, perSite: map[string]map[string]bool{}, firstSite: map[string]int64{}}
			all[k] = c
		}
		c.names[name] = true
		if rcode == "NXDOMAIN" {
			if t, ok := c.nx[name]; !ok || ts < t {
				c.nx[name] = ts
			}
		}
		site := graph.Site(name)
		if c.perSite[site] == nil {
			c.perSite[site] = map[string]bool{}
			c.firstSite[site] = ts
		}
		c.perSite[site][name] = true
		c.firstSite[site] = min(c.firstSite[site], ts)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var ids []int64
	for _, c := range all {
		ids = append(ids, c.dev)
	}
	devs, err := a.devices(ctx, ids)
	if err != nil {
		return err
	}
	for _, k := range slices.Sorted(maps.Keys(all)) {
		c := all[k]
		devID, who := a.who(devs, c.dev, c.ip)
		if nx := len(c.nx); nx >= 20 && float64(nx) >= 0.3*float64(len(c.names)) {
			sev := model.SeverityMedium
			if nx >= 100 {
				sev = model.SeverityHigh
			}
			names := slices.Sorted(maps.Keys(c.nx))
			a.add(model.Anomaly{Kind: model.AnomalyDNSFailures, Severity: sev, TS: slices.Min(slices.Collect(maps.Values(c.nx))), Device: devID, DeviceName: who,
				Summary:  fmt.Sprintf("%s looked up %d names that do not exist (%d%% of its lookups)", who, nx, nx*100/len(c.names)),
				Evidence: map[string]string{"nxdomain": strconv.Itoa(nx), "names": strconv.Itoa(len(c.names)), "examples": strings.Join(names[:min(len(names), 5)], ",")}})
		}
		for _, site := range slices.Sorted(maps.Keys(c.perSite)) {
			names := slices.Sorted(maps.Keys(c.perSite[site]))
			if len(names) < 50 {
				continue
			}
			lens := make([]float64, len(names))
			for i, n := range names {
				lens[i] = float64(len(anomaly.FirstLabel(n)))
			}
			if m := anomaly.Median(lens); m < 20 {
				continue
			}
			sev := model.SeverityMedium
			if len(names) >= 500 {
				sev = model.SeverityHigh
			}
			a.add(model.Anomaly{Kind: model.AnomalyDNSTunnel, Severity: sev, TS: c.firstSite[site], Device: devID, DeviceName: who, Entity: model.EntityID(model.KindSite, site),
				Summary:  fmt.Sprintf("%s looked up %d different long names under %s, the way data is smuggled out over DNS", who, len(names), site),
				Evidence: map[string]string{"names": strconv.Itoa(len(names)), "median_label": fmt.Sprintf("%.0f", anomaly.Median(lens)), "examples": strings.Join(names[:3], ",")}})
		}
	}
	return nil
}

// accessPoints: access points broadcasting one network name with security
// that does not match (an open twin of a protected network), and, with
// history, a new access point for a network the LAN's own devices use.
func (a *anomalies) accessPoints(ctx context.Context) error {
	rows, err := a.s.r.QueryContext(ctx, `SELECT ap.key, ap.first_seen, ss.key, ss.label, coalesce(json_extract(f.attrs, '$.security'), ''), min(f.first_seen)
		FROM facts f JOIN entities ap ON ap.id = f.src JOIN entities ss ON ss.id = f.dst
		WHERE f.rel = 'broadcasts' AND f.first_seen < ? AND f.last_seen >= ? AND json_valid(f.attrs)
		GROUP BY ap.id, ss.id, 5`, a.to, a.from)
	if err != nil {
		return err
	}
	type ap struct {
		bssid string
		first int64
		sec   map[string]bool
		seen  int64
	}
	type network struct {
		key, label string
		aps        map[string]*ap
	}
	nets := map[string]*network{}
	for rows.Next() {
		var bssid, key, label, sec string
		var first, seen int64
		if err := rows.Scan(&bssid, &first, &key, &label, &sec, &seen); err != nil {
			rows.Close()
			return err
		}
		n := nets[key]
		if n == nil {
			n = &network{key: key, label: cmp.Or(label, key), aps: map[string]*ap{}}
			nets[key] = n
		}
		p := n.aps[bssid]
		if p == nil {
			p = &ap{bssid: bssid, first: first, sec: map[string]bool{}, seen: seen}
			n.aps[bssid] = p
		}
		if sec != "" {
			p.sec[strings.ToLower(sec)] = true
		}
		p.seen = min(p.seen, seen)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	// The networks the LAN's own devices (ones that used an address on it)
	// associate with.
	own := map[string]bool{}
	if a.since != 0 && a.from-a.since >= AnomalyHistory.Milliseconds() {
		rows, err = a.s.r.QueryContext(ctx, `SELECT DISTINCT ss.key FROM facts asc_ JOIN entities d ON d.id = asc_.src
			JOIN facts br ON br.src = asc_.dst AND br.rel = 'broadcasts' JOIN entities ss ON ss.id = br.dst
			WHERE asc_.rel = 'associates' AND json_valid(d.attrs) AND json_extract(d.attrs, '$.joined') IS NOT NULL`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				rows.Close()
				return err
			}
			own[key] = true
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	for _, key := range slices.Sorted(maps.Keys(nets)) {
		n := nets[key]
		if strings.TrimSpace(n.label) == "" {
			continue // hidden networks share an empty name
		}
		ssid := model.EntityID(model.KindSSID, key)
		var open, protected []string
		bySec := map[string][]string{}
		for _, bssid := range slices.Sorted(maps.Keys(n.aps)) {
			for sec := range n.aps[bssid].sec {
				bySec[sec] = append(bySec[sec], bssid)
				if sec == "open" || sec == "wep" {
					open = append(open, bssid)
				} else {
					protected = append(protected, bssid)
				}
			}
		}
		if len(bySec) > 1 {
			var parts []string
			for _, sec := range slices.Sorted(maps.Keys(bySec)) {
				parts = append(parts, sec+": "+strings.Join(bySec[sec], " "))
			}
			// An open or WEP twin of a protected network is how clients
			// are lured; WPA2 next to WPA3 is how mesh and 6 GHz radios
			// are often set up.
			sev, what := model.SeverityLow, "access points disagree on its security"
			if len(open) > 0 && len(protected) > 0 {
				sev, what = model.SeverityHigh, "an open access point copies a protected network's name"
			}
			// The disagreement began when the second setting was first heard.
			var starts []int64
			for _, sec := range slices.Sorted(maps.Keys(bySec)) {
				var first int64
				for _, bssid := range bySec[sec] {
					if t := n.aps[bssid].seen; first == 0 || t < first {
						first = t
					}
				}
				starts = append(starts, first)
			}
			slices.Sort(starts)
			ts := starts[1]
			a.add(model.Anomaly{Kind: model.AnomalyRogueAP, Severity: sev, TS: max(ts, a.from), Entity: ssid,
				Summary: fmt.Sprintf("%q: %s", n.label, what), Evidence: map[string]string{"security": strings.Join(parts, "; ")}})
		}
		if !own[key] {
			continue
		}
		for _, bssid := range slices.Sorted(maps.Keys(n.aps)) {
			p := n.aps[bssid]
			if p.first < a.from || p.first >= a.to || p.first-a.since < AnomalyHistory.Milliseconds() || len(n.aps) < 2 {
				continue
			}
			a.add(model.Anomaly{Kind: model.AnomalyRogueAP, Severity: model.SeverityMedium, TS: p.first, Device: model.EntityID(model.KindDevice, bssid), DeviceName: bssid, Entity: ssid,
				Summary:  fmt.Sprintf("a new access point %s broadcasts %q, a network this LAN's devices use", bssid, n.label),
				Evidence: map[string]string{"bssid": bssid, "security": strings.Join(slices.Sorted(maps.Keys(p.sec)), ","), "access_points": strconv.Itoa(len(n.aps))}})
		}
	}
	return nil
}

func protoName(p int) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1, 58:
		return "icmp"
	}
	return strconv.Itoa(p)
}
