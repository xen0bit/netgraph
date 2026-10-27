package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/model"
)

// ErrNotFound is returned for an entity the database does not hold.
var ErrNotFound = errors.New("not found")

// Entity returns what is known about one entity in the window: its facts,
// the flows and lookups it took part in, and a timeline merging them with
// its identity observations.
func (s *Store) Entity(ctx context.Context, id string, f model.Filter) (*model.EntityDetail, error) {
	kind, key, ok := model.SplitEntityID(id)
	if !ok {
		return nil, fmt.Errorf("invalid entity id %q", id)
	}
	if kind == model.KindSite {
		return s.siteEntity(ctx, id, key, f)
	}
	from, to := s.window(f)
	d := &model.EntityDetail{ID: id, Kind: kind, Key: key}
	var eid int64
	var attrs string
	err := s.r.QueryRowContext(ctx, `SELECT id, label, first_seen, last_seen, attrs FROM entities WHERE kind = ? AND key = ?`, kind, key).
		Scan(&eid, &d.Label, &d.FirstSeen, &d.LastSeen, &attrs)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(attrs), &d.Attrs)
	delete(d.Attrs, "label_pri")
	if kind == model.KindDevice {
		d.Label = deviceLabel(key, d.Label, d.Attrs)
	}

	w := &where{}
	w.add("(f.src = ? OR f.dst = ?) AND f.first_seen < ? AND f.last_seen >= ?", eid, eid, to, from)
	if d.Facts, err = s.queryFacts(ctx, w, 500); err != nil {
		return nil, err
	}

	wf := model.Filter{From: time.UnixMilli(from), To: time.UnixMilli(to), Limit: 200, Multicast: true}
	wd := wf
	switch kind {
	case model.KindDevice:
		wf.Device, wd.Device = key, key
		devs, err := s.Devices(ctx, model.Filter{From: wf.From, To: wf.To, Device: key, Multicast: true})
		if err != nil {
			return nil, err
		}
		for i := range devs {
			if devs[i].MAC == key {
				d.Device = &devs[i]
			}
		}
	case model.KindIP:
		wf.IP, wd.IP = key, key
	case model.KindDomain:
		// Exact name rather than a substring.
		wf.Domain, wd.Domain = key, key
	default:
		wf.Limit, wd.Limit = -1, -1
	}
	if wf.Limit > 0 {
		if d.Flows, err = s.Flows(ctx, wf); err != nil {
			return nil, err
		}
		if kind == model.KindDomain {
			d.Flows = filterFlows(d.Flows, func(fl model.Flow) bool { return fl.Name == key || fl.QName == key })
		}
		if d.DNS, err = s.DNS(ctx, wd); err != nil {
			return nil, err
		}
		if kind == model.KindDomain {
			d.DNS = filterDNS(d.DNS, func(q model.DNSQuery) bool { return q.QName == key })
		}
	}
	d.Timeline, err = s.timeline(ctx, kind, key, eid, d, from, to)
	return d, err
}

// siteEntity is what the window holds for the names under one registrable
// domain (a graph's site node): their connections, lookups and facts, with
// the names it found listed in attrs.
func (s *Store) siteEntity(ctx context.Context, id, site string, f model.Filter) (*model.EntityDetail, error) {
	from, to := s.window(f)
	d := &model.EntityDetail{ID: id, Kind: model.KindSite, Key: site, Label: site}
	in := func(name string) bool { return name != "" && graph.Site(name) == site }
	// The domain filter matches a substring; the site test makes it exact.
	wf := model.Filter{From: time.UnixMilli(from), To: time.UnixMilli(to), Limit: 200, Multicast: true, Domain: site}
	var err error
	if d.Flows, err = s.Flows(ctx, wf); err != nil {
		return nil, err
	}
	d.Flows = filterFlows(d.Flows, func(fl model.Flow) bool { return in(fl.Name) || in(fl.QName) })
	if d.DNS, err = s.DNS(ctx, wf); err != nil {
		return nil, err
	}
	d.DNS = filterDNS(d.DNS, func(q model.DNSQuery) bool { return in(q.QName) })

	rows, err := s.r.QueryContext(ctx, `SELECT id, key, first_seen, last_seen FROM entities WHERE kind = 'domain' AND (key = ? OR key GLOB ?)`, site, "*."+site)
	if err != nil {
		return nil, err
	}
	var ids []int64
	names := map[string]bool{}
	for rows.Next() {
		var eid, first, last int64
		var key string
		if err := rows.Scan(&eid, &key, &first, &last); err != nil {
			rows.Close()
			return nil, err
		}
		if !in(key) || first >= to || last < from {
			continue
		}
		ids = append(ids, eid)
		names[key] = true
		if d.FirstSeen == 0 || first < d.FirstSeen {
			d.FirstSeen = first
		}
		d.LastSeen = max(d.LastSeen, last)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(ids) == 0 && len(d.Flows) == 0 && len(d.DNS) == 0 {
		return nil, ErrNotFound
	}
	for chunk := range slices.Chunk(ids, 500) {
		w := &where{}
		list := idList(chunk)
		w.add("(f.src IN ("+list+") OR f.dst IN ("+list+")) AND f.first_seen < ? AND f.last_seen >= ?", to, from)
		facts, err := s.queryFacts(ctx, w, 500)
		if err != nil {
			return nil, err
		}
		d.Facts = append(d.Facts, facts...)
	}
	for _, fl := range d.Flows {
		names[firstNonEmpty(fl.Name, fl.QName)] = true
	}
	for _, q := range d.DNS {
		names[q.QName] = true
	}
	delete(names, "")
	d.Attrs = map[string]string{"names": strings.Join(slices.Sorted(maps.Keys(names)), ",")}
	d.Timeline, err = s.timeline(ctx, model.KindSite, site, 0, d, from, to)
	return d, err
}

func filterFlows(in []model.Flow, keep func(model.Flow) bool) []model.Flow {
	var out []model.Flow
	for _, f := range in {
		if keep(f) {
			out = append(out, f)
		}
	}
	return out
}

func filterDNS(in []model.DNSQuery, keep func(model.DNSQuery) bool) []model.DNSQuery {
	var out []model.DNSQuery
	for _, q := range in {
		if keep(q) {
			out = append(out, q)
		}
	}
	return out
}

func (s *Store) timeline(ctx context.Context, kind, key string, eid int64, d *model.EntityDetail, from, to int64) ([]model.TimelineEvent, error) {
	var tl []model.TimelineEvent
	for _, fl := range d.Flows {
		// "client → remote", where remote is the name it was reached by
		// when there is one.
		remote := fmt.Sprintf("%s:%d/%s", fl.RemoteIP, fl.RemotePort, fl.Proto)
		if fl.Name != "" {
			remote = fmt.Sprintf("%s (%s:%d/%s)", fl.Name, fl.RemoteIP, fl.RemotePort, fl.Proto)
		}
		what := firstNonEmpty(fl.DeviceName, fl.ClientIP) + " → " + remote
		if fl.FirstSeen >= from {
			tl = append(tl, model.TimelineEvent{TS: fl.FirstSeen, Type: "flow-open", Detail: what})
		}
		if fl.Closed {
			tl = append(tl, model.TimelineEvent{TS: fl.LastSeen, Type: "flow-close", Detail: fmt.Sprintf("%s, %s, up %s down %s", what, fl.EndReason, model.FormatBytes(fl.BytesOut), model.FormatBytes(fl.BytesIn))})
		}
	}
	for _, q := range d.DNS {
		var ans []string
		for _, a := range q.Answers {
			ans = append(ans, a.Data)
		}
		who := ""
		if kind != model.KindDevice {
			who = firstNonEmpty(q.DeviceName, q.ClientIP) + " "
		}
		tl = append(tl, model.TimelineEvent{TS: q.TS, Type: "dns", Detail: strings.TrimSpace(fmt.Sprintf("%s%s %s %s %s", who, q.QType, q.QName, q.RCode, strings.Join(ans, " ")))})
	}
	if kind == model.KindDevice || kind == model.KindIP {
		col, arg := "device", any(eid)
		if kind == model.KindIP {
			col, arg = "ip", key
		}
		rows, err := s.r.QueryContext(ctx, `SELECT ts, type, data FROM observations WHERE `+col+` = ? AND ts >= ? AND ts < ? ORDER BY ts LIMIT 500`, arg, from, to)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var ev model.TimelineEvent
			var data string
			if err := rows.Scan(&ev.TS, &ev.Type, &data); err != nil {
				return nil, err
			}
			ev.Detail = summarizeObservation(ev.Type, data)
			tl = append(tl, ev)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(tl, func(i, j int) bool { return tl[i].TS < tl[j].TS })
	if len(tl) > 1000 {
		tl = tl[len(tl)-1000:]
	}
	return tl, nil
}

// summarizeObservation renders a stored observation in one line.
func summarizeObservation(typ, data string) string {
	var m map[string]any
	if json.Unmarshal([]byte(data), &m) != nil {
		return data
	}
	get := func(k string) string {
		if v, ok := m[k]; ok && v != nil {
			s := fmt.Sprint(v)
			if s != "" && s != "<nil>" {
				return s
			}
		}
		return ""
	}
	var parts []string
	add := func(label, k string) {
		if v := get(k); v != "" {
			parts = append(parts, label+v)
		}
	}
	switch typ {
	case "dhcp", "dhcp6":
		add("", "msg")
		add("hostname=", "hostname")
		add("fqdn=", "fqdn")
		add("ip=", "yiaddr")
		add("requested=", "requested")
		add("vendor=", "vendor_class")
		add("lease=", "lease")
	case "mdns":
		if hs, ok := m["hosts"].([]any); ok {
			for _, h := range hs {
				if hm, ok := h.(map[string]any); ok {
					parts = append(parts, fmt.Sprint(hm["name"]))
				}
			}
		}
		if ss, ok := m["services"].([]any); ok {
			for _, sv := range ss {
				if sm, ok := sv.(map[string]any); ok {
					parts = append(parts, fmt.Sprint(sm["instance"]))
				}
			}
		}
	case "binding":
		add("", "source")
		add("", "ip")
	case "ssdp":
		add("", "method")
		add("", "server")
		add("", "nt")
	case "lldp":
		add("", "sys_name")
		add("port ", "port")
	case "wifi":
		add("", "kind")
		add("ssid=", "ssid")
		add("client=", "client")
		add("security=", "security")
		if e, ok := m["eapol"].(map[string]any); ok {
			if v, ok := e["message"]; ok {
				parts = append(parts, "message="+fmt.Sprint(v))
			}
		}
	default:
		add("", "proto")
		add("", "name")
		add("", "suffix")
	}
	return strings.Join(parts, " ")
}
