package store

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/agent"
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
	if kind == model.KindSensor {
		return s.sensorEntity(ctx, id, key, f)
	}
	if kind == model.KindProcess {
		return s.processEntity(ctx, id, key, f)
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
				s.explainType(ctx, d.Device)
			}
		}
	case model.KindIP:
		wf.IP, wd.IP = key, key
	case model.KindDomain:
		// Exact name rather than a substring.
		wf.DomainExact, wd.DomainExact = key, key
	case model.KindASN:
		// Connections with the network's addresses; lookups do not say
		// which network answered.
		n, err := model.ParseASN(key)
		if err != nil {
			return nil, err
		}
		wf.ASN, wd.Limit = n, -1
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
		if wd.Limit > 0 {
			if d.DNS, err = s.DNS(ctx, wd); err != nil {
				return nil, err
			}
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
	// Match the registrable domain and its subdomains exactly, not every
	// name that happens to contain the string.
	wf := model.Filter{From: time.UnixMilli(from), To: time.UnixMilli(to), Limit: 200, Multicast: true, DomainSuffix: site}
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

// sensorEntity describes a sensor's health. Sensors are not entities in the
// store (they are infrastructure, not LAN devices), but an anomaly or a link
// should still be able to open one.
func (s *Store) sensorEntity(ctx context.Context, id, name string, f model.Filter) (*model.EntityDetail, error) {
	sensors, err := s.Sensors(ctx)
	if err != nil {
		return nil, err
	}
	for _, sn := range sensors {
		if sn.Name != name {
			continue
		}
		d := &model.EntityDetail{ID: id, Kind: model.KindSensor, Key: name, Label: name,
			FirstSeen: sn.FirstSeen, LastSeen: sn.LastSeen, Attrs: map[string]string{"version": sn.Version}}
		if len(sn.Interfaces) > 0 {
			d.Attrs["interfaces"] = strings.Join(sn.Interfaces, ", ")
		}
		for k, v := range sn.Stats {
			d.Attrs[k] = fmt.Sprint(v)
		}
		return d, nil
	}
	return nil, ErrNotFound
}

// processEntity describes a program on a device, as the graph draws it
// (process:<device id>/<name>): the device's connections a host agent
// attributed to it, at either end, and what the agent said about it.
func (s *Store) processEntity(ctx context.Context, id, key string, f model.Filter) (*model.EntityDetail, error) {
	dev, name, ok := strings.Cut(key, "/")
	kind, mac, _ := model.SplitEntityID(dev)
	if !ok || name == "" || kind != model.KindDevice {
		return nil, fmt.Errorf("invalid process id %q", id)
	}
	from, to := s.window(f)
	all, err := s.Flows(ctx, model.Filter{From: time.UnixMilli(from), To: time.UnixMilli(to), Device: mac, Limit: 5000, Multicast: true})
	if err != nil {
		return nil, err
	}
	d := &model.EntityDetail{ID: id, Kind: model.KindProcess, Key: key, Label: name, Attrs: map[string]string{"device": dev}}
	agents, pids := map[string]bool{}, map[int]bool{}
	for _, fl := range all {
		mine := fl.Device == dev && fl.Process == name
		if !mine && !(fl.PeerDevice == dev && fl.PeerProcess == name) {
			continue
		}
		if mine {
			agents[fl.Agent] = true
			if fl.PID > 0 {
				pids[fl.PID] = true
			}
		}
		if d.FirstSeen == 0 || fl.FirstSeen < d.FirstSeen {
			d.FirstSeen = fl.FirstSeen
		}
		d.LastSeen = max(d.LastSeen, fl.LastSeen)
		if len(d.Flows) < 200 {
			d.Flows = append(d.Flows, fl)
		}
	}
	delete(agents, "")
	if len(d.Flows) == 0 {
		return nil, ErrNotFound
	}
	if len(agents) > 0 {
		d.Attrs["agent"] = strings.Join(slices.Sorted(maps.Keys(agents)), ", ")
	}
	if len(pids) > 0 {
		var ps []string
		for _, p := range slices.Sorted(maps.Keys(pids)) {
			ps = append(ps, strconv.Itoa(p))
		}
		d.Attrs["pids"] = strings.Join(ps, ", ")
	}
	// What each PID ran, and who started it, as the agent described them.
	if len(pids) > 0 && len(agents) == 1 {
		newest := slices.Sorted(maps.Keys(pids))
		slices.Reverse(newest)
		cmds, by := s.lineage(ctx, slices.Collect(maps.Keys(agents))[0], newest)
		if len(cmds) > 0 {
			d.Attrs["cmdline"] = strings.Join(cmds, "\n")
		}
		if by != "" {
			d.Attrs["started by"] = by
		}
	}
	// The executable the agent hashed, newest first.
	for a := range agents {
		var path, code string
		err := s.r.QueryRowContext(ctx, `SELECT path, code_id FROM agent_connections WHERE agent = ? AND app = ? AND path != ''
			ORDER BY last_seen DESC LIMIT 1`, a, name).Scan(&path, &code)
		if err == nil {
			d.Attrs["path"], d.Attrs["code_id"] = path, code
			break
		}
	}
	return d, nil
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
		// "client → server", the server named by what the client asked
		// for when there is a name; up and down are the client's.
		what := fmt.Sprintf("%s → %s:%d/%s", firstNonEmpty(fl.DeviceName, fl.ClientIP), fl.ServerIP, fl.ServerPort, fl.Proto)
		if fl.Name != "" {
			what = fmt.Sprintf("%s → %s (%s:%d/%s)", firstNonEmpty(fl.DeviceName, fl.ClientIP), fl.Name, fl.ServerIP, fl.ServerPort, fl.Proto)
		}
		up, down := fl.BytesOut, fl.BytesIn
		if fl.Inbound() {
			what = fmt.Sprintf("%s:%d → %s %s", fl.ClientIP, fl.ClientPort, firstNonEmpty(fl.DeviceName, fl.ServerIP), fl.Service())
			if fl.Name != "" {
				what += " for " + fl.Name
			}
			up, down = fl.BytesIn, fl.BytesOut
		}
		if fl.FirstSeen >= from {
			tl = append(tl, model.TimelineEvent{TS: fl.FirstSeen, Type: "flow-open", Detail: what})
		}
		if fl.Closed {
			tl = append(tl, model.TimelineEvent{TS: fl.LastSeen, Type: "flow-close", Detail: fmt.Sprintf("%s, %s, up %s down %s", what, fl.EndReason, model.FormatBytes(up), model.FormatBytes(down))})
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
		rows, err := s.r.QueryContext(ctx, `SELECT ts, type, data FROM observations WHERE `+col+` = ? AND ts >= ? AND ts < ? ORDER BY ts DESC LIMIT 500`, arg, from, to)
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

// searchKinds are the entities Search finds, in the order it lists them.
var searchKinds = []string{model.KindDevice, model.KindIP, model.KindASN, model.KindDomain}

// Search finds entities by key or name: devices by MAC, name or label,
// addresses, DNS names and networks. Exact keys come first, then keys
// starting with q, then names containing it; devices before the rest, the
// most recently seen first. A query of fewer than two characters finds
// nothing. "kind:key" searches one kind.
func (s *Store) Search(ctx context.Context, q string, limit int) ([]model.SearchResult, error) {
	out := []model.SearchResult{}
	q = strings.ToLower(strings.TrimSpace(q))
	kinds := searchKinds
	if kind, key, ok := model.SplitEntityID(q); ok && slices.Contains(searchKinds, kind) {
		kinds, q = []string{kind}, key
	}
	if len(q) < 2 || len(q) > 256 {
		return out, nil
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	like := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q)
	order := "CASE kind"
	for i, k := range searchKinds {
		order += fmt.Sprintf(" WHEN '%s' THEN %d", k, i)
	}
	order += " END"
	marks := strings.TrimSuffix(strings.Repeat("?,", len(kinds)), ",")
	args := []any{}
	for _, k := range kinds {
		args = append(args, k)
	}
	args = append(args, like, like, like, q, like, limit)
	rows, err := s.r.QueryContext(ctx, `SELECT kind, key, label, last_seen, attrs FROM entities e
		WHERE kind IN (`+marks+`) AND (lower(key) LIKE ? || '%' ESCAPE '\' OR lower(label) LIKE '%' || ? || '%' ESCAPE '\'
			OR (kind = 'device' AND json_valid(attrs) AND lower(coalesce(json_extract(attrs, '$.auto_label'), '')) LIKE '%' || ? || '%' ESCAPE '\'))
			AND (kind IN ('device', 'asn')
				OR EXISTS (SELECT 1 FROM facts f WHERE f.src = e.id OR f.dst = e.id)
				OR EXISTS (SELECT 1 FROM connections c WHERE c.remote_ip = e.key OR c.client_ip = e.key)
				OR EXISTS (SELECT 1 FROM dns d WHERE d.qname = e.key))
		ORDER BY lower(key) = ? DESC, lower(key) LIKE ? || '%' ESCAPE '\' DESC, `+order+`, last_seen DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r model.SearchResult
		var attrs string
		if err := rows.Scan(&r.Kind, &r.Key, &r.Label, &r.LastSeen, &attrs); err != nil {
			return nil, err
		}
		r.ID = model.EntityID(r.Kind, r.Key)
		if r.Kind == model.KindDevice {
			var a map[string]string
			_ = json.Unmarshal([]byte(attrs), &a)
			r.Label = deviceLabel(r.Key, r.Label, a)
		}
		r.Label = cmp.Or(r.Label, r.Key)
		out = append(out, r)
	}
	return out, rows.Err()
}

// lineage is what an agent said about a program's PIDs (the newest
// first): each one's command line (the program alone unless the agent sends
// arguments), and the chain of processes that started the newest, oldest
// first: "sshd (10) › bash (20)".
func (s *Store) lineage(ctx context.Context, agentName string, pids []int) (cmdlines []string, startedBy string) {
	type proc struct {
		ppid          int
		path, cmdline string
	}
	get := func(pid int) (proc, bool) {
		var p proc
		err := s.r.QueryRowContext(ctx, `SELECT ppid, path, cmdline FROM agent_processes WHERE agent = ? AND pid = ?`,
			agentName, pid).Scan(&p.ppid, &p.path, &p.cmdline)
		return p, err == nil
	}
	newest, newestPID := proc{}, 0
	for _, pid := range pids {
		p, ok := get(pid)
		if !ok {
			continue
		}
		if len(cmdlines) < 10 && p.cmdline != "" {
			cmdlines = append(cmdlines, "pid "+strconv.Itoa(pid)+": "+p.cmdline)
		}
		if newestPID == 0 {
			newest, newestPID = p, pid
		}
	}
	if newestPID == 0 {
		return cmdlines, ""
	}
	var chain []string
	seen := map[int]bool{newestPID: true}
	for pp := newest.ppid; pp > 1 && !seen[pp] && len(chain) < 8; {
		seen[pp] = true
		p, ok := get(pp)
		if !ok {
			break
		}
		chain = append([]string{agent.AppName(p.path, p.cmdline) + " (" + strconv.Itoa(pp) + ")"}, chain...)
		pp = p.ppid
	}
	return cmdlines, strings.Join(chain, " › ")
}
