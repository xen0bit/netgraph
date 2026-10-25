package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"modernc.org/sqlite"

	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/oui"
)

func init() {
	// cidr_contains(prefix, addr): lets CIDR filters run in SQL, so LIMIT
	// applies after them.
	_ = sqlite.RegisterDeterministicScalarFunction("cidr_contains", 2, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		ps, _ := args[0].(string)
		as, _ := args[1].(string)
		p, err := netip.ParsePrefix(ps)
		if err != nil {
			return int64(0), nil
		}
		a, err := netip.ParseAddr(as)
		if err != nil {
			return int64(0), nil
		}
		if p.Contains(a.Unmap()) {
			return int64(1), nil
		}
		return int64(0), nil
	})
}

var _ model.Backend = (*Store)(nil)

// window normalises a filter's window: To defaults to now, From to an hour
// before To.
func (s *Store) window(f model.Filter) (from, to int64) {
	t := f.To
	if t.IsZero() {
		t = s.cfg.Now()
	}
	fr := f.From
	if fr.IsZero() {
		fr = t.Add(-time.Hour)
	}
	return ms(fr), ms(t)
}

// precision reports whether raw records still cover the window's start.
func (s *Store) precision(from int64) string {
	if from >= ms(s.cfg.Now().Add(-s.cfg.RawRetention)) {
		return model.PrecisionExact
	}
	return model.PrecisionHour
}

func limit(f model.Filter, def, maxN int) int {
	switch {
	case f.Limit <= 0:
		return def
	case f.Limit > maxN:
		return maxN
	}
	return f.Limit
}

// glob turns a user pattern into a lower-cased GLOB pattern; a pattern with
// no wildcards matches as a substring.
func glob(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if !strings.ContainsAny(p, "*?[") {
		p = "*" + p + "*"
	}
	return p
}

// where accumulates SQL conditions and their arguments.
type where struct {
	conds []string
	args  []any
}

func (w *where) add(cond string, args ...any) {
	w.conds = append(w.conds, cond)
	w.args = append(w.args, args...)
}

func (w *where) sql() string {
	if len(w.conds) == 0 {
		return "1"
	}
	return strings.Join(w.conds, " AND ")
}

// deviceIDs resolves a device pattern to entity IDs: MAC, label, or any
// hostname the device ever had.
func (s *Store) deviceIDs(ctx context.Context, pattern string) ([]int64, error) {
	g := glob(pattern)
	rows, err := s.r.QueryContext(ctx, `
		SELECT id FROM entities WHERE kind = 'device' AND (lower(key) GLOB ?1 OR lower(label) GLOB ?1)
		UNION
		SELECT f.src FROM facts f JOIN entities h ON h.id = f.dst WHERE f.rel = 'hostname' AND lower(h.key) GLOB ?1`, g)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func idList(ids []int64) string {
	if len(ids) == 0 {
		return "0"
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatInt(id, 10)
	}
	return strings.Join(parts, ",")
}

// ipCond matches column against an address or CIDR.
func ipCond(col, ip string) (string, any) {
	if strings.Contains(ip, "/") {
		return "cidr_contains(?, " + col + ") = 1", ip
	}
	if a, err := netip.ParseAddr(ip); err == nil {
		return col + " = ?", a.String()
	}
	return col + " = ?", ip
}

func protoNumber(p string) (int, bool) {
	switch strings.ToLower(p) {
	case "tcp":
		return 6, true
	case "udp":
		return 17, true
	case "icmp":
		return 1, true
	case "icmpv6":
		return 58, true
	}
	n, err := strconv.Atoi(p)
	return n, err == nil
}

// flowWhere builds the conditions shared by flow queries over table
// columns (raw flows and traffic_hourly name some columns differently).
func (s *Store) flowWhere(ctx context.Context, f model.Filter, w *where, nameCols []string) error {
	if f.Device != "" {
		ids, err := s.deviceIDs(ctx, f.Device)
		if err != nil {
			return err
		}
		w.add("client_device IN (" + idList(ids) + ")")
	}
	if f.IP != "" {
		c1, a1 := ipCond("client_ip", f.IP)
		c2, a2 := ipCond("remote_ip", f.IP)
		w.add("("+c1+" OR "+c2+")", a1, a2)
	}
	if f.Domain != "" {
		var ors []string
		for _, c := range nameCols {
			ors = append(ors, "lower("+c+") GLOB ?")
			w.args = append(w.args, glob(f.Domain))
		}
		w.conds = append(w.conds, "("+strings.Join(ors, " OR ")+")")
	}
	if f.Port != 0 {
		w.add("remote_port = ?", f.Port)
	}
	if f.Proto != "" {
		if n, ok := protoNumber(f.Proto); ok {
			w.add("proto = ?", n)
		}
	}
	if f.App != "" {
		w.add("app = ?", f.App)
	}
	if !f.Multicast {
		w.add("multicast = 0")
	}
	return nil
}

// labels returns display labels for device IDs.
func (s *Store) labels(ctx context.Context, ids map[int64]bool) (map[int64]string, map[int64]string, error) {
	out := map[int64]string{}
	macs := map[int64]string{}
	if len(ids) == 0 {
		return out, macs, nil
	}
	list := make([]int64, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	rows, err := s.r.QueryContext(ctx, `SELECT id, key, label, attrs FROM entities WHERE id IN (`+idList(list)+`)`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var key, label, attrs string
		if err := rows.Scan(&id, &key, &label, &attrs); err != nil {
			return nil, nil, err
		}
		var a map[string]string
		_ = json.Unmarshal([]byte(attrs), &a)
		out[id] = deviceLabel(key, label, a)
		macs[id] = key
	}
	return out, macs, rows.Err()
}

// deviceLabel is a device's display name: its best hostname, else its
// vendor and the end of its MAC.
func deviceLabel(mac, label string, attrs map[string]string) string {
	if label != "" {
		return label
	}
	suffix := mac
	if len(mac) >= 8 {
		suffix = mac[len(mac)-8:]
	}
	if v := attrs["vendor"]; v != "" {
		if v == oui.Randomized {
			return "private " + suffix
		}
		return oui.Short(v) + " " + suffix
	}
	return mac
}

// --- flows ------------------------------------------------------------------

// Flows returns each connection active in the window with the traffic it
// carried inside it. A record straddling a window edge contributes the
// fraction of its bytes that falls inside, assuming an even rate across
// the record's interval (at most the sensor's active timeout).
func (s *Store) Flows(ctx context.Context, f model.Filter) ([]model.Flow, error) {
	from, to := s.window(f)
	if s.precision(from) == model.PrecisionHour {
		return s.flowsHourly(ctx, f, from, to)
	}
	w := &where{}
	w.add("t_start < ? AND t_end >= ?", to, from)
	if err := s.flowWhere(ctx, f, w, []string{"sni", "http_host", "qname"}); err != nil {
		return nil, err
	}
	frac := func(col string) string {
		return fmt.Sprintf(`sum(CASE WHEN t_end > t_start THEN %[1]s * ((min(t_end, %[2]d) - max(t_start, %[3]d)) * 1.0 / (t_end - t_start)) ELSE %[1]s END)`, col, to, from)
	}
	q := `SELECT flow_key, proto, client_ip, client_port, client_mac, client_device, remote_ip, remote_port, direction,
		max(app), max(sni), max(http_host), max(qname), max(alpn), max(ja4), max(user_agent),
		min(first_seen), max(t_end), max(final), max(CASE WHEN final = 1 THEN end_reason ELSE '' END),
		` + frac("bytes_out") + `, ` + frac("bytes_in") + `, ` + frac("pkts_out") + `, ` + frac("pkts_in") + `
		FROM flows WHERE ` + w.sql() + `
		GROUP BY flow_key ORDER BY 21 + 22 DESC, 17 LIMIT ?`
	rows, err := s.r.QueryContext(ctx, q, append(w.args, limit(f, 1000, 100000))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Flow
	devs := map[int64]bool{}
	var devIDs []int64
	for rows.Next() {
		var fl model.Flow
		var proto, final int
		var dev int64
		var bo, bi, po, pi float64
		if err := rows.Scan(&fl.Key, &proto, &fl.ClientIP, &fl.ClientPort, &fl.ClientMAC, &dev, &fl.RemoteIP, &fl.RemotePort, &fl.Direction,
			&fl.App, &fl.SNI, &fl.HTTPHost, &fl.QName, &fl.ALPN, &fl.JA4, &fl.UserAgent,
			&fl.FirstSeen, &fl.LastSeen, &final, &fl.EndReason, &bo, &bi, &po, &pi); err != nil {
			return nil, err
		}
		fl.Proto = ProtoName(proto)
		fl.BytesOut, fl.BytesIn, fl.PktsOut, fl.PktsIn = uint64(bo+0.5), uint64(bi+0.5), uint64(po+0.5), uint64(pi+0.5)
		fl.Name = firstNonEmpty(fl.SNI, fl.HTTPHost, fl.QName)
		fl.State = model.StateOpened
		if fl.FirstSeen < from {
			fl.State = model.StateCarried
		}
		fl.Closed = final == 1 && fl.LastSeen < to
		if dev != 0 {
			devs[dev] = true
		}
		devIDs = append(devIDs, dev)
		out = append(out, fl)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	labels, macs, err := s.labels(ctx, devs)
	if err != nil {
		return nil, err
	}
	for i, id := range devIDs {
		if id != 0 {
			out[i].Device = model.EntityID(model.KindDevice, macs[id])
			out[i].DeviceName = labels[id]
		}
	}
	return out, nil
}

// flowsHourly answers Flows from rollups: one row per destination per
// device, with no per-connection detail.
func (s *Store) flowsHourly(ctx context.Context, f model.Filter, from, to int64) ([]model.Flow, error) {
	w := &where{}
	w.add("bucket < ? AND bucket >= ?", to, hourOf(from))
	if err := s.flowWhere(ctx, f, w, []string{"name"}); err != nil {
		return nil, err
	}
	rows, err := s.r.QueryContext(ctx, `SELECT client_device, client_ip, remote_ip, remote_port, proto, name, max(app),
		min(bucket), max(bucket), sum(flows), sum(bytes_out), sum(bytes_in)
		FROM traffic_hourly WHERE `+w.sql()+`
		GROUP BY client_device, client_ip, remote_ip, remote_port, proto, name ORDER BY 11 + 12 DESC LIMIT ?`, append(w.args, limit(f, 1000, 100000))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Flow
	devs := map[int64]bool{}
	var devIDs []int64
	for rows.Next() {
		var fl model.Flow
		var dev int64
		var proto, n int
		var first, last int64
		if err := rows.Scan(&dev, &fl.ClientIP, &fl.RemoteIP, &fl.RemotePort, &proto, &fl.Name, &fl.App, &first, &last, &n, &fl.BytesOut, &fl.BytesIn); err != nil {
			return nil, err
		}
		fl.Key = fmt.Sprintf("hourly:%d:%s:%s:%d:%d", dev, fl.ClientIP, fl.RemoteIP, fl.RemotePort, proto)
		fl.Proto = ProtoName(proto)
		fl.FirstSeen, fl.LastSeen = first, last+hourMS
		fl.State = model.StateOpened
		fl.Direction = "out"
		fl.PktsOut = uint64(n) // connection count; packet counts are not rolled up
		if dev != 0 {
			devs[dev] = true
		}
		devIDs = append(devIDs, dev)
		out = append(out, fl)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	labels, macs, err := s.labels(ctx, devs)
	if err != nil {
		return nil, err
	}
	for i, id := range devIDs {
		if id != 0 {
			out[i].Device = model.EntityID(model.KindDevice, macs[id])
			out[i].DeviceName = labels[id]
		}
	}
	return out, nil
}

// --- dns --------------------------------------------------------------------

// DNS returns lookups in the window, newest first.
func (s *Store) DNS(ctx context.Context, f model.Filter) ([]model.DNSQuery, error) {
	from, to := s.window(f)
	w := &where{}
	w.add("ts >= ? AND ts < ?", from, to)
	if f.Device != "" {
		ids, err := s.deviceIDs(ctx, f.Device)
		if err != nil {
			return nil, err
		}
		w.add("client_device IN (" + idList(ids) + ")")
	}
	if f.Domain != "" {
		w.add("(lower(qname) GLOB ? OR id IN (SELECT dns_id FROM dns_answers WHERE lower(data) GLOB ? AND ts >= ? AND ts < ?))", glob(f.Domain), glob(f.Domain), from, to)
	}
	if f.IP != "" {
		c1, a1 := ipCond("client_ip", f.IP)
		c2, a2 := ipCond("data", f.IP)
		w.add("("+c1+" OR id IN (SELECT dns_id FROM dns_answers WHERE "+c2+" AND ts >= ? AND ts < ?))", a1, a2, from, to)
	}
	rows, err := s.r.QueryContext(ctx, `SELECT ts, client_ip, client_device, server_ip, qname, qtype, rcode, coalesce(latency_ms, 0), answers
		FROM dns WHERE `+w.sql()+` ORDER BY ts DESC LIMIT ?`, append(w.args, limit(f, 500, 50000))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.DNSQuery
	devs := map[int64]bool{}
	var devIDs []int64
	for rows.Next() {
		var q model.DNSQuery
		var dev int64
		var answers string
		if err := rows.Scan(&q.TS, &q.ClientIP, &dev, &q.Server, &q.QName, &q.QType, &q.RCode, &q.LatencyMS, &answers); err != nil {
			return nil, err
		}
		var as []struct {
			Name, Type, Data string
			TTL              uint32
		}
		_ = json.Unmarshal([]byte(answers), &as)
		for _, a := range as {
			q.Answers = append(q.Answers, model.DNSAnswer{Name: a.Name, Type: a.Type, Data: a.Data, TTL: a.TTL, Expires: q.TS + int64(a.TTL)*1000})
		}
		if dev != 0 {
			devs[dev] = true
		}
		devIDs = append(devIDs, dev)
		out = append(out, q)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	labels, macs, err := s.labels(ctx, devs)
	if err != nil {
		return nil, err
	}
	for i, id := range devIDs {
		if id != 0 {
			out[i].Device = model.EntityID(model.KindDevice, macs[id])
			out[i].DeviceName = labels[id]
		}
	}
	return out, nil
}

// --- facts ------------------------------------------------------------------

// Facts returns relationships that held at some point in the window.
func (s *Store) Facts(ctx context.Context, f model.Filter) ([]model.Fact, error) {
	from, to := s.window(f)
	w := &where{}
	w.add("f.first_seen < ? AND f.last_seen >= ?", to, from)
	if f.Device != "" {
		ids, err := s.deviceIDs(ctx, f.Device)
		if err != nil {
			return nil, err
		}
		w.add("(f.src IN (" + idList(ids) + ") OR f.dst IN (" + idList(ids) + "))")
	}
	if f.Domain != "" {
		w.add("((a.kind = 'domain' AND lower(a.key) GLOB ?) OR (b.kind = 'domain' AND lower(b.key) GLOB ?))", glob(f.Domain), glob(f.Domain))
	}
	if f.IP != "" {
		c1, a1 := ipCond("a.key", f.IP)
		c2, a2 := ipCond("b.key", f.IP)
		w.add("((a.kind = 'ip' AND "+c1+") OR (b.kind = 'ip' AND "+c2+"))", a1, a2)
	}
	return s.queryFacts(ctx, w, limit(f, 2000, 100000))
}

func (s *Store) queryFacts(ctx context.Context, w *where, n int) ([]model.Fact, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT f.rel, a.kind, a.key, a.label, a.attrs, b.kind, b.key, b.label, f.first_seen, f.last_seen, f.count, f.source, f.attrs
		FROM facts f JOIN entities a ON a.id = f.src JOIN entities b ON b.id = f.dst
		WHERE `+w.sql()+` ORDER BY f.last_seen DESC LIMIT ?`, append(w.args, n)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Fact
	for rows.Next() {
		var ft model.Fact
		var ak, akey, al, aattrs, bk, bkey, bl, attrs string
		if err := rows.Scan(&ft.Rel, &ak, &akey, &al, &aattrs, &bk, &bkey, &bl, &ft.FirstSeen, &ft.LastSeen, &ft.Count, &ft.Source, &attrs); err != nil {
			return nil, err
		}
		ft.Src, ft.Dst = model.EntityID(ak, akey), model.EntityID(bk, bkey)
		ft.SrcLabel, ft.DstLabel = al, firstNonEmpty(bl, bkey)
		if ak == model.KindDevice {
			var a map[string]string
			_ = json.Unmarshal([]byte(aattrs), &a)
			ft.SrcLabel = deviceLabel(akey, al, a)
		}
		_ = json.Unmarshal([]byte(attrs), &ft.Attrs)
		if len(ft.Attrs) == 0 {
			ft.Attrs = nil
		}
		out = append(out, ft)
	}
	return out, rows.Err()
}

// --- devices ----------------------------------------------------------------

// Devices returns the local devices active in the window: any device with
// traffic, lookups or an identity observation in it.
func (s *Store) Devices(ctx context.Context, f model.Filter) ([]model.Device, error) {
	from, to := s.window(f)
	exact := s.precision(from) == model.PrecisionExact
	active := map[int64][2]int64{} // id -> active from/to
	note := func(id, a, b int64) {
		if id == 0 {
			return
		}
		r, ok := active[id]
		if !ok {
			active[id] = [2]int64{a, b}
			return
		}
		active[id] = [2]int64{min(r[0], a), max(r[1], b)}
	}
	collect := func(q string, args ...any) error {
		rows, err := s.r.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, a, b int64
			if err := rows.Scan(&id, &a, &b); err != nil {
				return err
			}
			note(id, max(a, from), min(b, to))
		}
		return rows.Err()
	}
	if exact {
		if err := collect(`SELECT client_device, min(t_start), max(t_end) FROM flows WHERE t_start < ? AND t_end >= ? AND client_device != 0 GROUP BY client_device`, to, from); err != nil {
			return nil, err
		}
		if err := collect(`SELECT client_device, min(ts), max(ts) FROM dns WHERE ts >= ? AND ts < ? AND client_device != 0 GROUP BY client_device`, from, to); err != nil {
			return nil, err
		}
	} else {
		if err := collect(`SELECT client_device, min(bucket), max(bucket) + 3600000 FROM traffic_hourly WHERE bucket < ? AND bucket >= ? AND client_device != 0 GROUP BY client_device`, to, hourOf(from)); err != nil {
			return nil, err
		}
	}
	if err := collect(`SELECT f.src, min(f.first_seen), max(f.last_seen) FROM facts f JOIN entities e ON e.id = f.src
		WHERE e.kind = 'device' AND f.first_seen < ? AND f.last_seen >= ? GROUP BY f.src`, to, from); err != nil {
		return nil, err
	}
	if f.Device != "" {
		ids, err := s.deviceIDs(ctx, f.Device)
		if err != nil {
			return nil, err
		}
		keep := map[int64]bool{}
		for _, id := range ids {
			keep[id] = true
		}
		for id := range active {
			if !keep[id] {
				delete(active, id)
			}
		}
	}
	if len(active) == 0 {
		return []model.Device{}, nil
	}
	ids := make([]int64, 0, len(active))
	for id := range active {
		ids = append(ids, id)
	}
	byID := map[int64]*model.Device{}
	rows, err := s.r.QueryContext(ctx, `SELECT id, key, label, attrs, first_seen, last_seen FROM entities WHERE id IN (`+idList(ids)+`)`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var d model.Device
		var attrs string
		if err := rows.Scan(&id, &d.MAC, &d.Label, &attrs, &d.FirstSeen, &d.LastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		var a map[string]string
		_ = json.Unmarshal([]byte(attrs), &a)
		d.ID = model.EntityID(model.KindDevice, d.MAC)
		d.Label = deviceLabel(d.MAC, d.Label, a)
		d.Vendor, d.Role = a["vendor"], a["role"]
		if d.Vendor == oui.Randomized {
			d.Vendor, d.Randomized = "", true
		}
		if d.Vendor != "" {
			d.VendorShort = oui.Short(d.Vendor)
		}
		d.ActiveFrom, d.ActiveTo = active[id][0], active[id][1]
		byID[id] = &d
	}
	rows.Close()

	// Identity facts in the window.
	rows, err = s.r.QueryContext(ctx, `SELECT f.src, f.rel, b.kind, b.key, b.label FROM facts f JOIN entities b ON b.id = f.dst
		WHERE f.src IN (`+idList(ids)+`) AND f.first_seen < ? AND f.last_seen >= ? ORDER BY f.last_seen DESC`, to, from)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for rows.Next() {
		var id int64
		var rel, kind, key, label string
		if err := rows.Scan(&id, &rel, &kind, &key, &label); err != nil {
			rows.Close()
			return nil, err
		}
		d := byID[id]
		k := fmt.Sprint(id, rel, key)
		if d == nil || seen[k] {
			continue
		}
		seen[k] = true
		switch rel {
		case model.RelHasIP:
			d.IPs = append(d.IPs, key)
		case model.RelHostname:
			d.Hostnames = append(d.Hostnames, firstNonEmpty(label, key))
		case model.RelAnnounces:
			d.Services = append(d.Services, firstNonEmpty(label, key))
		case model.RelFingerprint:
			d.Fingerprints = append(d.Fingerprints, key)
		case model.RelUserAgent:
			d.UserAgents = append(d.UserAgents, key)
		}
	}
	rows.Close()

	// Traffic and lookups in the window.
	if exact {
		flows, err := s.Flows(ctx, model.Filter{From: time.UnixMilli(from), To: time.UnixMilli(to), Multicast: f.Multicast, Limit: 100000})
		if err != nil {
			return nil, err
		}
		byKey := map[string]*model.Device{}
		for _, d := range byID {
			byKey[d.ID] = d
		}
		remotes := map[string]map[string]bool{}
		for _, fl := range flows {
			d := byKey[fl.Device]
			if d == nil {
				continue
			}
			d.Flows++
			d.BytesOut += fl.BytesOut
			d.BytesIn += fl.BytesIn
			if remotes[d.ID] == nil {
				remotes[d.ID] = map[string]bool{}
			}
			remotes[d.ID][fl.RemoteIP] = true
		}
		for _, d := range byID {
			d.Remotes = len(remotes[d.ID])
		}
		if err := s.countInto(ctx, byID, `SELECT client_device, count(*) FROM dns WHERE ts >= ? AND ts < ? AND client_device IN (`+idList(ids)+`) GROUP BY client_device`,
			func(d *model.Device, n int64) { d.DNSQueries = int(n) }, from, to); err != nil {
			return nil, err
		}
	} else {
		rows, err := s.r.QueryContext(ctx, `SELECT client_device, sum(flows), sum(bytes_out), sum(bytes_in), count(DISTINCT remote_ip) FROM traffic_hourly
			WHERE bucket < ? AND bucket >= ? AND client_device IN (`+idList(ids)+`) AND multicast <= ? GROUP BY client_device`, to, hourOf(from), boolInt(f.Multicast))
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id int64
			var n, rem int
			var bo, bi uint64
			if err := rows.Scan(&id, &n, &bo, &bi, &rem); err != nil {
				rows.Close()
				return nil, err
			}
			if d := byID[id]; d != nil {
				d.Flows, d.BytesOut, d.BytesIn, d.Remotes = n, bo, bi, rem
			}
		}
		rows.Close()
		if err := s.countInto(ctx, byID, `SELECT client_device, sum(count) FROM dns_hourly WHERE bucket < ? AND bucket >= ? AND client_device IN (`+idList(ids)+`) GROUP BY client_device`,
			func(d *model.Device, n int64) { d.DNSQueries = int(n) }, to, hourOf(from)); err != nil {
			return nil, err
		}
	}

	out := make([]model.Device, 0, len(byID))
	for _, d := range byID {
		if f.IP != "" && !matchAny(d.IPs, f.IP) {
			continue
		}
		sort.Strings(d.IPs)
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.BytesOut+a.BytesIn != b.BytesOut+b.BytesIn {
			return a.BytesOut+a.BytesIn > b.BytesOut+b.BytesIn
		}
		return a.Label < b.Label
	})
	if n := limit(f, 1000, 100000); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func (s *Store) countInto(ctx context.Context, byID map[int64]*model.Device, q string, set func(*model.Device, int64), args ...any) error {
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, n int64
		if err := rows.Scan(&id, &n); err != nil {
			return err
		}
		if d := byID[id]; d != nil {
			set(d, n)
		}
	}
	return rows.Err()
}

func matchAny(ips []string, filter string) bool {
	p, perr := netip.ParsePrefix(filter)
	for _, s := range ips {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if perr == nil && p.Contains(a) || s == filter {
			return true
		}
	}
	return false
}

// --- timeseries -------------------------------------------------------------

// Timeseries buckets traffic over the window. A zero step picks one giving
// about 60 buckets, rounded to a readable size.
func (s *Store) Timeseries(ctx context.Context, f model.Filter, step time.Duration) (*model.Timeseries, error) {
	from, to := s.window(f)
	if step <= 0 {
		step = niceStep(time.Duration(to-from) * time.Millisecond / 60)
	}
	st := step.Milliseconds()
	prec := s.precision(from)
	if prec == model.PrecisionHour && st < hourMS {
		st = hourMS
	}
	start := from - ((from%st)+st)%st
	n := int((to - start + st - 1) / st)
	if n > 5000 {
		return nil, fmt.Errorf("window/step gives %d buckets; use a larger step", n)
	}
	ts := &model.Timeseries{StepMS: st, Precision: prec, Buckets: make([]model.Bucket, n)}
	for i := range ts.Buckets {
		ts.Buckets[i].TS = start + int64(i)*st
	}
	idx := func(t int64) int {
		i := int((t - start) / st)
		if i < 0 || i >= n {
			return -1
		}
		return i
	}
	w := &where{}
	if prec == model.PrecisionExact {
		w.add("t_start < ? AND t_end >= ?", to, from)
		if err := s.flowWhere(ctx, f, w, []string{"sni", "http_host", "qname"}); err != nil {
			return nil, err
		}
		rows, err := s.r.QueryContext(ctx, `SELECT flow_key, t_start, t_end, first_seen, bytes_out, bytes_in, client_device FROM flows WHERE `+w.sql(), w.args...)
		if err != nil {
			return nil, err
		}
		devs := make([]map[int64]bool, n)
		counted := map[string]bool{}
		for rows.Next() {
			var key string
			var a, b, first, dev int64
			var bo, bi uint64
			if err := rows.Scan(&key, &a, &b, &first, &bo, &bi, &dev); err != nil {
				rows.Close()
				return nil, err
			}
			spreadBytes(ts.Buckets, start, st, a, b, bo, bi)
			if !counted[key] && first >= from {
				counted[key] = true
				if i := idx(first); i >= 0 {
					ts.Buckets[i].FlowsNew++
				}
			}
			if dev != 0 {
				for i := max(idx(max(a, from)), 0); i >= 0 && i < n && ts.Buckets[i].TS <= b; i++ {
					if devs[i] == nil {
						devs[i] = map[int64]bool{}
					}
					devs[i][dev] = true
				}
			}
		}
		rows.Close()
		for i := range devs {
			ts.Buckets[i].Devices = len(devs[i])
		}
		dw := &where{}
		dw.add("ts >= ? AND ts < ?", from, to)
		if f.Device != "" {
			ids, err := s.deviceIDs(ctx, f.Device)
			if err != nil {
				return nil, err
			}
			dw.add("client_device IN (" + idList(ids) + ")")
		}
		if f.Domain != "" {
			dw.add("lower(qname) GLOB ?", glob(f.Domain))
		}
		rows, err = s.r.QueryContext(ctx, `SELECT ts FROM dns WHERE `+dw.sql(), dw.args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var t int64
			if err := rows.Scan(&t); err != nil {
				rows.Close()
				return nil, err
			}
			if i := idx(t); i >= 0 {
				ts.Buckets[i].DNSQueries++
			}
		}
		rows.Close()
		return ts, nil
	}
	w.add("bucket < ? AND bucket >= ?", to, hourOf(from))
	if err := s.flowWhere(ctx, f, w, []string{"name"}); err != nil {
		return nil, err
	}
	rows, err := s.r.QueryContext(ctx, `SELECT bucket, sum(flows), sum(bytes_out), sum(bytes_in), count(DISTINCT client_device) FROM traffic_hourly WHERE `+w.sql()+` GROUP BY bucket`, w.args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var b int64
		var nf, nd int
		var bo, bi uint64
		if err := rows.Scan(&b, &nf, &bo, &bi, &nd); err != nil {
			rows.Close()
			return nil, err
		}
		if i := idx(b); i >= 0 {
			ts.Buckets[i].FlowsNew += nf
			ts.Buckets[i].BytesOut += bo
			ts.Buckets[i].BytesIn += bi
			ts.Buckets[i].Devices = max(ts.Buckets[i].Devices, nd)
		}
	}
	rows.Close()
	rows, err = s.r.QueryContext(ctx, `SELECT bucket, sum(count) FROM dns_hourly WHERE bucket < ? AND bucket >= ? GROUP BY bucket`, to, hourOf(from))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b int64
		var c int
		if err := rows.Scan(&b, &c); err != nil {
			return nil, err
		}
		if i := idx(b); i >= 0 {
			ts.Buckets[i].DNSQueries += c
		}
	}
	return ts, rows.Err()
}

// spreadBytes adds a record's bytes to the buckets its interval covers,
// in proportion to the overlap.
func spreadBytes(bs []model.Bucket, start, step, a, b int64, bo, bi uint64) {
	if b <= a {
		if i := int((a - start) / step); a >= start && i < len(bs) {
			bs[i].BytesOut += bo
			bs[i].BytesIn += bi
		}
		return
	}
	span := float64(b - a)
	for i := max(int((a-start)/step), 0); i < len(bs); i++ {
		lo, hi := max(a, bs[i].TS), min(b, bs[i].TS+step)
		if lo >= b {
			break
		}
		if hi <= lo {
			continue
		}
		frac := float64(hi-lo) / span
		bs[i].BytesOut += uint64(float64(bo)*frac + 0.5)
		bs[i].BytesIn += uint64(float64(bi)*frac + 0.5)
	}
}

func niceStep(d time.Duration) time.Duration {
	for _, s := range []time.Duration{time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second, time.Minute, 5 * time.Minute,
		10 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour} {
		if d <= s {
			return s
		}
	}
	return 7 * 24 * time.Hour
}

// --- graph ------------------------------------------------------------------

// Graph assembles the window's graph: devices, what they looked up, what
// the names resolved to and whom they connected to.
func (s *Store) Graph(ctx context.Context, f model.Filter, o model.GraphOptions) (*model.Graph, error) {
	from, to := s.window(f)
	in := graph.Input{FromMS: from, ToMS: to, Precision: s.precision(from)}
	var err error
	ff := f
	ff.Limit = 20000
	if in.Devices, err = s.Devices(ctx, f); err != nil {
		return nil, err
	}
	if in.Flows, err = s.Flows(ctx, ff); err != nil {
		return nil, err
	}
	if o.DNS || o.Collapse {
		dq := f
		dq.Limit = 20000
		dq.IP = "" // keep the lookups that explain the addresses in the graph
		if in.Precision == model.PrecisionExact {
			if in.DNS, err = s.DNS(ctx, dq); err != nil {
				return nil, err
			}
		} else if in.DNS, err = s.dnsHourly(ctx, dq, from, to); err != nil {
			return nil, err
		}
	}
	fq := model.Filter{From: f.From, To: f.To, Device: f.Device, Limit: 50000}
	if in.Facts, err = s.Facts(ctx, fq); err != nil {
		return nil, err
	}
	// Address -> name facts are not device-scoped; fetch them for the
	// addresses in play.
	if f.Device != "" {
		all, err := s.Facts(ctx, model.Filter{From: f.From, To: f.To, Limit: 50000})
		if err != nil {
			return nil, err
		}
		for _, ft := range all {
			if ft.Rel == model.RelResolvesTo || ft.Rel == model.RelServes || ft.Rel == model.RelCNAME {
				in.Facts = append(in.Facts, ft)
			}
		}
	}
	g := graph.Build(in, o)
	return g, nil
}

func (s *Store) dnsHourly(ctx context.Context, f model.Filter, from, to int64) ([]model.DNSQuery, error) {
	w := &where{}
	w.add("bucket < ? AND bucket >= ?", to, hourOf(from))
	if f.Device != "" {
		ids, err := s.deviceIDs(ctx, f.Device)
		if err != nil {
			return nil, err
		}
		w.add("client_device IN (" + idList(ids) + ")")
	}
	if f.Domain != "" {
		w.add("lower(qname) GLOB ?", glob(f.Domain))
	}
	rows, err := s.r.QueryContext(ctx, `SELECT bucket, client_device, client_ip, qname, qtype, rcode, count FROM dns_hourly WHERE `+w.sql()+` LIMIT ?`, append(w.args, limit(f, 20000, 100000))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.DNSQuery
	devs := map[int64]bool{}
	var devIDs []int64
	for rows.Next() {
		var q model.DNSQuery
		var dev int64
		var n int
		if err := rows.Scan(&q.TS, &dev, &q.ClientIP, &q.QName, &q.QType, &q.RCode, &n); err != nil {
			return nil, err
		}
		for range n {
			out = append(out, q)
			devIDs = append(devIDs, dev)
		}
		devs[dev] = dev != 0
	}
	labels, macs, err := s.labels(ctx, devs)
	if err != nil {
		return nil, err
	}
	for i, id := range devIDs {
		if id != 0 {
			out[i].Device = model.EntityID(model.KindDevice, macs[id])
			out[i].DeviceName = labels[id]
		}
	}
	return out, rows.Err()
}

// --- summary, sensors, entity -------------------------------------------------

// Summary returns a window's headline numbers.
func (s *Store) Summary(ctx context.Context, f model.Filter) (*model.Summary, error) {
	from, to := s.window(f)
	sum := &model.Summary{FromMS: from, ToMS: to, Precision: s.precision(from)}
	devs, err := s.Devices(ctx, f)
	if err != nil {
		return nil, err
	}
	sum.Devices = len(devs)
	ff := f
	ff.Limit = 100000
	flows, err := s.Flows(ctx, ff)
	if err != nil {
		return nil, err
	}
	sum.Flows = len(flows)
	remotes := map[string]bool{}
	names := map[string]bool{}
	type span struct{ a, b int64 }
	var spans []span
	for _, fl := range flows {
		sum.BytesOut += fl.BytesOut
		sum.BytesIn += fl.BytesIn
		remotes[fl.RemoteIP] = true
		if fl.Name != "" {
			names[fl.Name] = true
		}
		spans = append(spans, span{max(fl.FirstSeen, from), min(fl.LastSeen, to)})
	}
	sum.RemoteIPs = len(remotes)
	sum.PeakConns = graph.Peak(func(yield func(a, b int64) bool) {
		for _, sp := range spans {
			if !yield(sp.a, sp.b) {
				return
			}
		}
	})
	if sum.Precision == model.PrecisionExact {
		w := &where{}
		w.add("ts >= ? AND ts < ?", from, to)
		if err := s.r.QueryRowContext(ctx, `SELECT count(*), count(DISTINCT qname) FROM dns WHERE `+w.sql(), w.args...).Scan(&sum.DNSQueries, new(int)); err != nil {
			return nil, err
		}
		rows, err := s.r.QueryContext(ctx, `SELECT DISTINCT qname FROM dns WHERE ts >= ? AND ts < ?`, from, to)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var q string
			if err := rows.Scan(&q); err != nil {
				rows.Close()
				return nil, err
			}
			names[q] = true
		}
		rows.Close()
	} else if err := s.r.QueryRowContext(ctx, `SELECT coalesce(sum(count), 0) FROM dns_hourly WHERE bucket < ? AND bucket >= ?`, to, hourOf(from)).Scan(&sum.DNSQueries); err != nil {
		return nil, err
	}
	sum.Domains = len(names)
	var oldest, newest, rawOldest sql.NullInt64
	_ = s.r.QueryRowContext(ctx, `SELECT min(bucket), max(bucket) + 3600000 FROM traffic_hourly`).Scan(&oldest, &newest)
	_ = s.r.QueryRowContext(ctx, `SELECT min(t_start) FROM flows`).Scan(&rawOldest)
	sum.OldestData, sum.NewestData, sum.RawFrom = oldest.Int64, newest.Int64, rawOldest.Int64
	return sum, nil
}

// Sensors lists the sensors that have sent data.
func (s *Store) Sensors(ctx context.Context) ([]model.Sensor, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT name, version, first_seen, last_seen, hello, stats FROM sensors ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Sensor{}
	for rows.Next() {
		var sn model.Sensor
		var hello, stats string
		if err := rows.Scan(&sn.Name, &sn.Version, &sn.FirstSeen, &sn.LastSeen, &hello, &stats); err != nil {
			return nil, err
		}
		var h struct {
			Interfaces []struct{ Name string } `json:"interfaces"`
		}
		_ = json.Unmarshal([]byte(hello), &h)
		for _, i := range h.Interfaces {
			sn.Interfaces = append(sn.Interfaces, i.Name)
		}
		_ = json.Unmarshal([]byte(stats), &sn.Stats)
		out = append(out, sn)
	}
	return out, rows.Err()
}
