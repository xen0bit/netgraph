package store

import (
	"cmp"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"modernc.org/sqlite"

	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/oui"
	"github.com/xen0bit/netgraph/internal/wire"
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

// precision reports how a window is answered: from raw records when they
// still cover its start and it is no longer than ExactMax, else from the
// hourly rollups.
func (s *Store) precision(from, to int64) string {
	if from >= ms(s.cfg.Now().Add(-s.cfg.RawRetention)) && to-from <= s.cfg.ExactMax.Milliseconds() {
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

func offset(f model.Filter) int { return max(f.Offset, 0) }

// glob turns a user pattern into a lower-cased GLOB pattern; a pattern with
// no wildcards matches as a substring.
func glob(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if !strings.ContainsAny(p, "*?[") {
		p = "*" + p + "*"
	}
	return p
}

// flowsWindow adds the condition for flow records overlapping [from, to).
// Records span at most MaxRecordSpan, so t_end is bounded on both sides
// and the flows_time index range covers the window plus that span, not
// everything since from.
func flowsWindow(w *where, from, to int64) {
	w.add("t_end >= ? AND t_end < ? AND t_start < ?", from, to+MaxRecordSpan.Milliseconds(), to)
}

// flowsFrom is the FROM clause for window queries over raw flow records.
// The index is forced: SQLite otherwise may walk another index across the
// whole table.
const flowsFrom = "flows INDEXED BY flows_time"

// connBytes is a connection's col (bytes_out, ...) inside [from, to): its
// stored total when the connection lies wholly inside the window, else the
// prorated sum of its interval records. Only connections crossing an edge
// pay for the subquery.
func connBytes(col string, from, to int64) string {
	return fmt.Sprintf(`(CASE WHEN c.first_seen >= %[2]d AND c.last_seen < %[3]d THEN c.%[1]s ELSE
		(SELECT coalesce(sum(CASE WHEN f.t_end > f.t_start THEN f.%[1]s * ((min(f.t_end, %[3]d) - max(f.t_start, %[2]d)) * 1.0 / (f.t_end - f.t_start)) ELSE f.%[1]s END), 0)
		 FROM flows f WHERE f.flow_key = c.flow_key AND f.t_end >= %[2]d AND f.t_start < %[3]d) END)`, col, from, to)
}

// connsWindow adds the condition for connections active in [from, to).
func connsWindow(w *where, from, to int64) {
	w.add("c.last_seen >= ? AND c.first_seen < ?", from, to)
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

// inList is "expr IN (vals)" for any number of values, bound as one JSON
// array: a placeholder per value would run into SQLite's limit on bound
// variables (32766) in a busy window.
func inList(expr string, vals []string) (string, any) {
	if vals == nil {
		vals = []string{}
	}
	b, _ := json.Marshal(vals) // a []string always marshals
	return expr + " IN (SELECT value FROM json_each(?))", string(b)
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

// flowCols are the columns flowWhere filters on, which raw flows and
// traffic_hourly name differently.
type flowCols struct {
	names   []string // a connection's names
	port    string   // the server's port
	asn, cc string   // the remote end's network and country
}

var (
	// An inbound connection's server is the device: its port is the
	// device's own.
	rawCols    = flowCols{names: []string{"sni", "http_host", "qname"}, port: serverPort(""), asn: "remote_asn", cc: "remote_cc"}
	hourlyCols = flowCols{names: []string{"name"}, port: "remote_port", asn: "remote_asn", cc: "remote_cc"}
	// Interval records keep no network: their connection has it.
	recordCols = flowCols{names: rawCols.names, port: rawCols.port,
		asn: "(SELECT n.remote_asn FROM connections n WHERE n.flow_key = flows.flow_key)",
		cc:  "(SELECT n.remote_cc FROM connections n WHERE n.flow_key = flows.flow_key)"}
)

// serverPort is the SQL for the server's port of a connections or flows
// row, its columns qualified by alias ("c." or "").
func serverPort(alias string) string {
	return "(CASE WHEN " + alias + "direction = 'in' THEN " + alias + "client_port ELSE " + alias + "remote_port END)"
}

// flowWhere builds the conditions shared by flow queries over table
// columns (raw flows and traffic_hourly name some columns differently).
func (s *Store) flowWhere(ctx context.Context, f model.Filter, w *where, cols flowCols) error {
	nameCols := cols.names
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
		w.add(cols.port+" = ?", f.Port)
	}
	if f.Dir != "" {
		w.add("direction = ?", f.Dir)
	}
	if f.Proto != "" {
		if n, ok := protoNumber(f.Proto); ok {
			w.add("proto = ?", n)
		}
	}
	if f.App != "" {
		w.add("app = ?", f.App)
	}
	if f.ASN != 0 {
		w.add(cols.asn+" = ?", f.ASN)
	}
	if f.Country != "" {
		w.add(cols.cc+" = ?", f.Country)
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
	return s.flowsWhere(ctx, f, "", nil)
}

// flowsWhere is Flows with an extra SQL condition over connections c.
func (s *Store) flowsWhere(ctx context.Context, f model.Filter, extra string, extraArgs []any) ([]model.Flow, error) {
	from, to := s.window(f)
	if s.precision(from, to) == model.PrecisionHour {
		return s.flowsHourly(ctx, f, from, to)
	}
	w := &where{}
	connsWindow(w, from, to)
	if extra != "" {
		w.add(extra, extraArgs...)
	}
	if err := s.flowWhere(ctx, f, w, rawCols); err != nil {
		return nil, err
	}
	q := `SELECT flow_key, proto, client_ip, client_port, client_mac, client_device, remote_ip, remote_port, direction,
		app, sni, http_host, qname, alpn, ja4, user_agent, first_seen, last_seen, final, end_reason,
		coalesce(remote_asn, 0), remote_cc,
		` + connBytes("bytes_out", from, to) + ` AS bo, ` + connBytes("bytes_in", from, to) + ` AS bi,
		` + connBytes("pkts_out", from, to) + `, ` + connBytes("pkts_in", from, to) + `
		FROM connections c WHERE ` + w.sql() + `
		ORDER BY bo + bi DESC, first_seen LIMIT ? OFFSET ?`
	rows, err := s.r.QueryContext(ctx, q, append(w.args, limit(f, 1000, 100000), offset(f))...)
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
		var localIP string
		var localPort int
		if err := rows.Scan(&fl.Key, &proto, &localIP, &localPort, &fl.DeviceMAC, &dev, &fl.RemoteIP, &fl.RemotePort, &fl.Direction,
			&fl.App, &fl.SNI, &fl.HTTPHost, &fl.QName, &fl.ALPN, &fl.JA4, &fl.UserAgent,
			&fl.FirstSeen, &fl.LastSeen, &final, &fl.EndReason, &fl.ASN, &fl.Country, &bo, &bi, &po, &pi); err != nil {
			return nil, err
		}
		setEnds(&fl, localIP, localPort)
		fl.Proto = ProtoName(proto)
		fl.BytesOut, fl.BytesIn, fl.PktsOut, fl.PktsIn = uint64(bo+0.5), uint64(bi+0.5), uint64(po+0.5), uint64(pi+0.5)
		fl.Name = firstNonEmpty(fl.SNI, fl.HTTPHost, fl.QName)
		fl.Connections = 1
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
	peers, err := s.peerDevices(ctx, out, from, to)
	if err != nil {
		return nil, err
	}
	for _, id := range peers {
		if id != 0 {
			devs[id] = true
		}
	}
	labels, macs, err := s.labels(ctx, devs)
	if err != nil {
		return nil, err
	}
	if err := s.setASOrgs(ctx, out); err != nil {
		return nil, err
	}
	for i, id := range devIDs {
		if id != 0 {
			out[i].Device = model.EntityID(model.KindDevice, macs[id])
			out[i].DeviceName = labels[id]
		}
		if id := peers[out[i].RemoteIP]; id != 0 && out[i].Direction == model.DirLocal {
			out[i].PeerDevice = model.EntityID(model.KindDevice, macs[id])
			out[i].PeerName = labels[id]
		}
	}
	return out, nil
}

// peerDevices maps the remote addresses of LAN-to-LAN flows to the one
// device that held each in the window (an address two devices held maps
// to neither).
func (s *Store) peerDevices(ctx context.Context, flows []model.Flow, from, to int64) (map[string]int64, error) {
	ips := map[string]bool{}
	for _, fl := range flows {
		if fl.Direction == model.DirLocal {
			ips[fl.RemoteIP] = true
		}
	}
	out := map[string]int64{}
	if len(ips) == 0 {
		return out, nil
	}
	cond, arg := inList("ip.key", slices.Sorted(maps.Keys(ips)))
	rows, err := s.r.QueryContext(ctx, `SELECT ip.key, f.src FROM entities ip JOIN facts f ON f.dst = ip.id AND f.rel = 'has_ip'
		WHERE ip.kind = 'ip' AND `+cond+`
		AND f.last_seen >= ? AND f.first_seen < ? GROUP BY 1, 2`, arg, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var dev int64
		if err := rows.Scan(&ip, &dev); err != nil {
			return nil, err
		}
		if _, dup := out[ip]; dup {
			out[ip] = 0
		} else {
			out[ip] = dev
		}
	}
	return out, rows.Err()
}

// maxServes is how many of a device's served ports Devices lists.
const maxServes = 8

// serves fills each device's Serves from rows of (device, port, proto,
// connections): the ports it accepted connections on, busiest first.
func (s *Store) serves(ctx context.Context, byID map[int64]*model.Device, q string, args []any) error {
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	type svc struct {
		name string
		n    int
	}
	by := map[int64][]svc{}
	for rows.Next() {
		var dev int64
		var port, proto, n int
		if err := rows.Scan(&dev, &port, &proto, &n); err != nil {
			return err
		}
		by[dev] = append(by[dev], svc{model.Flow{ServerPort: port, Proto: ProtoName(proto)}.Service(), n})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for dev, ss := range by {
		d := byID[dev]
		if d == nil {
			continue
		}
		slices.SortFunc(ss, func(a, b svc) int { return cmp.Or(cmp.Compare(b.n, a.n), cmp.Compare(a.name, b.name)) })
		for _, x := range ss[:min(len(ss), maxServes)] {
			d.Serves = append(d.Serves, x.name)
		}
	}
	return nil
}

// setEnds fills a flow's client and server from its device's end and its
// remote end, as the tables keep them.
func setEnds(fl *model.Flow, localIP string, localPort int) {
	fl.ClientIP, fl.ClientPort, fl.ServerIP, fl.ServerPort = localIP, localPort, fl.RemoteIP, fl.RemotePort
	if fl.Inbound() {
		fl.ClientIP, fl.ClientPort, fl.ServerIP, fl.ServerPort = fl.RemoteIP, fl.RemotePort, localIP, localPort
	}
}

// flowsHourly answers Flows from rollups: one row per destination per
// device, with no per-connection detail.
func (s *Store) flowsHourly(ctx context.Context, f model.Filter, from, to int64) ([]model.Flow, error) {
	w := &where{}
	w.add("bucket < ? AND bucket >= ?", to, hourOf(from))
	if err := s.flowWhere(ctx, f, w, hourlyCols); err != nil {
		return nil, err
	}
	rows, err := s.r.QueryContext(ctx, `SELECT client_device, client_ip, remote_ip, remote_port, proto, name, direction, max(app),
		min(bucket), max(bucket), sum(flows), sum(bytes_out), sum(bytes_in), coalesce(max(remote_asn), 0), max(remote_cc)
		FROM traffic_hourly WHERE `+w.sql()+`
		GROUP BY client_device, client_ip, remote_ip, remote_port, proto, name, direction ORDER BY sum(bytes_out) + sum(bytes_in) DESC LIMIT ? OFFSET ?`, append(w.args, limit(f, 1000, 100000), offset(f))...)
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
		var localIP string
		var port int
		if err := rows.Scan(&dev, &localIP, &fl.RemoteIP, &port, &proto, &fl.Name, &fl.Direction, &fl.App, &first, &last, &n, &fl.BytesOut, &fl.BytesIn, &fl.ASN, &fl.Country); err != nil {
			return nil, err
		}
		fl.Key = fmt.Sprintf("hourly:%d:%s:%s:%d:%d:%s", dev, localIP, fl.RemoteIP, port, proto, fl.Direction)
		fl.Proto = ProtoName(proto)
		fl.FirstSeen, fl.LastSeen = first, last+hourMS
		fl.State = model.StateOpened
		// Rollups keep only the server's port, which is the device's own
		// when the connection came in.
		if fl.Direction != model.DirIn {
			fl.RemotePort, port = port, 0
		}
		setEnds(&fl, localIP, port)
		fl.Connections = n // packet counts are not rolled up
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
	if err := s.setASOrgs(ctx, out); err != nil {
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
	return s.dnsQuery(ctx, f, "", nil)
}

// dnsWhere selects the window's lookups that match the filter's device,
// domain and address. Ports, protocols and directions describe connections,
// not lookups.
func (s *Store) dnsWhere(ctx context.Context, f model.Filter, from, to int64) (*where, error) {
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
	return w, nil
}

func (s *Store) dnsQuery(ctx context.Context, f model.Filter, extra string, extraArgs []any) ([]model.DNSQuery, error) {
	from, to := s.window(f)
	w, err := s.dnsWhere(ctx, f, from, to)
	if err != nil {
		return nil, err
	}
	if extra != "" {
		w.add(extra, extraArgs...)
	}
	rows, err := s.r.QueryContext(ctx, `SELECT ts, client_ip, client_device, server_ip, qname, qtype, rcode, coalesce(latency_ms, 0), answers
		FROM dns WHERE `+w.sql()+` ORDER BY ts DESC LIMIT ? OFFSET ?`, append(w.args, limit(f, 500, 50000), offset(f))...)
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
	return s.queryFactsPage(ctx, w, limit(f, 2000, 100000), offset(f))
}

func (s *Store) queryFacts(ctx context.Context, w *where, n int) ([]model.Fact, error) {
	return s.queryFactsPage(ctx, w, n, 0)
}

func (s *Store) queryFactsPage(ctx context.Context, w *where, n, off int) ([]model.Fact, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT f.rel, a.kind, a.key, a.label, a.attrs, b.kind, b.key, b.label, f.first_seen, f.last_seen, f.count, f.source, f.attrs
		FROM facts f JOIN entities a ON a.id = f.src JOIN entities b ON b.id = f.dst
		WHERE `+w.sql()+` ORDER BY f.last_seen DESC LIMIT ? OFFSET ?`, append(w.args, n, off)...)
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
	exact := s.precision(from, to) == model.PrecisionExact
	byID := map[int64]*model.Device{}
	get := func(id int64) *model.Device {
		d := byID[id]
		if d == nil {
			d = &model.Device{ActiveFrom: to, ActiveTo: from}
			byID[id] = d
		}
		return d
	}
	active := func(d *model.Device, a, b int64) {
		d.ActiveFrom = min(d.ActiveFrom, max(a, from))
		d.ActiveTo = max(d.ActiveTo, min(b, to))
	}
	scan := func(q string, args []any, fn func(d *model.Device, a, b int64, vals []int64)) error {
		rows, err := s.r.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]int64, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				return err
			}
			d := get(vals[0])
			active(d, vals[1], vals[2])
			fn(d, vals[1], vals[2], vals[3:])
		}
		return rows.Err()
	}
	var err error
	flowSet := map[int64]bool{}
	if exact {
		w := &where{}
		connsWindow(w, from, to)
		w.add("c.client_device != 0")
		if err := s.flowWhere(ctx, f, w, rawCols); err != nil {
			return nil, err
		}
		err = scan(`SELECT c.client_device, min(c.first_seen), max(c.last_seen), count(*), count(DISTINCT c.remote_ip),
			CAST(round(sum(`+connBytes("bytes_out", from, to)+`)) AS INTEGER), CAST(round(sum(`+connBytes("bytes_in", from, to)+`)) AS INTEGER),
			sum(c.direction = 'in')
			FROM connections c WHERE `+w.sql()+` GROUP BY c.client_device`, w.args, func(d *model.Device, _, _ int64, v []int64) {
			d.Flows, d.Remotes, d.BytesOut, d.BytesIn, d.Inbound = int(v[0]), int(v[1]), uint64(v[2]), uint64(v[3]), int(v[4])
		})
		if err == nil {
			err = s.serves(ctx, byID, `SELECT c.client_device, c.client_port, c.proto, count(*) FROM connections c
				WHERE `+w.sql()+` AND c.direction = 'in' GROUP BY 1, 2, 3`, w.args)
		}
		for id := range byID {
			flowSet[id] = true
		}
		if err == nil {
			var dw *where
			dw, err = s.dnsWhere(ctx, f, from, to)
			if err == nil {
				err = scan(`SELECT client_device, min(ts), max(ts), count(*) FROM dns WHERE `+dw.sql()+` AND client_device != 0 GROUP BY client_device`,
					dw.args, func(d *model.Device, _, _ int64, v []int64) { d.DNSQueries = int(v[0]) })
			}
		}
	} else {
		w := &where{}
		w.add("bucket < ? AND bucket >= ? AND client_device != 0", to, hourOf(from))
		if err := s.flowWhere(ctx, f, w, hourlyCols); err != nil {
			return nil, err
		}
		err = scan(`SELECT client_device, min(bucket), max(bucket) + 3600000, sum(flows), count(DISTINCT remote_ip), sum(bytes_out), sum(bytes_in),
			sum(CASE WHEN direction = 'in' THEN flows ELSE 0 END)
			FROM traffic_hourly WHERE `+w.sql()+` GROUP BY client_device`,
			w.args, func(d *model.Device, _, _ int64, v []int64) {
				d.Flows, d.Remotes, d.BytesOut, d.BytesIn, d.Inbound = int(v[0]), int(v[1]), uint64(v[2]), uint64(v[3]), int(v[4])
			})
		if err == nil {
			err = s.serves(ctx, byID, `SELECT client_device, remote_port, proto, sum(flows) FROM traffic_hourly
				WHERE `+w.sql()+` AND direction = 'in' GROUP BY 1, 2, 3`, w.args)
		}
		for id := range byID {
			flowSet[id] = true
		}
		if err == nil {
			var dw *where
			dw, err = s.dnsHourlyWhere(ctx, f, from, to)
			if err == nil {
				dw.add("client_device != 0")
				err = scan(`SELECT client_device, min(bucket), max(bucket), sum(count) FROM dns_hourly WHERE `+dw.sql()+` GROUP BY client_device`,
					dw.args, func(d *model.Device, _, _ int64, v []int64) { d.DNSQueries = int(v[0]) })
			}
		}
	}
	if err != nil {
		return nil, err
	}
	dnsSet := map[int64]bool{}
	for id := range byID {
		if !flowSet[id] {
			dnsSet[id] = true
		}
	}
	// narrow filters describe connections, so only a device with a matching
	// connection qualifies. Domain and address filters may also match a
	// lookup or one of the device's own addresses.
	narrow := f.Port != 0 || f.Proto != "" || f.App != "" || f.Dir != "" || f.ASN != 0 || f.Country != ""
	var keep map[int64]bool
	switch {
	case narrow:
		keep = flowSet
		if f.Device != "" {
			matched, err := s.deviceIDs(ctx, f.Device)
			if err != nil {
				return nil, err
			}
			only := map[int64]bool{}
			for _, id := range matched {
				only[id] = true
			}
			for id := range keep {
				if !only[id] {
					delete(keep, id)
				}
			}
		}
	case f.Device != "":
		matched, err := s.deviceIDs(ctx, f.Device)
		if err != nil {
			return nil, err
		}
		keep = map[int64]bool{}
		for _, id := range matched {
			keep[id] = true
		}
	case f.Domain != "" || f.IP != "":
		keep = map[int64]bool{}
		for id := range flowSet {
			keep[id] = true
		}
		for id := range dnsSet {
			keep[id] = true
		}
	}
	selected := map[int64]bool{}
	for id := range flowSet {
		selected[id] = true
	}
	for id := range dnsSet {
		selected[id] = true
	}

	// Every device entity, then the identity facts of all of them in the
	// window, which facts_src (src, last_seen) answers directly.
	ents := map[int64]*model.Device{}
	rows, err := s.r.QueryContext(ctx, `SELECT id, key, label, attrs, first_seen, last_seen FROM entities WHERE kind = 'device'`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var e model.Device
		var attrs string
		if err := rows.Scan(&id, &e.MAC, &e.Label, &attrs, &e.FirstSeen, &e.LastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		var a map[string]string
		_ = json.Unmarshal([]byte(attrs), &a)
		e.ID = model.EntityID(model.KindDevice, e.MAC)
		e.Label = deviceLabel(e.MAC, e.Label, a)
		if a["user_label"] != "" {
			e.UserLabel, e.AutoLabel = true, deviceLabel(e.MAC, a["auto_label"], a)
		}
		e.Vendor, e.Role = a["vendor"], a["role"]
		if e.Vendor == oui.Randomized {
			e.Vendor, e.Randomized = "", true
		}
		if e.Vendor != "" {
			e.VendorShort = oui.Short(e.Vendor)
		}
		ents[id] = &e
	}
	rows.Close()
	ids := make([]int64, 0, len(ents))
	for id := range ents {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	seen := map[string]bool{}
	for chunk := range slices.Chunk(ids, 500) {
		rows, err := s.r.QueryContext(ctx, `SELECT f.src, f.rel, b.key, b.label, f.first_seen, f.last_seen FROM facts f JOIN entities b ON b.id = f.dst
			WHERE f.src IN (`+idList(chunk)+`) AND f.last_seen >= ? AND f.first_seen < ? ORDER BY f.last_seen DESC`, from, to)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, a, b int64
			var rel, key, label string
			if err := rows.Scan(&id, &rel, &key, &label, &a, &b); err != nil {
				rows.Close()
				return nil, err
			}
			allowed := keep == nil || keep[id]
			if !allowed && f.IP != "" && rel == model.RelHasIP && matchAny([]string{key}, f.IP) {
				allowed = true
				keep[id] = true
			}
			if !allowed {
				continue
			}
			d := get(id)
			active(d, a, b)
			k := fmt.Sprint(id, rel, key)
			if seen[k] {
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
	}

	out := make([]model.Device, 0, len(byID))
	for id, d := range byID {
		e := ents[id]
		if e == nil || keep != nil && !keep[id] {
			continue
		}
		d.ID, d.MAC, d.Label, d.Vendor, d.VendorShort, d.Randomized, d.Role = e.ID, e.MAC, e.Label, e.Vendor, e.VendorShort, e.Randomized, e.Role
		d.UserLabel, d.AutoLabel = e.UserLabel, e.AutoLabel
		d.FirstSeen, d.LastSeen = e.FirstSeen, e.LastSeen
		// An address filter can select a device by its own address even
		// when no connection or lookup matched; a remote address is
		// selected through the connections above.
		if f.IP != "" && !selected[id] && !matchAny(d.IPs, f.IP) {
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
	if off := offset(f); off > 0 {
		if off >= len(out) {
			out = nil
		} else {
			out = out[off:]
		}
	}
	if n := limit(f, 1000, 100000); len(out) > n {
		out = out[:n]
	}
	return out, nil
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
	prec := s.precision(from, to)
	if prec == model.PrecisionHour && st < hourMS {
		st = hourMS
	}
	// Whole-hour steps over an hour-aligned window are exactly what the
	// rollups hold, and far cheaper than the raw records.
	if st%hourMS == 0 && from%hourMS == 0 {
		prec = model.PrecisionHour
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
		flowsWindow(w, from, to)
		if err := s.flowWhere(ctx, f, w, recordCols); err != nil {
			return nil, err
		}
		rows, err := s.r.QueryContext(ctx, `SELECT flow_key, t_start, t_end, first_seen, bytes_out, bytes_in, client_device FROM `+flowsFrom+` WHERE `+w.sql(), w.args...)
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
		dw, err := s.dnsWhere(ctx, f, from, to)
		if err != nil {
			return nil, err
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
	if err := s.flowWhere(ctx, f, w, hourlyCols); err != nil {
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
	dw, err := s.dnsHourlyWhere(ctx, f, from, to)
	if err != nil {
		return nil, err
	}
	rows, err = s.r.QueryContext(ctx, `SELECT bucket, sum(count) FROM dns_hourly WHERE `+dw.sql()+` GROUP BY bucket`, dw.args...)
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
	in := graph.Input{FromMS: from, ToMS: to, Precision: s.precision(from, to)}
	var err error
	if in.Devices, err = s.Devices(ctx, f); err != nil {
		return nil, err
	}
	ff := f
	const graphFlowCap = 20000
	ff.Limit = graphFlowCap + 1 // one extra tells us the cap was reached
	var keepNames map[string]bool
	if o.TopN > 0 && in.Precision == model.PrecisionExact {
		// Pick each device's busiest destinations in SQL first, then fetch
		// only their connections: the graph shows at most TopN per device,
		// and a long window holds far more.
		cond, args, names, rest, restIn, err := s.topDestinations(ctx, f, from, to, o)
		if err != nil {
			return nil, err
		}
		in.Rest, in.RestIn = rest, restIn
		if in.Flows, err = s.flowsWhere(ctx, ff, cond, args); err != nil {
			return nil, err
		}
		keepNames = names
	} else if in.Flows, err = s.Flows(ctx, ff); err != nil {
		return nil, err
	}
	if len(in.Flows) > graphFlowCap {
		in.Flows = in.Flows[:graphFlowCap]
		in.Truncated = true
	}
	if f.IP != "" {
		// An address filter selects connections by either end, but devices
		// by their own addresses: a device talking to the address would
		// lose its name. Add the devices the connections belong to.
		df := f
		df.IP = ""
		all, err := s.Devices(ctx, df)
		if err != nil {
			return nil, err
		}
		have, used := map[string]bool{}, map[string]bool{}
		for _, d := range in.Devices {
			have[d.ID] = true
		}
		for _, fl := range in.Flows {
			used[fl.Device], used[fl.PeerDevice] = true, true
		}
		for _, d := range all {
			if used[d.ID] && !have[d.ID] {
				in.Devices = append(in.Devices, d)
			}
		}
	}
	if o.DNS || o.Collapse {
		const graphDNSCap = 20000
		dq := f
		dq.Limit = graphDNSCap + 1
		dq.IP = "" // keep the lookups that explain the addresses in the graph
		if in.Precision == model.PrecisionExact {
			if in.DNS, err = s.dnsNames(ctx, dq, keepNames); err != nil {
				return nil, err
			}
		} else if in.DNS, err = s.dnsHourly(ctx, dq, from, to); err != nil {
			return nil, err
		}
		if len(in.DNS) > graphDNSCap {
			in.DNS = in.DNS[:graphDNSCap]
			in.Truncated = true
		}
	}
	// Facts about what is in play only: answers and SNI for its names, and
	// (with Identity) what its devices are. The name an inbound connection
	// asked for is the device's own, not a destination.
	names := map[string]bool{}
	for _, fl := range in.Flows {
		if fl.Inbound() {
			continue
		}
		for _, n := range []string{fl.Name, fl.QName} {
			if n != "" {
				names[n] = true
			}
		}
	}
	for _, q := range in.DNS {
		names[q.QName] = true
	}
	domIDs, err := s.entityIDs(ctx, model.KindDomain, names)
	if err != nil {
		return nil, err
	}
	for chunk := range slices.Chunk(domIDs, 500) {
		w := &where{}
		list := idList(chunk)
		w.add("f.first_seen < ? AND f.last_seen >= ? AND ((f.rel IN ('resolves_to', 'cname') AND f.src IN ("+list+")) OR (f.rel = 'serves' AND f.dst IN ("+list+")))", to, from)
		facts, err := s.queryFacts(ctx, w, 50000)
		if err != nil {
			return nil, err
		}
		in.Facts = append(in.Facts, facts...)
	}
	if o.Identity {
		macs := map[string]bool{}
		for _, d := range in.Devices {
			macs[d.MAC] = true
		}
		devIDs, err := s.entityIDs(ctx, model.KindDevice, macs)
		if err != nil {
			return nil, err
		}
		for chunk := range slices.Chunk(devIDs, 500) {
			w := &where{}
			w.add("f.first_seen < ? AND f.last_seen >= ? AND f.src IN ("+idList(chunk)+")", to, from)
			facts, err := s.queryFacts(ctx, w, 50000)
			if err != nil {
				return nil, err
			}
			in.Facts = append(in.Facts, facts...)
		}
	}
	g := graph.Build(in, o)
	if o.Anomalies {
		rep, err := s.Anomalies(ctx, f)
		if err != nil {
			return nil, err
		}
		graph.MarkAnomalies(g, rep.Anomalies)
	}
	return g, nil
}

// destExpr is where a connection points in a graph: the name it was reached
// by when collapsing, else its remote address, or with Networks the
// address's network. An inbound connection's peer is the client that
// opened it, by address or network. It matches graph.Build's choice for
// everything but LAN-to-LAN connections, which it maps to devices.
func destExpr(o model.GraphOptions) string {
	addr := `'ip:' || c.remote_ip`
	if o.Networks {
		addr = `(CASE WHEN c.direction != 'local' AND coalesce(c.remote_asn, 0) != 0 THEN 'asn:' || c.remote_asn ELSE 'ip:' || c.remote_ip END)`
	}
	if o.Collapse {
		return `CASE WHEN c.direction NOT IN ('local', 'in') AND coalesce(nullif(c.sni, ''), nullif(c.http_host, ''), nullif(c.qname, '')) IS NOT NULL
			THEN 'domain:' || coalesce(nullif(c.sni, ''), nullif(c.http_host, ''), nullif(c.qname, '')) ELSE ` + addr + ` END`
	}
	return addr
}

// srcExpr is a connection's device in topDestinations' keys: "o" or "i"
// (outbound, or inbound: Top N keeps each side on its own), then "d<entity
// id>" or "c<address>".
const srcExpr = `(CASE WHEN c.direction = 'in' THEN 'i' ELSE 'o' END) || (CASE WHEN c.client_device != 0 THEN 'd' || c.client_device ELSE 'c' || c.client_ip END)`

// topDestinations returns a condition selecting the connections to each
// device's TopN destinations by traffic in the window, and from its TopN
// inbound clients; the DNS names among those destinations; and per device
// what the rest of each add up to. With Sites a destination is a
// registrable domain, as the graph draws it.
func (s *Store) topDestinations(ctx context.Context, f model.Filter, from, to int64, o model.GraphOptions) (string, []any, map[string]bool, map[string]graph.Rest, map[string]graph.Rest, error) {
	w := &where{}
	connsWindow(w, from, to)
	if err := s.flowWhere(ctx, f, w, rawCols); err != nil {
		return "", nil, nil, nil, nil, err
	}
	dest := destExpr(o)
	rows, err := s.r.QueryContext(ctx, `SELECT `+srcExpr+` AS src, `+dest+` AS dest,
		sum(`+connBytes("bytes_out", from, to)+`), sum(`+connBytes("bytes_in", from, to)+`), count(*)
		FROM connections c WHERE `+w.sql()+` GROUP BY src, dest`, w.args...)
	if err != nil {
		return "", nil, nil, nil, nil, err
	}
	defer rows.Close()
	type group struct {
		key   string
		dests []string
		out   float64
		in    float64
		conns int
	}
	groups := map[string]map[string]*group{} // src -> drawn destination -> its connections' destinations
	for rows.Next() {
		var src, d string
		var out, in float64
		var n int
		if err := rows.Scan(&src, &d, &out, &in, &n); err != nil {
			return "", nil, nil, nil, nil, err
		}
		key := d
		if name, ok := strings.CutPrefix(d, "domain:"); ok && o.Sites {
			key = model.EntityID(model.KindSite, graph.Site(name))
		}
		if groups[src] == nil {
			groups[src] = map[string]*group{}
		}
		g := groups[src][key]
		if g == nil {
			g = &group{key: key}
			groups[src][key] = g
		}
		g.dests = append(g.dests, d)
		g.out += out
		g.in += in
		g.conns += n
	}
	if err := rows.Err(); err != nil {
		return "", nil, nil, nil, nil, err
	}
	var keys []string
	names := map[string]bool{}
	rest := map[string]graph.Rest{}
	for _, src := range slices.Sorted(maps.Keys(groups)) {
		gs := slices.Collect(maps.Values(groups[src]))
		slices.SortFunc(gs, func(a, b *group) int {
			if c := cmp.Compare(b.out+b.in, a.out+a.in); c != 0 {
				return c
			}
			return cmp.Compare(a.key, b.key)
		})
		for i, g := range gs {
			if i >= o.TopN {
				r := rest[src]
				r.Destinations++
				r.Connections += g.conns
				r.BytesOut += uint64(g.out)
				r.BytesIn += uint64(g.in)
				rest[src] = r
				continue
			}
			for _, d := range g.dests {
				keys = append(keys, src+"|"+d)
				if n, ok := strings.CutPrefix(d, "domain:"); ok {
					names[n] = true
				}
			}
		}
	}
	out, in, err := s.restSources(ctx, rest)
	if err != nil {
		return "", nil, nil, nil, nil, err
	}
	if len(keys) == 0 {
		return "0", nil, names, out, in, nil
	}
	cond, arg := inList(srcExpr+` || '|' || `+dest, keys)
	return cond, []any{arg}, names, out, in, nil
}

// restSources rekeys topDestinations' per-source totals from its SQL keys
// ("od<entity id>", "ic<client ip>", ...) to the graph's source IDs, split
// into what was left out of outbound destinations and of inbound clients.
func (s *Store) restSources(ctx context.Context, rest map[string]graph.Rest) (map[string]graph.Rest, map[string]graph.Rest, error) {
	out, in := map[string]graph.Rest{}, map[string]graph.Rest{}
	side := func(k string) map[string]graph.Rest {
		if strings.HasPrefix(k, "i") {
			return in
		}
		return out
	}
	var ids []int64
	for k, r := range rest {
		if ip, ok := strings.CutPrefix(k[1:], "c"); ok {
			side(k)[model.EntityID(model.KindIP, ip)] = r
		} else if id, err := strconv.ParseInt(strings.TrimPrefix(k[1:], "d"), 10, 64); err == nil && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	for chunk := range slices.Chunk(ids, 500) {
		rows, err := s.r.QueryContext(ctx, `SELECT id, kind, key FROM entities WHERE id IN (`+idList(chunk)+`)`)
		if err != nil {
			return nil, nil, err
		}
		for rows.Next() {
			var id int64
			var kind, key string
			if err := rows.Scan(&id, &kind, &key); err != nil {
				rows.Close()
				return nil, nil, err
			}
			d := "d" + strconv.FormatInt(id, 10)
			if r, ok := rest["o"+d]; ok {
				out[model.EntityID(kind, key)] = r
			}
			if r, ok := rest["i"+d]; ok {
				in[model.EntityID(kind, key)] = r
			}
		}
		if err := rows.Close(); err != nil {
			return nil, nil, err
		}
	}
	return out, in, nil
}

// dnsNames returns the window's lookups, only of the given names when
// names is not nil.
func (s *Store) dnsNames(ctx context.Context, f model.Filter, names map[string]bool) ([]model.DNSQuery, error) {
	if names == nil {
		return s.DNS(ctx, f)
	}
	cond, arg := inList("qname", slices.Sorted(maps.Keys(names)))
	return s.dnsQuery(ctx, f, cond, []any{arg})
}

// entityIDs looks up the IDs of entities of one kind by key.
func (s *Store) entityIDs(ctx context.Context, kind string, keys map[string]bool) ([]int64, error) {
	all := make([]string, 0, len(keys))
	for k := range keys {
		all = append(all, k)
	}
	sort.Strings(all)
	var out []int64
	for chunk := range slices.Chunk(all, 500) {
		args := []any{kind}
		marks := make([]string, len(chunk))
		for i, k := range chunk {
			marks[i] = "?"
			args = append(args, k)
		}
		rows, err := s.r.QueryContext(ctx, `SELECT id FROM entities WHERE kind = ? AND key IN (`+strings.Join(marks, ",")+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, id)
		}
		rows.Close()
	}
	return out, nil
}

// dnsHourlyWhere is dnsWhere for the hourly rollup, which keeps names but
// not answers: a domain filter matches the name looked up, and an address
// filter, which may name an answer, does not apply.
func (s *Store) dnsHourlyWhere(ctx context.Context, f model.Filter, from, to int64) (*where, error) {
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
	return w, nil
}

func (s *Store) dnsHourly(ctx context.Context, f model.Filter, from, to int64) ([]model.DNSQuery, error) {
	w, err := s.dnsHourlyWhere(ctx, f, from, to)
	if err != nil {
		return nil, err
	}
	rows, err := s.r.QueryContext(ctx, `SELECT bucket, client_device, client_ip, qname, qtype, rcode, count FROM dns_hourly WHERE `+w.sql()+`
		ORDER BY bucket DESC, qname, qtype, rcode LIMIT ? OFFSET ?`, append(w.args, limit(f, 20000, 100000), offset(f))...)
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
		if err := rows.Scan(&q.TS, &dev, &q.ClientIP, &q.QName, &q.QType, &q.RCode, &q.Count); err != nil {
			return nil, err
		}
		out = append(out, q)
		devIDs = append(devIDs, dev)
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
	sum := &model.Summary{FromMS: from, ToMS: to, Precision: s.precision(from, to)}
	devs, err := s.Devices(ctx, f)
	if err != nil {
		return nil, err
	}
	sum.Devices = len(devs)
	if sum.Precision == model.PrecisionExact {
		w := &where{}
		connsWindow(w, from, to)
		if err := s.flowWhere(ctx, f, w, rawCols); err != nil {
			return nil, err
		}
		var bo, bi float64
		if err := s.r.QueryRowContext(ctx, `SELECT count(*), count(DISTINCT remote_ip), coalesce(sum(`+connBytes("bytes_out", from, to)+`), 0), coalesce(sum(`+connBytes("bytes_in", from, to)+`), 0),
			coalesce(sum(direction = 'in'), 0)
			FROM connections c WHERE `+w.sql(), w.args...).Scan(&sum.Flows, &sum.RemoteIPs, &bo, &bi, &sum.Inbound); err != nil {
			return nil, err
		}
		sum.BytesOut, sum.BytesIn = uint64(bo+0.5), uint64(bi+0.5)
		rows, err := s.r.QueryContext(ctx, `SELECT first_seen, last_seen FROM connections c WHERE `+w.sql(), w.args...)
		if err != nil {
			return nil, err
		}
		var spans [][2]int64
		for rows.Next() {
			var a, b int64
			if err := rows.Scan(&a, &b); err != nil {
				rows.Close()
				return nil, err
			}
			spans = append(spans, [2]int64{max(a, from), min(b, to)})
		}
		rows.Close()
		sum.PeakConns = graph.Peak(func(yield func(a, b int64) bool) {
			for _, sp := range spans {
				if !yield(sp[0], sp[1]) {
					return
				}
			}
		})
		dw, err := s.dnsWhere(ctx, f, from, to)
		if err != nil {
			return nil, err
		}
		if err := s.r.QueryRowContext(ctx, `SELECT count(*) FROM dns WHERE `+dw.sql(), dw.args...).Scan(&sum.DNSQueries); err != nil {
			return nil, err
		}
		args := append(append([]any{}, w.args...), dw.args...)
		if err := s.r.QueryRowContext(ctx, `SELECT count(*) FROM (
			SELECT coalesce(nullif(sni, ''), nullif(http_host, ''), nullif(qname, '')) AS n FROM connections c WHERE `+w.sql()+`
			UNION SELECT qname FROM dns WHERE `+dw.sql()+`) WHERE n IS NOT NULL AND n != ''`, args...).Scan(&sum.Domains); err != nil {
			return nil, err
		}
	} else {
		w := &where{}
		w.add("bucket < ? AND bucket >= ?", to, hourOf(from))
		if err := s.flowWhere(ctx, f, w, hourlyCols); err != nil {
			return nil, err
		}
		if err := s.r.QueryRowContext(ctx, `SELECT coalesce(sum(flows), 0), count(DISTINCT remote_ip), coalesce(sum(bytes_out), 0), coalesce(sum(bytes_in), 0),
			coalesce(sum(CASE WHEN direction = 'in' THEN flows ELSE 0 END), 0)
			FROM traffic_hourly WHERE `+w.sql(), w.args...).
			Scan(&sum.Flows, &sum.RemoteIPs, &sum.BytesOut, &sum.BytesIn, &sum.Inbound); err != nil {
			return nil, err
		}
		dw, err := s.dnsHourlyWhere(ctx, f, from, to)
		if err != nil {
			return nil, err
		}
		if err := s.r.QueryRowContext(ctx, `SELECT coalesce(sum(count), 0) FROM dns_hourly WHERE `+dw.sql(), dw.args...).Scan(&sum.DNSQueries); err != nil {
			return nil, err
		}
		args := append(append([]any{}, w.args...), dw.args...)
		if err := s.r.QueryRowContext(ctx, `SELECT count(*) FROM (
			SELECT nullif(name, '') AS n FROM traffic_hourly WHERE `+w.sql()+`
			UNION SELECT qname FROM dns_hourly WHERE `+dw.sql()+`) WHERE n IS NOT NULL AND n != ''`, args...).Scan(&sum.Domains); err != nil {
			return nil, err
		}
	}
	var oldest, newest, rawOldest sql.NullInt64
	_ = s.r.QueryRowContext(ctx, `SELECT min(bucket), max(bucket) + 3600000 FROM traffic_hourly`).Scan(&oldest, &newest)
	_ = s.r.QueryRowContext(ctx, `SELECT min(first_seen) FROM connections`).Scan(&rawOldest)
	sum.OldestData, sum.NewestData, sum.RawFrom = oldest.Int64, newest.Int64, rawOldest.Int64
	return sum, nil
}

// WiFi lists the SSIDs access points were seen broadcasting in the window,
// with how many clients associated to each AP. It is empty unless a
// monitor-mode sensor has reported Wi-Fi observations.
func (s *Store) WiFi(ctx context.Context, f model.Filter) ([]model.WiFiNetwork, error) {
	out := []model.WiFiNetwork{}
	err := s.WalkWiFi(ctx, f, func(n model.WiFiNetwork) error {
		out = append(out, n)
		return nil
	})
	return out, err
}

// Sensors lists the sensors that have sent data.
// WiFiHandshakes returns the stored handshake nonce records so a sensor can
// re-derive pairwise keys on startup. It returns public nonces only, never a
// key: a caller still needs the network's passphrase to derive anything.
func (s *Store) WiFiHandshakes(ctx context.Context) ([]wire.WiFiKey, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT bssid, sta, ssid, anonce, snonce, key_version FROM wifi_handshakes ORDER BY ts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []wire.WiFiKey{}
	for rows.Next() {
		var k wire.WiFiKey
		if err := rows.Scan(&k.BSSID, &k.STA, &k.SSID, &k.ANonce, &k.SNonce, &k.KeyVersion); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// WiFiGroupKeys returns the stored group-key records (still wrapped) for
// sensors to unwrap with their own PMKs.
func (s *Store) WiFiGroupKeys(ctx context.Context) ([]wire.WiFiGTK, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT bssid, key_id, sta, ssid, anonce, snonce, descriptor, key_info, key_length, iv, key_data, ts
		FROM wifi_group_keys ORDER BY ts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []wire.WiFiGTK{}
	for rows.Next() {
		var k wire.WiFiGTK
		var ts int64
		if err := rows.Scan(&k.BSSID, &k.KeyID, &k.STA, &k.SSID, &k.ANonce, &k.SNonce, &k.Descriptor, &k.KeyInfo, &k.KeyLength, &k.IV, &k.KeyData, &ts); err != nil {
			return nil, err
		}
		k.TS = time.UnixMilli(ts).UTC()
		out = append(out, k)
	}
	return out, rows.Err()
}

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
