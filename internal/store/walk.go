package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
)

// The Walk* methods expose the same rows as their slice counterparts but
// hand each one to a callback instead of retaining it. The CSV exporter uses
// them so a large window is bounded by the driver's read buffer, not by the
// number of rows in the result.
//
// Each walk runs on one connection of its own. Its lookups (device labels,
// peers, AS names) happen while its cursor is open; taken from the shared
// read pool instead, a few concurrent exports could hold every connection
// and wait on each other forever.

// queryer is what a walk's lookups need: a *sql.Conn or the pool.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// WalkFlows visits each connection active in the window.
func (s *Store) WalkFlows(ctx context.Context, f model.Filter, yield func(model.Flow) error) error {
	from, to := s.window(f)
	if s.precision(from, to) == model.PrecisionHour {
		return s.walkFlowsHourly(ctx, f, from, to, yield)
	}
	w := &where{}
	connsWindow(w, from, to)
	if err := s.flowWhere(ctx, f, w, rawCols); err != nil {
		return err
	}
	q := `SELECT flow_key, proto, client_ip, client_port, client_mac, client_device, remote_ip, remote_port, direction,
		app, sni, http_host, qname, alpn, ja4, user_agent, first_seen, last_seen, final, end_reason,
		coalesce(remote_asn, 0), remote_cc,
		` + connBytes("bytes_out", from, to) + ` AS bo, ` + connBytes("bytes_in", from, to) + ` AS bi,
		` + connBytes("pkts_out", from, to) + `, ` + connBytes("pkts_in", from, to) + `
		FROM connections c WHERE ` + w.sql() + `
		ORDER BY bo + bi DESC, first_seen LIMIT ? OFFSET ?`
	conn, err := s.r.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	rows, err := conn.QueryContext(ctx, q, append(w.args, limit(f, 1000, 100000), offset(f))...)
	if err != nil {
		return err
	}
	defer rows.Close()
	d := newFlowDecor(conn, from, to)
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
			return err
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
		if err := d.apply(ctx, &fl, dev); err != nil {
			return err
		}
		if err := yield(fl); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Store) walkFlowsHourly(ctx context.Context, f model.Filter, from, to int64, yield func(model.Flow) error) error {
	w := &where{}
	w.add("bucket < ? AND bucket >= ?", to, hourOf(from))
	if err := s.flowWhere(ctx, f, w, hourlyCols); err != nil {
		return err
	}
	conn, err := s.r.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	rows, err := conn.QueryContext(ctx, `SELECT client_device, client_ip, remote_ip, remote_port, proto, name, direction, max(app),
		min(bucket), max(bucket), sum(flows), sum(bytes_out), sum(bytes_in), coalesce(max(remote_asn), 0), max(remote_cc)
		FROM traffic_hourly WHERE `+w.sql()+`
		GROUP BY client_device, client_ip, remote_ip, remote_port, proto, name, direction ORDER BY sum(bytes_out) + sum(bytes_in) DESC LIMIT ? OFFSET ?`, append(w.args, limit(f, 1000, 100000), offset(f))...)
	if err != nil {
		return err
	}
	defer rows.Close()
	d := newFlowDecor(conn, from, to)
	for rows.Next() {
		var fl model.Flow
		var dev int64
		var proto, n int
		var first, last int64
		var localIP string
		var port int
		if err := rows.Scan(&dev, &localIP, &fl.RemoteIP, &port, &proto, &fl.Name, &fl.Direction, &fl.App, &first, &last, &n, &fl.BytesOut, &fl.BytesIn, &fl.ASN, &fl.Country); err != nil {
			return err
		}
		fl.Key = fmt.Sprintf("hourly:%d:%s:%s:%d:%d:%s", dev, localIP, fl.RemoteIP, port, proto, fl.Direction)
		fl.Proto = ProtoName(proto)
		fl.FirstSeen, fl.LastSeen = first, last+hourMS
		fl.State = model.StateOpened
		if fl.Direction != model.DirIn {
			fl.RemotePort, port = port, 0
		}
		setEnds(&fl, localIP, port)
		fl.Connections = n
		if err := d.apply(ctx, &fl, dev); err != nil {
			return err
		}
		if err := yield(fl); err != nil {
			return err
		}
	}
	return rows.Err()
}

// WalkDNS visits lookups in the window, newest first.
func (s *Store) WalkDNS(ctx context.Context, f model.Filter, yield func(model.DNSQuery) error) error {
	from, to := s.window(f)
	w, err := s.dnsWhere(ctx, f, from, to)
	if err != nil {
		return err
	}
	conn, err := s.r.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	rows, err := conn.QueryContext(ctx, `SELECT ts, client_ip, client_device, server_ip, qname, qtype, rcode, coalesce(latency_ms, 0), answers
		FROM dns WHERE `+w.sql()+` ORDER BY ts DESC LIMIT ? OFFSET ?`, append(w.args, limit(f, 500, 50000), offset(f))...)
	if err != nil {
		return err
	}
	defer rows.Close()
	devs := deviceCache{q: conn}
	for rows.Next() {
		var q model.DNSQuery
		var dev int64
		var answers string
		if err := rows.Scan(&q.TS, &q.ClientIP, &dev, &q.Server, &q.QName, &q.QType, &q.RCode, &q.LatencyMS, &answers); err != nil {
			return err
		}
		var as []struct {
			Name, Type, Data string
			TTL              uint32
		}
		_ = json.Unmarshal([]byte(answers), &as)
		for _, a := range as {
			q.Answers = append(q.Answers, model.DNSAnswer{Name: a.Name, Type: a.Type, Data: a.Data, TTL: a.TTL, Expires: q.TS + int64(a.TTL)*1000})
		}
		if err := devs.apply(ctx, &q, dev); err != nil {
			return err
		}
		if err := yield(q); err != nil {
			return err
		}
	}
	return rows.Err()
}

// WalkFacts visits relationships that held at some point in the window.
func (s *Store) WalkFacts(ctx context.Context, f model.Filter, yield func(model.Fact) error) error {
	from, to := s.window(f)
	w := &where{}
	w.add("f.first_seen < ? AND f.last_seen >= ?", to, from)
	if f.Device != "" {
		ids, err := s.deviceIDs(ctx, f.Device)
		if err != nil {
			return err
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
	rows, err := s.r.QueryContext(ctx, `SELECT f.rel, a.kind, a.key, a.label, a.attrs, b.kind, b.key, b.label, f.first_seen, f.last_seen, f.count, f.source, f.attrs
		FROM facts f JOIN entities a ON a.id = f.src JOIN entities b ON b.id = f.dst
		WHERE `+w.sql()+` ORDER BY f.last_seen DESC LIMIT ? OFFSET ?`,
		append(w.args, limit(f, 2000, 100000), offset(f))...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ft model.Fact
		var ak, akey, al, aattrs, bk, bkey, bl, attrs string
		if err := rows.Scan(&ft.Rel, &ak, &akey, &al, &aattrs, &bk, &bkey, &bl, &ft.FirstSeen, &ft.LastSeen, &ft.Count, &ft.Source, &attrs); err != nil {
			return err
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
		if err := yield(ft); err != nil {
			return err
		}
	}
	return rows.Err()
}

// WalkWiFi visits the SSIDs access points broadcast in the window.
func (s *Store) WalkWiFi(ctx context.Context, f model.Filter, yield func(model.WiFiNetwork) error) error {
	from, to := s.window(f)
	w := &where{}
	w.add("f.rel = 'broadcasts' AND f.first_seen < ? AND f.last_seen >= ?", to, from)
	if f.Device != "" {
		ids, err := s.deviceIDs(ctx, f.Device)
		if err != nil {
			return err
		}
		w.add("f.src IN (" + idList(ids) + ")")
	}
	if f.Domain != "" {
		w.add("lower(b.key) GLOB ?", glob(f.Domain))
	}
	args := []any{to, from}
	args = append(args, w.args...)
	args = append(args, limit(f, 1000, 10000), offset(f))
	rows, err := s.r.QueryContext(ctx, `
		SELECT a.key, b.key, b.label, f.attrs, min(f.first_seen), max(f.last_seen),
			(SELECT count(DISTINCT c.src) FROM facts c WHERE c.rel = 'associates' AND c.dst = a.id
			 AND c.first_seen < ? AND c.last_seen >= ?)
		FROM facts f JOIN entities a ON a.id = f.src JOIN entities b ON b.id = f.dst
		WHERE `+w.sql()+`
		GROUP BY a.id, b.id
		ORDER BY max(f.last_seen) DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var n model.WiFiNetwork
		var attrs, label string
		if err := rows.Scan(&n.BSSID, &n.SSID, &label, &attrs, &n.FirstSeen, &n.LastSeen, &n.Clients); err != nil {
			return err
		}
		if label != "" {
			n.SSID = label
		}
		var a map[string]string
		_ = json.Unmarshal([]byte(attrs), &a)
		n.Security = a["security"]
		n.Channel, _ = strconv.Atoi(a["channel"])
		if err := yield(n); err != nil {
			return err
		}
	}
	return rows.Err()
}

// deviceCache resolves device IDs to their display fields one at a time, for
// the streaming walkers. The number of devices in a window is small.
type deviceCache struct {
	q    queryer
	meta map[int64]deviceMeta
}

type deviceMeta struct {
	id, label, mac string
}

func (c *deviceCache) apply(ctx context.Context, q *model.DNSQuery, dev int64) error {
	if dev == 0 {
		return nil
	}
	m, err := c.get(ctx, dev)
	if err != nil {
		return err
	}
	q.Device = model.EntityID(model.KindDevice, m.mac)
	q.DeviceName = m.label
	return nil
}

func (c *deviceCache) get(ctx context.Context, id int64) (deviceMeta, error) {
	if c.meta == nil {
		c.meta = map[int64]deviceMeta{}
	}
	if m, ok := c.meta[id]; ok {
		return m, nil
	}
	var key, label, attrs string
	err := c.q.QueryRowContext(ctx, `SELECT key, label, attrs FROM entities WHERE id = ? AND kind = 'device'`, id).Scan(&key, &label, &attrs)
	if err == sql.ErrNoRows {
		c.meta[id] = deviceMeta{}
		return deviceMeta{}, nil
	}
	if err != nil {
		return deviceMeta{}, err
	}
	var a map[string]string
	_ = json.Unmarshal([]byte(attrs), &a)
	m := deviceMeta{id: model.EntityID(model.KindDevice, key), mac: key, label: deviceLabel(key, label, a)}
	c.meta[id] = m
	return m, nil
}

// flowDecor adds the device names, local peer and AS organisation that the
// slice path adds after reading all rows.
type flowDecor struct {
	q       queryer
	from    int64
	to      int64
	devices deviceCache
	peers   map[string]int64
	asns    map[uint32]string
}

func newFlowDecor(q queryer, from, to int64) *flowDecor {
	return &flowDecor{q: q, from: from, to: to, devices: deviceCache{q: q}, peers: map[string]int64{}, asns: map[uint32]string{}}
}

func (d *flowDecor) apply(ctx context.Context, fl *model.Flow, dev int64) error {
	if dev != 0 {
		m, err := d.devices.get(ctx, dev)
		if err != nil {
			return err
		}
		fl.Device, fl.DeviceName = m.id, m.label
	}
	if fl.Direction == model.DirLocal && fl.RemoteIP != "" {
		id, err := d.peer(ctx, fl.RemoteIP)
		if err != nil {
			return err
		}
		if id != 0 {
			m, err := d.devices.get(ctx, id)
			if err != nil {
				return err
			}
			fl.PeerDevice, fl.PeerName = m.id, m.label
		}
	}
	if fl.ASN != 0 {
		org, err := d.asOrg(ctx, fl.ASN)
		if err != nil {
			return err
		}
		fl.ASOrg = org
	}
	return nil
}

func (d *flowDecor) peer(ctx context.Context, ip string) (int64, error) {
	if id, ok := d.peers[ip]; ok {
		return id, nil
	}
	var n int
	var id int64
	err := d.q.QueryRowContext(ctx, `SELECT count(DISTINCT f.src), coalesce(min(f.src), 0)
		FROM entities ip JOIN facts f ON f.dst = ip.id AND f.rel = 'has_ip'
		WHERE ip.kind = 'ip' AND ip.key = ? AND f.last_seen >= ? AND f.first_seen < ?`, ip, d.from, d.to).Scan(&n, &id)
	if err != nil {
		return 0, err
	}
	if n != 1 {
		id = 0
	}
	d.peers[ip] = id
	return id, nil
}

func (d *flowDecor) asOrg(ctx context.Context, asn uint32) (string, error) {
	if org, ok := d.asns[asn]; ok {
		return org, nil
	}
	var label string
	err := d.q.QueryRowContext(ctx, `SELECT label FROM entities WHERE kind = 'asn' AND key = ?`, strconv.FormatUint(uint64(asn), 10)).Scan(&label)
	if err == sql.ErrNoRows {
		d.asns[asn] = ""
		return "", nil
	}
	if err != nil {
		return "", err
	}
	org, _ := strings.CutPrefix(label, "AS"+strconv.FormatUint(uint64(asn), 10))
	d.asns[asn] = strings.TrimSpace(org)
	return d.asns[asn], nil
}
