package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/oui"
	"github.com/xen0bit/netgraph/internal/wire"
)

// IngestResult reports what one batch did.
type IngestResult struct {
	Accepted   int
	Duplicates int
}

// Ingest stores one batch from a sensor. Events whose sequence number was
// already ingested for this sensor boot are skipped, so a batch retried
// after a lost response is not counted twice. The batch is one
// transaction: it is stored entirely or not at all.
func (s *Store) Ingest(ctx context.Context, sensor, boot string, events []wire.Event) (IngestResult, error) {
	if s.w == nil {
		return IngestResult{}, errors.New("database is open read-only")
	}
	if sensor == "" {
		return IngestResult{}, errors.New("missing sensor name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, live, err := s.ing.batch(ctx, sensor, boot, events)
	if err != nil {
		// Caches may now describe rows that were rolled back.
		s.ing = newIngester(s)
		if werr := s.ing.warm(ctx); werr != nil {
			s.log.Error("rewarm ingest caches", "err", werr)
		}
		return res, err
	}
	s.sub.publish(live)
	return res, nil
}

// ingester holds the caches that make ingest cheap: entity IDs, the open
// period of each fact, recent DNS answers by address, and MAC/IP bindings.
// Everything in it can be rebuilt from the database (warm).
type ingester struct {
	s *Store

	tx *sql.Tx // during a batch

	entities map[entKey]*entRow
	facts    map[factKey]*openFact
	answers  map[string][]answerRef // address -> recent answers naming it
	bindings map[string]binding     // local address -> device
	sensors  map[string]int64
	flowName map[string]string // flow_key -> correlated qname, for the flow's later records

	traffic map[trafficKey]*trafficAgg
	dnsAgg  map[dnsKey]int

	live []LiveEvent
}

type entKey struct{ kind, key string }

type entRow struct {
	id       int64
	lastSeen int64 // as last written
	label    string
	labelPri int
	attrs    map[string]string
	dirty    bool // label/attrs need writing
}

type factKey struct {
	rel      string
	src, dst int64
}

type openFact struct {
	id               int64
	first, last, cnt int64
	attrs            map[string]string
	dirty            bool
}

type answerRef struct {
	client  string
	qname   string
	ts      int64
	expires int64
}

type binding struct {
	device int64
	ts     int64
}

type trafficKey struct {
	bucket      int64
	device      int64
	client      string
	remote      string
	port, proto int
	name, app   string
	multicast   bool
}

type trafficAgg struct {
	flows     int64
	bout, bin int64
}

type dnsKey struct {
	bucket       int64
	device       int64
	client       string
	qname, qtype string
	rcode        string
}

func newIngester(s *Store) *ingester {
	return &ingester{
		s:        s,
		entities: map[entKey]*entRow{},
		facts:    map[factKey]*openFact{},
		answers:  map[string][]answerRef{},
		bindings: map[string]binding{},
		sensors:  map[string]int64{},
		flowName: map[string]string{},
		traffic:  map[trafficKey]*trafficAgg{},
		dnsAgg:   map[dnsKey]int{},
	}
}

// Correlation limits.
const (
	answerGrace      = 10 * 60 * 1000 // ms an answer stays usable past its TTL: clients cache past TTL and reuse connections
	answersPerIP     = 8
	maxAnswerCache   = 200_000
	maxFlowNameCache = 100_000
	entityTouchMS    = 60_000 // write an entity's last_seen at most this often
)

// warm loads recent answers and bindings so correlation works across a
// restart.
func (g *ingester) warm(ctx context.Context) error {
	cutoff := ms(g.s.cfg.Now()) - 6*3600*1000
	rows, err := g.s.w.QueryContext(ctx, `SELECT data, client_ip, qname, ts, expires FROM dns_answers WHERE expires >= ? ORDER BY ts`, cutoff)
	if err != nil {
		return err
	}
	for rows.Next() {
		var data string
		var a answerRef
		if err := rows.Scan(&data, &a.client, &a.qname, &a.ts, &a.expires); err != nil {
			rows.Close()
			return err
		}
		g.addAnswer(data, a)
	}
	rows.Close()
	rows, err = g.s.w.QueryContext(ctx, `
		SELECT e.key, f.src, f.last_seen FROM facts f JOIN entities e ON e.id = f.dst
		WHERE f.rel = 'has_ip' AND f.last_seen >= ? ORDER BY f.last_seen`, cutoff)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var b binding
		if err := rows.Scan(&ip, &b.device, &b.ts); err != nil {
			return err
		}
		g.bindings[ip] = b
	}
	return rows.Err()
}

func (g *ingester) batch(ctx context.Context, sensor, boot string, events []wire.Event) (IngestResult, []LiveEvent, error) {
	var res IngestResult
	tx, err := g.s.w.BeginTx(ctx, nil)
	if err != nil {
		return res, nil, err
	}
	g.tx = tx
	g.live = g.live[:0]
	defer func() { g.tx = nil }()

	now := ms(g.s.cfg.Now())
	sid, err := g.sensorID(ctx, sensor, now)
	if err != nil {
		tx.Rollback()
		return res, nil, err
	}
	var last int64 = -1
	if boot != "" {
		err := tx.QueryRowContext(ctx, `SELECT last_seq FROM ingest_seq WHERE sensor_id = ? AND boot = ?`, sid, boot).Scan(&last)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			tx.Rollback()
			return res, nil, err
		}
	}
	maxSeq := last
	for i := range events {
		ev := &events[i]
		if boot != "" && int64(ev.Seq) <= last {
			res.Duplicates++
			continue
		}
		if err := g.event(ctx, sid, sensor, boot, ev); err != nil {
			tx.Rollback()
			return res, nil, fmt.Errorf("event %d (%s): %w", ev.Seq, ev.Type, err)
		}
		res.Accepted++
		maxSeq = max(maxSeq, int64(ev.Seq))
	}
	if boot != "" && maxSeq > last {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ingest_seq (sensor_id, boot, last_seq, updated) VALUES (?, ?, ?, ?)
			ON CONFLICT (sensor_id, boot) DO UPDATE SET last_seq = excluded.last_seq, updated = excluded.updated`, sid, boot, maxSeq, now); err != nil {
			tx.Rollback()
			return res, nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sensors SET last_seen = max(last_seen, ?) WHERE id = ?`, now, sid); err != nil {
		tx.Rollback()
		return res, nil, err
	}
	if err := g.flushDirty(ctx); err != nil {
		tx.Rollback()
		return res, nil, err
	}
	if err := tx.Commit(); err != nil {
		return res, nil, err
	}
	g.trim()
	return res, append([]LiveEvent(nil), g.live...), nil
}

func (g *ingester) sensorID(ctx context.Context, name string, now int64) (int64, error) {
	if id, ok := g.sensors[name]; ok {
		return id, nil
	}
	var id int64
	err := g.tx.QueryRowContext(ctx, `INSERT INTO sensors (name, first_seen, last_seen) VALUES (?, ?, ?)
		ON CONFLICT (name) DO UPDATE SET last_seen = excluded.last_seen RETURNING id`, name, now, now).Scan(&id)
	if err == nil {
		g.sensors[name] = id
	}
	return id, err
}

func (g *ingester) event(ctx context.Context, sid int64, sensor, boot string, ev *wire.Event) error {
	ts := ms(ev.TS)
	switch ev.Type {
	case wire.TypeHello:
		if ev.Hello != nil {
			return g.hello(ctx, sid, sensor, ts, ev.Hello)
		}
	case wire.TypeStats:
		if ev.Stats != nil {
			b, _ := json.Marshal(ev.Stats)
			_, err := g.tx.ExecContext(ctx, `UPDATE sensors SET stats = ? WHERE id = ?`, string(b), sid)
			return err
		}
	case wire.TypeFlow:
		if ev.Flow != nil {
			return g.flow(ctx, sid, sensor, boot, ev.Flow)
		}
	case wire.TypeDNS:
		if ev.DNS != nil {
			return g.dns(ctx, sid, ts, ev.DNS)
		}
	case wire.TypeBinding:
		if ev.Binding != nil {
			return g.binding(ctx, sid, ts, ev.Binding)
		}
	case wire.TypeDHCP:
		if ev.DHCP != nil {
			return g.dhcp(ctx, sid, ts, ev.DHCP)
		}
	case wire.TypeMDNS:
		if ev.MDNS != nil {
			return g.mdns(ctx, sid, ts, ev.MDNS)
		}
	case wire.TypeName:
		if ev.Name != nil {
			return g.name(ctx, sid, ts, ev.Name)
		}
	case wire.TypeSSDP:
		if ev.SSDP != nil {
			return g.ssdp(ctx, sid, ts, ev.SSDP)
		}
	case wire.TypeLLDP:
		if ev.LLDP != nil {
			return g.lldp(ctx, sid, ts, ev.LLDP)
		}
	case wire.TypeWiFi:
		if ev.WiFi != nil {
			return g.wifi(ctx, sid, ts, ev.WiFi)
		}
	case wire.TypeWiFiKey:
		if ev.WiFiKey != nil {
			return g.wifiKey(ctx, sid, ts, ev.WiFiKey)
		}
	}
	return nil // unknown types are from a newer sensor; ignore them
}

// --- entities and facts ---------------------------------------------------

// entity returns the ID of (kind, key), creating it, and records it as seen
// at ts.
func (g *ingester) entity(ctx context.Context, kind, key string, ts int64, init func(*entRow)) (int64, error) {
	k := entKey{kind, key}
	if e, ok := g.entities[k]; ok {
		if ts > e.lastSeen+entityTouchMS {
			if _, err := g.tx.ExecContext(ctx, `UPDATE entities SET last_seen = max(last_seen, ?) WHERE id = ?`, ts, e.id); err != nil {
				return 0, err
			}
			e.lastSeen = ts
		}
		return e.id, nil
	}
	e := &entRow{attrs: map[string]string{}}
	var attrs string
	err := g.tx.QueryRowContext(ctx, `SELECT id, label, attrs, last_seen FROM entities WHERE kind = ? AND key = ?`, kind, key).Scan(&e.id, &e.label, &attrs, &e.lastSeen)
	switch {
	case err == nil:
		_ = json.Unmarshal([]byte(attrs), &e.attrs)
		e.labelPri, _ = strconv.Atoi(e.attrs["label_pri"])
		if _, err := g.tx.ExecContext(ctx, `UPDATE entities SET last_seen = max(last_seen, ?), first_seen = min(first_seen, ?) WHERE id = ?`, ts, ts, e.id); err != nil {
			return 0, err
		}
		e.lastSeen = max(e.lastSeen, ts)
	case errors.Is(err, sql.ErrNoRows):
		if init != nil {
			init(e)
		}
		b, _ := json.Marshal(e.attrs)
		if err := g.tx.QueryRowContext(ctx, `INSERT INTO entities (kind, key, label, first_seen, last_seen, attrs) VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
			kind, key, e.label, ts, ts, string(b)).Scan(&e.id); err != nil {
			return 0, err
		}
		e.lastSeen = ts
		e.dirty = false
	default:
		return 0, err
	}
	g.entities[k] = e
	return e.id, nil
}

func (g *ingester) row(kind, key string) *entRow { return g.entities[entKey{kind, key}] }

// setLabel sets an entity's label if pri beats the current label's source.
func (g *ingester) setLabel(kind, key, label string, pri int) {
	e := g.row(kind, key)
	if e == nil || label == "" || pri < e.labelPri || (pri == e.labelPri && label == e.label) {
		return
	}
	e.label, e.labelPri, e.dirty = label, pri, true
	e.attrs["label_pri"] = strconv.Itoa(pri)
}

// relabel sets a non-device entity's label to its latest form.
func (g *ingester) relabel(kind, key, label string) {
	if e := g.row(kind, key); e != nil && label != "" && e.label != label {
		e.label, e.dirty = label, true
	}
}

func (g *ingester) setAttr(kind, key, k, v string) {
	e := g.row(kind, key)
	if e == nil || v == "" || e.attrs[k] == v {
		return
	}
	e.attrs[k], e.dirty = v, true
}

// Label priorities: which source names a device best.
// Higher numbers are better names. Reverse DNS is deliberately the weakest
// source: a host that announced a name through DHCP, mDNS, NetBIOS, LLMNR or
// LLDP keeps it, and the sensor's own name for the router wins too.
const (
	priRDNS   = 5
	priRouter = 10
	priLLDP   = 20
	priLLMNR  = 30
	priNBNS   = 35
	priMDNS   = 40
	priDHCP6  = 45
	priDHCP   = 50
)

func (g *ingester) device(ctx context.Context, mac string, ts int64) (int64, error) {
	return g.entity(ctx, model.KindDevice, mac, ts, func(e *entRow) {
		if v := oui.Lookup(mac); v != "" {
			e.attrs["vendor"] = v
		}
	})
}

func (g *ingester) ipEntity(ctx context.Context, ip netip.Addr, ts int64) (int64, error) {
	return g.entity(ctx, model.KindIP, ip.String(), ts, func(e *entRow) {
		if g.s.nets.isLocal(ip) {
			e.attrs["local"] = "1"
		}
	})
}

// fact records rel(src, dst) as holding from ts to until.
func (g *ingester) fact(ctx context.Context, rel string, src, dst int64, ts, until int64, source string, attrs map[string]string) error {
	if until < ts {
		until = ts
	}
	gap := g.s.cfg.FactGap.Milliseconds()
	k := factKey{rel, src, dst}
	f := g.facts[k]
	if f == nil || ts > f.last+gap || until < f.first-gap {
		// Not the cached period: find the period this falls in, if any.
		var cand openFact
		var a string
		err := g.tx.QueryRowContext(ctx, `SELECT id, first_seen, last_seen, count, attrs FROM facts
			WHERE rel = ? AND src = ? AND dst = ? AND last_seen >= ? AND first_seen <= ? ORDER BY last_seen DESC LIMIT 1`,
			rel, src, dst, ts-gap, until+gap).Scan(&cand.id, &cand.first, &cand.last, &cand.cnt, &a)
		switch {
		case err == nil:
			cand.attrs = map[string]string{}
			_ = json.Unmarshal([]byte(a), &cand.attrs)
			f = &cand
		case errors.Is(err, sql.ErrNoRows):
			b, _ := json.Marshal(attrs)
			if attrs == nil {
				b = []byte("{}")
			}
			var id int64
			if err := g.tx.QueryRowContext(ctx, `INSERT INTO facts (rel, src, dst, first_seen, last_seen, count, source, attrs) VALUES (?, ?, ?, ?, ?, 1, ?, ?) RETURNING id`,
				rel, src, dst, ts, until, source, string(b)).Scan(&id); err != nil {
				return err
			}
			nf := &openFact{id: id, first: ts, last: until, cnt: 1, attrs: map[string]string{}}
			for k, v := range attrs {
				nf.attrs[k] = v
			}
			if old := g.facts[k]; old == nil || old.last <= until {
				g.facts[k] = nf
			}
			return nil
		default:
			return err
		}
		if old := g.facts[k]; old == nil || old.last <= f.last {
			g.facts[k] = f
		}
	}
	f.first = min(f.first, ts)
	f.last = max(f.last, until)
	f.cnt++
	for k, v := range attrs {
		if f.attrs == nil {
			f.attrs = map[string]string{}
		}
		f.attrs[k] = v
	}
	f.dirty = true
	return nil
}

func (g *ingester) flushDirty(ctx context.Context) error {
	for _, f := range g.facts {
		if !f.dirty {
			continue
		}
		b, _ := json.Marshal(f.attrs)
		if _, err := g.tx.ExecContext(ctx, `UPDATE facts SET first_seen = ?, last_seen = ?, count = ?, attrs = ? WHERE id = ?`, f.first, f.last, f.cnt, string(b), f.id); err != nil {
			return err
		}
		f.dirty = false
	}
	for _, e := range g.entities {
		if !e.dirty {
			continue
		}
		b, _ := json.Marshal(e.attrs)
		if _, err := g.tx.ExecContext(ctx, `UPDATE entities SET label = ?, attrs = ? WHERE id = ?`, e.label, string(b), e.id); err != nil {
			return err
		}
		e.dirty = false
	}
	return g.flushRollupsTx(ctx)
}

// trim bounds the caches after a batch.
func (g *ingester) trim() {
	if len(g.entities) > 200_000 {
		g.entities = map[entKey]*entRow{}
	}
	if len(g.facts) > 200_000 {
		g.facts = map[factKey]*openFact{}
	}
	if len(g.flowName) > maxFlowNameCache {
		g.flowName = map[string]string{}
	}
	if len(g.answers) > maxAnswerCache {
		// Drop the half with the oldest newest-answer.
		type kv struct {
			k  string
			ts int64
		}
		all := make([]kv, 0, len(g.answers))
		for k, v := range g.answers {
			all = append(all, kv{k, v[len(v)-1].ts})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].ts < all[j].ts })
		for _, e := range all[:len(all)/2] {
			delete(g.answers, e.k)
		}
	}
}

// --- events -----------------------------------------------------------------

func (g *ingester) hello(ctx context.Context, sid int64, sensor string, ts int64, h *wire.Hello) error {
	b, _ := json.Marshal(h)
	if _, err := g.tx.ExecContext(ctx, `UPDATE sensors SET hello = ?, version = ? WHERE id = ?`, string(b), h.Version, sid); err != nil {
		return err
	}
	g.s.nets.addHello(sensor, h)
	for _, ifc := range h.Interfaces {
		if ifc.MAC == "" {
			continue
		}
		if _, err := g.device(ctx, ifc.MAC, ts); err != nil {
			return err
		}
		g.setAttr(model.KindDevice, ifc.MAC, "role", "router")
		g.setAttr(model.KindDevice, ifc.MAC, "sensor", sensor)
		g.setLabel(model.KindDevice, ifc.MAC, sensor, priRouter)
		for _, p := range ifc.Prefixes {
			if err := g.hasIP(ctx, ifc.MAC, p.Addr(), ts, ts, "sensor"); err != nil {
				return err
			}
		}
	}
	return nil
}

// hasIP records that mac used ip, and remembers the binding for flow and
// DNS attribution.
func (g *ingester) hasIP(ctx context.Context, mac string, ip netip.Addr, ts, until int64, source string) error {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return nil
	}
	dev, err := g.device(ctx, mac, ts)
	if err != nil {
		return err
	}
	ipID, err := g.ipEntity(ctx, ip, ts)
	if err != nil {
		return err
	}
	if b, ok := g.bindings[ip.String()]; !ok || b.ts <= ts {
		g.bindings[ip.String()] = binding{device: dev, ts: ts}
	}
	return g.fact(ctx, model.RelHasIP, dev, ipID, ts, until, source, nil)
}

// deviceFor finds the device behind a local address: by the MAC that sent
// it if known, else by the latest binding. A sensor's own MAC on someone
// else's address is the router forwarding, not evidence, so that falls back
// to the binding too.
func (g *ingester) deviceFor(ctx context.Context, ip netip.Addr, mac string, ts int64) (int64, string, error) {
	if ip.IsUnspecified() && mac != "" && !isGroupMAC(mac) {
		// 0.0.0.0: a host before DHCP has given it an address.
		id, err := g.device(ctx, mac, ts)
		return id, mac, err
	}
	if !ip.IsValid() || !g.s.nets.isLocal(ip) {
		return 0, "", nil
	}
	if mac != "" && !isGroupMAC(mac) && !g.s.nets.forwarded(normMACOr(mac), ip) {
		if err := g.hasIP(ctx, mac, ip, ts, ts, "traffic"); err != nil {
			return 0, "", err
		}
		return g.row(model.KindDevice, mac).id, mac, nil
	}
	if b, ok := g.bindings[ip.String()]; ok {
		return b.device, "", nil
	}
	return 0, "", nil
}

// normMACOr is normMAC for a lookup: the canonical form, or s unchanged.
func normMACOr(s string) string {
	if m, ok := normMAC(s); ok {
		return m
	}
	return s
}

func isGroupMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err != nil || oui.IsMulticast(hw)
}

func (g *ingester) observation(ctx context.Context, sid, ts int64, typ string, device int64, ip netip.Addr, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	ipStr := ""
	if ip.IsValid() {
		ipStr = ip.String()
	}
	_, err = g.tx.ExecContext(ctx, `INSERT INTO observations (sensor_id, ts, type, device, ip, data) VALUES (?, ?, ?, ?, ?, ?)`, sid, ts, typ, device, ipStr, string(b))
	return err
}

// MaxRecordSpan is the longest interval one stored flow record covers.
// Window queries rely on it to bound their index range on both sides;
// longer records (a sensor with a long -active-timeout) are split, their
// counters shared out in proportion.
const MaxRecordSpan = 10 * time.Minute

func (g *ingester) flow(ctx context.Context, sid int64, sensor, boot string, f *wire.Flow) error {
	if span := f.End.Sub(f.Start); span > MaxRecordSpan {
		n := int64((span + MaxRecordSpan - 1) / MaxRecordSpan)
		total := *f
		var done [4]uint64
		for i := int64(0); i < n; i++ {
			part := total
			part.Start = total.Start.Add(time.Duration(i) * span / time.Duration(n))
			part.End = total.Start.Add(time.Duration(i+1) * span / time.Duration(n))
			last := i == n-1
			share := func(v uint64, j int) uint64 {
				if last {
					return v - done[j]
				}
				x := v * uint64(i+1) / uint64(n)
				out := x - done[j]
				done[j] = x
				return out
			}
			part.BytesOut, part.BytesIn = share(total.BytesOut, 0), share(total.BytesIn, 1)
			part.PktsOut, part.PktsIn = share(total.PktsOut, 2), share(total.PktsIn, 3)
			part.Final = total.Final && last
			if !last {
				part.EndReason = ""
			}
			if err := g.flowRecord(ctx, sid, sensor, boot, &part); err != nil {
				return err
			}
		}
		return nil
	}
	return g.flowRecord(ctx, sid, sensor, boot, f)
}

func (g *ingester) flowRecord(ctx context.Context, sid int64, sensor, boot string, f *wire.Flow) error {
	key := sensor + ":" + boot + ":" + strconv.FormatUint(f.ID, 10)
	nets := g.s.nets
	srcLocal, dstLocal := nets.isLocal(f.Src) || f.Src.IsUnspecified(), nets.isLocal(f.Dst)
	client, cport, cmac := f.Src, f.SrcPort, f.SrcMAC
	remote, rport := f.Dst, f.DstPort
	dir := "external"
	switch {
	case srcLocal && dstLocal:
		dir = "local"
	case srcLocal:
		dir = "out"
	case dstLocal:
		dir = "in"
		client, cport, cmac = f.Dst, f.DstPort, f.DstMAC
		remote, rport = f.Src, f.SrcPort
	}
	multicast := isGroupAddr(remote) || nets.isBroadcast(remote)
	start, end, first := ms(f.Start), ms(f.End), ms(f.FirstSeen)

	dev, devMAC, err := g.deviceFor(ctx, client, cmac, end)
	if err != nil {
		return err
	}
	if dir == "local" && !multicast {
		// Both ends are ours: the responder's MAC identifies it too.
		if _, _, err := g.deviceFor(ctx, remote, f.DstMAC, end); err != nil {
			return err
		}
	}
	if _, err := g.ipEntity(ctx, remote, end); err != nil {
		return err
	}

	qname, seen := g.flowName[key]
	if !seen {
		if !g.s.nets.isLocal(remote) && !multicast {
			qname = g.lookupName(remote.String(), client.String(), first, f.SNI, f.HTTPHost)
		}
		g.flowName[key] = qname
	}
	if f.Final {
		delete(g.flowName, key)
	}
	name := firstNonEmpty(f.SNI, f.HTTPHost, qname)

	if _, err := g.tx.ExecContext(ctx, `INSERT INTO flows (
		sensor_id, flow_key, proto, src_ip, src_port, dst_ip, dst_port, first_seen, t_start, t_end,
		bytes_out, bytes_in, pkts_out, pkts_in, tcp_flags, final, end_reason, app, sni, alpn, ja4, http_host, user_agent,
		qname, client_ip, client_port, client_mac, client_device, remote_ip, remote_port, direction, multicast)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sid, key, f.Proto, f.Src.String(), f.SrcPort, f.Dst.String(), f.DstPort, first, start, end,
		f.BytesOut, f.BytesIn, f.PktsOut, f.PktsIn, f.TCPFlags, boolInt(f.Final), f.EndReason, f.App, f.SNI, f.ALPN, f.JA4, f.HTTPHost, f.UserAgent,
		qname, client.String(), cport, devMAC, dev, remote.String(), rport, dir, boolInt(multicast)); err != nil {
		return err
	}
	if _, err := g.tx.ExecContext(ctx, `INSERT INTO connections (
		flow_key, sensor_id, proto, client_ip, client_port, client_mac, client_device, remote_ip, remote_port, direction, multicast,
		first_seen, last_seen, final, end_reason, app, sni, alpn, ja4, http_host, user_agent, qname, bytes_out, bytes_in, pkts_out, pkts_in)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (flow_key) DO UPDATE SET
			first_seen = min(first_seen, excluded.first_seen), last_seen = max(last_seen, excluded.last_seen),
			final = max(final, excluded.final),
			end_reason = CASE WHEN excluded.final = 1 THEN excluded.end_reason ELSE end_reason END,
			client_device = CASE WHEN client_device = 0 THEN excluded.client_device ELSE client_device END,
			client_mac = CASE WHEN client_mac = '' THEN excluded.client_mac ELSE client_mac END,
			app = CASE WHEN excluded.app != '' THEN excluded.app ELSE app END,
			sni = CASE WHEN excluded.sni != '' THEN excluded.sni ELSE sni END,
			alpn = CASE WHEN excluded.alpn != '' THEN excluded.alpn ELSE alpn END,
			ja4 = CASE WHEN excluded.ja4 != '' THEN excluded.ja4 ELSE ja4 END,
			http_host = CASE WHEN excluded.http_host != '' THEN excluded.http_host ELSE http_host END,
			user_agent = CASE WHEN excluded.user_agent != '' THEN excluded.user_agent ELSE user_agent END,
			qname = CASE WHEN excluded.qname != '' THEN excluded.qname ELSE qname END,
			bytes_out = bytes_out + excluded.bytes_out, bytes_in = bytes_in + excluded.bytes_in,
			pkts_out = pkts_out + excluded.pkts_out, pkts_in = pkts_in + excluded.pkts_in`,
		key, sid, f.Proto, client.String(), cport, devMAC, dev, remote.String(), rport, dir, boolInt(multicast),
		first, end, boolInt(f.Final), f.EndReason, f.App, f.SNI, f.ALPN, f.JA4, f.HTTPHost, f.UserAgent, qname,
		f.BytesOut, f.BytesIn, f.PktsOut, f.PktsIn); err != nil {
		return err
	}

	// What the flow reveals about its endpoints.
	if !multicast && !g.s.nets.isLocal(remote) {
		for src, host := range map[string]string{"sni": f.SNI, "http": f.HTTPHost} {
			if host == "" {
				continue
			}
			ipID := g.row(model.KindIP, remote.String()).id
			dom, err := g.entity(ctx, model.KindDomain, host, end, nil)
			if err != nil {
				return err
			}
			if err := g.fact(ctx, model.RelServes, ipID, dom, end, end, src, nil); err != nil {
				return err
			}
		}
	}
	if dev != 0 {
		if f.JA4 != "" {
			fp, err := g.entity(ctx, model.KindFingerprint, "ja4:"+f.JA4, end, func(e *entRow) { e.label = "JA4 " + f.JA4 })
			if err != nil {
				return err
			}
			if err := g.fact(ctx, model.RelFingerprint, dev, fp, end, end, "tls", nil); err != nil {
				return err
			}
		}
		if f.UserAgent != "" {
			ua, err := g.entity(ctx, model.KindUserAgent, f.UserAgent, end, func(e *entRow) { e.label = f.UserAgent })
			if err != nil {
				return err
			}
			if err := g.fact(ctx, model.RelUserAgent, dev, ua, end, end, "http", nil); err != nil {
				return err
			}
		}
	}

	g.addTraffic(trafficKey{device: dev, client: client.String(), remote: remote.String(), port: int(rport), proto: int(f.Proto), name: name, app: f.App, multicast: multicast},
		start, end, first, int64(f.BytesOut), int64(f.BytesIn))
	if start == first || f.Final {
		g.live = append(g.live, LiveEvent{Type: "flow", TS: end, Device: dev, Detail: fmt.Sprintf("%s → %s %s", client, firstNonEmpty(name, remote.String()), portProto(int(rport), f.Proto))})
	}
	return nil
}

// lookupName finds the DNS name a client resolved remote from before
// connecting at ts. Many names share an address (virtual hosting, CDNs),
// so a lookup naming what the connection itself names (its SNI or HTTP
// Host) wins; then the client's newest lookup; then anyone's.
func (g *ingester) lookupName(remote, client string, ts int64, hints ...string) string {
	const jitter = 50 // ms: a response and the first packet after it can be stamped out of order
	refs := g.answers[remote]
	var mine, any string
	var mineTS, anyTS int64
	for i := len(refs) - 1; i >= 0; i-- {
		a := refs[i]
		if a.ts > ts+jitter || a.expires+answerGrace < ts {
			continue
		}
		for _, h := range hints {
			if h != "" && strings.EqualFold(h, a.qname) {
				return a.qname
			}
		}
		if a.client == client && (mine == "" || a.ts > mineTS) {
			mine, mineTS = a.qname, a.ts
		}
		if any == "" || a.ts > anyTS {
			any, anyTS = a.qname, a.ts
		}
	}
	if mine != "" {
		return mine
	}
	return any
}

func (g *ingester) addAnswer(data string, a answerRef) {
	refs := g.answers[data]
	for i, r := range refs {
		if r.client == a.client && r.qname == a.qname {
			refs = append(refs[:i], refs[i+1:]...)
			break
		}
	}
	refs = append(refs, a)
	if len(refs) > answersPerIP {
		refs = refs[len(refs)-answersPerIP:]
	}
	g.answers[data] = refs
}

func (g *ingester) dns(ctx context.Context, sid, ts int64, d *wire.DNS) error {
	dev, _, err := g.deviceFor(ctx, d.Client, d.ClientMAC, ts)
	if err != nil {
		return err
	}
	answers, _ := json.Marshal(d.Answers)
	if d.Answers == nil {
		answers = []byte("[]")
	}
	var latency any
	if d.LatencyMS > 0 {
		latency = d.LatencyMS
	}
	var id int64
	if err := g.tx.QueryRowContext(ctx, `INSERT INTO dns (sensor_id, ts, client_ip, client_device, server_ip, proto, qname, qtype, rcode, latency_ms, answers)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
		sid, ts, d.Client.String(), dev, d.Server.String(), d.Proto, d.QName, d.QType, d.RCode, latency, string(answers)).Scan(&id); err != nil {
		return err
	}
	g.dnsAgg[dnsKey{bucket: hourOf(ts), device: dev, client: d.Client.String(), qname: d.QName, qtype: d.QType, rcode: d.RCode}]++
	if d.QName == "" {
		return nil
	}
	qdom, err := g.entity(ctx, model.KindDomain, d.QName, ts, nil)
	if err != nil {
		return err
	}
	for _, a := range d.Answers {
		expires := ts + int64(a.TTL)*1000
		if _, err := g.tx.ExecContext(ctx, `INSERT INTO dns_answers (dns_id, ts, expires, client_ip, qname, name, type, data, ttl) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, ts, expires, d.Client.String(), d.QName, a.Name, a.Type, a.Data, a.TTL); err != nil {
			return err
		}
		switch a.Type {
		case "CNAME":
			if a.Data == "" || a.Data == d.QName {
				continue
			}
			from, err := g.entity(ctx, model.KindDomain, a.Name, ts, nil)
			if err != nil {
				return err
			}
			to, err := g.entity(ctx, model.KindDomain, a.Data, ts, nil)
			if err != nil {
				return err
			}
			if err := g.fact(ctx, model.RelCNAME, from, to, ts, expires, "dns", map[string]string{"ttl": strconv.Itoa(int(a.TTL))}); err != nil {
				return err
			}
		case "A", "AAAA", "HTTPS", "SVCB":
			ip, err := netip.ParseAddr(a.Data)
			if err != nil {
				continue
			}
			g.addAnswer(ip.String(), answerRef{client: d.Client.String(), qname: d.QName, ts: ts, expires: expires})
			ipID, err := g.ipEntity(ctx, ip, ts)
			if err != nil {
				return err
			}
			attrs := map[string]string{"ttl": strconv.Itoa(int(a.TTL)), "type": a.Type}
			if a.Name != d.QName {
				attrs["via"] = a.Name
			}
			if err := g.fact(ctx, model.RelResolvesTo, qdom, ipID, ts, expires, "dns", attrs); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *ingester) binding(ctx context.Context, sid, ts int64, b *wire.Binding) error {
	if err := g.hasIP(ctx, b.MAC, b.IP, ts, ts, b.Source); err != nil {
		return err
	}
	if b.Router {
		g.setAttr(model.KindDevice, b.MAC, "role", "router")
	}
	return g.observation(ctx, sid, ts, "binding", g.row(model.KindDevice, b.MAC).id, b.IP, b)
}

func (g *ingester) hostname(ctx context.Context, dev int64, mac, name string, ts int64, source string, pri int) error {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return nil
	}
	h, err := g.entity(ctx, model.KindHostname, strings.ToLower(name), ts, func(e *entRow) { e.label = name })
	if err != nil {
		return err
	}
	if err := g.fact(ctx, model.RelHostname, dev, h, ts, ts, source, nil); err != nil {
		return err
	}
	label := name
	if source == "mdns" {
		label = strings.TrimSuffix(label, ".local")
	}
	g.setLabel(model.KindDevice, mac, label, pri)
	return nil
}

func (g *ingester) dhcp(ctx context.Context, sid, ts int64, d *wire.DHCP) error {
	if d.MAC == "" {
		return nil
	}
	dev, err := g.device(ctx, d.MAC, ts)
	if err != nil {
		return err
	}
	pri, src := priDHCP, "dhcp"
	if d.Version == 6 {
		pri, src = priDHCP6, "dhcp6"
	}
	if err := g.hostname(ctx, dev, d.MAC, d.Hostname, ts, src, pri); err != nil {
		return err
	}
	if d.FQDN != "" && d.FQDN != d.Hostname {
		if err := g.hostname(ctx, dev, d.MAC, d.FQDN, ts, src, pri-1); err != nil {
			return err
		}
	}
	if d.ParamList != "" || d.VendorClass != "" {
		key := "dhcp:" + d.ParamList
		if d.VendorClass != "" {
			key += "|" + d.VendorClass
		}
		fp, err := g.entity(ctx, model.KindFingerprint, key, ts, func(e *entRow) {
			e.label = "DHCP " + firstNonEmpty(d.VendorClass, d.ParamList)
			e.attrs["params"], e.attrs["vendor_class"] = d.ParamList, d.VendorClass
		})
		if err != nil {
			return err
		}
		if err := g.fact(ctx, model.RelFingerprint, dev, fp, ts, ts, src, nil); err != nil {
			return err
		}
	}
	if d.VendorClass != "" {
		g.setAttr(model.KindDevice, d.MAC, "dhcp_vendor_class", d.VendorClass)
	}
	lease := int64(d.LeaseSecs) * 1000
	switch d.MsgType {
	case "ACK", "REPLY":
		for _, ip := range append([]netip.Addr{d.YourIP}, d.Addresses...) {
			if ip.IsValid() {
				if err := g.hasIP(ctx, d.MAC, ip, ts, ts+lease, src); err != nil {
					return err
				}
			}
		}
	}
	if d.ClientIP.IsValid() {
		if err := g.hasIP(ctx, d.MAC, d.ClientIP, ts, ts, src); err != nil {
			return err
		}
	}
	g.live = append(g.live, LiveEvent{Type: "dhcp", TS: ts, Device: dev, Detail: strings.TrimSpace(d.MsgType + " " + d.Hostname)})
	return g.observation(ctx, sid, ts, src, dev, d.YourIP, d)
}

// reporter finds the device that sent an identity announcement.
func (g *ingester) reporter(ctx context.Context, ip netip.Addr, mac string, ts int64) (int64, string, error) {
	dev, devMAC, err := g.deviceFor(ctx, ip, mac, ts)
	if err != nil || dev == 0 {
		return dev, devMAC, err
	}
	if devMAC == "" {
		if devMAC, err = g.macOf(ctx, dev); err != nil {
			return 0, "", err
		}
	}
	return dev, devMAC, nil
}

// mdns credits each announced host to the device holding its address,
// not to the packet's sender: reflectors and sleep proxies answer for
// others. A host announced without addresses, or with the sender's own,
// is the sender's.
func (g *ingester) mdns(ctx context.Context, sid, ts int64, m *wire.MDNS) error {
	sender, senderMAC, err := g.reporter(ctx, m.IP, m.MAC, ts)
	if err != nil || sender == 0 {
		return err
	}
	if !m.Response && len(m.Services) == 0 && len(m.Hosts) == 0 {
		return nil // a bare query says little about the asker
	}
	owners := map[string][2]any{} // lower host name -> (device id, mac)
	for _, h := range m.Hosts {
		dev, mac := sender, senderMAC
		if len(h.Addrs) > 0 && !slices.Contains(h.Addrs, m.IP) {
			dev, mac = 0, ""
			for _, a := range h.Addrs {
				if b, ok := g.bindings[a.String()]; ok {
					if mac, err = g.macOf(ctx, b.device); err != nil {
						return err
					}
					dev = b.device
					break
				}
			}
		}
		if dev == 0 {
			continue // about a host we cannot place yet
		}
		owners[strings.ToLower(h.Name)] = [2]any{dev, mac}
		if err := g.hostname(ctx, dev, mac, h.Name, ts, "mdns", priMDNS); err != nil {
			return err
		}
		if dev == sender {
			for _, a := range h.Addrs {
				if err := g.hasIP(ctx, mac, a, ts, ts, "mdns"); err != nil {
					return err
				}
			}
		}
	}
	for _, sv := range m.Services {
		dev, mac := sender, senderMAC
		if o, ok := owners[strings.ToLower(sv.Target)]; ok {
			dev, mac = o[0].(int64), o[1].(string)
		} else if sv.Target != "" && len(m.Hosts) > 0 {
			continue // its host is someone we could not place
		}
		key := strings.ToLower(sv.Instance)
		instance, _, _ := strings.Cut(sv.Instance, "._")
		id, err := g.entity(ctx, model.KindService, key, ts, func(e *entRow) {
			e.label = instance
			e.attrs["type"] = sv.Type
		})
		if err != nil {
			return err
		}
		if sv.Port != 0 {
			g.setAttr(model.KindService, key, "port", strconv.Itoa(int(sv.Port)))
		}
		for _, k := range []string{"model", "md", "ty", "usb_mdl", "am", "fn"} {
			if v := sv.TXT[k]; v != "" {
				g.setAttr(model.KindService, key, "model", v)
				g.setAttr(model.KindDevice, mac, "model", v)
				break
			}
		}
		if err := g.fact(ctx, model.RelAnnounces, dev, id, ts, ts, "mdns", map[string]string{"type": sv.Type}); err != nil {
			return err
		}
	}
	return g.observation(ctx, sid, ts, "mdns", sender, m.IP, m)
}

// macOf returns a device entity's MAC.
func (g *ingester) macOf(ctx context.Context, dev int64) (string, error) {
	for k, e := range g.entities {
		if e.id == dev && k.kind == model.KindDevice {
			return k.key, nil
		}
	}
	var key string
	err := g.tx.QueryRowContext(ctx, `SELECT key FROM entities WHERE id = ?`, dev).Scan(&key)
	return key, err
}

func (g *ingester) name(ctx context.Context, sid, ts int64, n *wire.Name) error {
	dev, mac, err := g.reporter(ctx, n.IP, n.MAC, ts)
	if err != nil || dev == 0 || n.Group {
		return err
	}
	// A host registers its workgroup and browser roles as NetBIOS names
	// too; only its workstation and file-server names name it.
	switch n.Suffix {
	case "", "workstation", "file-server":
	default:
		return g.observation(ctx, sid, ts, n.Proto, dev, n.IP, n)
	}
	pri := priNBNS
	switch n.Proto {
	case "llmnr":
		pri = priLLMNR
	case "rdns":
		pri = priRDNS
	}
	if err := g.hostname(ctx, dev, mac, n.Name, ts, n.Proto, pri); err != nil {
		return err
	}
	return g.observation(ctx, sid, ts, n.Proto, dev, n.IP, n)
}

func (g *ingester) ssdp(ctx context.Context, sid, ts int64, s *wire.SSDP) error {
	dev, _, err := g.reporter(ctx, s.IP, s.MAC, ts)
	if err != nil || dev == 0 {
		return err
	}
	desc := firstNonEmpty(s.Server, s.UserAgent)
	if desc != "" && s.Method != "M-SEARCH" {
		id, err := g.entity(ctx, model.KindUPnP, desc, ts, func(e *entRow) { e.label = desc })
		if err != nil {
			return err
		}
		if s.Location != "" {
			g.setAttr(model.KindUPnP, desc, "location", s.Location)
		}
		attrs := map[string]string{}
		if s.NT != "" {
			attrs["nt"] = s.NT
		}
		if err := g.fact(ctx, model.RelUPnP, dev, id, ts, ts, "ssdp", attrs); err != nil {
			return err
		}
	}
	return g.observation(ctx, sid, ts, "ssdp", dev, s.IP, s)
}

// normMAC returns the canonical form of a MAC, or false for a missing or
// malformed one. Wi-Fi frames come from the air, so no value is trusted.
func normMAC(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 || hw[0]&1 != 0 {
		return "", false
	}
	return hw.String(), true
}

// wifi stores what a monitor-mode sensor decoded. Access points become
// devices with the role access_point; their SSIDs are entities, so the graph
// can show "ap broadcasts ssid" and "client probes/associates ap". Handshake
// events carry no key material, only whether the 4-way exchange completed.
func (g *ingester) wifi(ctx context.Context, sid, ts int64, w *wire.WiFi) error {
	ap, hasAP := normMAC(w.BSSID)
	client, hasClient := normMAC(w.Client)
	var dev int64
	var err error
	switch w.Kind {
	case "beacon", "probe_response":
		if !hasAP {
			return nil
		}
		if dev, err = g.device(ctx, ap, ts); err != nil {
			return err
		}
		if e := g.row(model.KindDevice, ap); e != nil && e.attrs["role"] == "" {
			g.setAttr(model.KindDevice, ap, "role", "access_point")
		}
		for k, v := range map[string]string{
			"ssid": w.SSID, "wifi_security": w.Security, "wifi_channel": strconv.Itoa(w.Channel),
		} {
			if v != "" && v != "0" {
				g.setAttr(model.KindDevice, ap, k, v)
			}
		}
		if w.SSID != "" {
			ssid, err := g.entity(ctx, model.KindSSID, strings.ToLower(w.SSID), ts, func(e *entRow) {
				e.label = w.SSID
			})
			if err != nil {
				return err
			}
			g.setAttr(model.KindSSID, strings.ToLower(w.SSID), "security", w.Security)
			attrs := map[string]string{}
			if w.Channel != 0 {
				attrs["channel"] = strconv.Itoa(w.Channel)
			}
			if w.Security != "" {
				attrs["security"] = w.Security
			}
			if err := g.fact(ctx, model.RelBroadcasts, dev, ssid, ts, ts, "wifi", attrs); err != nil {
				return err
			}
		}
	case "probe_request":
		if !hasClient || w.SSID == "" {
			return nil
		}
		if dev, err = g.device(ctx, client, ts); err != nil {
			return err
		}
		ssid, err := g.entity(ctx, model.KindSSID, strings.ToLower(w.SSID), ts, func(e *entRow) { e.label = w.SSID })
		if err != nil {
			return err
		}
		if err := g.fact(ctx, model.RelProbes, dev, ssid, ts, ts, "wifi", nil); err != nil {
			return err
		}
	case "association_request", "association_response":
		if !hasAP || !hasClient {
			return nil
		}
		if dev, err = g.device(ctx, client, ts); err != nil {
			return err
		}
		apDev, err := g.device(ctx, ap, ts)
		if err != nil {
			return err
		}
		if e := g.row(model.KindDevice, ap); e != nil && e.attrs["role"] == "" {
			g.setAttr(model.KindDevice, ap, "role", "access_point")
		}
		attrs := map[string]string{}
		if w.SSID != "" {
			attrs["ssid"] = w.SSID
		}
		if err := g.fact(ctx, model.RelAssociates, dev, apDev, ts, ts, "wifi", attrs); err != nil {
			return err
		}
	case "data":
		// Debug data-frame events are for live inspection; storing one
		// row per frame would dwarf the useful Wi-Fi facts.
		return nil
	case "handshake":
		if !hasAP || !hasClient {
			return nil
		}
		if dev, err = g.device(ctx, client, ts); err != nil {
			return err
		}
		apDev, err := g.device(ctx, ap, ts)
		if err != nil {
			return err
		}
		attrs := map[string]string{"cipher": ""}
		if w.EAPOL != nil {
			attrs["message"] = strconv.Itoa(w.EAPOL.Message)
			if w.EAPOL.Cipher != "" {
				attrs["cipher"] = w.EAPOL.Cipher
			}
			if w.EAPOL.Valid {
				attrs["valid"] = "1"
			}
			if w.EAPOL.Installed {
				attrs["installed"] = "1"
			}
			if w.EAPOL.Group {
				attrs["group"] = "1"
			}
			if w.EAPOL.GTK {
				attrs["gtk"] = "1"
			}
		}
		if err := g.fact(ctx, model.RelHandshake, dev, apDev, ts, ts, "wifi", attrs); err != nil {
			return err
		}
	default:
		if hasClient {
			if dev, err = g.device(ctx, client, ts); err != nil {
				return err
			}
		} else if hasAP {
			if dev, err = g.device(ctx, ap, ts); err != nil {
				return err
			}
		}
	}
	if dev == 0 {
		return nil
	}
	return g.observation(ctx, sid, ts, "wifi", dev, netip.Addr{}, w)
}

// wifiKey persists the public nonces of a 4-way handshake so a restarted or
// additional sensor can re-derive the pairwise key (see WiFiKey). It keeps
// the most recent handshake per (AP, station). It stores no key material.
func (g *ingester) wifiKey(ctx context.Context, sid, ts int64, w *wire.WiFiKey) error {
	bssid, ok1 := normMAC(w.BSSID)
	sta, ok2 := normMAC(w.STA)
	if !ok1 || !ok2 || w.SSID == "" || len(w.ANonce) != 64 || len(w.SNonce) != 64 {
		return nil // malformed; nonces are 32 bytes = 64 hex digits
	}
	_, err := g.tx.ExecContext(ctx, `
		INSERT INTO wifi_handshakes (bssid, sta, ssid, anonce, snonce, key_version, sensor_id, ts)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(bssid, sta) DO UPDATE SET
			ssid = excluded.ssid, anonce = excluded.anonce, snonce = excluded.snonce,
			key_version = excluded.key_version, sensor_id = excluded.sensor_id, ts = excluded.ts
		WHERE excluded.ts >= wifi_handshakes.ts`,
		bssid, sta, w.SSID, strings.ToLower(w.ANonce), strings.ToLower(w.SNonce), w.KeyVersion, sid, ts)
	return err
}

func (g *ingester) lldp(ctx context.Context, sid, ts int64, l *wire.LLDP) error {
	if l.MAC == "" {
		return nil
	}
	dev, err := g.device(ctx, l.MAC, ts)
	if err != nil {
		return err
	}
	key := l.ChassisID + "/" + l.PortID
	label := firstNonEmpty(l.SystemName, l.ChassisID) + " " + l.PortID
	id, err := g.entity(ctx, model.KindLLDP, key, ts, nil)
	if err != nil {
		return err
	}
	// Systems get renamed; the neighbour is what it last advertised.
	g.relabel(model.KindLLDP, key, label)
	g.setAttr(model.KindLLDP, key, "system", l.SystemName)
	g.setAttr(model.KindLLDP, key, "port", l.PortID)
	g.setAttr(model.KindLLDP, key, "description", l.SystemDesc)
	if err := g.fact(ctx, model.RelNeighbor, dev, id, ts, ts, "lldp", nil); err != nil {
		return err
	}
	g.setLabel(model.KindDevice, l.MAC, l.SystemName, priLLDP)
	// LLDP speakers are mostly switches and APs, but a router speaks it too:
	// never demote a known role.
	if e := g.row(model.KindDevice, l.MAC); e != nil && e.attrs["role"] == "" {
		g.setAttr(model.KindDevice, l.MAC, "role", "switch")
	}
	return g.observation(ctx, sid, ts, "lldp", dev, netip.Addr{}, l)
}

// --- rollups ----------------------------------------------------------------

const hourMS = 3600 * 1000

func hourOf(t int64) int64 { return t - ((t%hourMS)+hourMS)%hourMS }

// addTraffic spreads a record's bytes over the hours it covers and counts
// the flow once, in the hour it began.
func (g *ingester) addTraffic(k trafficKey, start, end, first, bout, bin int64) {
	add := func(bucket, flows, bo, bi int64) {
		kk := k
		kk.bucket = bucket
		a := g.traffic[kk]
		if a == nil {
			a = &trafficAgg{}
			g.traffic[kk] = a
		}
		a.flows += flows
		a.bout += bo
		a.bin += bi
	}
	if span := end - start; span <= 0 {
		add(hourOf(start), 0, bout, bin)
	} else {
		var doneOut, doneIn int64
		for b := hourOf(start); b < end; b += hourMS {
			overlap := min(end, b+hourMS) - max(start, b)
			bo, bi := bout*overlap/span, bin*overlap/span
			if b+hourMS >= end { // last bucket takes the rounding remainder
				bo, bi = bout-doneOut, bin-doneIn
			}
			add(b, 0, bo, bi)
			doneOut, doneIn = doneOut+bo, doneIn+bi
		}
	}
	if start == first {
		add(hourOf(first), 1, 0, 0)
	}
}

func (g *ingester) flushRollupsTx(ctx context.Context) error {
	for k, a := range g.traffic {
		if _, err := g.tx.ExecContext(ctx, `INSERT INTO traffic_hourly (bucket, client_device, client_ip, remote_ip, remote_port, proto, name, app, multicast, flows, bytes_out, bytes_in)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (bucket, client_device, client_ip, remote_ip, remote_port, proto, name) DO UPDATE SET
			flows = flows + excluded.flows, bytes_out = bytes_out + excluded.bytes_out, bytes_in = bytes_in + excluded.bytes_in,
			app = CASE WHEN excluded.app != '' THEN excluded.app ELSE app END`,
			k.bucket, k.device, k.client, k.remote, k.port, k.proto, k.name, k.app, boolInt(k.multicast), a.flows, a.bout, a.bin); err != nil {
			return err
		}
	}
	for k, n := range g.dnsAgg {
		if _, err := g.tx.ExecContext(ctx, `INSERT INTO dns_hourly (bucket, client_device, client_ip, qname, qtype, rcode, count) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (bucket, client_device, client_ip, qname, qtype, rcode) DO UPDATE SET count = count + excluded.count`,
			k.bucket, k.device, k.client, k.qname, k.qtype, k.rcode, n); err != nil {
			return err
		}
	}
	clear(g.traffic)
	clear(g.dnsAgg)
	return nil
}

// --- helpers ----------------------------------------------------------------

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isGroupAddr(a netip.Addr) bool {
	return a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// ProtoName names an IP protocol number.
func ProtoName(p int) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	}
	return strconv.Itoa(p)
}

func portProto(port int, proto uint8) string {
	if port == 0 {
		return ProtoName(int(proto))
	}
	return fmt.Sprintf("%d/%s", port, ProtoName(int(proto)))
}
