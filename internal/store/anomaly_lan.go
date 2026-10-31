package store

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

// arpConflicts reports an address two devices held at the same time for at
// least five minutes. DHCP moves and IPv4 address reuse are normal, but an
// overlap this long means one MAC is claiming another's address (a static
// misconfiguration, or ARP spoofing).
func (a *anomalies) arpConflicts(ctx context.Context) error {
	const minOverlap int64 = 5 * 60 * 1000
	// Read overlapping fact rows, not min/max over a group: a device can
	// hold an address in several separate periods, and only an actual
	// overlap is a conflict.
	rows, err := a.s.r.QueryContext(ctx, `
		SELECT ip.key, f1.src, f2.src,
		       max(f1.first_seen, f2.first_seen) AS overlap_start,
		       min(f1.last_seen, f2.last_seen) AS overlap_end
		FROM facts f1
		JOIN facts f2 ON f2.dst = f1.dst AND f2.rel = 'has_ip' AND f2.src > f1.src
		JOIN entities ip ON ip.id = f1.dst AND ip.kind = 'ip'
		WHERE f1.rel = 'has_ip'
		  AND f1.first_seen < ? AND f1.last_seen >= ?
		  AND f2.first_seen < ? AND f2.last_seen >= ?
		  AND f1.first_seen < f2.last_seen AND f2.first_seen < f1.last_seen
		ORDER BY ip.key, f1.src, f2.src, overlap_start`, a.to, a.from, a.to, a.from)
	if err != nil {
		return err
	}
	type pair struct {
		ip       string
		one, two int64
	}
	type span struct{ first, last int64 }
	type conflict struct {
		pair
		first, last int64
	}
	spans := map[pair][]span{}
	var order []pair
	for rows.Next() {
		var key pair
		var s span
		if err := rows.Scan(&key.ip, &key.one, &key.two, &s.first, &s.last); err != nil {
			rows.Close()
			return err
		}
		if _, ok := spans[key]; !ok {
			order = append(order, key)
		}
		spans[key] = append(spans[key], s)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var cs []conflict
	var ids []int64
	for _, key := range order {
		ss := spans[key]
		slices.SortFunc(ss, func(x, y span) int { return cmp.Compare(x.first, y.first) })
		merged := ss[0]
		best := span{}
		flush := func() {
			if merged.last-merged.first > best.last-best.first {
				best = merged
			}
		}
		for _, s := range ss[1:] {
			if s.first <= merged.last {
				merged.last = max(merged.last, s.last)
				continue
			}
			flush()
			merged = s
		}
		flush()
		if best.last-best.first < minOverlap {
			continue
		}
		cs = append(cs, conflict{pair: key, first: best.first, last: best.last})
		ids = append(ids, key.one, key.two)
	}
	devs, err := a.devices(ctx, ids)
	if err != nil {
		return err
	}
	for _, c := range cs {
		one, two := devs[c.one], devs[c.two]
		if one == nil || two == nil {
			continue
		}
		sev := model.SeverityMedium
		if one.randomized || two.randomized {
			sev = model.SeverityLow
		}
		a.add(model.Anomaly{Kind: model.AnomalyARPConflict, Severity: sev, TS: max(c.first, a.from),
			Device: one.id, DeviceName: one.name, Entity: model.EntityID(model.KindIP, c.ip),
			Summary: fmt.Sprintf("%s (%s) and %s (%s) both used %s for %s", one.name, one.mac, two.name, two.mac,
				c.ip, time.Duration(min(c.last, a.to)-max(c.first, a.from)).Round(time.Second)),
			Evidence: map[string]string{"ip": c.ip, "macs": one.mac + "," + two.mac,
				"first": strconv.FormatInt(c.first, 10), "last": strconv.FormatInt(c.last, 10)}})
	}
	return nil
}

// rogueDHCP reports a DHCP OFFER or ACK from an address that is not the
// router (or a sensor's own interface). A second DHCP server on a home LAN
// is either a misconfigured box or an attack; it hands clients a gateway
// and resolver the operator did not choose.
func (a *anomalies) rogueDHCP(ctx context.Context) error {
	rows, err := a.s.r.QueryContext(ctx, `
		SELECT json_extract(data, '$.server') AS server, count(*), min(ts), max(ts)
		FROM observations
		WHERE type = 'dhcp' AND ts >= ? AND ts < ?
		  AND json_valid(data)
		  AND json_extract(data, '$.msg') IN ('OFFER', 'ACK')
		  AND coalesce(json_extract(data, '$.server'), '') != ''
		GROUP BY server`, a.from, a.to)
	if err != nil {
		return err
	}
	type server struct {
		ip          string
		n           int
		first, last int64
	}
	var ss []server
	var ids []int64
	for rows.Next() {
		var s server
		if err := rows.Scan(&s.ip, &s.n, &s.first, &s.last); err != nil {
			rows.Close()
			return err
		}
		ss = append(ss, s)
		ids = append(ids, a.deviceForIP(ctx, s.ip, a.from, a.to))
	}
	if err := rows.Close(); err != nil {
		return err
	}
	devs, err := a.devices(ctx, ids)
	if err != nil {
		return err
	}
	for i, s := range ss {
		d := devs[ids[i]]
		if d != nil && (d.role == "router" || d.role == "sensor") {
			continue
		}
		if ip, err := netip.ParseAddr(s.ip); err == nil && a.s.nets.ownAddress(ip) {
			continue
		}
		// A DHCP server visible on the LAN with no device row at all is a
		// stronger warning: it is not one of ours.
		sev := model.SeverityMedium
		if d == nil {
			sev = model.SeverityHigh
		}
		who := "an unknown host"
		if d != nil {
			who = d.name
		}
		a.add(model.Anomaly{Kind: model.AnomalyRogueDHCP, Severity: sev, TS: max(s.first, a.from),
			Device: dID(d), DeviceName: dName(d), Entity: model.EntityID(model.KindIP, s.ip),
			Summary:  fmt.Sprintf("%s at %s answered %d DHCP offers/acks on the LAN", who, s.ip, s.n),
			Evidence: map[string]string{"server": s.ip, "messages": strconv.Itoa(s.n)}})
	}
	return nil
}

func dID(d *anomalyDevice) string {
	if d == nil {
		return ""
	}
	return d.id
}

func dName(d *anomalyDevice) string {
	if d == nil {
		return ""
	}
	return d.name
}

// deviceForIP returns the one device that held an address during the
// window, or 0.
func (a *anomalies) deviceForIP(ctx context.Context, ip string, from, to int64) int64 {
	var id int64
	rows, err := a.s.r.QueryContext(ctx, `SELECT f.src FROM facts f JOIN entities e ON e.id = f.dst
		WHERE f.rel = 'has_ip' AND e.kind = 'ip' AND e.key = ? AND f.first_seen < ? AND f.last_seen >= ?
		GROUP BY f.src ORDER BY max(f.last_seen) DESC LIMIT 2`, ip, to, from)
	if err != nil {
		return 0
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var got int64
		if err := rows.Scan(&got); err != nil {
			return 0
		}
		n++
		id = got
	}
	if n == 1 {
		return id
	}
	return 0
}
