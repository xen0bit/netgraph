package store

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/anomaly"
	"github.com/xen0bit/netgraph/internal/model"
)

// Checks for servers here: what connections from outside (direction "in")
// say. A server on the internet is scanned and guessed at around the clock,
// so these summarise, and only a few rise above low.
const (
	// A probe is a connection that never became a session: the client sent
	// at most this many packets and the device at most probeReply (a
	// refused port's RST, a SYN-ACK to a half-open scan, or nothing).
	probeAsk   = 3
	probeReply = 2
	// A session is one the device answered with at least this many packets.
	sessionReply = 3

	scanPorts         = 10 // ports one address tried on a device
	scanHosts         = 10 // or addresses here it tried one port on
	maxScansPerDevice = 10 // reported one by one; beyond, one summary

	bruteMax      = 10 * time.Second // a login attempt's session is short
	bruteMin      = 50               // sessions from one address: medium
	bruteHigh     = 500              // high
	bruteSpread   = 500              // sessions from many addresses together: low
	bruteSpreadBy = 20               // from at least this many addresses

	newServiceClients = 3       // clients of a new port, or
	newServiceBytes   = 1 << 20 // bytes it moved
	dynamicPorts      = 49152   // and up: peer-to-peer apps, not services
)

// loginPorts are the services guessed at: a login for each connection.
// Web logins look like any other page load, so flows cannot see them.
var loginPorts = []int{21, 22, 23, 25, 110, 143, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379}

var (
	isProbe   = fmt.Sprintf(`(c.pkts_in <= %d AND c.pkts_out <= %d)`, probeAsk, probeReply)
	isSession = fmt.Sprintf(`(c.pkts_out >= %d)`, sessionReply)
)

// inboundOpened selects connections from outside opened in the window; its
// arguments are from, from, to.
const inboundOpened = `c.direction = 'in' AND c.multicast = 0 AND c.last_seen >= ? AND c.first_seen >= ? AND c.first_seen < ?`

// remote is an address outside, with its network when the ASN table knew
// it.
type remote struct {
	ip  string
	asn uint32
	cc  string
}

// networks names the networks of remote addresses: "AS24940 HETZNER-AS".
func (a *anomalies) networks(ctx context.Context, rs []remote) (func(remote) string, error) {
	orgs, err := a.s.asOrgs(ctx, func(yield func(uint32) bool) {
		for _, r := range rs {
			if r.asn != 0 && !yield(r.asn) {
				return
			}
		}
	})
	if err != nil {
		return nil, err
	}
	return func(r remote) string {
		if r.asn == 0 {
			return ""
		}
		return ASNLabel(r.asn, orgs[r.asn])
	}, nil
}

// from describes where a remote address is: "5.9.10.1 (AS24940
// HETZNER-AS, DE)".
func from(r remote, network string) string {
	where := strings.Trim(network+", "+r.cc, ", ")
	if where == "" {
		return r.ip
	}
	return r.ip + " (" + where + ")"
}

// netEvidence adds a remote address's network to an anomaly's evidence.
func netEvidence(ev map[string]string, r remote, network string) map[string]string {
	if network != "" {
		ev["network"] = network
	}
	if r.cc != "" {
		ev["country"] = r.cc
	}
	return ev
}

// scans: an address outside tried many ports on one device (most of them
// probes that never became sessions), or one port on many addresses here.
// Low: a server on the internet is scanned all day. More than
// maxScansPerDevice scanners of one device are one summary.
func (a *anomalies) scans(ctx context.Context) error {
	type scan struct {
		remote
		dev     int64
		local   string
		ports   []string
		probes  int
		conns   int
		first   int64
		network string
	}
	rows, err := a.s.r.QueryContext(ctx, `SELECT c.client_device, c.client_ip, c.remote_ip, coalesce(c.remote_asn, 0), c.remote_cc,
		group_concat(DISTINCT c.client_port || '/' || c.proto), count(DISTINCT c.client_port), sum(`+isProbe+`), count(*), min(c.first_seen)
		FROM connections c WHERE `+inboundOpened+`
		GROUP BY 1, 2, 3 HAVING count(DISTINCT c.client_port) >= ? AND 2 * sum(`+isProbe+`) >= count(*)`,
		a.from, a.from, a.to, scanPorts)
	if err != nil {
		return err
	}
	var all []*scan
	for rows.Next() {
		s := &scan{}
		var ports string
		var n int
		if err := rows.Scan(&s.dev, &s.local, &s.ip, &s.asn, &s.cc, &ports, &n, &s.probes, &s.conns, &s.first); err != nil {
			rows.Close()
			return err
		}
		for _, p := range strings.Split(ports, ",") {
			port, proto, _ := strings.Cut(p, "/")
			n, _ := strconv.Atoi(proto)
			s.ports = append(s.ports, port+"/"+protoName(n))
		}
		slices.SortFunc(s.ports, comparePortProto)
		all = append(all, s)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var rs []remote
	var ids []int64
	byDev := map[string][]*scan{}
	for _, s := range all {
		rs, ids = append(rs, s.remote), append(ids, s.dev)
	}
	name, err := a.networks(ctx, rs)
	if err != nil {
		return err
	}
	devs, err := a.devices(ctx, ids)
	if err != nil {
		return err
	}
	for _, s := range all {
		s.network = name(s.remote)
		id, _ := a.who(devs, s.dev, s.local)
		byDev[cmp.Or(id, "ip:"+s.local)] = append(byDev[cmp.Or(id, "ip:"+s.local)], s)
	}
	for _, key := range slices.Sorted(maps.Keys(byDev)) {
		ss := byDev[key]
		devID, dname := a.who(devs, ss[0].dev, ss[0].local)
		if len(ss) <= maxScansPerDevice {
			for _, s := range ss {
				a.add(model.Anomaly{Kind: model.AnomalyScan, Severity: model.SeverityLow, TS: s.first, Device: devID, DeviceName: dname,
					Entity:  model.EntityID(model.KindIP, s.ip),
					Summary: fmt.Sprintf("%s tried %d ports on %s (%s)", from(s.remote, s.network), len(s.ports), dname, listSome(s.ports, 6)),
					Evidence: netEvidence(map[string]string{"ports": strconv.Itoa(len(s.ports)), "probes": strconv.Itoa(s.probes),
						"connections": strconv.Itoa(s.conns), "tried": listSome(s.ports, 20)}, s.remote, s.network)})
			}
			continue
		}
		// Many scanners: one finding, with the networks they came from.
		ports := map[string]bool{}
		nets := map[string]int{}
		first := ss[0].first
		for _, s := range ss {
			for _, p := range s.ports {
				ports[p] = true
			}
			if s.network != "" {
				nets[s.network]++
			}
			first = min(first, s.first)
		}
		top := slices.SortedFunc(maps.Keys(nets), func(x, y string) int { return cmp.Or(cmp.Compare(nets[y], nets[x]), cmp.Compare(x, y)) })
		var tops []string
		for _, n := range top[:min(len(top), 3)] {
			tops = append(tops, fmt.Sprintf("%s ×%d", n, nets[n]))
		}
		summary := fmt.Sprintf("%d addresses scanned %d ports on %s", len(ss), len(ports), dname)
		if len(tops) > 0 {
			summary += ", most from " + strings.Join(tops, ", ")
		}
		a.add(model.Anomaly{Kind: model.AnomalyScan, Severity: model.SeverityLow, TS: first, Device: devID, DeviceName: dname,
			Summary: summary,
			Evidence: map[string]string{"scanners": strconv.Itoa(len(ss)), "ports": strconv.Itoa(len(ports)), "networks": strconv.Itoa(len(nets)),
				"top_networks": strings.Join(tops, "; ")}})
	}

	// Sweeps: one port on many addresses here.
	rows, err = a.s.r.QueryContext(ctx, `SELECT c.remote_ip, coalesce(c.remote_asn, 0), c.remote_cc, c.client_port, c.proto, count(DISTINCT c.client_ip), min(c.first_seen)
		FROM connections c WHERE `+inboundOpened+`
		GROUP BY 1, 4, 5 HAVING count(DISTINCT c.client_ip) >= ?`, a.from, a.from, a.to, scanHosts)
	if err != nil {
		return err
	}
	type sweep struct {
		remote
		port, proto, hosts int
		first              int64
	}
	var sweeps []sweep
	rs = rs[:0]
	for rows.Next() {
		var s sweep
		if err := rows.Scan(&s.ip, &s.asn, &s.cc, &s.port, &s.proto, &s.hosts, &s.first); err != nil {
			rows.Close()
			return err
		}
		sweeps, rs = append(sweeps, s), append(rs, s.remote)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if name, err = a.networks(ctx, rs); err != nil {
		return err
	}
	for _, s := range sweeps {
		network := name(s.remote)
		port := fmt.Sprintf("%d/%s", s.port, protoName(s.proto))
		a.add(model.Anomaly{Kind: model.AnomalyScan, Severity: model.SeverityLow, TS: s.first, Entity: model.EntityID(model.KindIP, s.ip),
			Summary:  fmt.Sprintf("%s tried %s on %d addresses here", from(s.remote, network), port, s.hosts),
			Evidence: netEvidence(map[string]string{"port": port, "hosts": strconv.Itoa(s.hosts)}, s.remote, network)})
	}
	return nil
}

// bruteForce: many short sessions to a login service from one address
// outside (someone guessing passwords), or from many addresses together.
func (a *anomalies) bruteForce(ctx context.Context) error {
	ports := make([]string, len(loginPorts))
	for i, p := range loginPorts {
		ports[i] = strconv.Itoa(p)
	}
	rows, err := a.s.r.QueryContext(ctx, `SELECT c.client_device, c.client_ip, c.client_port, c.proto, c.remote_ip, coalesce(c.remote_asn, 0), c.remote_cc,
		count(*), min(c.first_seen)
		FROM connections c WHERE `+inboundOpened+` AND c.client_port IN (`+strings.Join(ports, ",")+`)
		AND c.last_seen - c.first_seen < ? AND `+isSession+`
		GROUP BY 1, 2, 3, 4, 5`, a.from, a.from, a.to, bruteMax.Milliseconds())
	if err != nil {
		return err
	}
	type service struct {
		dev          int64
		local        string
		port, proto  int
		conns, addrs int
		first        int64
	}
	type guess struct {
		remote
		svc   *service
		conns int
		first int64
	}
	services := map[string]*service{}
	var guesses []guess
	for rows.Next() {
		var g guess
		var sv service
		if err := rows.Scan(&sv.dev, &sv.local, &sv.port, &sv.proto, &g.ip, &g.asn, &g.cc, &g.conns, &g.first); err != nil {
			rows.Close()
			return err
		}
		k := fmt.Sprintf("%d|%s|%d|%d", sv.dev, sv.local, sv.port, sv.proto)
		if services[k] == nil {
			sv.first = g.first
			services[k] = &sv
		}
		g.svc = services[k]
		g.svc.first = min(g.svc.first, g.first)
		if g.conns >= bruteMin {
			guesses = append(guesses, g)
		} else {
			// Addresses below the bar still count toward a spread attack.
			g.svc.conns += g.conns
			g.svc.addrs++
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var rs []remote
	var ids []int64
	for _, g := range guesses {
		rs = append(rs, g.remote)
	}
	for _, sv := range services {
		ids = append(ids, sv.dev)
	}
	name, err := a.networks(ctx, rs)
	if err != nil {
		return err
	}
	devs, err := a.devices(ctx, ids)
	if err != nil {
		return err
	}
	for _, g := range guesses {
		devID, dname := a.who(devs, g.svc.dev, g.svc.local)
		network := name(g.remote)
		port := fmt.Sprintf("%d/%s", g.svc.port, protoName(g.svc.proto))
		sev := model.SeverityMedium
		if g.conns >= bruteHigh {
			sev = model.SeverityHigh
		}
		a.add(model.Anomaly{Kind: model.AnomalyBruteForce, Severity: sev, TS: g.first, Device: devID, DeviceName: dname,
			Entity:   model.EntityID(model.KindIP, g.ip),
			Summary:  fmt.Sprintf("%s opened %d short sessions to %s on %s: guessing a login", from(g.remote, network), g.conns, port, dname),
			Evidence: netEvidence(map[string]string{"sessions": strconv.Itoa(g.conns), "port": port, "under": bruteMax.String()}, g.remote, network)})
	}
	for _, k := range slices.Sorted(maps.Keys(services)) {
		sv := services[k]
		if sv.conns < bruteSpread || sv.addrs < bruteSpreadBy {
			continue
		}
		devID, dname := a.who(devs, sv.dev, sv.local)
		port := fmt.Sprintf("%d/%s", sv.port, protoName(sv.proto))
		a.add(model.Anomaly{Kind: model.AnomalyBruteForce, Severity: model.SeverityLow, TS: sv.first, Device: devID, DeviceName: dname,
			Summary:  fmt.Sprintf("%d addresses opened %d short sessions to %s on %s, each under %d", sv.addrs, sv.conns, port, dname, bruteMin),
			Evidence: map[string]string{"sessions": strconv.Itoa(sv.conns), "addresses": strconv.Itoa(sv.addrs), "port": port}})
	}
	return nil
}

// newServices: a device here held sessions with clients outside on a port
// it had not served in the last week: something newly exposed (a forwarded
// port, a container published by mistake). Dynamic ports are left out:
// peer-to-peer apps open them as a matter of course.
func (a *anomalies) newServices(ctx context.Context) error {
	rows, err := a.s.r.QueryContext(ctx, `SELECT c.client_device, c.client_port, c.proto, count(DISTINCT c.remote_ip), sum(c.bytes_out + c.bytes_in), min(c.first_seen)
		FROM connections c WHERE `+inboundOpened+` AND c.client_device != 0 AND c.client_port < ? AND `+isSession+`
		GROUP BY 1, 2, 3`, a.from, a.from, a.to, dynamicPorts)
	if err != nil {
		return err
	}
	type svc struct {
		dev         int64
		port, proto int
		clients     int
		bytes       int64
		first       int64
	}
	var now []svc
	for rows.Next() {
		var s svc
		if err := rows.Scan(&s.dev, &s.port, &s.proto, &s.clients, &s.bytes, &s.first); err != nil {
			rows.Close()
			return err
		}
		if s.clients >= newServiceClients || s.bytes >= newServiceBytes {
			now = append(now, s)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(now) == 0 {
		return nil
	}
	// What each device served in the week before, from raw connections:
	// the rollups cannot tell a session from a refused probe.
	before := map[string]bool{}
	rows, err = a.s.r.QueryContext(ctx, `SELECT DISTINCT c.client_device, c.client_port, c.proto FROM connections c
		WHERE c.direction = 'in' AND c.client_device != 0 AND c.last_seen >= ? AND c.first_seen < ? AND `+isSession,
		a.from-anomalyBaseline.Milliseconds(), a.from)
	if err != nil {
		return err
	}
	for rows.Next() {
		var dev int64
		var port, proto int
		if err := rows.Scan(&dev, &port, &proto); err != nil {
			rows.Close()
			return err
		}
		before[fmt.Sprintf("%d|%d|%d", dev, port, proto)] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var ids []int64
	for _, s := range now {
		ids = append(ids, s.dev)
	}
	devs, err := a.devices(ctx, ids)
	if err != nil {
		return err
	}
	for _, s := range now {
		d := devs[s.dev]
		// A device new to the network serves everything for the first time.
		if d == nil || before[fmt.Sprintf("%d|%d|%d", s.dev, s.port, s.proto)] || a.from-d.first < AnomalyHistory.Milliseconds() {
			continue
		}
		port := fmt.Sprintf("%d/%s", s.port, protoName(s.proto))
		a.add(model.Anomaly{Kind: model.AnomalyNewService, Severity: model.SeverityMedium, TS: s.first, Device: d.id, DeviceName: d.name,
			Summary: fmt.Sprintf("%s started serving %s to clients outside: %d of them, %s, and not once in the last 7 days", d.name, port,
				s.clients, model.FormatBytes(uint64(s.bytes))),
			Evidence: map[string]string{"port": port, "clients": strconv.Itoa(s.clients), "bytes": model.FormatBytes(uint64(s.bytes))}})
	}
	return nil
}

// inboundSurges: far more connections from outside to a device in an hour
// than in its busiest hour of the last week (a flood, or a sudden rush).
func (a *anomalies) inboundSurges(ctx context.Context) error {
	rows, err := a.s.r.QueryContext(ctx, `SELECT c.client_device, count(*), min(c.first_seen), count(DISTINCT c.remote_ip)
		FROM connections c WHERE `+inboundOpened+` AND c.client_device != 0 GROUP BY 1`, a.from, a.from, a.to)
	if err != nil {
		return err
	}
	type count struct {
		n, addrs int
		first    int64
	}
	now := map[int64]count{}
	for rows.Next() {
		var dev int64
		var c count
		if err := rows.Scan(&dev, &c.n, &c.first, &c.addrs); err != nil {
			rows.Close()
			return err
		}
		now[dev] = c
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(now) == 0 {
		return nil
	}
	hours := map[int64][]float64{}
	rows, err = a.s.r.QueryContext(ctx, `SELECT client_device, sum(flows) FROM traffic_hourly
		WHERE bucket >= ? AND bucket + 3600000 <= ? AND direction = 'in' AND client_device != 0 GROUP BY client_device, bucket HAVING sum(flows) > 0`,
		a.from-anomalyBaseline.Milliseconds(), a.from)
	if err != nil {
		return err
	}
	for rows.Next() {
		var dev int64
		var n float64
		if err := rows.Scan(&dev, &n); err != nil {
			rows.Close()
			return err
		}
		hours[dev] = append(hours[dev], n)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	devs, err := a.devices(ctx, slices.Collect(maps.Keys(now)))
	if err != nil {
		return err
	}
	// As for upload spikes, a window shorter than an hour is compared as it
	// is.
	span := max(float64(a.to-a.from)/float64(time.Hour.Milliseconds()), 1)
	for _, dev := range slices.Sorted(maps.Keys(now)) {
		d, c := devs[dev], now[dev]
		if d == nil {
			continue
		}
		rate := float64(c.n) / span
		surge, high, peak := anomaly.Surge(rate, hours[dev])
		if !surge {
			continue
		}
		sev := model.SeverityMedium
		if high {
			sev = model.SeverityHigh
		}
		a.add(model.Anomaly{Kind: model.AnomalyInboundSurge, Severity: sev, TS: max(c.first, a.from), Device: d.id, DeviceName: d.name,
			Summary: fmt.Sprintf("%s accepted %d connections from outside (%.0f an hour, from %d addresses); its busiest hour in the last 7 days had %.0f",
				d.name, c.n, rate, c.addrs, peak),
			Evidence: map[string]string{"connections": strconv.Itoa(c.n), "per_hour": fmt.Sprintf("%.0f", rate), "addresses": strconv.Itoa(c.addrs),
				"busiest_hour": fmt.Sprintf("%.0f", peak), "hours": strconv.Itoa(len(hours[dev]))}})
	}
	return nil
}

// listSome lists the first n items, and how many more there are.
func listSome(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" +%d", len(items)-n)
}

// comparePortProto orders "443/tcp" style port and protocol pairs by port.
func comparePortProto(x, y string) int {
	px, _, _ := strings.Cut(x, "/")
	py, _, _ := strings.Cut(y, "/")
	nx, _ := strconv.Atoi(px)
	ny, _ := strconv.Atoi(py)
	return cmp.Or(cmp.Compare(nx, ny), cmp.Compare(x, y))
}
