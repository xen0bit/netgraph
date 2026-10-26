// Package graph turns a window's rows (devices, flows, lookups, facts) into
// a graph of entities and relationships, and renders graphs as d2 scripts.
//
// It depends only on the model package, so the server, the TUI and the
// WASM web UI all build and draw graphs with the same code.
package graph

import (
	"cmp"
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
)

// Input is everything a graph is built from.
type Input struct {
	FromMS, ToMS int64
	Precision    string
	Devices      []model.Device
	Flows        []model.Flow
	DNS          []model.DNSQuery
	Facts        []model.Fact
}

type builder struct {
	in      Input
	o       model.GraphOptions
	nodes   map[string]*model.Node
	edges   map[string]*model.Edge
	spans   map[string][][2]int64 // edge -> connection spans, for peak concurrency
	order   []string
	eord    []string
	owner   func(ip string) string // the one device holding a local address
	devices map[string]*model.Device
}

// Build assembles a graph.
//
// The shape, with DNS and Collapse on (the default):
//
//	device ──queried──▶ domain ──resolves_to──▶ address
//	device ──connects─────────▶ domain           (when the address was reached by that name)
//	device ──connects─────────▶ address          (when it was not)
//
// With Collapse off, connections always point at addresses and names hang
// off them through resolves_to/serves. Identity adds the device's
// hostnames, services, fingerprints and vendor as their own nodes.
func Build(in Input, o model.GraphOptions) *model.Graph {
	if o.TopN == 0 {
		o.TopN = 15
	}
	b := &builder{in: in, o: o, nodes: map[string]*model.Node{}, edges: map[string]*model.Edge{}, spans: map[string][][2]int64{}}
	g := &model.Graph{FromMS: in.FromMS, ToMS: in.ToMS, Precision: in.Precision}

	devices := map[string]*model.Device{}
	owners := map[string][]string{} // local address -> devices that had it
	for i := range in.Devices {
		d := &in.Devices[i]
		devices[d.ID] = d
		for _, ip := range d.IPs {
			owners[ip] = append(owners[ip], d.ID)
		}
	}
	b.devices = devices
	b.owner = func(ip string) string {
		if o := owners[ip]; len(o) == 1 {
			return o[0]
		}
		return ""
	}

	// Connections, grouped per device and destination; then keep each
	// device's busiest TopN destinations.
	type dest struct {
		key   string
		bytes uint64
		flows []model.Flow
	}
	perDev := map[string]map[string]*dest{}
	for _, fl := range in.Flows {
		src := fl.Device
		if src == "" {
			src = model.EntityID(model.KindIP, fl.ClientIP)
		}
		to := b.destination(fl)
		m := perDev[src]
		if m == nil {
			m = map[string]*dest{}
			perDev[src] = m
		}
		d := m[to]
		if d == nil {
			d = &dest{key: to}
			m[to] = d
		}
		d.bytes += fl.BytesOut + fl.BytesIn
		d.flows = append(d.flows, fl)
	}
	keptDest := map[string]bool{}
	for src, m := range perDev {
		ds := make([]*dest, 0, len(m))
		for _, d := range m {
			ds = append(ds, d)
		}
		sort.Slice(ds, func(i, j int) bool {
			if ds[i].bytes != ds[j].bytes {
				return ds[i].bytes > ds[j].bytes
			}
			return ds[i].key < ds[j].key
		})
		if o.TopN > 0 && len(ds) > o.TopN {
			ds = ds[:o.TopN]
			g.Truncated = true
		}
		b.sourceNode(src, devices)
		for _, d := range ds {
			keptDest[d.key] = true
			for _, fl := range d.flows {
				b.connect(src, d.key, fl)
			}
		}
	}

	if o.Identity {
		// Identity is about every device in the window, talkative or not.
		for _, d := range in.Devices {
			b.sourceNode(d.ID, devices)
		}
	}

	// Lookups: device -> domain, then domain -> address for answers whose
	// address the graph already shows (or for every answer of a domain the
	// graph shows, when there are no flows to anchor on).
	if o.DNS {
		for _, q := range in.DNS {
			src := q.Device
			if src == "" {
				src = model.EntityID(model.KindIP, q.ClientIP)
			}
			dom := model.EntityID(model.KindDomain, q.QName)
			if o.TopN > 0 && len(in.Flows) > 0 && !keptDest[dom] && !b.answersKept(q, keptDest) {
				continue // a lookup that led nowhere the graph shows
			}
			b.sourceNode(src, devices)
			b.node(dom, model.KindDomain, q.QName, "")
			e := b.edge(src, dom, model.RelQueried)
			e.Count++
			if q.RCode != "NOERROR" {
				if e.Attrs == nil {
					e.Attrs = map[string]string{}
				}
				e.Attrs["rcode"] = q.RCode
			}
			b.span(e, q.TS, q.TS)
		}
	}

	// Facts: answers and SNI tie names to addresses; identity facts describe
	// devices.
	for _, ft := range in.Facts {
		switch ft.Rel {
		case model.RelResolvesTo, model.RelServes:
			dom, ip := ft.Src, ft.Dst
			if ft.Rel == model.RelServes {
				dom, ip = ft.Dst, ft.Src
			}
			if !b.hasNode(dom) {
				continue
			}
			if o.Collapse {
				// The address belongs on the domain node rather than as
				// a node of its own, unless it is already one.
				if !b.hasNode(ip) {
					b.addAddr(dom, ip)
					continue
				}
			} else if !b.hasNode(ip) && !o.DNS {
				continue
			}
			_, key, _ := model.SplitEntityID(ip)
			b.node(ip, model.KindIP, key, "")
			e := b.edge(dom, ip, model.RelResolvesTo)
			e.Count += ft.Count
			if v, err := strconv.ParseUint(ft.Attrs["ttl"], 10, 32); err == nil {
				e.TTL = max(e.TTL, uint32(v))
			}
			b.span(e, ft.FirstSeen, ft.LastSeen)
		case model.RelCNAME:
			if o.DNS && b.hasNode(ft.Src) {
				_, key, _ := model.SplitEntityID(ft.Dst)
				b.node(ft.Dst, model.KindDomain, key, "")
				e := b.edge(ft.Src, ft.Dst, model.RelCNAME)
				e.Count += ft.Count
				b.span(e, ft.FirstSeen, ft.LastSeen)
			}
		default:
			if !o.Identity || !b.hasNode(ft.Src) {
				continue
			}
			kind, _, _ := model.SplitEntityID(ft.Dst)
			switch ft.Rel {
			case model.RelHasIP, model.RelHostname, model.RelAnnounces, model.RelFingerprint, model.RelUserAgent, model.RelUPnP, model.RelNeighbor,
				model.RelBroadcasts, model.RelProbes, model.RelAssociates, model.RelHandshake:
			default:
				continue
			}
			b.node(ft.Dst, kind, ft.DstLabel, "")
			e := b.edge(ft.Src, ft.Dst, ft.Rel)
			e.Count += ft.Count
			if ft.Source != "" {
				if e.Attrs == nil {
					e.Attrs = map[string]string{}
				}
				e.Attrs["source"] = ft.Source
			}
			b.span(e, ft.FirstSeen, ft.LastSeen)
		}
	}
	if o.Identity {
		for id := range perDev {
			if d := devices[id]; d != nil && d.Vendor != "" {
				v := model.EntityID(model.KindVendor, d.Vendor)
				b.node(v, model.KindVendor, d.Vendor, "")
				b.edge(id, v, model.RelVendor).Count = 1
			}
		}
	}

	for _, k := range b.eord {
		e := b.edges[k]
		if e.Rel == model.RelConnects {
			e.Peak = Peak(spanSeq(b.spans[k]))
		}
		slices.Sort(e.Ports)
		g.Edges = append(g.Edges, *e)
	}
	for _, id := range b.order {
		n := b.nodes[id]
		if a := n.Attrs["addresses"]; a != "" {
			ips := strings.Split(a, ",")
			slices.SortFunc(ips, compareAddr)
			n.Attrs["addresses"] = strings.Join(ips, ",")
		}
		g.Nodes = append(g.Nodes, *n)
	}
	return g
}

func compareAddr(a, b string) int {
	x, e1 := netip.ParseAddr(a)
	y, e2 := netip.ParseAddr(b)
	if e1 != nil || e2 != nil {
		return cmp.Compare(a, b)
	}
	return x.Compare(y)
}

// destination is where a flow points in the graph.
func (b *builder) destination(fl model.Flow) string {
	if fl.Direction == "local" {
		// Device to device on the LAN: point at the other device when one
		// device holds that address.
		if d := b.owner(fl.RemoteIP); d != "" && d != fl.Device {
			return d
		}
		return model.EntityID(model.KindIP, fl.RemoteIP)
	}
	if b.o.Collapse && fl.Name != "" {
		return model.EntityID(model.KindDomain, fl.Name)
	}
	return model.EntityID(model.KindIP, fl.RemoteIP)
}

func (b *builder) hasNode(id string) bool { _, ok := b.nodes[id]; return ok }

func (b *builder) node(id, kind, label, sub string) *model.Node {
	if n, ok := b.nodes[id]; ok {
		return n
	}
	n := &model.Node{ID: id, Kind: kind, Label: label, Sub: sub}
	b.nodes[id] = n
	b.order = append(b.order, id)
	return n
}

func (b *builder) sourceNode(id string, devices map[string]*model.Device) {
	if b.hasNode(id) {
		return
	}
	if d := devices[id]; d != nil {
		sub := firstNonEmpty(d.VendorShort, d.Vendor)
		if d.Randomized {
			sub = "private MAC"
		}
		if len(d.IPs) > 0 {
			sub = strings.TrimSpace(sub + " · " + strings.Join(d.IPs[:min(len(d.IPs), 2)], ", "))
		}
		n := b.node(id, model.KindDevice, d.Label, strings.TrimPrefix(sub, " · "))
		n.Local = true
		n.Attrs = map[string]string{"mac": d.MAC}
		for k, v := range map[string]string{"vendor": d.Vendor, "role": d.Role, "hostnames": strings.Join(d.Hostnames, ","),
			"services": strings.Join(d.Services, ","), "ips": strings.Join(d.IPs, ",")} {
			if v != "" {
				n.Attrs[k] = v
			}
		}
		return
	}
	kind, key, _ := model.SplitEntityID(id)
	n := b.node(id, kind, key, "")
	n.Local = true
}

func (b *builder) addAddr(dom, ip string) {
	n := b.nodes[dom]
	_, key, _ := model.SplitEntityID(ip)
	if n.Attrs == nil {
		n.Attrs = map[string]string{}
	}
	cur := n.Attrs["addresses"]
	for _, a := range strings.Split(cur, ",") {
		if a == key {
			return
		}
	}
	if cur == "" {
		n.Attrs["addresses"] = key
	} else {
		n.Attrs["addresses"] = cur + "," + key
	}
}

func (b *builder) edge(from, to, rel string) *model.Edge {
	k := from + "\x00" + to + "\x00" + rel
	if e, ok := b.edges[k]; ok {
		return e
	}
	e := &model.Edge{From: from, To: to, Rel: rel}
	b.edges[k] = e
	b.eord = append(b.eord, k)
	return e
}

func (b *builder) span(e *model.Edge, first, last int64) {
	if e.FirstSeen == 0 || first < e.FirstSeen {
		e.FirstSeen = first
	}
	e.LastSeen = max(e.LastSeen, last)
}

func (b *builder) connect(src, dst string, fl model.Flow) {
	kind, key, _ := model.SplitEntityID(dst)
	var n *model.Node
	if kind == model.KindDevice {
		b.sourceNode(dst, b.devices)
		n = b.nodes[dst]
	} else {
		n = b.node(dst, kind, key, "")
	}
	n.BytesOut += fl.BytesOut
	n.BytesIn += fl.BytesIn
	if kind == model.KindDomain {
		b.addAddr(dst, model.EntityID(model.KindIP, fl.RemoteIP))
	}
	if kind == model.KindIP {
		if a, err := netip.ParseAddr(key); err == nil && (a.IsPrivate() || a.IsLinkLocalUnicast()) {
			n.Local = true
		}
	}
	e := b.edge(src, dst, model.RelConnects)
	e.Count++
	e.BytesOut += fl.BytesOut
	e.BytesIn += fl.BytesIn
	switch fl.State {
	case model.StateCarried:
		e.Carried++
	case model.StateOpened:
		e.Opened++
	}
	if fl.Closed {
		e.Closed++
	}
	port := fmt.Sprintf("%d/%s", fl.RemotePort, fl.Proto)
	if fl.RemotePort == 0 {
		port = fl.Proto
	}
	if !slices.Contains(e.Ports, port) {
		e.Ports = append(e.Ports, port)
	}
	if fl.App != "" {
		if e.Attrs == nil {
			e.Attrs = map[string]string{}
		}
		if !strings.Contains(","+e.Attrs["apps"]+",", ","+fl.App+",") {
			e.Attrs["apps"] = strings.Trim(e.Attrs["apps"]+","+fl.App, ",")
		}
	}
	lo, hi := max(fl.FirstSeen, b.in.FromMS), min(fl.LastSeen, b.in.ToMS)
	if b.in.ToMS == 0 {
		lo, hi = fl.FirstSeen, fl.LastSeen
	}
	k := src + "\x00" + dst + "\x00" + model.RelConnects
	b.spans[k] = append(b.spans[k], [2]int64{lo, hi})
	b.span(e, fl.FirstSeen, fl.LastSeen)
}

// answersKept reports whether one of a lookup's answers is an address the
// graph shows (so the lookup explains a connection).
func (b *builder) answersKept(q model.DNSQuery, kept map[string]bool) bool {
	for _, a := range q.Answers {
		if kept[model.EntityID(model.KindIP, a.Data)] {
			return true
		}
	}
	return false
}

func spanSeq(spans [][2]int64) iter.Seq2[int64, int64] {
	return func(yield func(a, b int64) bool) {
		for _, s := range spans {
			if !yield(s[0], s[1]) {
				return
			}
		}
	}
}

// Peak is the largest number of intervals [a, b] overlapping at one
// instant: the most connections open at once.
func Peak(spans iter.Seq2[int64, int64]) int {
	type ev struct {
		t int64
		d int
	}
	var evs []ev
	for a, b := range spans {
		if b < a {
			a, b = b, a
		}
		evs = append(evs, ev{a, 1}, ev{b, -1})
	}
	// Opens before closes at the same instant: touching intervals overlap.
	sort.Slice(evs, func(i, j int) bool {
		if evs[i].t != evs[j].t {
			return evs[i].t < evs[j].t
		}
		return evs[i].d > evs[j].d
	})
	cur, peak := 0, 0
	for _, e := range evs {
		cur += e.d
		peak = max(peak, cur)
	}
	return peak
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
