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
	"maps"
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
	// Rest is, per source, what the store's own Top N left out of Flows:
	// the graph shows it as one "N more destinations" node. RestIn is the
	// same for the clients that connected in to a device.
	Rest, RestIn map[string]Rest
	// Truncated says the input itself was capped, not just Top N.
	Truncated bool
}

// Rest summarises destinations a graph does not draw one by one.
type Rest struct {
	Destinations int
	Connections  int
	BytesOut     uint64
	BytesIn      uint64
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
	names   map[string]map[string]bool // site node -> the names it stands for
	addrs   map[string]map[string]bool // name node -> the addresses in its "addresses"
}

// Build assembles a graph.
//
// Every connects edge points from the client to the server: the end that
// opened the connection to the end that accepted it. The shape, with DNS
// and Collapse on (the default):
//
//	device ──queried──▶ domain ──resolves_to──▶ address
//	device ──connects─────────▶ domain           (when the address was reached by that name)
//	device ──connects─────────▶ address          (when it was not)
//	address ──connects────────▶ device           (a connection from outside, to a server here)
//
// With Collapse off, connections always point at addresses and names hang
// off them through resolves_to/serves. With Sites, a name node stands for
// every name under one registrable domain. Identity adds what devices are:
// services, UPnP and LLDP descriptions, Wi-Fi networks, and the hostnames,
// addresses, fingerprints, user agents and vendors that two or more devices
// share (one device's own are on its node already).
//
// A graph stays readable by drawing each relationship once: a device that
// looked a name up and connected to it has one connects edge (with the
// lookup count), a CNAME chain is folded into the name it started from
// ("via" the CDN) unless its target is drawn anyway, and what Top N left
// out is one "N more destinations" (or "N more clients") node per device.
func Build(in Input, o model.GraphOptions) *model.Graph {
	if o.TopN == 0 {
		o.TopN = 15
	}
	b := &builder{in: in, o: o, nodes: map[string]*model.Node{}, edges: map[string]*model.Edge{}, spans: map[string][][2]int64{},
		names: map[string]map[string]bool{}, addrs: map[string]map[string]bool{}}
	g := &model.Graph{FromMS: in.FromMS, ToMS: in.ToMS, Precision: in.Precision, Truncated: in.Truncated}

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

	// Connections, grouped per device and peer, one side at a time: the
	// destinations it connected to, and the clients that connected to it.
	// Then keep each device's busiest TopN of each.
	type dest struct {
		key   string
		bytes uint64
		flows []model.Flow
	}
	perDev := [2]map[string]map[string]*dest{{}, {}} // [outbound, inbound]
	serves := map[string][2]map[string]bool{}        // device -> its ports, and the names asked of it
	served := func(dev, port, name string) {
		sv, ok := serves[dev]
		if !ok {
			sv = [2]map[string]bool{{}, {}}
			serves[dev] = sv
		}
		sv[0][port] = true
		if name != "" {
			sv[1][name] = true
		}
	}
	for _, fl := range in.Flows {
		src := fl.Device
		if src == "" {
			src = model.EntityID(model.KindIP, fl.LocalIP())
		}
		to := b.destination(fl)
		// What each device serves, whether Top N draws its clients or not.
		if fl.Inbound() {
			served(src, fl.Service(), fl.Name)
		} else if strings.HasPrefix(to, model.KindDevice+":") {
			served(to, fl.Service(), "")
		}
		side := perDev[sideOf(fl)]
		m := side[src]
		if m == nil {
			m = map[string]*dest{}
			side[src] = m
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
	rest := [2]map[string]Rest{maps.Clone(in.Rest), maps.Clone(in.RestIn)}
	for i := range rest {
		if rest[i] == nil {
			rest[i] = map[string]Rest{}
		}
	}
	// In key order: the order nodes are added is the order the layout
	// places them.
	for side, devs := range perDev {
		for _, src := range slices.Sorted(maps.Keys(devs)) {
			m := devs[src]
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
				r := rest[side][src]
				for _, d := range ds[o.TopN:] {
					r.Destinations++
					for _, fl := range d.flows {
						r.Connections += b.conns(fl)
						r.BytesOut += fl.BytesOut
						r.BytesIn += fl.BytesIn
					}
				}
				rest[side][src] = r
				ds = ds[:o.TopN]
			}
			b.sourceNode(src, devices)
			for _, d := range ds {
				if side == outbound {
					keptDest[d.key] = true
				}
				for _, fl := range d.flows {
					b.connect(src, d.key, fl)
				}
			}
		}
	}

	for side, rs := range rest {
		for _, src := range slices.Sorted(maps.Keys(rs)) {
			r := rs[src]
			if r.Destinations == 0 {
				continue
			}
			g.Truncated = true
			b.sourceNode(src, devices)
			b.nodes[src].BytesOut += r.BytesOut
			b.nodes[src].BytesIn += r.BytesIn
			if side == outbound {
				id := model.EntityID(model.KindOther, src)
				n := b.node(id, model.KindOther, fmt.Sprintf("%d more destinations", r.Destinations), "")
				n.BytesOut, n.BytesIn = r.BytesOut, r.BytesIn
				n.Attrs = map[string]string{"destinations": strconv.Itoa(r.Destinations), "device": src}
				e := b.edge(src, id, model.RelConnects)
				e.Count = r.Connections
				e.BytesOut, e.BytesIn = r.BytesOut, r.BytesIn
				continue
			}
			// Drawn like the clients themselves: an edge into the device,
			// its bytes counted along the edge (what the clients sent).
			id := model.EntityID(model.KindOther, ClientsPrefix+src)
			n := b.node(id, model.KindOther, fmt.Sprintf("%d more clients", r.Destinations), "")
			n.BytesOut, n.BytesIn = r.BytesIn, r.BytesOut
			n.Attrs = map[string]string{"clients": strconv.Itoa(r.Destinations), "device": src}
			e := b.edge(id, src, model.RelConnects)
			e.Count = r.Connections
			e.BytesOut, e.BytesIn = r.BytesIn, r.BytesOut
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
			dom := b.nameID(q.QName)
			if o.TopN > 0 && len(in.Flows) > 0 && !keptDest[dom] && !b.answersKept(q, keptDest) {
				continue // a lookup that led nowhere the graph shows
			}
			b.sourceNode(src, devices)
			b.nameNode(q.QName)
			e := b.edge(src, dom, model.RelQueried)
			e.Count += max(q.Count, 1)
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
	cnames := map[string][]string{} // name -> its CNAME targets
	var leaves []model.Fact         // identity facts drawn only if shared
	for _, ft := range in.Facts {
		switch ft.Rel {
		case model.RelResolvesTo, model.RelServes:
			dom, ip := ft.Src, ft.Dst
			if ft.Rel == model.RelServes {
				dom, ip = ft.Dst, ft.Src
			}
			_, name, _ := model.SplitEntityID(dom)
			if !b.drawn(name) {
				continue
			}
			dom = b.nameID(name)
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
			_, from, _ := model.SplitEntityID(ft.Src)
			_, to, _ := model.SplitEntityID(ft.Dst)
			if !slices.Contains(cnames[from], to) {
				cnames[from] = append(cnames[from], to)
			}
			src, dst := b.nameID(from), b.nameID(to)
			// Folded into the name node unless the target is drawn anyway
			// (with Collapse) or names are drawn as the chain they are.
			if !o.DNS || !b.drawn(from) || src == dst || (o.Collapse && !b.hasNode(dst)) {
				continue
			}
			b.nameNode(to)
			e := b.edge(src, dst, model.RelCNAME)
			e.Count += ft.Count
			b.span(e, ft.FirstSeen, ft.LastSeen)
		default:
			if !o.Identity || !b.hasNode(ft.Src) {
				continue
			}
			switch ft.Rel {
			case model.RelAnnounces, model.RelUPnP, model.RelNeighbor,
				model.RelBroadcasts, model.RelProbes, model.RelAssociates, model.RelHandshake:
				b.identity(ft)
			case model.RelHasIP, model.RelHostname, model.RelFingerprint, model.RelUserAgent:
				leaves = append(leaves, ft)
			}
		}
	}
	if o.Identity {
		for _, id := range slices.Sorted(maps.Keys(perDev[outbound])) {
			if d := devices[id]; d != nil && d.Vendor != "" {
				leaves = append(leaves, model.Fact{Src: id, Rel: model.RelVendor, Dst: model.EntityID(model.KindVendor, d.Vendor), DstLabel: d.Vendor, Count: 1})
			}
		}
		// A hostname, address, fingerprint, user agent or vendor of one
		// device is already on its node; drawn, it is a node per device
		// that says nothing. Shared, it ties devices together.
		holders := map[string]map[string]bool{}
		for _, ft := range leaves {
			if holders[ft.Dst] == nil {
				holders[ft.Dst] = map[string]bool{}
			}
			holders[ft.Dst][ft.Src] = true
		}
		for _, ft := range leaves {
			if len(holders[ft.Dst]) > 1 {
				b.identity(ft)
			}
		}
	}
	if o.Collapse {
		for _, id := range b.order {
			if n := b.nodes[id]; n.Kind == model.KindDomain || n.Kind == model.KindSite {
				b.via(n, cnames)
			}
		}
	}
	b.foldLookups()

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
		if sv, ok := serves[id]; ok && n.Kind == model.KindDevice {
			if n.Attrs == nil {
				n.Attrs = map[string]string{}
			}
			n.Attrs["serves"] = strings.Join(slices.SortedFunc(maps.Keys(sv[0]), comparePort), ",")
			if len(sv[1]) > 0 {
				n.Attrs["served_names"] = strings.Join(slices.Sorted(maps.Keys(sv[1])), ",")
			}
		}
		if names := b.names[id]; len(names) > 0 {
			list := slices.Sorted(maps.Keys(names))
			if n.Attrs == nil {
				n.Attrs = map[string]string{}
			}
			n.Attrs["names"] = strings.Join(list, ",")
			// A site of one name reads as that name.
			if len(list) > 1 {
				n.Sub = fmt.Sprintf("%d names", len(list))
			} else {
				n.Label = list[0]
			}
		}
		if a := n.Attrs["addresses"]; a != "" {
			ips := strings.Split(a, ",")
			slices.SortFunc(ips, compareAddr)
			n.Attrs["addresses"] = strings.Join(ips, ",")
			if n.Kind == model.KindASN {
				// "DE · 14 addresses"
				n.Sub = fmt.Sprintf("%d addresses", len(ips))
				if len(ips) == 1 {
					n.Sub = ips[0]
				}
				if cc := n.Attrs["country"]; cc != "" {
					n.Sub = cc + " · " + n.Sub
				}
			}
		}
		g.Nodes = append(g.Nodes, *n)
	}
	return g
}

// comparePort orders "443/tcp" services by port number, then protocol.
func comparePort(a, b string) int {
	pa, ta, _ := strings.Cut(a, "/")
	pb, tb, _ := strings.Cut(b, "/")
	x, _ := strconv.Atoi(pa)
	y, _ := strconv.Atoi(pb)
	return cmp.Or(cmp.Compare(x, y), cmp.Compare(ta, tb), cmp.Compare(a, b))
}

func compareAddr(a, b string) int {
	x, e1 := netip.ParseAddr(a)
	y, e2 := netip.ParseAddr(b)
	if e1 != nil || e2 != nil {
		return cmp.Compare(a, b)
	}
	return x.Compare(y)
}

// Sides of a device's connections, which Top N keeps apart.
const (
	outbound = iota // the device connected out
	inbound         // a client outside connected in to it
)

func sideOf(fl model.Flow) int {
	if fl.Inbound() {
		return inbound
	}
	return outbound
}

// ClientsPrefix starts the key of what stands for a device's inbound
// clients: its "N more clients" node ("other:clients:" + the device's ID)
// and the grid of them ("clients:" + the device's ID).
const ClientsPrefix = "clients:"

// destination is the far end of a flow in the graph: where it points, or
// for an inbound connection the client it came from.
func (b *builder) destination(fl model.Flow) string {
	if fl.Inbound() {
		return b.addrID(fl)
	}
	if fl.Direction == model.DirLocal {
		// Device to device on the LAN: point at the other device when one
		// device holds that address.
		if d := b.owner(fl.RemoteIP); d != "" && d != fl.Device {
			return d
		}
		return model.EntityID(model.KindIP, fl.RemoteIP)
	}
	if b.o.Collapse && fl.Name != "" {
		return b.nameID(fl.Name)
	}
	return b.addrID(fl)
}

// addrID is the node a connection's remote address is drawn as: its own,
// or with Networks its network's.
func (b *builder) addrID(fl model.Flow) string {
	if b.o.Networks && fl.ASN != 0 {
		return model.EntityID(model.KindASN, strconv.FormatUint(uint64(fl.ASN), 10))
	}
	return model.EntityID(model.KindIP, fl.RemoteIP)
}

// nameID is the node a DNS name is drawn as: its own, or with Sites its
// registrable domain's.
func (b *builder) nameID(name string) string {
	if b.o.Sites {
		return model.EntityID(model.KindSite, Site(name))
	}
	return model.EntityID(model.KindDomain, name)
}

// drawn reports whether the graph shows a name: its node, and with Sites
// that name among the site's.
func (b *builder) drawn(name string) bool {
	id := b.nameID(name)
	return b.hasNode(id) && (!b.o.Sites || b.names[id][name])
}

// nameNode adds the node for a name, and the name to its site.
func (b *builder) nameNode(name string) *model.Node {
	id := b.nameID(name)
	if !b.o.Sites {
		return b.node(id, model.KindDomain, name, "")
	}
	_, site, _ := model.SplitEntityID(id)
	n := b.node(id, model.KindSite, site, "")
	if b.names[id] == nil {
		b.names[id] = map[string]bool{}
	}
	b.names[id][name] = true
	return n
}

// identity draws one identity fact as a device -> descriptor edge.
func (b *builder) identity(ft model.Fact) {
	kind, _, _ := model.SplitEntityID(ft.Dst)
	b.node(ft.Dst, kind, ft.DstLabel, "")
	e := b.edge(ft.Src, ft.Dst, ft.Rel)
	e.Count += ft.Count
	if ft.Source != "" {
		if e.Attrs == nil {
			e.Attrs = map[string]string{}
		}
		e.Attrs["source"] = ft.Source
	}
	if ft.FirstSeen != 0 || ft.LastSeen != 0 {
		b.span(e, ft.FirstSeen, ft.LastSeen)
	}
}

// via notes on a name node the sites its names' CNAME chains lead to (the
// CDN that serves them), following each chain a few hops.
func (b *builder) via(n *model.Node, cnames map[string][]string) {
	names := []string{n.Label}
	if n.Kind == model.KindSite {
		names = slices.Sorted(maps.Keys(b.names[n.ID]))
	}
	own := Site(n.Label)
	var sites []string
	seen := map[string]bool{}
	for _, name := range names {
		next := []string{name}
		for hop := 0; hop < 8 && len(next) > 0; hop++ {
			var more []string
			for _, cur := range next {
				for _, t := range cnames[cur] {
					if seen[t] {
						continue
					}
					seen[t] = true
					more = append(more, t)
					if st := Site(t); st != own && !slices.Contains(sites, st) {
						sites = append(sites, st)
					}
				}
			}
			next = more
		}
	}
	if len(sites) == 0 {
		return
	}
	slices.Sort(sites)
	if n.Attrs == nil {
		n.Attrs = map[string]string{}
	}
	n.Attrs["via"] = strings.Join(sites, ",")
}

// foldLookups merges each device's lookups of a name into its connects
// edge to that name: one edge per relationship, with the lookups counted on
// it. Lookups that led to no connection keep their own edge.
func (b *builder) foldLookups() {
	keep := b.eord[:0]
	for _, k := range b.eord {
		e := b.edges[k]
		if e.Rel == model.RelQueried {
			if c, ok := b.edges[e.From+"\x00"+e.To+"\x00"+model.RelConnects]; ok {
				if c.Attrs == nil {
					c.Attrs = map[string]string{}
				}
				c.Attrs["lookups"] = strconv.Itoa(e.Count)
				if rc := e.Attrs["rcode"]; rc != "" {
					c.Attrs["rcode"] = rc
				}
				delete(b.edges, k)
				continue
			}
		}
		keep = append(keep, k)
	}
	b.eord = keep
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
	// A site can collect thousands of addresses: look them up in a set
	// rather than in the list.
	seen := b.addrs[dom]
	if seen == nil {
		seen = map[string]bool{}
		b.addrs[dom] = seen
	}
	if seen[key] {
		return
	}
	seen[key] = true
	cur := n.Attrs["addresses"]
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

// connect draws one connection between a device (src) and its peer (dst):
// an edge from the client to the server, whose bytes are counted along it
// (BytesOut is what the client sent).
func (b *builder) connect(src, dst string, fl model.Flow) {
	kind, key, _ := model.SplitEntityID(dst)
	var n *model.Node
	if kind == model.KindDevice {
		b.sourceNode(dst, b.devices)
		n = b.nodes[dst]
	} else {
		n = b.node(dst, kind, key, "")
	}
	from, to := src, dst
	sent, got := fl.BytesOut, fl.BytesIn // by the client
	if fl.Inbound() {
		from, to = dst, src
		sent, got = fl.BytesIn, fl.BytesOut
	}
	// A device node totals what it sent and received; any other node, the
	// traffic along its edges.
	b.nodes[src].BytesOut += fl.BytesOut
	b.nodes[src].BytesIn += fl.BytesIn
	if kind == model.KindDevice {
		n.BytesOut += fl.BytesIn
		n.BytesIn += fl.BytesOut
	} else {
		n.BytesOut += sent
		n.BytesIn += got
	}
	switch kind {
	case model.KindSite:
		b.nameNode(fl.Name)
		b.addAddr(dst, model.EntityID(model.KindIP, fl.RemoteIP))
	case model.KindDomain:
		b.addAddr(dst, model.EntityID(model.KindIP, fl.RemoteIP))
	case model.KindASN:
		b.addAddr(dst, model.EntityID(model.KindIP, fl.RemoteIP))
		n.Label = network(fl.ASN, fl.ASOrg)
		setAttr(n, "country", fl.Country)
	}
	if kind == model.KindIP {
		if a, err := netip.ParseAddr(key); err == nil && (a.IsPrivate() || a.IsLinkLocalUnicast()) {
			n.Local = true
		}
		// The address's network, when it is not drawn as one.
		if fl.ASN != 0 && key == fl.RemoteIP {
			setAttr(n, "asn", strconv.FormatUint(uint64(fl.ASN), 10))
			setAttr(n, "as_org", fl.ASOrg)
			setAttr(n, "country", fl.Country)
			n.Sub = strings.TrimSuffix(network(fl.ASN, "")+" · "+fl.Country, " · ")
		}
	}
	e := b.edge(from, to, model.RelConnects)
	e.Count += b.conns(fl)
	e.BytesOut += sent
	e.BytesIn += got
	switch fl.State {
	case model.StateCarried:
		e.Carried++
	case model.StateOpened:
		e.Opened++
	}
	if fl.Closed {
		e.Closed++
	}
	if port := fl.Service(); !slices.Contains(e.Ports, port) {
		e.Ports = append(e.Ports, port)
	}
	if fl.App != "" {
		addList(e, "apps", fl.App)
	}
	if fl.Inbound() && fl.Name != "" {
		addList(e, "names", fl.Name)
	}
	lo, hi := max(fl.FirstSeen, b.in.FromMS), min(fl.LastSeen, b.in.ToMS)
	if b.in.ToMS == 0 {
		lo, hi = fl.FirstSeen, fl.LastSeen
	}
	k := from + "\x00" + to + "\x00" + model.RelConnects
	b.spans[k] = append(b.spans[k], [2]int64{lo, hi})
	b.span(e, fl.FirstSeen, fl.LastSeen)
}

// conns is how many connections a flow stands for: one, or for a row of
// hourly rollups the count it carries in PktsOut.
func (b *builder) conns(fl model.Flow) int {
	if fl.Connections > 0 {
		return fl.Connections
	}
	return 1
}

// addList adds v to the comma-separated list in an edge's attribute k,
// once.
func addList(e *model.Edge, k, v string) {
	if e.Attrs == nil {
		e.Attrs = map[string]string{}
	}
	cur := e.Attrs[k]
	if strings.Contains(","+cur+",", ","+v+",") {
		return
	}
	e.Attrs[k] = strings.TrimPrefix(cur+","+v, ",")
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

// network names an autonomous system: "AS13335 CLOUDFLARENET", or
// "AS13335" when its organisation is unknown.
func network(asn uint32, org string) string {
	s := "AS" + strconv.FormatUint(uint64(asn), 10)
	if org != "" {
		s += " " + org
	}
	return s
}

func setAttr(n *model.Node, k, v string) {
	if v == "" {
		return
	}
	if n.Attrs == nil {
		n.Attrs = map[string]string{}
	}
	n.Attrs[k] = v
}
