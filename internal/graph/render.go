package graph

import (
	"cmp"
	"fmt"
	"maps"
	"math"
	"slices"
	"sort"
	"strings"

	"github.com/xen0bit/netgraph/internal/model"
)

// RenderOptions shape a d2 script.
type RenderOptions struct {
	Direction string // right (default), down, left, up
	Theme     string // "dark" or "light"; colours the classes
	// ASCII drops styling the text renderer cannot draw and keeps labels
	// short enough for a terminal.
	ASCII bool
}

// palette per entity kind: fill, stroke (light theme); the dark theme uses
// the stroke as the fill's accent.
var palette = map[string][2]string{
	model.KindDevice:      {"#dbeafe", "#1d4ed8"},
	model.KindDomain:      {"#dcfce7", "#15803d"},
	model.KindIP:          {"#f3f4f6", "#4b5563"},
	model.KindHostname:    {"#fef3c7", "#b45309"},
	model.KindService:     {"#fae8ff", "#a21caf"},
	model.KindVendor:      {"#ffedd5", "#c2410c"},
	model.KindFingerprint: {"#e0e7ff", "#4338ca"},
	model.KindUserAgent:   {"#e0e7ff", "#4338ca"},
	model.KindUPnP:        {"#fae8ff", "#a21caf"},
	model.KindLLDP:        {"#fef3c7", "#b45309"},
	model.KindSSID:        {"#e0f2fe", "#0369a1"},
	model.KindSite:        {"#dcfce7", "#15803d"},
	model.KindASN:         {"#ecfeff", "#0e7490"},
	model.KindOther:       {"#f9fafb", "#9ca3af"},
}

var darkPalette = map[string][2]string{
	model.KindDevice:      {"#1e3a8a", "#93c5fd"},
	model.KindDomain:      {"#14532d", "#86efac"},
	model.KindIP:          {"#374151", "#d1d5db"},
	model.KindHostname:    {"#78350f", "#fcd34d"},
	model.KindService:     {"#701a75", "#f0abfc"},
	model.KindVendor:      {"#7c2d12", "#fdba74"},
	model.KindFingerprint: {"#312e81", "#a5b4fc"},
	model.KindUserAgent:   {"#312e81", "#a5b4fc"},
	model.KindUPnP:        {"#701a75", "#f0abfc"},
	model.KindLLDP:        {"#78350f", "#fcd34d"},
	model.KindSSID:        {"#075985", "#7dd3fc"},
	model.KindSite:        {"#14532d", "#86efac"},
	model.KindASN:         {"#164e63", "#67e8f9"},
	model.KindOther:       {"#1f2937", "#9ca3af"},
}

// RenderD2 writes a graph as a d2 script. Every key is quoted: an
// unquoted "example.com" or address would be read as nested containers.
func RenderD2(g *model.Graph, o RenderOptions) string {
	var b strings.Builder
	dir := o.Direction
	if dir == "" {
		dir = "right"
	}
	fmt.Fprintf(&b, "direction: %s\n", dir)
	if !o.ASCII {
		pal := palette
		if o.Theme == "dark" {
			pal = darkPalette
		}
		kinds := make([]string, 0, len(pal))
		for k := range pal {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		b.WriteString("classes: {\n")
		for _, k := range kinds {
			c := pal[k]
			shape, extra := "rectangle", ""
			switch k {
			case model.KindDomain, model.KindSite, model.KindSSID:
				shape = "oval"
			case model.KindService, model.KindUPnP:
				shape = "hexagon"
			case model.KindOther:
				extra = "; stroke-dash: 4"
			}
			fmt.Fprintf(&b, "  %s: {shape: %s; style: {fill: %q; stroke: %q; border-radius: 6; font-size: 14%s}}\n", k, shape, c[0], c[1], extra)
		}
		b.WriteString("  connects: {style: {stroke: \"#2563eb\"}}\n")
		b.WriteString("  queried: {style: {stroke: \"#16a34a\"; stroke-dash: 3}}\n")
		b.WriteString("  resolves_to: {style: {stroke: \"#6b7280\"; stroke-dash: 5}}\n")
		b.WriteString("  identity: {style: {stroke: \"#d97706\"; stroke-dash: 2}}\n")
		group := [2]string{"#f8fafc", "#94a3b8"}
		if o.Theme == "dark" {
			group = [2]string{"#111827", "#4b5563"}
		}
		fmt.Fprintf(&b, "  group: {style: {fill: %q; stroke: %q; border-radius: 8; font-size: 16}}\n", group[0], group[1])
		b.WriteString("}\n")
	}
	// A device's many private destinations (or clients) are drawn as a
	// grid rather than a fan: the text renderer cannot draw grids.
	var groups []leafGroup
	inGroup := map[string]bool{}
	grouped := map[int]bool{}
	if !o.ASCII {
		groups = leafGroups(g)
		for _, lg := range groups {
			for _, i := range lg.edges {
				grouped[i] = true
				inGroup[lg.leaf(g.Edges[i])] = true
			}
		}
	}
	nodes := map[string]model.Node{}
	for _, n := range g.Nodes {
		nodes[n.ID] = n
		if inGroup[n.ID] {
			continue
		}
		label := nodeLabel(n, o.ASCII)
		if o.ASCII {
			fmt.Fprintf(&b, "%s: %s\n", quote(n.ID), quote(label))
			continue
		}
		fmt.Fprintf(&b, "%s: {label: %s; class: %s%s}\n", quote(n.ID), quote(label), nodeClass(n), anomalyStyle(n.Attrs, true))
	}
	for _, lg := range groups {
		writeGroup(&b, g, nodes, lg)
	}
	for i, e := range g.Edges {
		if grouped[i] {
			continue
		}
		label := EdgeLabel(e)
		if o.ASCII {
			label = ShortEdgeLabel(e)
			fmt.Fprintf(&b, "%s -> %s: %s\n", quote(e.From), quote(e.To), quote(label))
			continue
		}
		cls := e.Rel
		switch e.Rel {
		case model.RelConnects, model.RelQueried, model.RelResolvesTo:
		case model.RelCNAME:
			cls = model.RelResolvesTo
		default:
			cls = "identity"
		}
		fmt.Fprintf(&b, "%s -> %s: %s {class: %s%s}\n", quote(e.From), quote(e.To), quote(label), cls, anomalyStyle(e.Attrs, false))
	}
	return b.String()
}

// anomalyStyle is the d2 style of a node or edge an anomaly marked (see
// MarkAnomalies): a red (high) or orange (medium) outline, and the reasons
// as a node's tooltip.
func anomalyStyle(attrs map[string]string, tooltip bool) string {
	color := map[string]string{model.SeverityHigh: "#dc2626", model.SeverityMedium: "#ea580c"}[attrs["anomaly"]]
	if color == "" {
		return ""
	}
	s := fmt.Sprintf("; style: {stroke: %q; stroke-width: 3}", color)
	if tooltip {
		s += "; tooltip: " + quote(attrs["anomalies"])
	}
	return s
}

func nodeClass(n model.Node) string {
	if _, ok := palette[n.Kind]; ok {
		return n.Kind
	}
	return model.KindIP
}

// GroupMin is how many private destinations (or clients) a device needs
// before they are drawn as a grid.
const GroupMin = 8

// GroupPrefix starts the key of the grid holding a device's private
// destinations: "dests:" + the device's ID. Its inbound clients' grid is
// ClientsPrefix + the device's ID.
const GroupPrefix = "dests:"

// leafGroup is one device's private destinations, or its private clients:
// the connects edges between it and nodes nothing else touches.
type leafGroup struct {
	src     string // the device
	clients bool   // the edges point into the device: its clients
	edges   []int  // into g.Edges, busiest first
}

// leaf is the end of one of the group's edges that is not its device.
func (lg leafGroup) leaf(e model.Edge) string {
	if lg.clients {
		return e.From
	}
	return e.To
}

func leafGroups(g *model.Graph) []leafGroup {
	degree := map[string]int{}
	for _, e := range g.Edges {
		degree[e.From]++
		degree[e.To]++
	}
	kinds := map[string]string{}
	for _, n := range g.Nodes {
		kinds[n.ID] = n.Kind
	}
	leaf := func(id string) bool {
		return degree[id] == 1 && kinds[id] != model.KindOther && kinds[id] != model.KindDevice
	}
	by := [2]map[string][]int{{}, {}} // destinations, clients
	for i, e := range g.Edges {
		switch {
		case e.Rel != model.RelConnects:
		case leaf(e.To):
			by[0][e.From] = append(by[0][e.From], i)
		case leaf(e.From) && kinds[e.To] == model.KindDevice:
			by[1][e.To] = append(by[1][e.To], i)
		}
	}
	var out []leafGroup
	for side, m := range by {
		for _, src := range slices.Sorted(maps.Keys(m)) {
			idx := m[src]
			if len(idx) < GroupMin {
				continue
			}
			slices.SortStableFunc(idx, func(a, b int) int {
				ea, eb := g.Edges[a], g.Edges[b]
				return cmp.Compare(eb.BytesOut+eb.BytesIn, ea.BytesOut+ea.BytesIn)
			})
			out = append(out, leafGroup{src: src, clients: side == 1, edges: idx})
		}
	}
	return out
}

// writeGroup draws a leaf group as a grid container with one edge between
// it and its device carrying the totals. Each member keeps its ports and
// connection count on its own label.
func writeGroup(b *strings.Builder, g *model.Graph, nodes map[string]model.Node, lg leafGroup) {
	var out, in uint64
	var conns int
	for _, i := range lg.edges {
		e := g.Edges[i]
		out += e.BytesOut
		in += e.BytesIn
		conns += e.Count
	}
	key, what := GroupPrefix+lg.src, "destinations"
	if lg.clients {
		key, what = ClientsPrefix+lg.src, "clients"
	}
	n := len(lg.edges)
	cols := int(math.Ceil(math.Sqrt(float64(n) * 1.5)))
	fmt.Fprintf(b, "%s: {label: %s; class: group; grid-columns: %d; grid-gap: 12\n", quote(key),
		quote(fmt.Sprintf("%s · %d %s", nodes[lg.src].Label, n, what)), cols)
	for _, i := range lg.edges {
		e := g.Edges[i]
		id := lg.leaf(e)
		leaf := nodes[id]
		label := nodeLabel(leaf, false)
		if s := leafSummary(e); s != "" {
			label += "\n" + s
		}
		fmt.Fprintf(b, "  %s: {label: %s; class: %s%s}\n", quote(id), quote(label), nodeClass(leaf), anomalyStyle(leaf.Attrs, true))
	}
	b.WriteString("}\n")
	from, to := lg.src, key
	if lg.clients {
		from, to = key, lg.src
	}
	fmt.Fprintf(b, "%s -> %s: %s {class: connects}\n", quote(from), quote(to),
		quote(fmt.Sprintf("%d %s up %s down %s x%d", n, what, model.FormatBytes(out), model.FormatBytes(in), conns)))
}

// leafSummary is a grouped connects edge's ports and count, for its
// destination's label.
func leafSummary(e model.Edge) string {
	s := strings.Join(e.Ports[:min(len(e.Ports), 2)], ",")
	if len(e.Ports) > 2 {
		s += ",…"
	}
	if e.Count > 1 {
		s += fmt.Sprintf(" x%d", e.Count)
	}
	return strings.TrimSpace(s)
}

func nodeLabel(n model.Node, ascii bool) string {
	if ascii && n.Attrs["anomaly"] != "" {
		n.Label += " [!]"
	}
	if ascii {
		// The text renderer cannot draw multi-line labels; keep one line.
		if n.Kind == model.KindDevice && n.Sub != "" {
			return n.Label + " (" + strings.ReplaceAll(n.Sub, " · ", ", ") + ")"
		}
		if n.Kind == model.KindASN && n.Sub != "" {
			return n.Label + " (" + strings.ReplaceAll(n.Sub, " · ", ", ") + ")"
		}
		if names := strings.Split(n.Attrs["names"], ","); n.Kind == model.KindSite && len(names) > 1 {
			s := strings.Join(names[:min(len(names), 2)], ", ")
			if len(names) > 2 {
				s += fmt.Sprintf(" +%d", len(names)-2)
			}
			return n.Label + " (" + s + ")"
		}
		return n.Label
	}
	lines := []string{n.Label}
	if n.Sub != "" {
		lines = append(lines, n.Sub)
	}
	if v := n.Attrs["serves"]; v != "" && n.Kind == model.KindDevice {
		ports := strings.Split(v, ",")
		s := "serves " + strings.Join(ports[:min(len(ports), 3)], ", ")
		if len(ports) > 3 {
			s += fmt.Sprintf(" +%d", len(ports)-3)
		}
		lines = append(lines, s)
	}
	if addrs := n.Attrs["addresses"]; addrs != "" && n.Kind == model.KindDomain {
		ips := strings.Split(addrs, ",")
		s := strings.Join(ips[:min(len(ips), 2)], ", ")
		if len(ips) > 2 {
			s += fmt.Sprintf(" +%d", len(ips)-2)
		}
		lines = append(lines, s)
	}
	if v := n.Attrs["via"]; v != "" {
		sites := strings.Split(v, ",")
		s := "via " + strings.Join(sites[:min(len(sites), 2)], ", ")
		if len(sites) > 2 {
			s += fmt.Sprintf(" +%d", len(sites)-2)
		}
		lines = append(lines, s)
	}
	if n.BytesOut+n.BytesIn > 0 && !ascii {
		lines = append(lines, model.FormatBytes(n.BytesOut+n.BytesIn))
	}
	return strings.Join(lines, "\n")
}

// EdgeLabel summarises an edge in one line.
func EdgeLabel(e model.Edge) string {
	switch e.Rel {
	case model.RelConnects:
		parts := []string{strings.Join(e.Ports[:min(len(e.Ports), 3)], ",")}
		if len(e.Ports) > 3 {
			parts[0] += ",…"
		}
		parts = append(parts, "up "+model.FormatBytes(e.BytesOut), "down "+model.FormatBytes(e.BytesIn))
		conns := fmt.Sprintf("x%d", e.Count)
		var st []string
		if e.Carried > 0 {
			st = append(st, fmt.Sprintf("%d carried", e.Carried))
		}
		if e.Closed > 0 {
			st = append(st, fmt.Sprintf("%d closed", e.Closed))
		}
		if e.Peak > 1 {
			st = append(st, fmt.Sprintf("peak %d", e.Peak))
		}
		if len(st) > 0 {
			conns += " (" + strings.Join(st, ", ") + ")"
		}
		parts = append(parts, conns)
		if l := e.Attrs["lookups"]; l != "" {
			parts = append(parts, "dns x"+l)
		}
		if v := e.Attrs["names"]; v != "" {
			// What an inbound connection's client asked the server for.
			names := strings.Split(v, ",")
			s := "for " + names[0]
			if len(names) > 1 {
				s += fmt.Sprintf(" +%d", len(names)-1)
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, " ")
	case model.RelQueried:
		s := fmt.Sprintf("dns x%d", e.Count)
		if rc := e.Attrs["rcode"]; rc != "" {
			s += " " + rc
		}
		return s
	case model.RelResolvesTo:
		if e.TTL > 0 {
			return fmt.Sprintf("ttl %ds", e.TTL)
		}
		return "resolves"
	}
	return strings.ReplaceAll(e.Rel, "_", " ")
}

// quote renders a d2 double-quoted string.
func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", "", "\t", " ")
	return `"` + r.Replace(s) + `"`
}

// ShortEdgeLabel is EdgeLabel for narrow output: ports, total bytes and the
// connection count.
func ShortEdgeLabel(e model.Edge) string {
	if e.Rel != model.RelConnects {
		return EdgeLabel(e)
	}
	port := ""
	if len(e.Ports) > 0 {
		port = e.Ports[0]
		if len(e.Ports) > 1 {
			port += "+"
		}
	}
	// Whole units only: the text renderer can draw edges over a '.'.
	s := fmt.Sprintf("%s %s", port, model.FormatBytesWhole(e.BytesOut+e.BytesIn))
	if e.Count > 1 {
		s += fmt.Sprintf(" x%d", e.Count)
	}
	if e.Carried > 0 {
		s += " (carried)"
	}
	return s
}
