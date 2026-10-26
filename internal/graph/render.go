package graph

import (
	"fmt"
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
			shape := "rectangle"
			switch k {
			case model.KindDomain, model.KindSSID:
				shape = "oval"
			case model.KindService, model.KindUPnP:
				shape = "hexagon"
			}
			fmt.Fprintf(&b, "  %s: {shape: %s; style: {fill: %q; stroke: %q; border-radius: 6; font-size: 14}}\n", k, shape, c[0], c[1])
		}
		b.WriteString("  connects: {style: {stroke: \"#2563eb\"}}\n")
		b.WriteString("  queried: {style: {stroke: \"#16a34a\"; stroke-dash: 3}}\n")
		b.WriteString("  resolves_to: {style: {stroke: \"#6b7280\"; stroke-dash: 5}}\n")
		b.WriteString("  identity: {style: {stroke: \"#d97706\"; stroke-dash: 2}}\n")
		b.WriteString("}\n")
	}
	for _, n := range g.Nodes {
		label := nodeLabel(n, o.ASCII)
		if o.ASCII {
			fmt.Fprintf(&b, "%s: %s\n", quote(n.ID), quote(label))
			continue
		}
		cls := n.Kind
		if _, ok := palette[cls]; !ok {
			cls = model.KindIP
		}
		fmt.Fprintf(&b, "%s: {label: %s; class: %s}\n", quote(n.ID), quote(label), cls)
	}
	for _, e := range g.Edges {
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
		fmt.Fprintf(&b, "%s -> %s: %s {class: %s}\n", quote(e.From), quote(e.To), quote(label), cls)
	}
	return b.String()
}

func nodeLabel(n model.Node, ascii bool) string {
	if ascii {
		// The text renderer cannot draw multi-line labels; keep one line.
		if n.Kind == model.KindDevice && n.Sub != "" {
			return n.Label + " (" + strings.ReplaceAll(n.Sub, " · ", ", ") + ")"
		}
		return n.Label
	}
	lines := []string{n.Label}
	if n.Sub != "" {
		lines = append(lines, n.Sub)
	}
	if addrs := n.Attrs["addresses"]; addrs != "" && n.Kind == model.KindDomain {
		ips := strings.Split(addrs, ",")
		s := strings.Join(ips[:min(len(ips), 2)], ", ")
		if len(ips) > 2 {
			s += fmt.Sprintf(" +%d", len(ips)-2)
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
		return strings.Join(append(parts, conns), " ")
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
