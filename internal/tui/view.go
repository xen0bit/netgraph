package tui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/model"
)

// bodyChrome is the rows the header, tab bar, sparkline and footer take.
const bodyChrome = 6

type styles struct {
	title, dim, tab, tabActive, head, sel, err, live, ok, key lipgloss.Style
	spark                                                     lipgloss.Style
}

func newStyles(r *lipgloss.Renderer, dark bool) styles {
	accent := lipgloss.AdaptiveColor{Light: "#1d4ed8", Dark: "#93c5fd"}
	dim := lipgloss.AdaptiveColor{Light: "#6b7280", Dark: "#9ca3af"}
	return styles{
		title:     r.NewStyle().Bold(true).Foreground(accent),
		dim:       r.NewStyle().Foreground(dim),
		tab:       r.NewStyle().Padding(0, 1).Foreground(dim),
		tabActive: r.NewStyle().Padding(0, 1).Bold(true).Foreground(accent).Underline(true),
		head:      r.NewStyle().Bold(true),
		sel:       r.NewStyle().Reverse(true),
		err:       r.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#b91c1c", Dark: "#fca5a5"}),
		live:      r.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#15803d", Dark: "#86efac"}),
		ok:        r.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#15803d", Dark: "#86efac"}),
		key:       r.NewStyle().Bold(true),
		spark:     r.NewStyle().Foreground(accent),
	}
}

// View renders the screen.
func (m Model) View() string {
	if m.width == 0 {
		return "loading…"
	}
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteByte('\n')
	b.WriteString(m.tabBar())
	b.WriteByte('\n')
	b.WriteString(m.sparkline())
	b.WriteByte('\n')
	body := m.body()
	lines := strings.Split(body, "\n")
	h := max(m.height-bodyChrome, 1)
	for i := 0; i < h; i++ {
		if i < len(lines) {
			b.WriteString(ansi.Truncate(lines[i], m.width, "…"))
		}
		b.WriteByte('\n')
	}
	b.WriteString(m.footer())
	return b.String()
}

func (m Model) header() string {
	from := m.to.Add(-m.span)
	layout := "2006-01-02 15:04:05"
	w := fmt.Sprintf("%s → %s (%s)", from.Local().Format(layout), m.to.Local().Format(layout), fmtSpan(m.span))
	parts := []string{m.st.title.Render("netgraph"), m.st.dim.Render(m.opts.Source), w}
	if m.live {
		parts = append(parts, m.st.live.Render("● live"))
	}
	if s := m.summary; s != nil {
		prec := ""
		if s.Precision == model.PrecisionHour {
			prec = m.st.dim.Render(" (hourly)")
		}
		parts = append(parts, fmt.Sprintf("%d devices · %d conns (peak %d) · %d lookups · ↑%s ↓%s%s",
			s.Devices, s.Flows, s.PeakConns, s.DNSQueries, model.FormatBytes(s.BytesOut), model.FormatBytes(s.BytesIn), prec))
	}
	return ansi.Truncate(strings.Join(parts, "  "), m.width, "…")
}

func fmtSpan(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.Round(time.Second).String()
}

func (m Model) tabBar() string {
	var parts []string
	for i, n := range tabNames {
		label := fmt.Sprintf("%d %s", i+1, n)
		if tab(i) == m.tab {
			parts = append(parts, m.st.tabActive.Render(label))
		} else {
			parts = append(parts, m.st.tab.Render(label))
		}
	}
	right := ""
	if m.filterText != "" {
		right = m.st.dim.Render("filter: ") + m.filterText
	}
	if m.tab == tabGraph {
		var o []string
		flag := func(name string, on bool) {
			if on {
				o = append(o, name)
			}
		}
		flag("collapse", m.gopts.Collapse)
		flag("dns", m.gopts.DNS)
		flag("sites", m.gopts.Sites)
		flag("identity", m.gopts.Identity)
		o = append(o, fmt.Sprintf("top %d", m.gopts.TopN))
		if m.outline {
			o = append(o, "outline")
		}
		right = strings.TrimSpace(right + "  " + m.st.dim.Render("["+strings.Join(o, " ")+"]"))
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, strings.Join(parts, ""), "  ", right)
}

var blocks = []rune(" ▁▂▃▄▅▆▇█")

// sparkline draws traffic across the window, one column per bucket.
func (m Model) sparkline() string {
	label := m.st.dim.Render("traffic ")
	if m.series == nil || len(m.series.Buckets) == 0 {
		return label
	}
	bs := m.series.Buckets
	width := max(m.width-24, 10)
	if len(bs) > width {
		bs = bs[len(bs)-width:]
	}
	var peak uint64
	for _, b := range bs {
		peak = max(peak, b.BytesIn+b.BytesOut)
	}
	var sb strings.Builder
	for _, b := range bs {
		v := b.BytesIn + b.BytesOut
		i := 0
		if peak > 0 && v > 0 {
			i = 1 + int(float64(v)/float64(peak)*float64(len(blocks)-2))
		}
		sb.WriteRune(blocks[min(i, len(blocks)-1)])
	}
	step := time.Duration(m.series.StepMS) * time.Millisecond
	return label + m.st.spark.Render(sb.String()) + m.st.dim.Render(fmt.Sprintf(" peak %s/%s", model.FormatBytes(peak), fmtSpan(step)))
}

func (m Model) footer() string {
	if m.editing {
		return m.input.View()
	}
	var left string
	switch {
	case m.status != "":
		left = m.status
	case m.err != nil:
		left = m.st.err.Render("error: " + m.err.Error())
	case m.loading > 0:
		left = m.st.dim.Render("loading…")
	}
	keys := "? help  tab views  [ ] shift  - + zoom  t preset  l live  / filter  enter detail  q quit"
	if m.detail != nil {
		keys = "↑↓ scroll  esc back"
	} else if m.tab == tabGraph {
		keys = "c collapse  d dns  w sites  i identity  < > top  o outline  s save  ←→↑↓ pan  ? help"
	}
	return ansi.Truncate(left+"  "+m.st.dim.Render(keys), m.width, "…")
}

func (m Model) tableHeight() int { return max(m.height-bodyChrome-1, 1) }

func (m Model) body() string {
	switch {
	case m.showHelp:
		return helpText
	case m.detail != nil:
		return m.dview.View()
	}
	switch m.tab {
	case tabSummary:
		return m.summaryView()
	case tabDevices:
		return m.table(devicesCols, len(m.devices), func(i int) []string { return deviceRow(m.devices[i]) })
	case tabFlows:
		return m.table(flowsCols, len(m.flows), func(i int) []string { return flowRow(m.flows[i]) })
	case tabDNS:
		return m.table(dnsCols, len(m.dns), func(i int) []string { return dnsRow(m.dns[i]) })
	case tabFacts:
		return m.table(factsCols, len(m.facts), func(i int) []string { return factRow(m.facts[i]) })
	case tabGraph:
		if m.graph == nil {
			return ""
		}
		if len(m.graph.Nodes) == 0 {
			return m.st.dim.Render("No activity in this window.")
		}
		if m.outline {
			return m.outlineView()
		}
		if m.gerr != nil {
			return m.st.err.Render("diagram: "+m.gerr.Error()) + "\n\n" + m.st.dim.Render("press o for the outline view")
		}
		if m.gtext == "" {
			return m.st.dim.Render("laying out…")
		}
		return m.gview.View()
	}
	return ""
}

type col struct {
	name  string
	width int // 0: flexible, takes the rest
}

var (
	devicesCols = []col{{"DEVICE", 24}, {"VENDOR", 14}, {"ADDRESSES", 26}, {"HOSTNAMES/SERVICES", 0}, {"CONNS", 6}, {"DNS", 5}, {"SENT", 8}, {"RECV", 8}}
	flowsCols   = []col{{"OPENED", 8}, {"DIR", 5}, {"CLIENT", 22}, {"SERVER", 26}, {"NAME", 0}, {"APP", 6}, {"STATE", 13}, {"SENT", 8}, {"RECV", 8}}
	dnsCols     = []col{{"TIME", 8}, {"DEVICE", 18}, {"TYPE", 5}, {"NAME", 36}, {"RCODE", 8}, {"ANSWERS", 0}}
	factsCols   = []col{{"REL", 11}, {"FROM", 22}, {"TO", 0}, {"FIRST", 8}, {"LAST", 8}, {"N", 4}, {"SOURCE", 6}}
)

func (m Model) table(cols []col, n int, row func(int) []string) string {
	fixed := 0
	for _, c := range cols {
		fixed += c.width + 1
	}
	flex := max(m.width-fixed, 10)
	widths := make([]int, len(cols))
	for i, c := range cols {
		widths[i] = c.width
		if c.width == 0 {
			widths[i] = flex
		}
	}
	line := func(cells []string) string {
		var b strings.Builder
		for i, c := range cells {
			if i >= len(widths) {
				break
			}
			b.WriteString(pad(c, widths[i]))
			b.WriteByte(' ')
		}
		return b.String()
	}
	var heads []string
	for _, c := range cols {
		heads = append(heads, c.name)
	}
	out := []string{m.st.head.Render(line(heads))}
	if n == 0 {
		out = append(out, m.st.dim.Render("(nothing in this window)"))
		return strings.Join(out, "\n")
	}
	h := m.tableHeight()
	off := m.offset[m.tab]
	for i := off; i < min(n, off+h); i++ {
		l := line(row(i))
		if i == m.cursor[m.tab] {
			l = m.st.sel.Render(pad(l, m.width))
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// pad truncates or pads s to exactly w cells.
func pad(s string, w int) string {
	if w <= 0 {
		return ""
	}
	s = ansi.Truncate(s, w, "…")
	if d := w - lipgloss.Width(s); d > 0 {
		s += strings.Repeat(" ", d)
	}
	return s
}

func hhmmss(msec int64) string {
	if msec == 0 {
		return ""
	}
	return time.UnixMilli(msec).Local().Format("15:04:05")
}

func deviceRow(d model.Device) []string {
	vendor := d.VendorShort
	if d.Randomized {
		vendor = "private MAC"
	}
	if d.Role != "" {
		vendor = d.Role
	}
	ids := append(append([]string{}, d.Hostnames...), d.Services...)
	if len(d.Serves) > 0 {
		ids = append(ids, "serves "+strings.Join(d.Serves, ","))
	}
	return []string{d.Label, vendor, strings.Join(d.IPs, ","), strings.Join(ids, ", "), strconv.Itoa(d.Flows), strconv.Itoa(d.DNSQueries), model.FormatBytes(d.BytesOut), model.FormatBytes(d.BytesIn)}
}

func flowRow(f model.Flow) []string {
	state := f.State
	if f.Closed {
		state += "/" + f.EndReason
	}
	client, server := f.Ends()
	return []string{hhmmss(f.FirstSeen), f.Direction, client, server, f.Name, f.App, state, model.FormatBytes(f.BytesOut), model.FormatBytes(f.BytesIn)}
}

func dnsRow(q model.DNSQuery) []string {
	var ans []string
	for _, a := range q.Answers {
		ans = append(ans, fmt.Sprintf("%s (%ds)", a.Data, a.TTL))
	}
	dev := q.DeviceName
	if dev == "" {
		dev = q.ClientIP
	}
	return []string{hhmmss(q.TS), dev, q.QType, q.QName, q.RCode, strings.Join(ans, " ")}
}

func factRow(f model.Fact) []string {
	return []string{f.Rel, f.SrcLabel, f.DstLabel, hhmmss(f.FirstSeen), hhmmss(f.LastSeen), strconv.Itoa(f.Count), f.Source}
}

func (m Model) summaryView() string {
	s := m.summary
	if s == nil {
		return ""
	}
	kv := [][2]string{
		{"devices", strconv.Itoa(s.Devices)},
		{"connections", fmt.Sprintf("%d, %d of them inbound (peak %d at once)", s.Flows, s.Inbound, s.PeakConns)},
		{"dns lookups", fmt.Sprintf("%d (%d names)", s.DNSQueries, s.Domains)},
		{"remote addresses", strconv.Itoa(s.RemoteIPs)},
		{"traffic", fmt.Sprintf("devices sent %s, received %s", model.FormatBytes(s.BytesOut), model.FormatBytes(s.BytesIn))},
		{"precision", s.Precision},
	}
	var b strings.Builder
	for _, p := range kv {
		fmt.Fprintf(&b, "  %-18s %s\n", m.st.dim.Render(p[0]), p[1])
	}
	b.WriteString("\n")
	b.WriteString(m.st.head.Render("  busiest devices"))
	b.WriteString("\n")
	ds := append([]model.Device(nil), m.devices...)
	sort.SliceStable(ds, func(i, j int) bool { return ds[i].BytesIn+ds[i].BytesOut > ds[j].BytesIn+ds[j].BytesOut })
	for i, d := range ds {
		if i >= 10 {
			break
		}
		fmt.Fprintf(&b, "  %-26s %-14s ↑%-8s ↓%-8s %3d conns %3d lookups\n", pad(d.Label, 26), pad(d.VendorShort, 14), model.FormatBytes(d.BytesOut), model.FormatBytes(d.BytesIn), d.Flows, d.DNSQueries)
	}
	return b.String()
}

// outlineRow is one line of the graph outline and the entity it names.
type outlineRow struct {
	text string
	id   string
}

// outline renders the graph as a tree: each device, then the clients that
// connected to it, what it talked to and looked up, and where those names
// pointed. It stays readable when the diagram is too large for the
// terminal.
func outline(g *model.Graph) []outlineRow {
	if g == nil {
		return nil
	}
	nodes := map[string]model.Node{}
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}
	out := map[string][]model.Edge{}
	clients := map[string][]model.Edge{} // device -> connects edges into it from outside
	hasIn := map[string]bool{}
	for _, e := range g.Edges {
		if e.Rel == model.RelConnects && nodes[e.To].Kind == model.KindDevice && nodes[e.From].Kind != model.KindDevice {
			// A client from outside: listed under the device it reached.
			clients[e.To] = append(clients[e.To], e)
			continue
		}
		out[e.From] = append(out[e.From], e)
		hasIn[e.To] = true
	}
	var rows []outlineRow
	label := func(id string) string {
		if n, ok := nodes[id]; ok {
			if n.Sub != "" {
				return n.Label + "  (" + n.Sub + ")"
			}
			return n.Label
		}
		return id
	}
	var walk func(id, prefix string, depth int, seen map[string]bool)
	walk = func(id, prefix string, depth int, seen map[string]bool) {
		in := clients[id]
		es := out[id]
		for i, e := range in {
			branch := "├─ "
			if i == len(in)-1 && len(es) == 0 {
				branch = "└─ "
			}
			rows = append(rows, outlineRow{text: fmt.Sprintf("%s%saccepts %s  %s", prefix, branch, label(e.From), graph.EdgeLabel(e)), id: e.From})
		}
		for i, e := range es {
			last := i == len(es)-1
			branch, next := "├─ ", "│  "
			if last {
				branch, next = "└─ ", "   "
			}
			txt := fmt.Sprintf("%s%s%s %s  %s", prefix, branch, e.Rel, label(e.To), graph.EdgeLabel(e))
			if n := nodes[e.To]; n.Attrs["addresses"] != "" {
				txt += "  → " + n.Attrs["addresses"]
			}
			rows = append(rows, outlineRow{text: txt, id: e.To})
			if depth < 2 && !seen[e.To] && e.Rel != model.RelConnects {
				seen[e.To] = true
				walk(e.To, prefix+next, depth+1, seen)
			}
		}
	}
	for _, n := range g.Nodes {
		if n.Kind != model.KindDevice && hasIn[n.ID] {
			continue
		}
		if len(out[n.ID]) == 0 && n.Kind != model.KindDevice {
			continue // nothing of its own, or a client listed under its device
		}
		rows = append(rows, outlineRow{text: label(n.ID), id: n.ID})
		walk(n.ID, "", 0, map[string]bool{n.ID: true})
	}
	return rows
}

func (m Model) outlineView() string {
	h := m.tableHeight() + 1
	off := m.offset[m.tab]
	var lines []string
	for i := off; i < min(len(m.outRows), off+h); i++ {
		l := m.outRows[i].text
		if !strings.HasPrefix(l, "├") && !strings.HasPrefix(l, "└") && !strings.HasPrefix(l, "│") && !strings.HasPrefix(l, " ") {
			l = m.st.head.Render(l)
		}
		if i == m.cursor[m.tab] {
			l = m.st.sel.Render(pad(ansi.Strip(l), m.width))
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n")
}

func (m Model) renderDetail(d *model.EntityDetail) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s\n", m.st.title.Render(d.Label), m.st.dim.Render(d.ID))
	fmt.Fprintf(&b, "first seen %s · last seen %s\n", time.UnixMilli(d.FirstSeen).Local().Format("2006-01-02 15:04:05"), time.UnixMilli(d.LastSeen).Local().Format("2006-01-02 15:04:05"))
	keys := make([]string, 0, len(d.Attrs))
	for k := range d.Attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "  %s %s\n", m.st.dim.Render(k+":"), d.Attrs[k])
	}
	section := func(name string) { fmt.Fprintf(&b, "\n%s\n", m.st.head.Render(name)) }
	if len(d.Facts) > 0 {
		section("Relationships in this window")
		for _, f := range d.Facts {
			other, dir := f.DstLabel, "→"
			if f.Dst == d.ID {
				other, dir = f.SrcLabel, "←"
			}
			fmt.Fprintf(&b, "  %s %s %s  %s–%s ×%d %s\n", f.Rel, dir, other, hhmmss(f.FirstSeen), hhmmss(f.LastSeen), f.Count, m.st.dim.Render(f.Source))
		}
	}
	if len(d.Flows) > 0 {
		section("Connections")
		for _, f := range d.Flows {
			r := flowRow(f)
			fmt.Fprintf(&b, "  %s  %s → %s %s  %s  sent %s recv %s\n", r[0], r[2], r[3], r[4], r[6], r[7], r[8])
		}
	}
	if len(d.DNS) > 0 {
		section("Lookups")
		for _, q := range d.DNS {
			r := dnsRow(q)
			fmt.Fprintf(&b, "  %s  %s  %s %s %s  %s\n", r[0], r[1], r[2], r[3], r[4], r[5])
		}
	}
	if len(d.Timeline) > 0 {
		section("Timeline")
		for _, e := range d.Timeline {
			fmt.Fprintf(&b, "  %s  %-10s %s\n", hhmmss(e.TS), e.Type, e.Detail)
		}
	}
	return b.String()
}

const helpText = `  netgraph — keys

  Window                              Views
    [ ]    shift back / forward ½       tab, 1-6   switch view
    { }    shift back / forward 1       enter      details of the selected row
    - +    zoom out / in                esc        back
    t      cycle 15m 1h 6h 24h 7d       ↑↓ pgup pgdn home end   move
    n      end the window now
    l      live: follow now (5s)      Graph
    r      refresh                      c  collapse addresses into names
                                        d  lookups and answers
                                        w  group names into sites
  Filter                                i  identity (hostnames, services, ...)
    /      edit: device:alice-*         < >  fewer / more destinations per device
           domain:*.example.com         o  outline / diagram
           ip:10.0.0.0/8 port:443       s  save SVG and d2 to the current directory
           proto:udp app:quic           ←→↑↓  pan the diagram
           (a bare word is a domain)
    x      clear                      q  quit

  Press any key.`
