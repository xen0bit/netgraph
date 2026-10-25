package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/graph/d2render"
	"github.com/xen0bit/netgraph/internal/model"
)

type tab int

const (
	tabSummary tab = iota
	tabDevices
	tabFlows
	tabDNS
	tabFacts
	tabGraph
	numTabs
)

var tabNames = [numTabs]string{"Summary", "Devices", "Flows", "DNS", "Facts", "Graph"}

// presets are the window lengths 't' cycles through.
var presets = []time.Duration{15 * time.Minute, time.Hour, 6 * time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}

// liveEvery is how often live mode refreshes.
var liveEvery = 5 * time.Second

// Model is the TUI state.
type Model struct {
	opts Options
	st   styles
	be   model.Backend
	now  func() time.Time

	width, height int
	tab           tab

	to   time.Time
	span time.Duration
	live bool

	filter     model.Filter // narrowing only; the window lives in to/span
	filterText string
	input      textinput.Model
	editing    bool

	gopts   model.GraphOptions
	outline bool

	summary *model.Summary
	series  *model.Timeseries
	devices []model.Device
	flows   []model.Flow
	dns     []model.DNSQuery
	facts   []model.Fact
	graph   *model.Graph
	gtext   string
	gerr    error
	gview   viewport.Model
	outRows []outlineRow

	seq     int // drops results of superseded requests
	loading int
	err     error
	status  string

	cursor [numTabs]int
	offset [numTabs]int

	detail   *model.EntityDetail
	dview    viewport.Model
	showHelp bool
}

// New returns the initial model.
func New(opts Options, st styles) Model {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	span := opts.Span
	if span <= 0 {
		span = time.Hour
	}
	to := opts.Filter.To
	if to.IsZero() {
		to = now()
	}
	if !opts.Filter.From.IsZero() {
		span = to.Sub(opts.Filter.From)
	}
	in := textinput.New()
	in.Prompt = "filter: "
	in.Placeholder = "device:alice domain:*.example.com ip:10.0.0.0/8 port:443 proto:udp app:quic"
	in.CharLimit = 256
	f := opts.Filter
	f.From, f.To = time.Time{}, time.Time{}
	m := Model{
		opts: opts, st: st, be: opts.Backend, now: now,
		to: to, span: span, live: opts.Live,
		filter: f, filterText: filterString(f), input: in,
		gopts: model.DefaultGraphOptions,
		gview: viewport.New(80, 20), dview: viewport.New(80, 20),
	}
	m.gview.SetHorizontalStep(8)
	return m
}

// window is the current filter with the window applied.
func (m Model) window() model.Filter {
	f := m.filter
	f.From, f.To = m.to.Add(-m.span), m.to
	return f
}

// Init loads the first window. The load starts from Update: Init cannot
// change the model, and fetch records the request it starts.
func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{func() tea.Msg { return refreshMsg{} }}
	if m.live {
		cmds = append(cmds, liveTick())
	}
	return tea.Batch(cmds...)
}

type refreshMsg struct{}

type liveMsg struct{}

func liveTick() tea.Cmd { return tea.Tick(liveEvery, func(time.Time) tea.Msg { return liveMsg{} }) }

// dataMsg carries one query's result for request seq.
type dataMsg struct {
	seq  int
	kind tab
	what string // "summary", "series", or "" for the tab's rows
	v    any
	err  error
}

type graphTextMsg struct {
	seq  int
	text string
	err  error
}

type entityMsg struct {
	d   *model.EntityDetail
	err error
}

type savedMsg struct {
	paths []string
	err   error
}

// fetch reloads the header data and the current tab.
func (m *Model) fetch() tea.Cmd {
	m.seq++
	seq := m.seq
	f := m.window()
	be := m.be
	// One bucket per sparkline column.
	step := max(m.span/time.Duration(max(m.width-24, 20)), time.Second)
	cmds := []tea.Cmd{
		func() tea.Msg {
			s, err := be.Summary(context.Background(), f)
			return dataMsg{seq: seq, what: "summary", v: s, err: err}
		},
		func() tea.Msg {
			s, err := be.Timeseries(context.Background(), f, step)
			return dataMsg{seq: seq, what: "series", v: s, err: err}
		},
	}
	if c := m.fetchTab(seq, f); c != nil {
		cmds = append(cmds, c)
	}
	m.loading = len(cmds)
	return tea.Batch(cmds...)
}

func (m *Model) fetchTab(seq int, f model.Filter) tea.Cmd {
	be, t := m.be, m.tab
	switch t {
	case tabDevices:
		return func() tea.Msg {
			v, err := be.Devices(context.Background(), f)
			return dataMsg{seq: seq, kind: t, v: v, err: err}
		}
	case tabFlows:
		return func() tea.Msg {
			v, err := be.Flows(context.Background(), f)
			return dataMsg{seq: seq, kind: t, v: v, err: err}
		}
	case tabDNS:
		return func() tea.Msg {
			v, err := be.DNS(context.Background(), f)
			return dataMsg{seq: seq, kind: t, v: v, err: err}
		}
	case tabFacts:
		return func() tea.Msg {
			v, err := be.Facts(context.Background(), f)
			return dataMsg{seq: seq, kind: t, v: v, err: err}
		}
	case tabGraph:
		o := m.gopts
		return func() tea.Msg {
			v, err := be.Graph(context.Background(), f, o)
			return dataMsg{seq: seq, kind: t, v: v, err: err}
		}
	case tabSummary:
		return func() tea.Msg {
			v, err := be.Devices(context.Background(), f)
			return dataMsg{seq: seq, kind: tabDevices, v: v, err: err}
		}
	}
	return nil
}

func renderGraphText(seq int, g *model.Graph) tea.Cmd {
	return func() tea.Msg {
		txt, err := d2render.Text(g, d2render.Options{Unicode: true})
		return graphTextMsg{seq: seq, text: txt, err: err}
	}
}

// Update handles a message.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resize()
		return m, nil
	case refreshMsg:
		return m, m.fetch()
	case liveMsg:
		if !m.live {
			return m, nil
		}
		m.to = m.now()
		return m, tea.Batch(m.fetch(), liveTick())
	case dataMsg:
		return m.onData(msg)
	case graphTextMsg:
		if msg.seq == m.seq {
			m.loading = max(m.loading-1, 0)
			m.gtext, m.gerr = msg.text, msg.err
			m.gview.SetContent(m.gtext)
		}
		return m, nil
	case entityMsg:
		m.loading = max(m.loading-1, 0)
		if msg.err != nil {
			m.status = "detail: " + msg.err.Error()
			return m, nil
		}
		m.detail = msg.d
		m.dview.SetContent(m.renderDetail(msg.d))
		m.dview.GotoTop()
		return m, nil
	case savedMsg:
		if msg.err != nil {
			m.status = "save: " + msg.err.Error()
		} else {
			m.status = "saved " + strings.Join(msg.paths, ", ")
		}
		return m, nil
	case tea.KeyMsg:
		return m.onKey(msg)
	}
	return m, nil
}

func (m Model) onData(msg dataMsg) (tea.Model, tea.Cmd) {
	if msg.seq != m.seq {
		return m, nil
	}
	m.loading = max(m.loading-1, 0)
	if msg.err != nil {
		m.err = msg.err
		return m, nil
	}
	m.err = nil
	switch msg.what {
	case "summary":
		m.summary = msg.v.(*model.Summary)
		return m, nil
	case "series":
		m.series = msg.v.(*model.Timeseries)
		return m, nil
	}
	switch msg.kind {
	case tabDevices:
		m.devices = msg.v.([]model.Device)
	case tabFlows:
		m.flows = msg.v.([]model.Flow)
	case tabDNS:
		m.dns = msg.v.([]model.DNSQuery)
	case tabFacts:
		m.facts = msg.v.([]model.Fact)
	case tabGraph:
		m.graph = msg.v.(*model.Graph)
		m.outRows = outline(m.graph)
		m.loading++
		return m, renderGraphText(m.seq, m.graph)
	}
	m.clampCursor()
	return m, nil
}

func (m *Model) resize() {
	h := max(m.height-bodyChrome, 3)
	m.gview.Width, m.gview.Height = m.width, h
	m.dview.Width, m.dview.Height = m.width, h
	m.input.Width = max(m.width-12, 10)
}

func (m Model) onKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.editing {
		switch k.String() {
		case "enter":
			f, err := parseFilter(m.input.Value())
			if err != nil {
				m.status = err.Error()
				return m, nil
			}
			m.editing = false
			m.input.Blur()
			m.filter, m.filterText = f, filterString(f)
			m.resetCursors()
			return m, m.fetch()
		case "esc":
			m.editing = false
			m.input.Blur()
			return m, nil
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(k)
		return m, cmd
	}
	if m.detail != nil {
		switch k.String() {
		case "esc", "q", "backspace", "left":
			m.detail = nil
			return m, nil
		case "ctrl+c":
			return m, tea.Quit
		}
		var cmd tea.Cmd
		m.dview, cmd = m.dview.Update(k)
		return m, cmd
	}
	if m.showHelp {
		m.showHelp = false
		return m, nil
	}
	m.status = ""
	switch s := k.String(); s {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "?":
		m.showHelp = true
		return m, nil
	case "tab", "shift+tab":
		d := 1
		if s == "shift+tab" {
			d = int(numTabs) - 1
		}
		m.tab = (m.tab + tab(d)) % numTabs
		return m, m.fetch()
	case "1", "2", "3", "4", "5", "6":
		m.tab = tab(s[0] - '1')
		return m, m.fetch()
	case "[", "]", "{", "}":
		d := m.span / 2
		if s == "{" || s == "}" {
			d = m.span
		}
		if s == "[" || s == "{" {
			d = -d
		}
		m.to = m.to.Add(d)
		m.live = false
		return m, m.fetch()
	case "-", "_":
		m.to = m.to.Add(m.span / 2)
		m.span *= 2
		m.live = m.live && !m.to.After(m.now())
		return m, m.fetch()
	case "+", "=":
		if m.span > 2*time.Minute {
			m.to = m.to.Add(-m.span / 4)
			m.span /= 2
			m.live = false
		}
		return m, m.fetch()
	case "t":
		m.span = nextPreset(m.span)
		m.to = m.now()
		return m, m.fetch()
	case "n":
		m.to = m.now()
		return m, m.fetch()
	case "l":
		m.live = !m.live
		if m.live {
			m.to = m.now()
			return m, tea.Batch(m.fetch(), liveTick())
		}
		return m, nil
	case "r":
		return m, m.fetch()
	case "/":
		m.editing = true
		m.input.SetValue(m.filterText)
		m.input.CursorEnd()
		return m, m.input.Focus()
	case "x":
		m.filter, m.filterText = model.Filter{}, ""
		m.resetCursors()
		return m, m.fetch()
	case "enter":
		if id := m.selectedEntity(); id != "" {
			m.loading++
			be, f := m.be, m.window()
			return m, func() tea.Msg { d, err := be.Entity(context.Background(), id, f); return entityMsg{d, err} }
		}
		return m, nil
	}
	if m.tab == tabGraph {
		return m.graphKey(k)
	}
	m.moveCursor(k.String())
	return m, nil
}

func (m Model) graphKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "c":
		m.gopts.Collapse = !m.gopts.Collapse
		return m, m.fetch()
	case "i":
		m.gopts.Identity = !m.gopts.Identity
		return m, m.fetch()
	case "d":
		m.gopts.DNS = !m.gopts.DNS
		return m, m.fetch()
	case ">", ".":
		m.gopts.TopN = min(m.gopts.TopN+5, 200)
		return m, m.fetch()
	case "<", ",":
		m.gopts.TopN = max(m.gopts.TopN-5, 1)
		return m, m.fetch()
	case "o":
		m.outline = !m.outline
		return m, nil
	case "s":
		return m, m.saveGraph()
	}
	if m.outline {
		m.moveCursor(k.String())
		return m, nil
	}
	var cmd tea.Cmd
	m.gview, cmd = m.gview.Update(k)
	return m, cmd
}

func (m Model) saveGraph() tea.Cmd {
	g := m.graph
	dir := m.opts.SaveDir
	if dir == "" {
		dir = "."
	}
	stamp := m.to.Format("20060102-150405")
	return func() tea.Msg {
		if g == nil {
			return savedMsg{err: fmt.Errorf("no graph loaded")}
		}
		base := filepath.Join(dir, "netgraph-"+stamp)
		svg, err := d2render.SVG(g, d2render.Options{})
		if err != nil {
			return savedMsg{err: err}
		}
		if err := os.WriteFile(base+".svg", svg, 0o644); err != nil {
			return savedMsg{err: err}
		}
		if err := os.WriteFile(base+".d2", []byte(graph.RenderD2(g, graph.RenderOptions{})), 0o644); err != nil {
			return savedMsg{err: err}
		}
		return savedMsg{paths: []string{base + ".svg", base + ".d2"}}
	}
}

func nextPreset(cur time.Duration) time.Duration {
	for _, p := range presets {
		if p > cur {
			return p
		}
	}
	return presets[0]
}

func (m *Model) resetCursors() {
	m.cursor = [numTabs]int{}
	m.offset = [numTabs]int{}
}

func (m Model) rows() int {
	switch m.tab {
	case tabDevices, tabSummary:
		return len(m.devices)
	case tabFlows:
		return len(m.flows)
	case tabDNS:
		return len(m.dns)
	case tabFacts:
		return len(m.facts)
	case tabGraph:
		return len(m.outRows)
	}
	return 0
}

func (m *Model) clampCursor() {
	n := m.rows()
	c := &m.cursor[m.tab]
	*c = max(min(*c, n-1), 0)
}

func (m *Model) moveCursor(key string) {
	n := m.rows()
	page := max(m.tableHeight()-1, 1)
	c := &m.cursor[m.tab]
	switch key {
	case "up", "k":
		*c--
	case "down", "j":
		*c++
	case "pgup", "ctrl+u":
		*c -= page
	case "pgdown", "ctrl+d", " ":
		*c += page
	case "home", "g":
		*c = 0
	case "end", "G":
		*c = n - 1
	}
	*c = max(min(*c, n-1), 0)
	o := &m.offset[m.tab]
	if *c < *o {
		*o = *c
	}
	if *c >= *o+page {
		*o = *c - page + 1
	}
}

// selectedEntity is the entity the cursor's row is about.
func (m Model) selectedEntity() string {
	c := m.cursor[m.tab]
	switch m.tab {
	case tabDevices, tabSummary:
		if c < len(m.devices) {
			return m.devices[c].ID
		}
	case tabFlows:
		if c < len(m.flows) {
			f := m.flows[c]
			if f.Name != "" {
				return model.EntityID(model.KindDomain, f.Name)
			}
			return model.EntityID(model.KindIP, f.RemoteIP)
		}
	case tabDNS:
		if c < len(m.dns) {
			return model.EntityID(model.KindDomain, m.dns[c].QName)
		}
	case tabFacts:
		if c < len(m.facts) {
			return m.facts[c].Dst
		}
	case tabGraph:
		if m.outline && c < len(m.outRows) {
			return m.outRows[c].id
		}
	}
	return ""
}
