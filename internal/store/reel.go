package store

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/graph"
	"github.com/xen0bit/netgraph/internal/model"
)

const (
	minuteMS = int64(60_000)
	// maxReelSteps bounds a reel's series: a browser holds all of it.
	maxReelSteps = 600
	// reelRawSpan is the longest window a reel reads raw records for. They
	// are the only source finer than a minute.
	reelRawSpan = 2 * time.Hour
)

// A precision a reel or timeseries can answer with, finer than hours.
const precisionMinute = "minute"

// reelStep picks a step of at most maxReelSteps for the window, no finer than
// what its source holds.
func (s *Store) reelStep(from, to int64, want time.Duration) (step int64, source string) {
	span := to - from
	source = model.PrecisionHour
	switch {
	case time.Duration(span)*time.Millisecond <= reelRawSpan && from >= ms(s.cfg.Now().Add(-s.cfg.RawRetention)):
		source = model.PrecisionExact
	case from >= ms(s.cfg.Now().Add(-s.cfg.MinuteRetention)):
		source = precisionMinute
	}
	floor := int64(5000)
	switch source {
	case precisionMinute:
		floor = minuteMS
	case model.PrecisionHour:
		floor = hourMS
	}
	step = max(want.Milliseconds(), floor, span/maxReelSteps+1)
	if step > floor {
		step = niceStep(time.Duration(step) * time.Millisecond).Milliseconds()
	}
	return step, source
}

// Reel is a window's graph with each edge's traffic per step, which a client
// can scrub through without asking again. See model.Reel.
func (s *Store) Reel(ctx context.Context, f model.Filter, o model.GraphOptions, want time.Duration) (*model.Reel, error) {
	from, to := s.window(f)
	if to <= from {
		return nil, fmt.Errorf("%w: empty window", ErrInvalid)
	}
	step, source := s.reelStep(from, to, want)
	o.Anomalies = false
	g, err := s.Graph(ctx, f, o)
	if err != nil {
		return nil, err
	}
	out := &model.Reel{FromMS: from, ToMS: to, StepMS: step, Precision: source, Graph: g, Series: []model.ReelSeries{}}
	out.Steps = int((to - from + step - 1) / step)

	res := newReelResolver(g)
	points := map[int]map[int]*[2]uint64{}
	add := func(edge, i int, up, down uint64) {
		if i < 0 || i >= out.Steps || (up == 0 && down == 0) {
			return
		}
		m := points[edge]
		if m == nil {
			m = map[int]*[2]uint64{}
			points[edge] = m
		}
		p := m[i]
		if p == nil {
			p = &[2]uint64{}
			m[i] = p
		}
		p[0] += up
		p[1] += down
	}
	// deliver places a row's bytes on its edge. A connection's bytes are from
	// the device's side; an edge's up is what the client sent.
	deliver := func(r reelRow, a, b int64) error {
		edge, ok := res.edge(r)
		if !ok {
			out.Unassigned += r.out + r.in
			return nil
		}
		up, down := r.out, r.in
		if r.direction == model.DirIn {
			up, down = r.in, r.out
		}
		if b <= a {
			add(edge, int((a-from)/step), up, down)
			return nil
		}
		span := float64(b - a)
		for i := max(int((a-from)/step), 0); i < out.Steps; i++ {
			lo, hi := max(a, from+int64(i)*step), min(b, from+int64(i+1)*step, to)
			if lo >= to || lo >= b {
				break
			}
			if hi <= lo {
				continue
			}
			frac := float64(hi-lo) / span
			add(edge, i, uint64(float64(up)*frac+0.5), uint64(float64(down)*frac+0.5))
		}
		return nil
	}
	if err := s.reelRows(ctx, f, from, to, source, res, deliver); err != nil {
		return nil, err
	}
	for edge, m := range points {
		se := model.ReelSeries{Edge: edge, Points: make([][3]uint64, 0, len(m))}
		for i, p := range m {
			se.Points = append(se.Points, [3]uint64{uint64(i), p[0], p[1]})
		}
		slices.SortFunc(se.Points, func(a, b [3]uint64) int { return int(a[0]) - int(b[0]) })
		out.Series = append(out.Series, se)
	}
	slices.SortFunc(out.Series, func(a, b model.ReelSeries) int { return a.Edge - b.Edge })
	out.Markers, err = s.ReelMarkers(ctx, f)
	return out, err
}

// ReelMarkers are the moments worth seeking to in a window: notes, bookmarks,
// new devices and anomalies. They are cut at a number a timeline can show.
func (s *Store) ReelMarkers(ctx context.Context, f model.Filter) ([]model.ReelMarker, error) {
	const most = 500
	out := []model.ReelMarker{}
	page, err := s.Timeline(ctx, f, model.TimelineQuery{Kinds: []string{"annotation", "bookmark", "device_new"}, Limit: most})
	if err != nil {
		return nil, err
	}
	for _, e := range page.Events {
		out = append(out, model.ReelMarker{TS: e.TS, Kind: e.Kind, Title: e.Title, Entity: e.Entity})
	}
	rep, err := s.Anomalies(ctx, f)
	if err != nil {
		return nil, err
	}
	for _, a := range rep.Anomalies {
		out = append(out, model.ReelMarker{TS: a.TS, Kind: "anomaly", Severity: a.Severity, Title: a.Summary, Entity: firstNonEmpty(a.Device, a.Entity)})
	}
	slices.SortFunc(out, func(a, b model.ReelMarker) int {
		if a.TS != b.TS {
			if a.TS < b.TS {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Kind+a.Title, b.Kind+b.Title)
	})
	return firstN(out, most), nil
}

type reelRow struct {
	device    int64
	client    string
	remote    string
	name      string
	direction string
	asn       sql.NullInt64
	out, in   uint64
}

// reelRows reads the window's traffic from one source and delivers it with the
// interval each row's bytes belong to.
func (s *Store) reelRows(ctx context.Context, f model.Filter, from, to int64, source string, res *reelResolver, deliver func(r reelRow, a, b int64) error) error {
	w := &where{}
	var q string
	width := int64(0)
	switch source {
	case model.PrecisionExact:
		flowsWindow(w, from, to)
		if err := s.flowWhere(ctx, f, w, recordCols); err != nil {
			return err
		}
		q = `SELECT client_device, client_ip, remote_ip, coalesce(nullif(sni, ''), nullif(http_host, ''), qname), direction, ` + recordCols.asn + `, t_start, t_end, bytes_out, bytes_in FROM ` + flowsFrom + ` WHERE ` + w.sql()
	case precisionMinute:
		width = minuteMS
		w.add("bucket < ? AND bucket >= ?", to, from-from%minuteMS)
		if err := s.flowWhere(ctx, f, w, hourlyCols); err != nil {
			return err
		}
		q = `SELECT client_device, client_ip, remote_ip, name, direction, remote_asn, bucket, bucket, sum(bytes_out), sum(bytes_in) FROM traffic_minute WHERE ` + w.sql() + ` GROUP BY bucket, client_device, client_ip, remote_ip, name, direction, remote_asn`
	default:
		width = hourMS
		w.add("bucket < ? AND bucket >= ?", to, hourOf(from))
		if err := s.flowWhere(ctx, f, w, hourlyCols); err != nil {
			return err
		}
		q = `SELECT client_device, client_ip, remote_ip, name, direction, remote_asn, bucket, bucket, sum(bytes_out), sum(bytes_in) FROM traffic_hourly WHERE ` + w.sql() + ` GROUP BY bucket, client_device, client_ip, remote_ip, name, direction, remote_asn`
	}
	rows, err := s.r.QueryContext(ctx, q, w.args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	var all []reelRow
	var spans [][2]int64
	devs := map[int64]bool{}
	for rows.Next() {
		var r reelRow
		var a, b int64
		if err := rows.Scan(&r.device, &r.client, &r.remote, &r.name, &r.direction, &r.asn, &a, &b, &r.out, &r.in); err != nil {
			return err
		}
		if width > 0 {
			b = a + width
		}
		devs[r.device] = true
		all = append(all, r)
		spans = append(spans, [2]int64{a, b})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	delete(devs, 0)
	_, macs, err := s.labels(ctx, devs)
	if err != nil {
		return err
	}
	res.macs = macs
	for i, r := range all {
		if err := deliver(r, spans[i][0], spans[i][1]); err != nil {
			return err
		}
	}
	return nil
}

// reelResolver finds the graph edge a traffic row was drawn as. The graph has
// already decided what is a name, a site, a network, or left out by Top N, so
// this tries those in graph.Build's order of preference and takes the first
// edge that exists.
type reelResolver struct {
	edges map[string]int
	addr  map[string][]string
	macs  map[int64]string
	memo  map[string]int
}

func newReelResolver(g *model.Graph) *reelResolver {
	r := &reelResolver{edges: map[string]int{}, addr: map[string][]string{}, memo: map[string]int{}}
	for i, e := range g.Edges {
		if e.Rel == model.RelConnects {
			r.edges[e.From+"\x00"+e.To] = i
		}
	}
	for _, n := range g.Nodes {
		for _, attr := range []string{"addresses", "ips"} {
			for _, a := range strings.Split(n.Attrs[attr], ",") {
				if a != "" {
					r.addr[a] = append(r.addr[a], n.ID)
				}
			}
		}
	}
	return r
}

func (r *reelResolver) edge(row reelRow) (int, bool) {
	key := fmt.Sprint(row.device, "\x00", row.client, "\x00", row.remote, "\x00", row.name, "\x00", row.direction, "\x00", row.asn.Int64)
	if e, ok := r.memo[key]; ok {
		return e, e >= 0
	}
	e := r.find(row)
	r.memo[key] = e
	return e, e >= 0
}

func (r *reelResolver) find(row reelRow) int {
	here := model.EntityID(model.KindIP, row.client)
	if mac := r.macs[row.device]; mac != "" {
		here = model.EntityID(model.KindDevice, mac)
	}
	var peers []string
	if row.direction != model.DirIn && row.name != "" {
		peers = append(peers, model.EntityID(model.KindDomain, row.name), model.EntityID(model.KindSite, graph.Site(row.name)))
	}
	peers = append(peers, r.addr[row.remote]...)
	peers = append(peers, model.EntityID(model.KindIP, row.remote))
	if row.asn.Valid && row.asn.Int64 != 0 {
		peers = append(peers, model.EntityID(model.KindASN, strconv.FormatInt(row.asn.Int64, 10)))
	}
	if row.direction == model.DirIn {
		peers = append(peers, model.EntityID(model.KindOther, "clients:"+here))
		for _, p := range peers {
			if e, ok := r.edges[p+"\x00"+here]; ok {
				return e
			}
		}
		return -1
	}
	peers = append(peers, model.EntityID(model.KindOther, here))
	for _, p := range peers {
		if e, ok := r.edges[here+"\x00"+p]; ok {
			return e
		}
	}
	return -1
}
