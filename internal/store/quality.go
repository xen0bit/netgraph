package store

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

const (
	// qualityBaseline is what "usual" is measured against.
	qualityBaseline = 7 * 24 * time.Hour
	// qualityMaxWindow keeps a query over raw connections bounded.
	qualityMaxWindow = 7 * 24 * time.Hour
	// qualityMinSamples is the fewest handshakes worth saying anything about.
	qualityMinSamples = 5
	// Past these, the local network itself looks like the problem. A wired LAN answers
	// in about a millisecond, and decent Wi-Fi in a few.
	qualitySlowLANMS = 30.0
	qualityLossyPct  = 5.0
	// Upstream is slow if it's this much worse than usual, by both measures: a small
	// baseline doubling isn't anything anyone would feel.
	qualitySlowFactor = 2.0
	qualitySlowAddMS  = 30.0
	// An outage is minutes with this many attempts outward, none answered.
	qualityOutageAttempts = 3
	qualityOutageMinutes  = 2
)

type qualitySample struct {
	first                int64
	dir                  string
	device               int64
	server, client       float64 // ms
	retrans, pkts        int64
	unanswered, answered bool
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[min(int(float64(len(sorted))*p), len(sorted)-1)]
}

func pathStats(v []float64) model.PathStats {
	slices.Sort(v)
	return model.PathStats{P50MS: percentile(v, .5), P95MS: percentile(v, .95), Samples: len(v)}
}

func (s *Store) qualitySamples(ctx context.Context, from, to int64, deviceFilter string) ([]qualitySample, error) {
	w := &where{}
	w.add("first_seen >= ? AND first_seen < ? AND multicast = 0 AND proto = 6", from, to)
	if deviceFilter != "" {
		ids, err := s.deviceIDs(ctx, deviceFilter)
		if err != nil {
			return nil, err
		}
		w.add("client_device IN (" + idList(ids) + ")")
	}
	rows, err := s.r.QueryContext(ctx, `SELECT first_seen, direction, client_device, rtt_server_us, rtt_client_us, retrans, pkts_out + pkts_in, pkts_in FROM connections WHERE `+w.sql(), w.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []qualitySample
	for rows.Next() {
		var q qualitySample
		var server, client, pktsIn int64
		if err := rows.Scan(&q.first, &q.dir, &q.device, &server, &client, &q.retrans, &q.pkts, &pktsIn); err != nil {
			return nil, err
		}
		q.server, q.client = float64(server)/1000, float64(client)/1000
		q.unanswered = pktsIn == 0
		q.answered = pktsIn > 0
		out = append(out, q)
	}
	return out, rows.Err()
}

// legs says which leg of a handshake crossed which network. From a sensor on the
// router, whoever's outside is the far end of the WAN leg.
func (q qualitySample) legs() (wan, lan float64) {
	switch q.dir {
	case "out":
		return q.server, q.client
	case "in":
		return q.client, q.server
	case "local":
		return 0, q.server
	}
	return 0, 0
}

// Quality says how the network is doing, passively: from TCP handshakes, retransmits
// and DNS. It can't see speed, only delay and loss, and the verdict says what the
// numbers look like, not what caused them.
func (s *Store) Quality(ctx context.Context, f model.Filter) (*model.Quality, error) {
	from, to := s.window(f)
	if to <= from {
		return nil, fmt.Errorf("%w: from must be before to", ErrInvalid)
	}
	out := &model.Quality{FromMS: from, ToMS: to, Series: []model.QualityPoint{}, Devices: []model.QualityDevice{}, Outages: []model.Outage{}}
	if to-from > qualityMaxWindow.Milliseconds() {
		from = to - qualityMaxWindow.Milliseconds()
		out.FromMS = from
		out.Gaps = append(out.Gaps, "only the last 7 days of the window are read")
	}
	if retained := ms(s.cfg.Now().Add(-s.cfg.RawRetention)); from < retained {
		out.Gaps = append(out.Gaps, "handshakes are only kept with raw data, so the start of the window has none")
	}
	samples, err := s.qualitySamples(ctx, from, to, f.Device)
	if err != nil {
		return nil, err
	}
	step := max((to-from)/60, time.Minute.Milliseconds())
	step -= step % time.Minute.Milliseconds()
	out.StepMS = step
	type agg struct {
		wan, lan      []float64
		retrans, pkts int64
		attempts      int
		answered      int
	}
	total := &agg{}
	byStep := map[int64]*agg{}
	byDevice := map[int64]*agg{}
	byMinute := map[int64]*agg{}
	get := func(m map[int64]*agg, k int64) *agg {
		a := m[k]
		if a == nil {
			a = &agg{}
			m[k] = a
		}
		return a
	}
	for _, q := range samples {
		wan, lan := q.legs()
		minute := q.first - pmod(q.first, time.Minute.Milliseconds())
		for _, a := range []*agg{total, get(byStep, q.first-pmod(q.first, step)), get(byDevice, q.device)} {
			if wan > 0 {
				a.wan = append(a.wan, wan)
			}
			if lan > 0 {
				a.lan = append(a.lan, lan)
			}
			a.retrans += q.retrans
			a.pkts += q.pkts
		}
		if q.dir == "out" {
			m := get(byMinute, minute)
			m.attempts++
			if q.answered {
				m.answered++
			}
			if q.unanswered {
				total.attempts++
			}
		}
	}
	out.WAN, out.LAN = pathStats(total.wan), pathStats(total.lan)
	out.Unanswered = total.attempts
	if total.pkts > 0 {
		out.RetransPct = float64(total.retrans) / float64(total.pkts) * 100
	}
	steps := make([]int64, 0, len(byStep))
	for k := range byStep {
		steps = append(steps, k)
	}
	slices.Sort(steps)
	for _, k := range steps {
		a := byStep[k]
		w, l := pathStats(a.wan), pathStats(a.lan)
		p := model.QualityPoint{TS: k, WANP50MS: w.P50MS, LANP50MS: l.P50MS}
		if a.pkts > 0 {
			p.RetransPct = float64(a.retrans) / float64(a.pkts) * 100
		}
		out.Series = append(out.Series, p)
	}
	minutes := make([]minuteCount, 0, len(byMinute))
	for k, a := range byMinute {
		minutes = append(minutes, minuteCount{k, a.attempts, a.answered})
	}
	slices.SortFunc(minutes, func(a, b minuteCount) int { return cmp.Compare(a.ts, b.ts) })
	out.Outages = findOutages(minutes)

	if err := s.qualityDNS(ctx, out, from, to, f.Device); err != nil {
		return nil, err
	}
	devices := make([]deviceCount, 0, len(byDevice))
	for id, a := range byDevice {
		devices = append(devices, deviceCount{id, a.wan, a.lan, a.retrans, a.pkts})
	}
	if err := s.qualityDevices(ctx, out, devices); err != nil {
		return nil, err
	}
	// What's usual: the week before, as far as it goes.
	before, err := s.qualitySamples(ctx, from-qualityBaseline.Milliseconds(), from, f.Device)
	if err != nil {
		return nil, err
	}
	var usual []float64
	for _, q := range before {
		if wan, _ := q.legs(); wan > 0 {
			usual = append(usual, wan)
		}
	}
	out.Usual = pathStats(usual)
	out.Verdict, out.Summary = qualityVerdict(out)
	return out, nil
}

type minuteCount struct {
	ts                 int64
	attempts, answered int
}

// findOutages merges runs of minutes when nothing outward was answered. minutes is in
// order, and a minute with no attempts isn't in it: silence isn't failure.
func findOutages(minutes []minuteCount) []model.Outage {
	const minute = int64(time.Minute / time.Millisecond)
	out := []model.Outage{}
	var cur *model.Outage
	span := 0
	flush := func() {
		if cur != nil && span >= qualityOutageMinutes {
			out = append(out, *cur)
		}
		cur, span = nil, 0
	}
	for _, m := range minutes {
		if m.attempts < qualityOutageAttempts || m.answered > 0 {
			flush()
			continue
		}
		if cur != nil && m.ts-cur.ToMS > 5*minute {
			flush()
		}
		if cur == nil {
			cur = &model.Outage{FromMS: m.ts}
		}
		cur.ToMS = m.ts + minute
		cur.Attempts += m.attempts
		span++
	}
	flush()
	return out
}

func (s *Store) qualityDNS(ctx context.Context, out *model.Quality, from, to int64, device string) error {
	w := &where{}
	w.add("ts >= ? AND ts < ?", from, to)
	if device != "" {
		ids, err := s.deviceIDs(ctx, device)
		if err != nil {
			return err
		}
		w.add("client_device IN (" + idList(ids) + ")")
	}
	rows, err := s.r.QueryContext(ctx, `SELECT coalesce(latency_ms, 0), rcode FROM dns WHERE `+w.sql(), w.args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	var lat []float64
	for rows.Next() {
		var l float64
		var rcode string
		if err := rows.Scan(&l, &rcode); err != nil {
			return err
		}
		out.DNSQueries++
		if rcode == "TIMEOUT" {
			out.DNSTimeouts++
		} else if l > 0 {
			lat = append(lat, l)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	out.DNS = pathStats(lat)
	return nil
}

type deviceCount struct {
	id            int64
	wan, lan      []float64
	retrans, pkts int64
}

func (s *Store) qualityDevices(ctx context.Context, out *model.Quality, devices []deviceCount) error {
	if len(devices) == 0 {
		return nil
	}
	ids := make(map[int64]bool, len(devices))
	for _, d := range devices {
		ids[d.id] = true
	}
	labels, macs, err := s.labels(ctx, ids)
	if err != nil {
		return err
	}
	for _, c := range devices {
		mac := macs[c.id]
		if mac == "" {
			continue // not a device here: a transit address
		}
		d := model.QualityDevice{ID: model.EntityID(model.KindDevice, mac), Label: firstNonEmpty(labels[c.id], mac), WAN: pathStats(c.wan), LAN: pathStats(c.lan)}
		if c.pkts > 0 {
			d.RetransPct = float64(c.retrans) / float64(c.pkts) * 100
		}
		if d.WAN.Samples+d.LAN.Samples > 0 || c.retrans > 0 {
			out.Devices = append(out.Devices, d)
		}
	}
	// Worst link first: what someone would want to look at.
	slices.SortFunc(out.Devices, func(a, b model.QualityDevice) int {
		return cmp.Or(cmp.Compare(b.LAN.P50MS, a.LAN.P50MS), cmp.Compare(b.RetransPct, a.RetransPct), cmp.Compare(a.Label, b.Label))
	})
	return nil
}

// qualityVerdict says, plainly, what the numbers look like. It's "looks like": a slow
// destination and a slow connection read the same from here.
func qualityVerdict(q *model.Quality) (string, string) {
	if n := len(q.Outages); n > 0 {
		last := q.Outages[n-1]
		return model.QualityOutage, fmt.Sprintf("Connections outward went unanswered for %s, starting %s.",
			time.Duration(last.ToMS-last.FromMS)*time.Millisecond, time.UnixMilli(last.FromMS).UTC().Format(time.RFC3339))
	}
	if q.WAN.Samples+q.LAN.Samples < qualityMinSamples {
		return model.QualityUnknown, fmt.Sprintf("Too few connections to say: %d handshakes measured.", q.WAN.Samples+q.LAN.Samples)
	}
	if q.LAN.Samples >= qualityMinSamples && q.LAN.P50MS > qualitySlowLANMS {
		return model.QualitySlowLocal, fmt.Sprintf("It looks like your own network: devices here take %.0f ms to answer, when a few would be normal. Wi-Fi is the usual reason.", q.LAN.P50MS)
	}
	if q.RetransPct > qualityLossyPct {
		return model.QualityLossy, fmt.Sprintf("Packets are being lost: %.1f%% are sent again.", q.RetransPct)
	}
	if q.WAN.Samples >= qualityMinSamples && q.Usual.Samples >= qualityMinSamples &&
		q.WAN.P50MS > q.Usual.P50MS*qualitySlowFactor && q.WAN.P50MS > q.Usual.P50MS+qualitySlowAddMS {
		return model.QualitySlowUpstream, fmt.Sprintf("It looks upstream of you: the internet is taking %.0f ms to answer, against a usual %.0f ms, while your own network is fine. That's your ISP or the sites being reached.", q.WAN.P50MS, q.Usual.P50MS)
	}
	if q.Usual.Samples < qualityMinSamples {
		return model.QualityGood, fmt.Sprintf("Nothing looks wrong: the internet answers in %.0f ms. There isn't a week's history to compare with yet.", q.WAN.P50MS)
	}
	return model.QualityGood, fmt.Sprintf("Nothing looks wrong: the internet answers in %.0f ms, about the usual %.0f ms.", q.WAN.P50MS, q.Usual.P50MS)
}
