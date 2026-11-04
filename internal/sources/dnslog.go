package sources

import (
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

// RCodeBlocked marks a lookup a DNS filter refused. It's not a real response code, and
// it says what someone would want to know: this was stopped on purpose.
const RCodeBlocked = "BLOCKED"

// RCodeUnknown marks a lookup the log shows no reply to. That isn't a timeout: dnsmasq
// logs nothing for some answers it gives, so all that's known is that it was asked.
const RCodeUnknown = "UNKNOWN"

const (
	maxPendingLookups = 4096
	lookupPatience    = 5 * time.Second // how long to wait for a reply to a query
	maxLogLine        = 8 << 10
	maxAnswers        = 32
	clockDisagrees    = 2 * time.Minute
)

type pendingLookup struct {
	at      time.Time
	client  netip.Addr
	qname   string
	qtype   string
	answers []wire.Answer
	rcode   string
	done    bool
}

// DNSMasqLog reads dnsmasq's log-queries output, which Pi-hole's pihole.log shares.
// A query and its reply are separate lines, joined here by name.
type DNSMasqLog struct {
	Now func() time.Time
	// History says the lines are old, so their timestamps are all there is. Otherwise a
	// line has only just been written, which settles a timestamp that disagrees: syslog
	// doesn't say its timezone, and a DNS server in a container is often on UTC.
	History bool
	pending map[string]*pendingLookup
	order   []*pendingLookup // oldest first; a finished one waits here to be dropped
}

// Line reads one log line, and returns any lookups now complete.
func (l *DNSMasqLog) Line(line string) []wire.Event {
	if len(line) > maxLogLine {
		return nil
	}
	if l.pending == nil {
		l.pending = map[string]*pendingLookup{}
	}
	now := l.now()
	ts, msg, ok := splitSyslog(line, now)
	if !ok {
		return nil
	}
	if d := now.Sub(ts); !l.History && (d > clockDisagrees || d < -clockDisagrees) {
		ts = now
	}
	f := strings.Fields(msg)
	if len(f) < 4 {
		return l.flush(ts)
	}
	switch {
	case strings.HasPrefix(f[0], "query[") && strings.HasSuffix(f[0], "]") && f[2] == "from":
		client, err := netip.ParseAddr(f[3])
		qname := cleanName(f[1])
		if err != nil || qname == "" {
			return l.flush(ts)
		}
		done := l.flush(ts)
		// A second query for the name closes the first: it got no reply worth waiting for.
		if p := l.pending[qname]; p != nil {
			done = append(done, l.finish(p))
		}
		if len(l.pending) >= maxPendingLookups {
			done = append(done, l.oldest()...)
		}
		p := &pendingLookup{at: ts, client: client.Unmap(), qname: qname, qtype: f[0][len("query[") : len(f[0])-1]}
		l.pending[qname] = p
		l.order = append(l.order, p)
		l.compact()
		return done
	case f[0] == "reply", f[0] == "cached":
		if p := l.pending[cleanName(f[1])]; p != nil && f[2] == "is" {
			p.answers = appendAnswer(p.answers, p.qname, f[3])
			if strings.HasPrefix(f[3], "NXDOMAIN") {
				p.rcode = "NXDOMAIN"
			}
			if strings.HasPrefix(f[3], "NODATA") && p.rcode == "" {
				p.rcode = "NOERROR"
			}
		}
	case f[0] == "config" || f[0] == "gravity" || strings.HasPrefix(f[0], "/"):
		// Pi-hole: "gravity blocked ads.example is 0.0.0.0". dnsmasq: "config x is 0.0.0.0",
		// or a hosts file. An answer of nothing is a block; a real address is local config.
		i := 1
		if f[0] == "gravity" && f[1] == "blocked" {
			i = 2
		}
		if i+2 < len(f) && f[i+1] == "is" {
			if p := l.pending[cleanName(f[i])]; p != nil {
				switch {
				case strings.HasPrefix(f[i+2], "NODATA"):
					// Answered: there's no such record, as for AAAA on a v4-only name.
					if f[0] == "gravity" {
						p.rcode = RCodeBlocked
					} else if p.rcode == "" {
						p.rcode = "NOERROR"
					}
				case f[0] == "gravity" || f[i+2] == "0.0.0.0" || f[i+2] == "::" || f[i+2] == "NXDOMAIN":
					p.rcode = RCodeBlocked
				default:
					p.answers = appendAnswer(p.answers, p.qname, f[i+2])
				}
			}
		}
	}
	return l.flush(ts)
}

func (l *DNSMasqLog) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func appendAnswer(a []wire.Answer, name, v string) []wire.Answer {
	if len(a) >= maxAnswers {
		return a
	}
	ip, err := netip.ParseAddr(v)
	if err != nil {
		return a
	}
	typ := "A"
	if ip.Is6() {
		typ = "AAAA"
	}
	return append(a, wire.Answer{Name: name, Type: typ, Data: ip.String()})
}

// Tick completes what's waited long enough. A quiet log has no next line to do it.
func (l *DNSMasqLog) Tick() []wire.Event { return l.flush(l.now()) }

// compact drops finished lookups from the front, so a name queried over and over can't
// grow the list: every entry past the front is either waiting or about to be dropped.
func (l *DNSMasqLog) compact() {
	for len(l.order) > 0 && l.order[0].done {
		l.order = l.order[1:]
	}
}

// flush completes lookups that have waited long enough.
func (l *DNSMasqLog) flush(now time.Time) []wire.Event {
	var out []wire.Event
	for {
		l.compact()
		if len(l.order) == 0 || now.Sub(l.order[0].at) < lookupPatience {
			return out
		}
		out = append(out, l.finish(l.order[0]))
	}
}

func (l *DNSMasqLog) oldest() []wire.Event {
	l.compact()
	if len(l.order) == 0 {
		return nil
	}
	return []wire.Event{l.finish(l.order[0])}
}

// Close completes everything still waiting.
func (l *DNSMasqLog) Close() []wire.Event {
	var out []wire.Event
	for _, p := range l.order {
		if !p.done {
			out = append(out, l.finish(p))
		}
	}
	l.order = nil
	return out
}

func (l *DNSMasqLog) finish(p *pendingLookup) wire.Event {
	p.done = true
	if l.pending[p.qname] == p {
		delete(l.pending, p.qname)
	}
	rcode := p.rcode
	if rcode == "" {
		rcode = "NOERROR"
		if len(p.answers) == 0 {
			rcode = RCodeUnknown
		}
	}
	return wire.Event{Type: wire.TypeDNS, TS: p.at, DNS: &wire.DNS{Client: p.client, Proto: "log", QName: p.qname, QType: p.qtype, RCode: rcode, Answers: p.answers}}
}

func cleanName(s string) string {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if s == "" || len(s) > 253 || strings.ContainsAny(s, " \t\x00/") {
		return ""
	}
	return s
}

// splitSyslog reads "Nov  4 09:15:35 dnsmasq[123]: message". Syslog leaves out the year,
// so it's whichever makes the time the most recent past.
func splitSyslog(line string, now time.Time) (time.Time, string, bool) {
	const stamp = len("Jan _2 15:04:05")
	if len(line) < stamp+1 {
		return time.Time{}, "", false
	}
	t, err := time.ParseInLocation("Jan _2 15:04:05", line[:stamp], now.Location())
	if err != nil {
		return time.Time{}, "", false
	}
	t = t.AddDate(now.Year(), 0, 0)
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	rest := line[stamp:]
	i := strings.Index(rest, "]: ")
	if i < 0 {
		return time.Time{}, "", false
	}
	return t, rest[i+3:], true
}

// AdGuardLine reads one line of AdGuard Home's querylog.json. Its answers are raw DNS
// messages, which aren't decoded here: this says what was asked and whether it was
// blocked, not what it resolved to.
func AdGuardLine(line string) (wire.Event, bool) {
	if len(line) > maxLogLine {
		return wire.Event{}, false
	}
	var r struct {
		T      time.Time `json:"T"`
		QH     string    `json:"QH"`
		QT     string    `json:"QT"`
		IP     string    `json:"IP"`
		Result struct {
			IsFiltered bool `json:"IsFiltered"`
		} `json:"Result"`
		Elapsed int64 `json:"Elapsed"`
	}
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		return wire.Event{}, false
	}
	client, err := netip.ParseAddr(r.IP)
	qname := cleanName(r.QH)
	if err != nil || qname == "" || r.T.IsZero() {
		return wire.Event{}, false
	}
	d := &wire.DNS{Client: client.Unmap(), Proto: "log", QName: qname, QType: r.QT, RCode: "NOERROR"}
	if r.Result.IsFiltered {
		d.RCode = RCodeBlocked
	}
	if r.Elapsed > 0 { // nanoseconds
		d.LatencyMS = float64(r.Elapsed) / 1e6
	}
	return wire.Event{Type: wire.TypeDNS, TS: r.T, DNS: d}, true
}
