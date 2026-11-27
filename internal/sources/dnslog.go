package sources

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/decode"
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
	l.init()
	now := l.now()
	ts, msg, ok := splitSyslog(line, now)
	if !ok {
		return nil
	}
	return l.at(ts, msg)
}

// Message reads one log message whose syslog header has already been taken off,
// as a syslog receiver gets it. ts is when the message was written, or when it
// arrived if the header had no usable time.
func (l *DNSMasqLog) Message(msg string, ts time.Time) []wire.Event {
	if len(msg) > maxLogLine {
		return nil
	}
	l.init()
	return l.at(ts, msg)
}

func (l *DNSMasqLog) init() {
	if l.pending == nil {
		l.pending = map[string]*pendingLookup{}
	}
}

func (l *DNSMasqLog) at(ts time.Time, msg string) []wire.Event {
	if d := l.now().Sub(ts); !l.History && (d > clockDisagrees || d < -clockDisagrees) {
		ts = l.now()
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

type adguardAnswer struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// adguardEntry is one line of AdGuard Home's querylog.json, in either the file's own
// form (T/QH/QT/Answer, where Answer is a base64 DNS message) or the shape its API
// returns (time/question/answer). Reading both costs little and keeps older and newer
// installations working.
type adguardEntry struct {
	T      time.Time `json:"T"`
	Time   time.Time `json:"time"`
	QH     string    `json:"QH"`
	QT     string    `json:"QT"`
	IP     string    `json:"IP"`
	Client string    `json:"client"`
	// Answer is the legacy base64 message; answer is the API's list of records.
	Answer      json.RawMessage `json:"Answer"`
	AnswerList  json.RawMessage `json:"answer"`
	AnswersList json.RawMessage `json:"answers"`
	Elapsed     int64           `json:"Elapsed"`
	ElapsedMS   json.RawMessage `json:"elapsedMs"`
	// Result.Reason is a number in the file and a name in the API; keep it raw
	// so either unmarshals.
	Result struct {
		IsFiltered bool            `json:"IsFiltered"`
		Reason     json.RawMessage `json:"reason"`
	} `json:"Result"`
	Reason   json.RawMessage `json:"reason"`
	Question struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"question"`
	Status string `json:"status"`
}

// AdGuardLine reads one line of AdGuard Home's querylog.json. Its answers are normally
// a base64-encoded DNS response; those are decoded to A, AAAA and CNAME records so an
// AdGuard-fed server can use them for correlation and answer validity, as it does for
// dnsmasq. The API-shaped fields are accepted too.
func AdGuardLine(line string) (wire.Event, bool) {
	if len(line) > maxLogLine {
		return wire.Event{}, false
	}
	var r adguardEntry
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		return wire.Event{}, false
	}
	ts := r.T
	if ts.IsZero() {
		ts = r.Time
	}
	qname := cleanName(r.QH)
	if qname == "" {
		qname = cleanName(r.Question.Name)
	}
	clientIP := r.IP
	if clientIP == "" {
		clientIP = r.Client
	}
	client, err := netip.ParseAddr(clientIP)
	qtype := strings.ToUpper(r.QT)
	if qtype == "" {
		qtype = strings.ToUpper(r.Question.Type)
	}
	if err != nil || qname == "" || ts.IsZero() {
		return wire.Event{}, false
	}
	answers, rcode := adguardAnswers(r, qname)
	if rcode == "" {
		rcode = strings.ToUpper(r.Status)
	}
	d := &wire.DNS{Client: client.Unmap(), Proto: "log", QName: qname, QType: qtype, RCode: rcode, Answers: answers}
	if d.RCode == "" {
		d.RCode = "NOERROR"
	}
	reason := strings.ToLower(jsonText(r.Result.Reason))
	if reason == "" {
		reason = strings.ToLower(jsonText(r.Reason))
	}
	if r.Result.IsFiltered || strings.HasPrefix(reason, "filtered") || strings.Contains(reason, "block") {
		// A blocked lookup's answer is the filter's (0.0.0.0, ::, a block
		// page), not the name's: it would tie the name to that address.
		d.RCode, d.Answers = RCodeBlocked, nil
	}
	if r.Elapsed > 0 { // nanoseconds
		d.LatencyMS = float64(r.Elapsed) / 1e6
	} else if ms, ok := jsonFloat(r.ElapsedMS); ok && ms > 0 {
		d.LatencyMS = ms
	}
	return wire.Event{Type: wire.TypeDNS, TS: ts, DNS: d}, true
}

// adguardAnswers reads whichever answer form the line carries: a base64 DNS message, or
// a JSON list of records. It also returns the message's response code when there is one.
func adguardAnswers(r adguardEntry, qname string) ([]wire.Answer, string) {
	for _, raw := range []json.RawMessage{r.Answer, r.AnswerList, r.AnswersList} {
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		var b64 string
		if err := json.Unmarshal(raw, &b64); err == nil {
			return answersFromDNS(b64)
		}
		var list []adguardAnswer
		if err := json.Unmarshal(raw, &list); err == nil {
			return answersFromList(list, qname), ""
		}
	}
	return nil, ""
}

// answersFromDNS decodes AdGuard's base64-encoded DNS response. Only the records the
// log path uses are kept: A, AAAA and CNAME.
func answersFromDNS(s string) ([]wire.Answer, string) {
	if s == "" {
		return nil, ""
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, ""
	}
	m, err := decode.ParseDNS(b)
	if err != nil && m == nil {
		return nil, ""
	}
	var out []wire.Answer
	for _, rr := range m.Answers {
		if len(out) >= maxAnswers {
			break
		}
		switch rr.Type {
		case decode.TypeA, decode.TypeAAAA:
			if rr.Addr.IsValid() {
				out = append(out, wire.Answer{Name: strings.ToLower(rr.Name), Type: decode.TypeName(rr.Type), TTL: rr.TTL, Data: rr.Addr.String()})
			}
		case decode.TypeCNAME:
			name := cleanName(rr.Target)
			if name != "" {
				out = append(out, wire.Answer{Name: strings.ToLower(rr.Name), Type: "CNAME", TTL: rr.TTL, Data: name})
			}
		}
	}
	return out, decode.RCodeName(m.RCode)
}

func answersFromList(list []adguardAnswer, qname string) []wire.Answer {
	var out []wire.Answer
	for _, a := range list {
		if len(out) >= maxAnswers {
			break
		}
		typ := strings.ToUpper(strings.TrimSpace(a.Type))
		value := strings.TrimSpace(a.Value)
		switch typ {
		case "A", "AAAA":
			ip, err := netip.ParseAddr(value)
			if err != nil {
				continue
			}
			out = append(out, wire.Answer{Name: qname, Type: typ, TTL: a.TTL, Data: ip.Unmap().String()})
		case "CNAME":
			name := cleanName(value)
			if name != "" {
				out = append(out, wire.Answer{Name: qname, Type: "CNAME", TTL: a.TTL, Data: name})
			}
		}
	}
	return out
}

func jsonText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	return ""
}

func jsonFloat(raw json.RawMessage) (float64, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		v, err := strconv.ParseFloat(s, 64)
		return v, err == nil
	}
	var v float64
	if err := json.Unmarshal(raw, &v); err == nil {
		return v, true
	}
	return 0, false
}

// UnboundLine reads one line of Unbound's query log, such as
// "info: 192.168.1.5 example.com A IN NOERROR 0.001 0 74".
func UnboundLine(line string) (wire.Event, bool) {
	return unboundLine(line, time.Now())
}

func unboundLine(line string, now time.Time) (wire.Event, bool) {
	if len(line) > maxLogLine {
		return wire.Event{}, false
	}
	ts, msg := stripLogHeader(line, now)
	i := strings.Index(msg, "info: ")
	if i < 0 {
		if strings.HasPrefix(msg, "info:") {
			msg = msg[len("info:"):]
		} else {
			return wire.Event{}, false
		}
	} else {
		msg = msg[i+len("info: "):]
	}
	f := strings.Fields(msg)
	// The client address is the first field that parses as one; the query, type,
	// class and response code follow it.
	for i := 0; i+4 < len(f); i++ {
		client, err := netip.ParseAddr(f[i])
		if err != nil {
			continue
		}
		qname := cleanName(f[i+1])
		if qname == "" {
			return wire.Event{}, false
		}
		qtype := strings.ToUpper(f[i+2])
		rcode := strings.ToUpper(f[i+4])
		if !knownRCode(rcode) {
			return wire.Event{}, false
		}
		d := &wire.DNS{Client: client.Unmap(), Proto: "log", QName: qname, QType: qtype, RCode: rcode}
		if i+5 < len(f) {
			if secs, err := strconv.ParseFloat(f[i+5], 64); err == nil && secs >= 0 {
				d.LatencyMS = secs * 1000
			}
		}
		return wire.Event{Type: wire.TypeDNS, TS: ts, DNS: d}, true
	}
	return wire.Event{}, false
}

// BindLine reads one line of BIND9's query log, such as
// "client @0x7f 192.168.1.5#1234 (example.com): query: example.com IN A + (192.168.1.1)".
func BindLine(line string) (wire.Event, bool) {
	return bindLine(line, time.Now())
}

func bindLine(line string, now time.Time) (wire.Event, bool) {
	if len(line) > maxLogLine {
		return wire.Event{}, false
	}
	ts, msg := stripLogHeader(line, now)
	f := strings.Fields(msg)
	// Skip "client", then an optional pointer such as "@0x7f..." before addr#port.
	i := 0
	for i < len(f) && f[i] != "client" {
		i++
	}
	if i >= len(f) {
		return wire.Event{}, false
	}
	i++
	if i < len(f) && strings.HasPrefix(f[i], "@") {
		i++
	}
	if i >= len(f) {
		return wire.Event{}, false
	}
	addr, _, ok := strings.Cut(f[i], "#")
	if !ok {
		return wire.Event{}, false
	}
	client, err := netip.ParseAddr(addr)
	if err != nil {
		return wire.Event{}, false
	}
	// The queried name follows "query:"; the "(name)" before it is the same, but
	// may be shortened.
	for i < len(f) && !strings.HasPrefix(f[i], "query:") {
		i++
	}
	if i >= len(f) {
		return wire.Event{}, false
	}
	i++
	if i+2 >= len(f) {
		return wire.Event{}, false
	}
	qname := cleanName(f[i])
	if qname == "" {
		return wire.Event{}, false
	}
	// The tokens after the name are its class (IN) and type (A, AAAA, ...).
	d := &wire.DNS{Client: client.Unmap(), Proto: "log", QName: qname, QType: strings.ToUpper(f[i+2]), RCode: RCodeUnknown}
	return wire.Event{Type: wire.TypeDNS, TS: ts, DNS: d}, true
}

func knownRCode(s string) bool {
	switch s {
	case "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE":
		return true
	}
	return false
}

// stripLogHeader takes off an RFC 3164 or RFC 5424 syslog header, returning the
// message and its time. A line with no header is its own message, timed now.
func stripLogHeader(line string, now time.Time) (time.Time, string) {
	s := line
	if strings.HasPrefix(s, "<") {
		if i := strings.IndexByte(s, '>'); i > 1 && i <= 5 {
			s = s[i+1:]
		}
	}
	if strings.HasPrefix(s, "1 ") {
		if ts, rest, ok := stripRFC5424(s[2:], now); ok {
			return ts, rest
		}
	}
	const stamp = len("Jan _2 15:04:05")
	if len(s) > stamp {
		if t, err := time.ParseInLocation("Jan _2 15:04:05", s[:stamp], now.Location()); err == nil {
			t = t.AddDate(now.Year(), 0, 0)
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			rest := s[stamp:]
			if i := strings.Index(rest, "]: "); i >= 0 {
				return t, rest[i+3:]
			}
			if i := strings.Index(rest, ": "); i >= 0 {
				return t, rest[i+2:]
			}
			return t, strings.TrimSpace(rest)
		}
	}
	// BIND's own timestamp: "25-Oct-2026 12:00:00.000".
	for _, layout := range []string{"02-Jan-2006 15:04:05.000", "02-Jan-2006 15:04:05"} {
		if len(s) <= len(layout) {
			continue
		}
		if t, err := time.ParseInLocation(layout, s[:len(layout)], now.Location()); err == nil {
			rest := strings.TrimSpace(s[len(layout):])
			return t, rest
		}
	}
	// Unbound with a Unix timestamp: "[1621847131] unbound[pid:0] info: ...".
	if strings.HasPrefix(s, "[") {
		if i := strings.IndexByte(s, ']'); i > 1 && i <= 12 {
			if sec, err := strconv.ParseInt(s[1:i], 10, 64); err == nil {
				return time.Unix(sec, 0), strings.TrimSpace(s[i+1:])
			}
		}
	}
	return now, s
}

func stripRFC5424(s string, now time.Time) (time.Time, string, bool) {
	// s starts after "<PRI>1 ": TIMESTAMP HOST APP PROCID MSGID [SD] MSG.
	tok := func() (string, bool) {
		i := strings.IndexByte(s, ' ')
		if i < 0 {
			return "", false
		}
		v := s[:i]
		s = s[i+1:]
		return v, true
	}
	stamp, ok := tok()
	if !ok {
		return time.Time{}, "", false
	}
	ts := now
	if stamp != "-" {
		t, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil {
			return time.Time{}, "", false
		}
		ts = t
	}
	for range 4 { // host, app-name, procid, msgid
		if _, ok := tok(); !ok {
			return time.Time{}, "", false
		}
	}
	if strings.HasPrefix(s, "- ") {
		s = s[2:]
	} else if s == "-" {
		s = ""
	} else if strings.HasPrefix(s, "[") {
		// Structured data may hold spaces; skip balanced brackets, then a space.
		for strings.HasPrefix(s, "[") {
			depth, i := 0, 0
			for ; i < len(s); i++ {
				switch s[i] {
				case '[':
					depth++
				case ']':
					depth--
				}
				if depth == 0 {
					break
				}
			}
			if depth != 0 || i >= len(s) {
				return time.Time{}, "", false
			}
			s = s[i+1:]
		}
		s = strings.TrimPrefix(s, " ")
	}
	return ts, s, true
}

// logParser reads one DNS server's log lines in the format it was told.
type logParser struct {
	format  string
	history bool
	dns     *DNSMasqLog
}

func newLogParser(format string, history bool) *logParser {
	p := &logParser{format: format, history: history}
	switch format {
	case "", "dnsmasq", "pihole":
		p.format = "dnsmasq"
		p.dns = &DNSMasqLog{History: history}
	}
	return p
}

// Line reads one line that still has its log prefix.
func (p *logParser) Line(line string) []wire.Event {
	switch p.format {
	case "adguard":
		if e, ok := AdGuardLine(line); ok {
			return p.one(e)
		}
	case "unbound":
		if e, ok := UnboundLine(line); ok {
			return p.one(e)
		}
	case "bind":
		if e, ok := BindLine(line); ok {
			return p.one(e)
		}
	default:
		if p.dns != nil {
			return p.dns.Line(line)
		}
	}
	return nil
}

// Message reads one message whose syslog header has already been stripped.
func (p *logParser) Message(msg string, ts time.Time) []wire.Event {
	switch p.format {
	case "adguard":
		if e, ok := AdGuardLine(msg); ok {
			return p.one(e)
		}
	case "unbound":
		if e, ok := unboundLine(msg, ts); ok {
			return p.one(e)
		}
	case "bind":
		if e, ok := bindLine(msg, ts); ok {
			return p.one(e)
		}
	default:
		if p.dns != nil {
			return p.dns.Message(msg, ts)
		}
	}
	return nil
}

// one takes a line's time as written only when reading history: live, a time
// far from the clock is the writer's clock (or a forged datagram), and a lookup
// placed days away would tie names to addresses in the wrong window. dnsmasq's
// lines get the same treatment in DNSMasqLog. AdGuard is the exception: it
// buffers its query log and writes entries long after they happened, so its
// own time is the right one.
func (p *logParser) one(e wire.Event) []wire.Event {
	if now := time.Now(); !p.history && p.format != "adguard" && (e.TS.Sub(now) > clockDisagrees || now.Sub(e.TS) > clockDisagrees) {
		e.TS = now
	}
	return []wire.Event{e}
}

func (p *logParser) Tick() []wire.Event {
	if p.dns != nil {
		return p.dns.Tick()
	}
	return nil
}

func (p *logParser) Close() []wire.Event {
	if p.dns != nil {
		return p.dns.Close()
	}
	return nil
}
