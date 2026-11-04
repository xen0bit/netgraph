package sources

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

var rx = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func be16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }
func be32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }

func v5Packet(records int, unix uint32) []byte {
	b := be16(nil, 5)
	b = be16(b, uint16(records))
	b = be32(b, 600_000) // up ten minutes
	b = be32(b, unix)
	b = be32(b, 0)
	b = append(b, make([]byte, 8)...)
	for i := range records {
		r := make([]byte, 48)
		copy(r[0:], netip.MustParseAddr("192.168.1.23").AsSlice())
		copy(r[4:], netip.MustParseAddr("93.184.216.34").AsSlice())
		binary.BigEndian.PutUint32(r[16:], 10)
		binary.BigEndian.PutUint32(r[20:], 1500)
		binary.BigEndian.PutUint32(r[24:], 590_000)
		binary.BigEndian.PutUint32(r[28:], 599_000)
		binary.BigEndian.PutUint16(r[32:], uint16(40000+i))
		binary.BigEndian.PutUint16(r[34:], 443)
		r[37], r[38] = 0x12, 6
		b = append(b, r...)
	}
	return b
}

func TestNetFlowV5(t *testing.T) {
	flows, err := ParseNetFlow(v5Packet(2, uint32(rx.Unix())), &Templates{}, rx)
	if err != nil || len(flows) != 2 {
		t.Fatalf("%+v, %v", flows, err)
	}
	f := flows[0]
	if f.Src.String() != "192.168.1.23" || f.Dst.String() != "93.184.216.34" || f.SrcPort != 40000 || f.DstPort != 443 || f.Proto != 6 || f.BytesOut != 1500 || f.PktsOut != 10 {
		t.Errorf("%+v", f)
	}
	if !f.End.Equal(rx.Add(-time.Second)) || !f.Start.Equal(rx.Add(-10*time.Second)) {
		t.Errorf("start %s, end %s", f.Start, f.End)
	}
	if flows[1].ID == f.ID {
		t.Error("two flows, one id")
	}
	// A later report of the same flow joins up with it.
	again, _ := ParseNetFlow(v5Packet(1, uint32(rx.Unix())), &Templates{}, rx)
	if again[0].ID != f.ID {
		t.Error("the same flow's id changed")
	}
	// A router with no clock: we trust when we heard it.
	flows, err = ParseNetFlow(v5Packet(1, 0), &Templates{}, rx)
	if err != nil || !flows[0].End.Equal(rx.Add(-time.Second)) {
		t.Errorf("no clock: %+v, %v", flows, err)
	}
}

// The reply to a device's connection must not read as a connection in from outside.
func TestRepliesJoinTheirConnection(t *testing.T) {
	addr := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	out := wire.Flow{Src: addr("192.168.1.23"), SrcPort: 40000, Dst: addr("93.184.216.34"), DstPort: 443, Proto: 6, BytesOut: 100, PktsOut: 2, Start: rx, End: rx}
	back := wire.Flow{Src: addr("93.184.216.34"), SrcPort: 443, Dst: addr("192.168.1.23"), DstPort: 40000, Proto: 6, BytesOut: 5000, PktsOut: 9, Start: rx.Add(20 * time.Millisecond), End: rx.Add(time.Second)}
	finish(&out, rx.Add(time.Minute))
	finish(&back, rx.Add(time.Minute))
	if back.Src != out.Src || back.DstPort != 443 || back.SrcPort != 40000 || back.BytesIn != 5000 || back.BytesOut != 0 || back.PktsIn != 9 {
		t.Errorf("the reply: %+v", back)
	}
	if back.ID != out.ID {
		t.Error("the two directions aren't one connection")
	}
	// Someone reaching a server here reads as in from outside, both ways.
	in := wire.Flow{Src: addr("8.8.4.4"), SrcPort: 50000, Dst: addr("192.168.1.10"), DstPort: 22, Proto: 6, BytesOut: 10, Start: rx, End: rx}
	inBack := wire.Flow{Src: addr("192.168.1.10"), SrcPort: 22, Dst: addr("8.8.4.4"), DstPort: 50000, Proto: 6, BytesOut: 70, Start: rx, End: rx}
	finish(&in, rx.Add(time.Minute))
	finish(&inBack, rx.Add(time.Minute))
	if inBack.Src != in.Src || inBack.BytesIn != 70 || inBack.ID != in.ID {
		t.Errorf("in: %+v, %+v", in, inBack)
	}
	// Two high ports: nothing says who began, so it's left as reported. ICMP has no ports.
	p2p := wire.Flow{Src: addr("8.8.4.4"), SrcPort: 50000, Dst: addr("192.168.1.10"), DstPort: 50001, Proto: 17, BytesOut: 10, Start: rx, End: rx}
	finish(&p2p, rx.Add(time.Minute))
	if p2p.Src.String() != "8.8.4.4" || p2p.BytesOut != 10 {
		t.Errorf("p2p: %+v", p2p)
	}
}

func flowFields() []field {
	return []field{{8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1}, {1, 4}, {2, 4}}
}

func templateSet(setID, id uint16, fields []field) []byte {
	b := be16(nil, setID)
	b = be16(b, uint16(8+len(fields)*4))
	b = be16(b, id)
	b = be16(b, uint16(len(fields)))
	for _, f := range fields {
		b = be16(b, f.id)
		b = be16(b, f.length)
	}
	return b
}

func dataSet(id uint16) []byte {
	b := be16(nil, id)
	b = be16(b, 4+21)
	b = append(b, netip.MustParseAddr("192.168.1.23").AsSlice()...)
	b = append(b, netip.MustParseAddr("8.8.8.8").AsSlice()...)
	b = be16(b, 5353)
	b = be16(b, 53)
	b = append(b, 17)
	b = be32(b, 99)
	b = be32(b, 1)
	return b
}

func v9Header() []byte {
	b := be16(nil, 9)
	b = be16(b, 2)
	b = be32(b, 1000)
	b = be32(b, uint32(rx.Unix()))
	b = be32(b, 1)
	return be32(b, 7) // source id
}

func ipfixMsg(body []byte) []byte {
	b := be16(nil, 10)
	b = be16(b, uint16(16+len(body)))
	b = be32(b, uint32(rx.Unix()))
	b = be32(b, 1)
	b = be32(b, 7)
	return append(b, body...)
}

func TestNetFlowV9AndIPFIXNeedTemplates(t *testing.T) {
	for name, c := range map[string]struct {
		msg     func(body []byte) []byte
		tmplSet uint16
	}{
		"v9":    {func(b []byte) []byte { return append(v9Header(), b...) }, 0},
		"ipfix": {ipfixMsg, 2},
	} {
		t.Run(name, func(t *testing.T) {
			var tmpl Templates
			// Data before its template can't be read, and isn't an error.
			flows, err := ParseNetFlow(c.msg(dataSet(300)), &tmpl, rx)
			if err != nil || len(flows) != 0 {
				t.Fatalf("%+v, %v", flows, err)
			}
			flows, err = ParseNetFlow(c.msg(append(templateSet(c.tmplSet, 300, flowFields()), dataSet(300)...)), &tmpl, rx)
			if err != nil || len(flows) != 1 {
				t.Fatalf("%+v, %v", flows, err)
			}
			f := flows[0]
			if f.Dst.String() != "8.8.8.8" || f.DstPort != 53 || f.Proto != 17 || f.BytesOut != 99 || !f.End.Equal(rx) {
				t.Errorf("%+v", f)
			}
			// The template is remembered.
			flows, err = ParseNetFlow(c.msg(dataSet(300)), &tmpl, rx)
			if err != nil || len(flows) != 1 {
				t.Fatalf("later: %+v, %v", flows, err)
			}
		})
	}
}

// An exporter can't make the server remember without limit.
func TestTemplatesAreBounded(t *testing.T) {
	var tmpl Templates
	for i := range 2000 {
		_, _ = ParseNetFlow(ipfixMsg(templateSet(2, uint16(256+i), flowFields())), &tmpl, rx)
	}
	if len(tmpl.byID) > maxTemplates {
		t.Errorf("%d templates", len(tmpl.byID))
	}
	huge := make([]field, maxTemplateFields+1)
	for i := range huge {
		huge[i] = field{1, 4}
	}
	var fresh Templates
	_, _ = ParseNetFlow(ipfixMsg(templateSet(2, 300, huge)), &fresh, rx)
	if len(fresh.byID) != 0 {
		t.Error("a template past the field limit was kept")
	}
}

func TestBadDatagramsAreRefused(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty": nil, "one byte": {5}, "unknown": {0, 7, 0, 0},
		"v5 short":          v5Packet(2, 1)[:40],
		"v5 claims 65535":   append(be16(be16(nil, 5), 65535), make([]byte, 100)...),
		"ipfix length past": be16(be16(nil, 10), 9000),
		"ipfix set length":  ipfixMsg(be16(be16(nil, 2), 60000)),
		"ipfix set zero":    ipfixMsg(be16(be16(nil, 2), 0)),
	} {
		if flows, err := ParseNetFlow(b, &Templates{}, rx); err == nil && len(flows) > 0 {
			t.Errorf("%s: %+v", name, flows)
		}
	}
}

// An enterprise field takes more bytes than a template's count allows for. This one
// panicked, which would have taken the server down.
func TestTemplateWithEnterpriseFieldsPastTheEnd(t *testing.T) {
	b := be16(nil, 2)
	b = be16(b, 4+4+8)
	b = be16(b, 300)
	b = be16(b, 2)
	b = be16(b, 0x8001)
	b = be16(b, 4)
	b = be32(b, 99)
	var tmpl Templates
	if flows, _ := ParseNetFlow(ipfixMsg(b), &tmpl, rx); len(flows) != 0 || len(tmpl.byID) != 0 {
		t.Errorf("%+v, %+v", flows, tmpl.byID)
	}
}

func FuzzParseNetFlow(f *testing.F) {
	f.Add(v5Packet(1, 1))
	f.Add(append(v9Header(), templateSet(0, 300, flowFields())...))
	f.Add(ipfixMsg(append(templateSet(2, 300, flowFields()), dataSet(300)...)))
	f.Fuzz(func(t *testing.T, b []byte) {
		var tmpl Templates
		for range 2 { // twice: a template in the first pass applies to data in the second
			flows, _ := ParseNetFlow(b, &tmpl, rx)
			for _, fl := range flows {
				if !fl.Src.IsValid() || !fl.Dst.IsValid() || fl.End.After(rx.Add(time.Minute)) || fl.Start.After(fl.End) || fl.End.Sub(fl.Start) > 24*time.Hour {
					t.Fatalf("%+v", fl)
				}
			}
		}
		if len(tmpl.byID) > maxTemplates {
			t.Fatalf("%d templates", len(tmpl.byID))
		}
	})
}

const logStart = "Oct 25 12:00:0"

func dnsLogAt(l *DNSMasqLog, sec int, msg string) []wire.Event {
	return l.Line(logStart + string(rune('0'+sec)) + " dnsmasq[12]: " + msg)
}

func newLog() *DNSMasqLog {
	return &DNSMasqLog{History: true, Now: func() time.Time { return rx.Add(time.Hour) }}
}

// syslog doesn't name its timezone: a line just written, on a server five hours away,
// happened now, not five hours from now.
func TestLiveLogIgnoresAnotherTimezone(t *testing.T) {
	for _, offset := range []time.Duration{5 * time.Hour, -5 * time.Hour} {
		now := rx
		l := &DNSMasqLog{Now: func() time.Time { return now }}
		stamp := rx.Add(offset).Format("Jan _2 15:04:05")
		l.Line(stamp + " dnsmasq[1]: query[A] a.example from 192.168.1.5")
		got := l.Close()
		if len(got) != 1 || !got[0].TS.Equal(now) {
			t.Errorf("offset %s: %+v", offset, got)
		}
	}
	// Close enough to be believed: the log's own second is more exact than ours.
	l := &DNSMasqLog{Now: func() time.Time { return rx }}
	l.Line(rx.Add(-30*time.Second).Format("Jan _2 15:04:05") + " dnsmasq[1]: query[A] a.example from 192.168.1.5")
	if got := l.Close(); !got[0].TS.Equal(rx.Add(-30 * time.Second)) {
		t.Errorf("%+v", got)
	}
}

func TestDNSMasqLog(t *testing.T) {
	l := newLog()
	var got []wire.Event
	got = append(got, dnsLogAt(l, 0, "query[A] Example.COM. from 192.168.1.23")...)
	got = append(got, dnsLogAt(l, 0, "forwarded example.com to 1.1.1.1")...)
	got = append(got, dnsLogAt(l, 1, "reply example.com is 93.184.216.34")...)
	got = append(got, dnsLogAt(l, 1, "reply example.com is 2606:2800:220:1::1")...)
	got = append(got, dnsLogAt(l, 1, "query[AAAA] nope.example from 192.168.1.24")...)
	got = append(got, dnsLogAt(l, 1, "reply nope.example is NXDOMAIN")...)
	got = append(got, dnsLogAt(l, 1, "query[A] ads.example from 192.168.1.23")...)
	got = append(got, dnsLogAt(l, 1, "gravity blocked ads.example is 0.0.0.0")...)
	got = append(got, dnsLogAt(l, 1, "query[AAAA] v4only.example from 192.168.1.23")...)
	got = append(got, dnsLogAt(l, 1, "config v4only.example is NODATA-IPv6")...)
	got = append(got, dnsLogAt(l, 1, "query[A] silent.example from 192.168.1.23")...)
	got = append(got, l.Close()...)
	by := map[string]*wire.DNS{}
	for _, e := range got {
		by[e.DNS.QName] = e.DNS
	}
	ok := by["example.com"]
	if ok == nil || ok.Client.String() != "192.168.1.23" || ok.QType != "A" || ok.RCode != "NOERROR" || len(ok.Answers) != 2 || ok.Answers[1].Type != "AAAA" {
		t.Errorf("example.com: %+v", ok)
	}
	if d := by["nope.example"]; d == nil || d.RCode != "NXDOMAIN" || len(d.Answers) != 0 {
		t.Errorf("nope: %+v", d)
	}
	if d := by["ads.example"]; d == nil || d.RCode != RCodeBlocked {
		t.Errorf("ads: %+v", d)
	}
	// As real dnsmasq answers an AAAA for a name it only has an A for: an answer, not a timeout.
	if d := by["v4only.example"]; d == nil || d.RCode != "NOERROR" {
		t.Errorf("v4only: %+v", d)
	}
	if d := by["silent.example"]; d == nil || d.RCode != RCodeUnknown {
		t.Errorf("silent: %+v", d)
	}
}

func TestDNSMasqLogFinishesLookupsAsTimePasses(t *testing.T) {
	l := newLog()
	if got := dnsLogAt(l, 0, "query[A] a.example from 192.168.1.1"); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
	got := l.Line("Oct 25 12:01:00 dnsmasq[12]: reply other.example is 1.2.3.4")
	if len(got) != 1 || got[0].DNS.QName != "a.example" {
		t.Errorf("%+v", got)
	}
}

// The last lookup in a quiet log has no next line to finish it.
func TestQuietLogStillFinishesLookups(t *testing.T) {
	now := rx
	l := &DNSMasqLog{Now: func() time.Time { return now }}
	stamp := rx.Format("Jan _2 15:04:05")
	l.Line(stamp + " dnsmasq[1]: query[A] ads.example from 192.168.1.5")
	l.Line(stamp + " dnsmasq[1]: config ads.example is 0.0.0.0")
	if got := l.Tick(); len(got) != 0 {
		t.Fatalf("too soon: %+v", got)
	}
	now = rx.Add(lookupPatience)
	got := l.Tick()
	if len(got) != 1 || got[0].DNS.RCode != RCodeBlocked {
		t.Errorf("%+v", got)
	}
}

// A name asked over and over, or a flood of names, can't grow what's held.
func TestDNSMasqLogIsBounded(t *testing.T) {
	l := newLog()
	for range 20000 {
		dnsLogAt(l, 0, "query[A] busy.example from 192.168.1.1")
	}
	if len(l.order) > 2 || len(l.pending) > 1 {
		t.Errorf("one busy name: order %d, pending %d", len(l.order), len(l.pending))
	}
	l = newLog()
	var sb strings.Builder
	for i := range maxPendingLookups * 2 {
		sb.Reset()
		sb.WriteString("query[A] n")
		sb.WriteString(strings.Repeat("x", i%50))
		sb.WriteString(string(rune('a' + i%26)))
		sb.WriteString(".example")
		sb.WriteString(itoa(i))
		sb.WriteString(" from 192.168.1.1")
		dnsLogAt(l, 0, sb.String())
	}
	if len(l.pending) > maxPendingLookups {
		t.Errorf("%d pending", len(l.pending))
	}
}

func itoa(i int) string {
	return strings.TrimSpace(strings.Join([]string{string(rune('0' + i%10)), string(rune('0' + i/10%10)), string(rune('0' + i/100%10)), string(rune('0' + i/1000%10))}, ""))
}

func TestSyslogYearAcrossNewYear(t *testing.T) {
	now := time.Date(2027, 1, 1, 0, 0, 30, 0, time.UTC)
	ts, _, ok := splitSyslog("Dec 31 23:59:50 dnsmasq[1]: x", now)
	if !ok || ts.Year() != 2026 {
		t.Errorf("%v, %v", ts, ok)
	}
}

func TestAdGuardLine(t *testing.T) {
	e, ok := AdGuardLine(`{"T":"2026-10-25T12:00:00Z","QH":"ads.example","QT":"A","QC":"IN","CP":"","IP":"192.168.1.5","Result":{"IsFiltered":true},"Elapsed":2500000}`)
	if !ok || e.DNS.RCode != RCodeBlocked || e.DNS.QName != "ads.example" || e.DNS.LatencyMS != 2.5 || !e.TS.Equal(rx) {
		t.Errorf("%+v", e)
	}
	e, ok = AdGuardLine(`{"T":"2026-10-25T12:00:00Z","QH":"ok.example","QT":"A","IP":"192.168.1.5","Result":{}}`)
	if !ok || e.DNS.RCode != "NOERROR" {
		t.Errorf("%+v", e)
	}
	for _, bad := range []string{"", "{", `{"QH":"x"}`, `{"T":"2026-10-25T12:00:00Z","QH":"x","IP":"nope"}`, `{"T":"2026-10-25T12:00:00Z","QH":"a b","IP":"1.1.1.1"}`} {
		if _, ok := AdGuardLine(bad); ok {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func FuzzDNSLogs(f *testing.F) {
	f.Add("Oct 25 12:00:00 dnsmasq[1]: query[A] a.example from 1.1.1.1")
	f.Add("Oct 25 12:00:00 dnsmasq[1]: reply a.example is 1.2.3.4")
	f.Add("Oct 25 12:00:00 dnsmasq[1]: gravity blocked a.example is 0.0.0.0")
	f.Add(`{"T":"2026-10-25T12:00:00Z","QH":"a","IP":"1.1.1.1"}`)
	f.Fuzz(func(t *testing.T, line string) {
		l := newLog()
		for range 3 {
			l.Line(line)
		}
		l.Close()
		AdGuardLine(line)
		ParseDNSMasqLeases(line)
	})
}

func TestLeases(t *testing.T) {
	text := "1893456000 3c:22:fb:01:02:03 192.168.1.23 alice-iphone 01:3c:22\n" +
		"0 aa:bb:cc:00:00:02 192.168.1.24 * *\n" +
		"duid 00:01:00:01\n" +
		"bad line\n" +
		"1893456000 not-a-mac 192.168.1.25 x y\n" +
		"1893456000 aa:bb:cc:00:00:03 not-an-ip x y\n"
	got := ParseDNSMasqLeases(text)
	if len(got) != 2 || got[0].Hostname != "alice-iphone" || got[0].Expires.IsZero() || got[1].Hostname != "" || !got[1].Expires.IsZero() {
		t.Fatalf("%+v", got)
	}
	evs := LeaseEvents(got[0], rx)
	if len(evs) != 2 || evs[0].DHCP.MsgType != "ACK" || evs[0].DHCP.YourIP != got[0].IP || evs[0].DHCP.LeaseSecs == 0 || evs[1].Binding.IP != got[0].IP {
		t.Errorf("%+v", evs)
	}
}

type collected struct {
	mu   sync.Mutex
	evs  []wire.Event
	name []string
}

func (c *collected) sink(_ context.Context, sensor, _ string, evs []wire.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !slices.Contains(c.name, sensor) {
		c.name = append(c.name, sensor)
	}
	c.evs = append(c.evs, evs...)
	return nil
}

func (c *collected) count(typ wire.Type) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.evs {
		if e.Type == typ {
			n++
		}
	}
	return n
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(8 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out: %s", what)
}

// Real sockets: only allowed exporters are heard.
func TestNetFlowListener(t *testing.T) {
	c := &collected{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	n := &NetFlow{Listen: "127.0.0.1:0", Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Sink: c.sink, Ready: func(a string) { ready <- a }}
	go func() { _ = n.Run(ctx) }()
	conn, err := net.Dial("udp", <-ready)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(v5Packet(3, uint32(time.Now().Unix()))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the flows", func() bool { return c.count(wire.TypeFlow) == 3 && c.count(wire.TypeHello) >= 1 })
	if c.name[0] != "netflow-127.0.0.1" {
		t.Errorf("names %v", c.name)
	}
}

func TestNetFlowRefusesStrangers(t *testing.T) {
	c := &collected{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	n := &NetFlow{Listen: "127.0.0.1:0", Allow: []netip.Prefix{netip.MustParsePrefix("10.9.9.0/24")}, Sink: c.sink, Ready: func(a string) { ready <- a }}
	go func() { _ = n.Run(ctx) }()
	conn, err := net.Dial("udp", <-ready)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write(v5Packet(3, uint32(time.Now().Unix())))
	time.Sleep(2500 * time.Millisecond)
	if n := c.count(wire.TypeFlow); n != 0 {
		t.Errorf("%d flows from a stranger", n)
	}
	if err := (&NetFlow{Listen: "127.0.0.1:0", Sink: c.sink}).Run(ctx); err == nil {
		t.Error("it ran with nobody allowed")
	}
}

// The file: only what's new, across rotation and truncation, and through it being away.
func TestDNSLogFollowsTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq.log")
	now := time.Now()
	stamp := now.Format("Jan _2 15:04:05")
	line := func(name string) string {
		return stamp + " dnsmasq[1]: query[A] " + name + " from 192.168.1.5\n" + stamp + " dnsmasq[1]: reply " + name + " is 1.2.3.4\n"
	}
	if err := os.WriteFile(path, []byte(line("old.example")), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &collected{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	d := &DNSLog{Path: path, Format: "dnsmasq", Sink: c.sink, Every: 10 * time.Millisecond}
	go func() { _ = d.Run(ctx); close(done) }()
	waitFor(t, "the hello", func() bool { return c.count(wire.TypeHello) >= 1 })
	appendTo := func(p, s string) {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteString(s); err != nil {
			t.Fatal(err)
		}
	}
	appendTo(path, line("new.example"))
	appendTo(path, stamp+" dnsmasq[1]: query[A] half") // no line end yet
	time.Sleep(50 * time.Millisecond)
	appendTo(path, ".example from 192.168.1.5\n")
	// Rotated: a new file under the same name.
	time.Sleep(50 * time.Millisecond)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	appendTo(path, line("rotated.example"))
	time.Sleep(100 * time.Millisecond)
	// Truncated in place, as copytruncate does.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	appendTo(path, line("cut.example"))
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	names := []string{}
	c.mu.Lock()
	for _, e := range c.evs {
		if e.DNS != nil {
			names = append(names, e.DNS.QName)
		}
	}
	c.mu.Unlock()
	slices.Sort(names)
	want := []string{"cut.example", "half.example", "new.example", "rotated.example"}
	if !slices.Equal(names, want) {
		t.Errorf("got %v, want %v", names, want)
	}
}

func TestLeaseFileSkipsExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases")
	if err := os.WriteFile(path, []byte("1 aa:bb:cc:00:00:01 192.168.1.5 old *\n0 aa:bb:cc:00:00:02 192.168.1.6 fixed *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &collected{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = (&LeaseFile{Path: path, Sink: c.sink, Every: time.Hour}).Run(ctx) }()
	waitFor(t, "the lease", func() bool { return c.count(wire.TypeDHCP) >= 1 })
	if n := c.count(wire.TypeDHCP); n != 1 {
		t.Errorf("%d leases", n)
	}
}

const iscFile = `# The format of this file is documented in the dhcpd.leases(5) manual page.
authoring-byte-order little-endian;

lease 192.168.1.50 {
  starts 4 2026/10/29 10:00:00;
  ends 4 2026/10/29 11:00:00;
  binding state active;
  hardware ethernet 00:11:22:33:44:55;
  client-hostname "old-name";
}
lease 192.168.1.50 {
  starts 4 2026/10/29 11:00:00;
  ends 4 2026/10/29 12:00:00;
  cltt 4 2026/10/29 11:00:00;
  binding state active;
  next binding state free;
  rewind binding state free;
  hardware ethernet 00:11:22:33:44:55;
  uid "\001\000\021\"3DU";
  client-hostname "laptop";
}
lease 192.168.1.51 {
  ends epoch 1793232000; # Thu Oct 29 2026
  binding state active;
  hardware ethernet 00:11:22:33:44:66;
}
lease 192.168.1.52 {
  ends never;
  binding state active;
  hardware ethernet 00:11:22:33:44:77;
}
lease 192.168.1.60 {
  binding state active;
  hardware ethernet 00:11:22:33:44:88;
}
lease 192.168.1.60 {
  binding state free;
  hardware ethernet 00:11:22:33:44:88;
}
lease not-an-address {
  binding state active;
}
`

func TestISCLeases(t *testing.T) {
	got := ParseISCLeases(iscFile)
	if len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	if got[0].Hostname != "laptop" || got[0].MAC != "00:11:22:33:44:55" || !got[0].Expires.Equal(time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("the last block should win: %+v", got[0])
	}
	if got[1].Expires.Unix() != 1793232000 {
		t.Errorf("epoch form: %+v", got[1])
	}
	if !got[2].Expires.IsZero() {
		t.Errorf("never: %+v", got[2])
	}
}

const keaFile = `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
192.168.1.70,00:11:22:33:44:01,01:00:11,3600,1793232000,1,0,0,tv.example.,0,,0
192.168.1.71,00:11:22:33:44:02,,3600,1793232000,1,0,0,,0,,0
192.168.1.71,00:11:22:33:44:02,,3600,1793232100,1,0,0,phone,0,,0
192.168.1.72,00:11:22:33:44:03,,3600,1793232000,1,0,0,gone,0,,0
192.168.1.72,00:11:22:33:44:03,,0,1793232000,1,0,0,gone,2,,0
192.168.1.73,,,3600,1793232000,1,0,0,,0,,0
not-an-address,00:11:22:33:44:04,,3600,1793232000,1,0,0,,0,,0
short
`

func TestKeaLeases(t *testing.T) {
	got := ParseKeaLeases(keaFile)
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	if got[0].Hostname != "tv.example" || got[0].Expires.Unix() != 1793232000 {
		t.Errorf("%+v", got[0])
	}
	if got[1].Hostname != "phone" || got[1].Expires.Unix() != 1793232100 {
		t.Errorf("the last row should win: %+v", got[1])
	}
	if ParseKeaLeases("not,a,lease,file\n1,2,3,4\n") != nil {
		t.Error("read a file with no address column")
	}
}

func TestKeaLeasesWithNoStateColumn(t *testing.T) {
	got := ParseKeaLeases("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname\n192.168.1.70,00:11:22:33:44:01,,3600,1793232000,1,0,0,tv\n")
	if len(got) != 1 || got[0].Hostname != "tv" {
		t.Errorf("%+v", got)
	}
}

func TestKeaLeases6(t *testing.T) {
	text := "address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state\n" +
		"2001:db8::5,00:01,3600,1793232000,1,1800,0,1,128,0,0,nas,00:11:22:33:44:09,0\n"
	got := ParseLeases("kea", text)
	if len(got) != 1 || got[0].IP.String() != "2001:db8::5" || got[0].MAC != "00:11:22:33:44:09" {
		t.Fatalf("%+v", got)
	}
	evs := LeaseEvents(got[0], rx)
	for _, e := range evs {
		if e.Type == wire.TypeDHCP {
			t.Errorf("an IPv6 lease as a DHCPv4 event: %+v", e.DHCP)
		}
	}
	if len(evs) != 2 || evs[1].Name.Name != "nas" {
		t.Errorf("%+v", evs)
	}
}

func FuzzLeases(f *testing.F) {
	f.Add(iscFile)
	f.Add(keaFile)
	f.Add("1793232000 aa:bb:cc:dd:ee:ff 10.0.0.1 host *\n")
	f.Fuzz(func(t *testing.T, s string) {
		for _, format := range []string{"dnsmasq", "isc", "kea"} {
			for _, l := range ParseLeases(format, s) {
				if !l.IP.IsValid() || l.MAC == "" || len(l.Hostname) > 253 {
					t.Fatalf("%s: %+v", format, l)
				}
				LeaseEvents(l, rx)
			}
		}
	})
}

type runner interface{ Run(context.Context) error }

// testCollector sends a datagram from an allowed and then a refused address's point of
// view, and waits for done to see the events.
func testCollector(t *testing.T, datagram []byte, build func(ready func(string), allow []netip.Prefix, sink Sink) runner, done func([]wire.Event) bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var mu sync.Mutex
	var seen []wire.Event
	sink := func(_ context.Context, _, _ string, evs []wire.Event) error {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, evs...)
		return nil
	}
	addr := make2(ctx, t, build, sink)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for ctx.Err() == nil {
		if _, err := conn.Write(datagram); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
		mu.Lock()
		ok := done(seen)
		mu.Unlock()
		if ok {
			return
		}
	}
	t.Fatal("never arrived")
}

func make2(ctx context.Context, t *testing.T, build func(ready func(string), allow []netip.Prefix, sink Sink) runner, sink Sink) string {
	t.Helper()
	ready := make(chan string, 1)
	r := build(func(a string) { ready <- a }, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, sink)
	go func() { _ = r.Run(ctx) }()
	select {
	case a := <-ready:
		return a
	case <-ctx.Done():
		t.Fatal("never listened")
		return ""
	}
}
