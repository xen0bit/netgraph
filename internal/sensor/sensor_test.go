package sensor

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/flow"
	"github.com/xen0bit/netgraph/internal/rdns"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wifi"
	"github.com/xen0bit/netgraph/internal/wire"
	"golang.org/x/net/dns/dnsmessage"
)

// A monitor-mode frame goes to the Wi-Fi decoder instead of the Ethernet
// parser, and its observation leaves through the same emitter.
func TestWiFiLinkDispatch(t *testing.T) {
	var out collector
	wp := wifi.NewProcessor(wifi.Config{Emit: func(ev wire.Event) { out.Emit(ev) }})
	p := NewProcessor(Config{WiFi: wp}, &out)

	ap := []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b, 0x0080)
	copy(b[4:10], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(b[10:16], ap)
	copy(b[16:22], ap)
	b = append(b, make([]byte, 12)...)
	b = append(b, 0, 4, 'h', 'o', 'm', 'e')
	p.Handle(testutil.Base, b, capture.LinkIEEE80211)
	ev := out.of(wire.TypeWiFi)
	if len(ev) != 1 || ev[0].WiFi == nil || ev[0].WiFi.SSID != "home" || ev[0].WiFi.BSSID != "aa:bb:cc:00:00:01" {
		t.Fatalf("wifi events = %+v", ev)
	}
}

type ptrResolver struct {
	mu    sync.Mutex
	names map[string][]string
	calls int
}

func (r *ptrResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return r.names[addr], nil
}

// The sensor asks for a reverse name when it first sees a host, and emits the
// answer stamped with that observation time.
func TestReverseDNSAtObservation(t *testing.T) {
	capt := testutil.Home(t)
	ts, frames := capt.Frames()
	var arp []byte
	var at time.Time
	for i, f := range frames {
		if len(f) >= 14 && f[12] == 0x08 && f[13] == 0x06 {
			arp, at = f, ts[i]
			break
		}
	}
	if arp == nil {
		t.Fatal("scenario has no ARP frame")
	}
	res := &ptrResolver{names: map[string][]string{testutil.Phone.IP.String(): {"alice-iphone.lan."}}}
	names := make(chan wire.Event, 4)
	lookup := rdns.New(rdns.Config{Resolver: res, Workers: 1, Emit: func(n rdns.Name) {
		names <- wire.Event{Type: wire.TypeName, TS: n.TS, Name: &wire.Name{MAC: n.MAC, IP: n.IP, Name: n.Name, Proto: "rdns"}}
	}})
	defer lookup.Close()

	var out collector
	p := NewProcessor(Config{RDNS: lookup, IsLocal: LocalAddr}, &out)
	p.Handle(at, arp, capture.LinkEthernet)
	select {
	case ev := <-names:
		if ev.Name == nil || ev.Name.Proto != "rdns" || ev.Name.Name != "alice-iphone.lan" ||
			ev.Name.IP != testutil.Phone.IP || ev.Name.MAC != testutil.Phone.MAC.String() {
			t.Fatalf("rdns event = %+v", ev.Name)
		}
		if !ev.TS.Equal(at) {
			t.Errorf("rdns ts = %v, want observation %v", ev.TS, at)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no rDNS event")
	}
}

type collector struct{ events []wire.Event }

func (c *collector) Emit(ev wire.Event) { c.events = append(c.events, ev) }

func (c *collector) of(t wire.Type) []wire.Event {
	var out []wire.Event
	for _, e := range c.events {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

func replayHome(t *testing.T) (*collector, *testutil.Capture) {
	t.Helper()
	capt := testutil.Home(t)
	src, err := capture.OpenFile(capt.WriteFile())
	if err != nil {
		t.Fatal(err)
	}
	var out collector
	proc := NewProcessor(Config{Flow: flow.Config{ActiveTimeout: 30 * time.Second}}, &out)
	r := &Runner{Processor: proc, Out: &out, Hello: wire.Hello{Name: "test"}}
	if err := r.RunFile(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	return &out, capt
}

func TestReplayHome(t *testing.T) {
	out, capt := replayHome(t)
	if len(out.of(wire.TypeHello)) != 1 || len(out.of(wire.TypeStats)) != 1 {
		t.Errorf("hello/stats: %d/%d", len(out.of(wire.TypeHello)), len(out.of(wire.TypeStats)))
	}
	_, _, decodeErrors, _, _ := NewProcessor(Config{}, out).Counters()
	_ = decodeErrors

	t.Run("dhcp", func(t *testing.T) {
		dh := out.of(wire.TypeDHCP)
		if len(dh) != 2 {
			t.Fatalf("got %d dhcp events", len(dh))
		}
		req, ack := dh[0].DHCP, dh[1].DHCP
		if req.MsgType != "REQUEST" || req.Hostname != "alice-iphone" || req.MAC != testutil.Phone.MAC.String() || req.VendorClass != "apple-ios" || req.ParamList != "1,3,6,15,119,252" {
			t.Errorf("request = %+v", req)
		}
		if ack.MsgType != "ACK" || ack.YourIP != testutil.Phone.IP || ack.LeaseSecs != 86400 || ack.MAC != testutil.Phone.MAC.String() {
			t.Errorf("ack = %+v", ack)
		}
	})

	t.Run("bindings", func(t *testing.T) {
		var got []string
		for _, e := range out.of(wire.TypeBinding) {
			got = append(got, e.Binding.Source+" "+e.Binding.MAC+" "+e.Binding.IP.String())
		}
		want := []string{"arp " + testutil.Phone.MAC.String() + " 192.168.1.23", "ndp " + testutil.TV.MAC.String() + " fd00::50"}
		if !slices.Equal(got, want) {
			t.Errorf("bindings = %q, want %q", got, want)
		}
	})

	t.Run("dns", func(t *testing.T) {
		byName := map[string]*wire.DNS{}
		for _, e := range out.of(wire.TypeDNS) {
			byName[e.DNS.QName] = e.DNS
		}
		www := byName["www.example.com"]
		if www == nil || www.RCode != "NOERROR" || www.Client != testutil.Phone.IP || www.ClientMAC != testutil.Phone.MAC.String() || len(www.Answers) != 2 ||
			www.Answers[1].Data != testutil.ExampleIP.String() || www.Answers[1].TTL != 300 || www.LatencyMS != 12 {
			t.Errorf("www = %+v", www)
		}
		if nx := byName["nope.invalid"]; nx == nil || nx.RCode != "NXDOMAIN" {
			t.Errorf("nxdomain = %+v", nx)
		}
		if lost := byName["lost.example.com"]; lost == nil || lost.RCode != "TIMEOUT" {
			t.Errorf("timeout = %+v", lost)
		}
	})

	t.Run("flows", func(t *testing.T) {
		cli := netip.AddrPortFrom(testutil.Phone.IP, 50000)
		srv := netip.AddrPortFrom(testutil.ExampleIP, 443)
		var recs []*wire.Flow
		var bout, bin uint64
		for _, e := range out.of(wire.TypeFlow) {
			if f := e.Flow; f.Src == cli.Addr() && f.SrcPort == 50000 {
				recs = append(recs, f)
				bout += f.BytesOut
				bin += f.BytesIn
			}
		}
		wantOut, wantIn := capt.FlowBytes(cli, srv)
		if bout != wantOut || bin != wantIn {
			t.Errorf("tls bytes = %d/%d, want %d/%d", bout, bin, wantOut, wantIn)
		}
		// 6s..125s with a 30s active timeout: several interval records,
		// one final, all sharing the flow ID and the learned metadata.
		if len(recs) < 4 || !recs[len(recs)-1].Final || recs[len(recs)-1].EndReason != "fin" {
			t.Fatalf("records = %d, last %+v", len(recs), recs[len(recs)-1])
		}
		for _, f := range recs {
			if f.ID != recs[0].ID || f.SNI != "www.example.com" || f.App != "tls" || f.ALPN != "h2" || f.JA4 == "" || !f.FirstSeen.Equal(testutil.Base.Add(testutil.AtTLSOpen)) {
				t.Fatalf("record %+v", f)
			}
		}
		var quic, http *wire.Flow
		for _, e := range out.of(wire.TypeFlow) {
			switch e.Flow.Dst {
			case testutil.QUICIP:
				quic = e.Flow
			case testutil.PlainIP:
				http = e.Flow
			}
		}
		if quic == nil || quic.App != "quic" || quic.SNI != "quic.example.org" || quic.ALPN != "h3" || quic.JA4[0] != 'q' {
			t.Errorf("quic = %+v", quic)
		}
		if http == nil || http.App != "http" || http.HTTPHost != "plain.example.net" || http.UserAgent != "CrKey/1.56" || http.SrcMAC != testutil.TV.MAC.String() {
			t.Errorf("http = %+v", http)
		}
	})

	t.Run("identity", func(t *testing.T) {
		md := out.of(wire.TypeMDNS)
		if len(md) != 1 || len(md[0].MDNS.Services) != 1 || md[0].MDNS.Services[0].Type != "_ipp._tcp" || md[0].MDNS.Services[0].TXT["ty"] != "Brother HL-L2350DW" ||
			len(md[0].MDNS.Hosts) != 1 || md[0].MDNS.Hosts[0].Name != "BRN001BA9.local" {
			t.Errorf("mdns = %+v", md)
		}
		names := out.of(wire.TypeName)
		if len(names) != 2 || names[0].Name.Name != "desktop-1" || names[0].Name.Proto != "nbns" || names[1].Name.Proto != "llmnr" {
			t.Errorf("names = %+v %+v", names[0].Name, names[1].Name)
		}
		ss := out.of(wire.TypeSSDP)
		if len(ss) != 1 || ss[0].SSDP.Server != "Linux/4.9 UPnP/1.0 Chromecast/1.56" || ss[0].SSDP.MAC != testutil.TV.MAC.String() {
			t.Errorf("ssdp = %+v", ss)
		}
		ll := out.of(wire.TypeLLDP)
		if len(ll) != 1 || ll[0].LLDP.SystemName != "core-switch" || ll[0].LLDP.PortID != "port-7" {
			t.Errorf("lldp = %+v", ll)
		}
	})
}

// Replaying twice gives identical events: replay depends on packet time
// alone, never the wall clock.
func TestDNSOverTCPReassembly(t *testing.T) {
	var out collector
	p := NewProcessor(Config{}, &out)
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, ID: 7})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("split.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := b.AResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("split.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
		dnsmessage.AResource{A: testutil.ExampleIP.As4()}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(payload, uint16(len(msg)))
	copy(payload[2:], msg)
	mk := func(seq uint32, part []byte) []byte {
		eth := make([]byte, 14)
		copy(eth[0:6], []byte{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03})
		copy(eth[6:12], []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01})
		binary.BigEndian.PutUint16(eth[12:], 0x0800)
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+20+len(part)))
		ip[8], ip[9] = 64, 6
		copy(ip[12:16], testutil.Router.IP.AsSlice())
		copy(ip[16:20], testutil.Phone.IP.AsSlice())
		tcp := make([]byte, 20)
		binary.BigEndian.PutUint16(tcp[0:], 53)
		binary.BigEndian.PutUint16(tcp[2:], 40000)
		binary.BigEndian.PutUint32(tcp[4:], seq)
		tcp[12] = 0x50
		tcp[13] = 0x18
		return append(append(append(eth, ip...), tcp...), part...)
	}
	p.Handle(testutil.Base, mk(1000, payload[:5]), capture.LinkEthernet)
	p.Handle(testutil.Base.Add(time.Millisecond), mk(1005, payload[5:]), capture.LinkEthernet)
	var got *wire.DNS
	for _, e := range out.of(wire.TypeDNS) {
		if e.DNS != nil && e.DNS.QName == "split.example" {
			got = e.DNS
		}
	}
	if got == nil || len(got.Answers) != 1 || got.RCode != "NOERROR" {
		t.Fatalf("dns event = %+v", got)
	}
}

func TestReplayDeterministic(t *testing.T) {
	a, _ := replayHome(t)
	b, _ := replayHome(t)
	var ja, jb bytes.Buffer
	wa, wb := wire.NewJSONWriter(&ja), wire.NewJSONWriter(&jb)
	for _, e := range a.events {
		if e.Type != wire.TypeStats {
			wa.Emit(e)
		}
	}
	for _, e := range b.events {
		if e.Type != wire.TypeStats {
			wb.Emit(e)
		}
	}
	if ja.String() != jb.String() {
		t.Fatal("two replays of the same capture differ")
	}
}

func TestDedupe(t *testing.T) {
	var out collector
	p := NewProcessor(Config{Dedupe: time.Minute}, &out)
	capt := testutil.Home(t)
	ts, frames := capt.Frames()
	// Find the SSDP frame and feed it three times.
	for i, f := range frames {
		if bytes.Contains(f, []byte("NOTIFY * HTTP/1.1")) {
			p.Handle(ts[i], f, capture.LinkEthernet)
			p.Handle(ts[i].Add(10*time.Second), f, capture.LinkEthernet)
			p.Handle(ts[i].Add(2*time.Minute), f, capture.LinkEthernet)
		}
	}
	if n := len(out.of(wire.TypeSSDP)); n != 2 {
		t.Fatalf("got %d ssdp events, want 2", n)
	}
}

func FuzzHandle(f *testing.F) {
	capt := testutil.Home(f)
	_, frames := capt.Frames()
	for _, fr := range frames {
		f.Add(fr)
	}
	p := NewProcessor(Config{}, &collector{})
	f.Fuzz(func(t *testing.T, b []byte) {
		var fr frame
		parseFrame(b, capture.LinkEthernet, &fr)
		parseFrame(b, capture.LinkSLL, &fr)
		parseFrame(b, capture.LinkRaw, &fr)
		p.Handle(time.Unix(0, 0), b, capture.LinkEthernet)
	})
}

// A pcap with radiotap link type replays through the same Wi-Fi decoder,
// which is how captures can be tested without a monitor interface.
func TestWiFiPcapReplay(t *testing.T) {
	ap := []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02}
	b := make([]byte, 24)
	binary.LittleEndian.PutUint16(b, 0x0080)
	copy(b[4:10], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(b[10:16], ap)
	copy(b[16:22], ap)
	b = append(b, make([]byte, 12)...)
	b = append(b, 0, 5, 'l', 'a', 'b', 'w', 'i')
	frame := wifiRadiotap(2412, -55, b)

	var buf bytes.Buffer
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 65535)
	binary.LittleEndian.PutUint32(hdr[20:], capture.LinkIEEE80211Radiotap)
	buf.Write(hdr)
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[0:], uint32(testutil.Base.Unix()))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(frame)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(frame)))
	buf.Write(rec)
	buf.Write(frame)
	path := filepath.Join(t.TempDir(), "wifi.pcap")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	src, err := capture.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if src.LinkType() != capture.LinkIEEE80211Radiotap {
		t.Fatalf("link type = %d", src.LinkType())
	}
	var out collector
	wp := wifi.NewProcessor(wifi.Config{Emit: func(ev wire.Event) { out.Emit(ev) }})
	r := &Runner{Processor: NewProcessor(Config{WiFi: wp}, &out), Out: &out}
	if err := r.RunFile(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	ev := out.of(wire.TypeWiFi)
	if len(ev) != 1 || ev[0].WiFi.SSID != "labwi" || ev[0].WiFi.Channel != 1 {
		t.Fatalf("wifi pcap events = %+v", ev)
	}
}

func wifiRadiotap(freq, signal int, frame []byte) []byte {
	rt := make([]byte, 15)
	binary.LittleEndian.PutUint16(rt[2:], 15)
	binary.LittleEndian.PutUint32(rt[4:], 1<<1|1<<3|1<<5)
	binary.LittleEndian.PutUint16(rt[10:], uint16(freq))
	rt[14] = byte(int8(signal))
	return append(rt, frame...)
}

// testdata/curl-clienthello.pcap holds real ClientHellos from curl 8.14
// (OpenSSL), TLS 1.3 and TLS 1.2. The expected JA4 values were computed by
// Wireshark 4.6.6 (tls.handshake.ja4) on the same file: an independent
// implementation pinning ours.
func TestJA4MatchesWireshark(t *testing.T) {
	src, err := capture.OpenFile("testdata/curl-clienthello.pcap")
	if err != nil {
		t.Fatal(err)
	}
	var out collector
	r := &Runner{Processor: NewProcessor(Config{}, &out), Out: &out}
	if err := r.RunFile(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"example.com": "t13d3012h2_1d37bd780c83_882d495ac381",
		"example.org": "t12d2708h2_a2460661a67a_eed5f1524d5c",
	}
	got := map[string]string{}
	for _, e := range out.of(wire.TypeFlow) {
		if e.Flow.SNI != "" {
			got[e.Flow.SNI] = e.Flow.JA4
		}
	}
	for sni, ja4 := range want {
		if got[sni] != ja4 {
			t.Errorf("%s: ja4 %q, want %q (Wireshark)", sni, got[sni], ja4)
		}
	}
}

func TestResolveInterface(t *testing.T) {
	if n, err := ResolveInterface("br-lan"); err != nil || n != "br-lan" {
		t.Fatalf("name: %q %v", n, err)
	}
	if n, err := ResolveInterface("127.0.0.1"); err != nil || n == "" {
		t.Fatalf("loopback by address: %q %v", n, err)
	}
	if n, err := ResolveInterface("127.0.0.0/8"); err != nil || n == "" {
		t.Fatalf("loopback by prefix: %q %v", n, err)
	}
	if _, err := ResolveInterface("203.0.113.254"); err == nil {
		t.Fatal("found an interface for an address nobody holds")
	}
}

func dnsResponseName(t *testing.T, name string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, ID: 9})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := b.AResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
		dnsmessage.AResource{A: testutil.ExampleIP.As4()}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func udpDNSPacket(msg []byte) []byte {
	b := make([]byte, 8+len(msg))
	binary.BigEndian.PutUint16(b[0:], 53)
	binary.BigEndian.PutUint16(b[2:], 40000)
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)))
	binary.BigEndian.PutUint16(b[6:], 0)
	copy(b[8:], msg)
	return b
}

func TestIPv4FragmentReassembly(t *testing.T) {
	var out collector
	p := NewProcessor(Config{}, &out)
	msg := udpDNSPacket(dnsResponseName(t, "v4frag.example."))
	mk := func(off int, more bool, part []byte) []byte {
		eth := make([]byte, 14)
		copy(eth[0:6], []byte{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03})
		copy(eth[6:12], []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01})
		binary.BigEndian.PutUint16(eth[12:], 0x0800)
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(part)))
		binary.BigEndian.PutUint16(ip[4:], 0x1234)
		flags := uint16(off / 8)
		if more {
			flags |= 0x2000
		}
		binary.BigEndian.PutUint16(ip[6:], flags)
		ip[8], ip[9] = 64, 17
		copy(ip[12:16], testutil.Router.IP.AsSlice())
		copy(ip[16:20], testutil.Phone.IP.AsSlice())
		return append(append(eth, ip...), part...)
	}
	p.Handle(testutil.Base, mk(0, true, msg[:16]), capture.LinkEthernet)
	p.Handle(testutil.Base.Add(time.Millisecond), mk(16, false, msg[16:]), capture.LinkEthernet)
	var got *wire.DNS
	for _, e := range out.of(wire.TypeDNS) {
		if e.DNS != nil && e.DNS.QName == "v4frag.example" {
			got = e.DNS
		}
	}
	if got == nil || len(got.Answers) != 1 {
		t.Fatalf("fragmented DNS event = %+v", got)
	}
}

func TestIPv6FragmentReassembly(t *testing.T) {
	var out collector
	p := NewProcessor(Config{}, &out)
	msg := udpDNSPacket(dnsResponseName(t, "v6frag.example."))
	mk := func(off int, more bool, part []byte) []byte {
		eth := make([]byte, 14)
		copy(eth[0:6], []byte{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03})
		copy(eth[6:12], []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01})
		binary.BigEndian.PutUint16(eth[12:], 0x86dd)
		ip := make([]byte, 48)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], uint16(8+len(part)))
		ip[6] = 44
		ip[7] = 64
		src16, dst16 := testutil.Router.IP.As16(), testutil.Phone.IP.As16()
		copy(ip[8:24], src16[:])
		copy(ip[24:40], dst16[:])
		ip[40] = 17
		f := uint16(off)
		if more {
			f |= 1
		}
		binary.BigEndian.PutUint16(ip[42:], f)
		binary.BigEndian.PutUint32(ip[44:], 0x12345678)
		return append(append(eth, ip...), part...)
	}
	p.Handle(testutil.Base, mk(0, true, msg[:16]), capture.LinkEthernet)
	p.Handle(testutil.Base.Add(time.Millisecond), mk(16, false, msg[16:]), capture.LinkEthernet)
	var got *wire.DNS
	for _, e := range out.of(wire.TypeDNS) {
		if e.DNS != nil && e.DNS.QName == "v6frag.example" {
			got = e.DNS
		}
	}
	if got == nil || len(got.Answers) != 1 {
		t.Fatalf("fragmented IPv6 DNS event = %+v", got)
	}
}

func tcpDNSSegment(seq uint32, part []byte) []byte {
	eth := make([]byte, 14)
	copy(eth[0:6], []byte{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03})
	copy(eth[6:12], []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01})
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(40+len(part)))
	ip[8], ip[9] = 64, 6
	copy(ip[12:16], testutil.Router.IP.AsSlice())
	copy(ip[16:20], testutil.Phone.IP.AsSlice())
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 53)
	binary.BigEndian.PutUint16(tcp[2:], 40000)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 0x50
	tcp[13] = 0x18
	return append(append(append(eth, ip...), tcp...), part...)
}

func TestDNSOverTCPOutOfOrder(t *testing.T) {
	var out collector
	p := NewProcessor(Config{}, &out)
	msg := dnsResponseName(t, "reorder.example.")
	payload := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(payload, uint16(len(msg)))
	copy(payload[2:], msg)
	p.Handle(testutil.Base, tcpDNSSegment(1005, payload[5:]), capture.LinkEthernet)
	p.Handle(testutil.Base.Add(time.Millisecond), tcpDNSSegment(1000, payload[:5]), capture.LinkEthernet)
	var got *wire.DNS
	for _, e := range out.of(wire.TypeDNS) {
		if e.DNS != nil && e.DNS.QName == "reorder.example" {
			got = e.DNS
		}
	}
	if got == nil || len(got.Answers) != 1 {
		t.Fatalf("out-of-order DNS event = %+v", got)
	}
}
