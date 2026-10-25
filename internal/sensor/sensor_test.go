package sensor

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/capture"
	"github.com/xen0bit/netgraph/internal/flow"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

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
