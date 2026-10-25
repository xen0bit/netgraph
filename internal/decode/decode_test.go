package decode

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func mustName(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }

// buildDNS builds a message with dnsmessage, which compresses names: that
// is what exercises readName's pointer handling against an independent
// encoder.
func buildDNS(t testing.TB, hdr dnsmessage.Header, qs []dnsmessage.Question, fill func(b *dnsmessage.Builder)) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, hdr)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	for _, q := range qs {
		if err := b.Question(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if fill != nil {
		fill(&b)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func rh(name string, typ dnsmessage.Type, ttl uint32) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{Name: mustName(name), Type: typ, Class: dnsmessage.ClassINET, TTL: ttl}
}

func TestParseDNSResponse(t *testing.T) {
	msg := buildDNS(t, dnsmessage.Header{ID: 0xbeef, Response: true, RCode: dnsmessage.RCodeSuccess},
		[]dnsmessage.Question{{Name: mustName("www.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		func(b *dnsmessage.Builder) {
			must(t, b.CNAMEResource(rh("www.example.com.", dnsmessage.TypeCNAME, 300), dnsmessage.CNAMEResource{CNAME: mustName("edge.example.net.")}))
			must(t, b.AResource(rh("edge.example.net.", dnsmessage.TypeA, 60), dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}))
			must(t, b.AAAAResource(rh("edge.example.net.", dnsmessage.TypeAAAA, 60), dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2606:2800:220:1::1").As16()}))
			https := dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{Priority: 1, Target: mustName(".")}}
			https.SetParam(dnsmessage.SVCParamIPv4Hint, []byte{203, 0, 113, 7})
			must(t, b.HTTPSResource(rh("www.example.com.", dnsmessage.TypeHTTPS, 120), https))
		})
	m, err := ParseDNS(msg)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != 0xbeef || !m.Response || m.Questions[0].Name != "www.example.com" || m.Questions[0].Type != TypeA {
		t.Fatalf("header/question wrong: %+v", m)
	}
	got := Answers(m)
	want := []struct {
		name, typ, data string
		ttl             uint32
	}{
		{"www.example.com", "CNAME", "edge.example.net", 300},
		{"edge.example.net", "A", "93.184.216.34", 60},
		{"edge.example.net", "AAAA", "2606:2800:220:1::1", 60},
		{"www.example.com", "HTTPS", ".", 120},
		{"www.example.com", "HTTPS", "203.0.113.7", 120},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d answers: %+v", len(got), got)
	}
	for i, w := range want {
		if g := got[i]; g.Name != w.name || g.Type != w.typ || g.Data != w.data || g.TTL != w.ttl {
			t.Errorf("answer %d = %+v, want %+v", i, g, w)
		}
	}
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadNameRejectsLoops(t *testing.T) {
	// Header, then a question whose name is a pointer to itself.
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:], 1)
	msg = append(msg, 0xc0, 12, 0, 1, 0, 1)
	if _, err := ParseDNS(msg); err == nil {
		t.Fatal("self-pointer accepted")
	}
	// Forward pointer.
	msg = msg[:12]
	msg = append(msg, 0xc0, 20, 0, 1, 0, 1, 0, 0, 3, 'f', 'o', 'o', 0)
	if _, err := ParseDNS(msg); err == nil {
		t.Fatal("forward pointer accepted")
	}
}

func TestMDNSServices(t *testing.T) {
	msg := buildDNS(t, dnsmessage.Header{Response: true, Authoritative: true}, nil, func(b *dnsmessage.Builder) {
		must(t, b.PTRResource(rh("_airplay._tcp.local.", dnsmessage.TypePTR, 4500), dnsmessage.PTRResource{PTR: mustName("Living Room._airplay._tcp.local.")}))
		must(t, b.SRVResource(rh("Living Room._airplay._tcp.local.", dnsmessage.TypeSRV, 120), dnsmessage.SRVResource{Port: 7000, Target: mustName("Apple-TV.local.")}))
		must(t, b.TXTResource(rh("Living Room._airplay._tcp.local.", dnsmessage.TypeTXT, 4500), dnsmessage.TXTResource{TXT: []string{"model=AppleTV11,1", "deviceid=AA:BB"}}))
		must(t, b.AResource(rh("Apple-TV.local.", dnsmessage.TypeA, 120), dnsmessage.AResource{A: [4]byte{192, 168, 1, 50}}))
	})
	m, err := ParseDNS(msg)
	if err != nil {
		t.Fatal(err)
	}
	ev := MDNS(m, netip.MustParseAddr("192.168.1.50"), "aa:bb:cc:dd:ee:ff")
	if ev == nil || len(ev.Services) != 1 {
		t.Fatalf("got %+v", ev)
	}
	s := ev.Services[0]
	if s.Instance != "Living Room._airplay._tcp.local" || s.Type != "_airplay._tcp" || s.Port != 7000 || s.Target != "Apple-TV.local" || s.TXT["model"] != "AppleTV11,1" {
		t.Errorf("service = %+v", s)
	}
	if !slices.Equal(ev.Hostnames, []string{"Apple-TV.local"}) || len(ev.Addresses) != 1 {
		t.Errorf("hostnames=%v addrs=%v", ev.Hostnames, ev.Addresses)
	}
}

func TestLLMNRResponse(t *testing.T) {
	msg := buildDNS(t, dnsmessage.Header{ID: 7, Response: true},
		[]dnsmessage.Question{{Name: mustName("DESKTOP-1."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		func(b *dnsmessage.Builder) {
			must(t, b.AResource(rh("DESKTOP-1.", dnsmessage.TypeA, 30), dnsmessage.AResource{A: [4]byte{10, 0, 0, 5}}))
		})
	m, _ := ParseDNS(msg)
	names := LLMNR(m, netip.MustParseAddr("10.0.0.5"), "")
	if len(names) != 1 || names[0].Name != "desktop-1" || names[0].Proto != "llmnr" {
		t.Fatalf("got %+v", names)
	}
}

// nbEncode is RFC 1001 first-level encoding of a 15-char name plus suffix.
func nbEncode(name string, suffix byte) string {
	raw := []byte(name)
	for len(raw) < 15 {
		raw = append(raw, ' ')
	}
	raw = append(raw[:15], suffix)
	out := make([]byte, 0, 32)
	for _, c := range raw {
		out = append(out, 'A'+c>>4, 'A'+c&0xf)
	}
	return string(out)
}

func TestNBNSRegistration(t *testing.T) {
	msg := []byte{0x12, 0x34, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 1} // opcode 5 registration, RD, B
	name := encodeName(nbEncode("FILESERVER", 0x20))
	msg = append(msg, name...)
	msg = append(msg, 0, 0x20, 0, 1)           // question NB IN
	msg = append(msg, 0xc0, 12)                // additional: pointer to the name
	msg = append(msg, 0, 0x20, 0, 1)           // NB IN
	msg = append(msg, 0, 0, 0x0e, 0x10)        // TTL
	msg = append(msg, 0, 6, 0, 0, 10, 0, 0, 9) // rdata: flags, 10.0.0.9
	m, err := ParseDNS(msg)
	if err != nil {
		t.Fatal(err)
	}
	names := NBNS(m, netip.MustParseAddr("10.0.0.9"), "00:11:22:33:44:55")
	if len(names) != 1 || names[0].Name != "fileserver" || names[0].Suffix != "file-server" || names[0].IP.String() != "10.0.0.9" {
		t.Fatalf("got %+v", names)
	}
}

func dhcp4Packet(msgType byte, opts ...[]byte) []byte {
	b := make([]byte, 240)
	b[0], b[1], b[2] = 1, 1, 6
	copy(b[28:], []byte{0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03})
	binary.BigEndian.PutUint32(b[236:], 0x63825363)
	b = append(b, 53, 1, msgType)
	for _, o := range opts {
		b = append(b, o...)
	}
	return append(b, 255)
}

func TestDHCPv4(t *testing.T) {
	pkt := dhcp4Packet(3,
		[]byte{12, 12, 'a', 'l', 'i', 'c', 'e', '-', 'i', 'p', 'h', 'o', 'n', 'e'},
		[]byte{50, 4, 192, 168, 1, 23},
		[]byte{55, 4, 1, 3, 6, 15},
		[]byte{60, 4, 'M', 'S', 'F', 'T'},
		[]byte{61, 7, 1, 0x3c, 0x22, 0xfb, 0x01, 0x02, 0x03},
		append([]byte{81, byte(3 + len(encodeName("alice.home.arpa"))), 0x04, 0, 0}, encodeName("alice.home.arpa")...),
	)
	ev, err := DHCPv4(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if ev.MsgType != "REQUEST" || ev.MAC != "3c:22:fb:01:02:03" || ev.Hostname != "alice-iphone" ||
		ev.RequestedIP.String() != "192.168.1.23" || ev.ParamList != "1,3,6,15" || ev.VendorClass != "MSFT" ||
		ev.ClientID != "013c22fb010203" || ev.FQDN != "alice.home.arpa" {
		t.Fatalf("got %+v", ev)
	}
	if _, err := DHCPv4(pkt[:100]); err == nil {
		t.Fatal("short packet accepted")
	}
}

func TestDHCPv6(t *testing.T) {
	duid := []byte{0, 3, 0, 1, 0x3c, 0x22, 0xfb, 0x0a, 0x0b, 0x0c} // DUID-LL
	ia := make([]byte, 12)
	addr := netip.MustParseAddr("fd00::23").As16()
	iaaddr := append(append([]byte{}, addr[:]...), 0, 0, 0x0e, 0x10, 0, 0, 0x1c, 0x20)
	ia = append(ia, opt6(5, iaaddr)...)
	fqdn := append([]byte{0}, encodeName("bob-laptop.lan")...)
	msg := append([]byte{7, 1, 2, 3}, opt6(1, duid)...)
	msg = append(msg, opt6(3, ia)...)
	msg = append(msg, opt6(39, fqdn)...)
	ev, err := DHCPv6(msg, "02:00:00:00:00:01")
	if err != nil {
		t.Fatal(err)
	}
	if ev.MsgType != "REPLY" || ev.MAC != "3c:22:fb:0a:0b:0c" || ev.Hostname != "bob-laptop" || ev.FQDN != "bob-laptop.lan" ||
		len(ev.Addresses) != 1 || ev.Addresses[0].String() != "fd00::23" || ev.LeaseSecs != 7200 {
		t.Fatalf("got %+v", ev)
	}
}

func opt6(code uint16, v []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, code)
	b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
	return append(b, v...)
}

func TestARP(t *testing.T) {
	pkt := []byte{0, 1, 8, 0, 6, 4, 0, 2, 0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 192, 168, 1, 9}
	b := ARP(pkt)
	if b == nil || b.MAC != "aa:bb:cc:00:00:01" || b.IP.String() != "192.168.1.1" {
		t.Fatalf("got %+v", b)
	}
	probe := slices.Clone(pkt)
	copy(probe[14:18], []byte{0, 0, 0, 0})
	if ARP(probe) != nil {
		t.Fatal("ARP probe produced a binding")
	}
}

func TestNDP(t *testing.T) {
	target := netip.MustParseAddr("fe80::1").As16()
	na := append([]byte{136, 0, 0, 0, 0x60, 0, 0, 0}, target[:]...)
	na = append(na, 2, 1, 0x02, 0x42, 0xac, 0x11, 0x00, 0x02)
	b := NDP(na, netip.MustParseAddr("fe80::1"))
	if b == nil || b.MAC != "02:42:ac:11:00:02" || b.IP.String() != "fe80::1" || b.Source != "ndp" {
		t.Fatalf("got %+v", b)
	}
	dad := append([]byte{135, 0, 0, 0, 0, 0, 0, 0}, target[:]...)
	if NDP(dad, netip.IPv6Unspecified()) != nil {
		t.Fatal("DAD probe produced a binding")
	}
}

func lldpTLV(t uint16, v []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, t<<9|uint16(len(v))), v...)
}

func TestLLDP(t *testing.T) {
	var b []byte
	b = append(b, lldpTLV(1, []byte{4, 0x00, 0x1b, 0x21, 0x01, 0x02, 0x03})...)
	b = append(b, lldpTLV(2, append([]byte{5}, "ge-0/0/1"...))...)
	b = append(b, lldpTLV(3, []byte{0, 120})...)
	b = append(b, lldpTLV(5, []byte("core-switch"))...)
	b = append(b, lldpTLV(8, []byte{5, 1, 10, 0, 0, 2, 2, 0, 0, 0, 1, 0})...)
	b = append(b, lldpTLV(0, nil)...)
	ev, err := LLDP(b, "00:1b:21:01:02:03")
	if err != nil {
		t.Fatal(err)
	}
	if ev.ChassisID != "00:1b:21:01:02:03" || ev.PortID != "ge-0/0/1" || ev.SystemName != "core-switch" || ev.MgmtAddress != "10.0.0.2" {
		t.Fatalf("got %+v", ev)
	}
}

func TestSSDPAndHTTP(t *testing.T) {
	ev := SSDP([]byte("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: urn:schemas-upnp-org:device:MediaRenderer:1\r\nNTS: ssdp:alive\r\nSERVER: Linux/5.4 UPnP/1.0 Sonos/70.3\r\nUSN: uuid:RINCON_1::urn:schemas-upnp-org:device:MediaRenderer:1\r\nLOCATION: http://192.168.1.60:1400/xml/device_description.xml\r\n\r\n"),
		netip.MustParseAddr("192.168.1.60"), "")
	if ev == nil || ev.Method != "NOTIFY" || ev.Server != "Linux/5.4 UPnP/1.0 Sonos/70.3" || ev.NT != "urn:schemas-upnp-org:device:MediaRenderer:1" || ev.Location == "" {
		t.Fatalf("got %+v", ev)
	}
	host, ua, ok, complete := HTTPRequest([]byte("GET /x HTTP/1.1\r\nHost: Plain.Example.com\r\nUser-Agent: curl/8.11.0\r\n\r\n"))
	if !ok || !complete || host != "plain.example.com" || ua != "curl/8.11.0" {
		t.Fatalf("http: %q %q %v %v", host, ua, ok, complete)
	}
	if _, _, ok, _ := HTTPRequest([]byte("\x16\x03\x01")); ok {
		t.Fatal("TLS taken for HTTP")
	}
}

// goClientHello captures the ClientHello crypto/tls sends, a real
// implementation's output rather than a hand-built fixture.
func goClientHello(t testing.TB, sni string, alpn []string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		c := tls.Client(client, &tls.Config{ServerName: sni, NextProtos: alpn, InsecureSkipVerify: true})
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_ = c.Handshake()
		c.Close()
	}()
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		n, err := server.Read(tmp)
		buf.Write(tmp[:n])
		if _, perr := ParseTLSRecords(buf.Bytes()); perr != ErrNeedMore || err != nil {
			break
		}
	}
	return buf.Bytes()
}

var ja4Re = regexp.MustCompile(`^t13d\d{4}h2_[0-9a-f]{12}_[0-9a-f]{12}$`)

func TestClientHelloFromCryptoTLS(t *testing.T) {
	raw := goClientHello(t, "www.Example.com", []string{"h2", "http/1.1"})
	ch, err := ParseTLSRecords(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ch.SNI != "www.example.com" || !slices.Equal(ch.ALPN, []string{"h2", "http/1.1"}) {
		t.Fatalf("sni=%q alpn=%v", ch.SNI, ch.ALPN)
	}
	if !ja4Re.MatchString(ch.JA4) {
		t.Fatalf("ja4 %q does not look like a TLS 1.3 h2 fingerprint", ch.JA4)
	}
	// Byte-at-a-time arrival must report ErrNeedMore until complete.
	for i := 1; i < len(raw); i++ {
		if _, err := ParseTLSRecords(raw[:i]); err != ErrNeedMore {
			if ch2, err2 := ParseTLSRecords(raw[:i]); err2 == nil && ch2.SNI == ch.SNI {
				break // complete before the end: trailing bytes are other records
			}
			t.Fatalf("prefix %d: err=%v, want ErrNeedMore", i, err)
		}
	}
	if _, err := ParseTLSRecords([]byte("GET / HTTP/1.1\r\n")); err != ErrNotTLS {
		t.Fatalf("http taken for tls: %v", err)
	}
}

// A fixed hello gives a fixed fingerprint: this pins the JA4 computation
// (sorting, GREASE removal, SNI/ALPN exclusion) against regressions.
func TestJA4Stable(t *testing.T) {
	ch := &ClientHello{
		SNI: "x", ALPN: []string{"h2"}, legacyVersion: 0x0303,
		versions:   []uint16{0x2a2a, 0x0304, 0x0303},
		ciphers:    []uint16{0x0a0a, 0x1301, 0x1302, 0xc02b},
		extensions: []uint16{0x1a1a, 0x0000, 0x0010, 0x000d, 0x002b, 0x000a},
		sigAlgs:    []uint16{0x0403, 0x0804},
	}
	got := ch.ja4('t')
	// b = sha256("1301,1302,c02b")[:12]; c = sha256("000a,000d,002b_0403,0804")[:12]
	want := "t13d0305h2_" + hash12("1301,1302,c02b") + "_" + hash12("000a,000d,002b_0403,0804")
	if got != want {
		t.Fatalf("ja4 = %s, want %s", got, want)
	}
	if alpnChars("h2") != "h2" || alpnChars("http/1.1") != "h1" || alpnChars("\x00a") != "01" {
		t.Fatalf("alpn chars: %s %s %s", alpnChars("h2"), alpnChars("http/1.1"), alpnChars("\x00a"))
	}
}

// RFC 9001 Appendix A.1: client Initial keys for DCID 0x8394c8f03e515708.
func TestQUICInitialKeysRFC9001(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	initial, _ := hkdfExtractForTest(dcid)
	client, _ := expandLabel(initial, "client in", 32)
	if got := hex.EncodeToString(client); got != "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea" {
		t.Fatalf("client_initial_secret = %s", got)
	}
	key, _ := expandLabel(client, "quic key", 16)
	iv, _ := expandLabel(client, "quic iv", 12)
	hp, _ := expandLabel(client, "quic hp", 16)
	if hex.EncodeToString(key) != "1f369613dd76d5467730efcbe3b1a22d" ||
		hex.EncodeToString(iv) != "fa044b2f42a3fd3b46fb255c" ||
		hex.EncodeToString(hp) != "9f50449e04a0e810283a1e9933adedd2" {
		t.Fatalf("key=%x iv=%x hp=%x", key, iv, hp)
	}
}

func TestQUICInitialRoundTrip(t *testing.T) {
	hello := goClientHello(t, "quic.example.com", []string{"h3"})
	ch, err := ParseTLSRecords(hello)
	if err != nil {
		t.Fatal(err)
	}
	// Strip the record header: QUIC carries the bare handshake message.
	hs := hello[5:]
	hs = hs[:4+int(hs[1])<<16|int(hs[2])<<8|int(hs[3])]
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for _, v := range []uint32{QUICv1, QUICv2} {
		// Split the hello into two reordered CRYPTO frames across two
		// packets, as Chrome does.
		mid := len(hs) / 2
		p1 := SealInitial(v, dcid, 0, CryptoFrame(uint64(mid), hs[mid:]))
		p2 := SealInitial(v, dcid, 1, CryptoFrame(0, hs[:mid]))
		var cs CryptoStream
		for _, p := range [][]byte{p1, p2} {
			ini, err := ParseQUICInitial(p)
			if err != nil {
				t.Fatalf("v%x: %v", v, err)
			}
			cs.Add(ini.Crypto)
		}
		qch, err := ParseHandshake(cs.Prefix(), 'q')
		if err != nil {
			t.Fatalf("v%x: %v", v, err)
		}
		if qch.SNI != "quic.example.com" || qch.ALPN[0] != "h3" || qch.JA4[0] != 'q' || qch.JA4[1:] != ch.ja4('q')[1:] {
			t.Fatalf("v%x: sni=%q alpn=%v ja4=%s", v, qch.SNI, qch.ALPN, qch.JA4)
		}
	}
}
