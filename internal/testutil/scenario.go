// Package testutil builds packet captures for tests: a scripted home
// network whose every packet is known, so the sensor, the server and the
// queries over them can all be checked against exact expectations.
//
// Frames are serialised with gopacket, ClientHellos come from crypto/tls,
// and QUIC Initials are sealed with the RFC 9001 keys, so the bytes are
// what real implementations put on the wire.
package testutil

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/xen0bit/netgraph/internal/decode"
)

// TB is the part of testing.TB the builders use, so cmd/genpcap can build
// scenarios outside a test.
type TB interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	TempDir() string
}

// Host is one machine in a scenario.
type Host struct {
	MAC net.HardwareAddr
	IP  netip.Addr
	IP6 netip.Addr
}

// The home scenario's cast. MAC prefixes are real OUIs so vendor lookup
// has something to find.
var (
	Router  = Host{mac("02:00:5e:00:00:01"), netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("fd00::1")}
	Phone   = Host{mac("3c:22:fb:01:02:03"), netip.MustParseAddr("192.168.1.23"), netip.Addr{}}                    // Apple
	Printer = Host{mac("00:1b:a9:44:55:66"), netip.MustParseAddr("192.168.1.40"), netip.Addr{}}                    // Brother
	TV      = Host{mac("f4:f5:d8:aa:bb:cc"), netip.MustParseAddr("192.168.1.50"), netip.MustParseAddr("fd00::50")} // Google
	Desktop = Host{mac("00:15:5d:01:02:03"), netip.MustParseAddr("192.168.1.60"), netip.Addr{}}                    // Microsoft
	Switch  = Host{mac("00:1b:21:aa:00:01"), netip.Addr{}, netip.Addr{}}                                           // Intel

	ExampleIP = netip.MustParseAddr("93.184.216.34")
	QUICIP    = netip.MustParseAddr("203.0.113.10")
	PlainIP   = netip.MustParseAddr("198.51.100.7")
)

// Scenario timing, relative to Base.
var Base = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

const (
	AtDHCP     = 0 * time.Second
	AtDNS      = 5 * time.Second
	AtTLSOpen  = 6 * time.Second
	AtQUIC     = 10 * time.Second
	AtHTTP     = 20 * time.Second
	AtNXDOMAIN = 30 * time.Second
	AtTLSClose = 125 * time.Second // the TLS connection spans windows
)

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

// Capture accumulates timestamped frames.
type Capture struct {
	t      TB
	frames []frame
}

type frame struct {
	ts   time.Time
	data []byte
}

// Home builds the home scenario.
func Home(t TB) *Capture {
	c := &Capture{t: t}
	at := func(d time.Duration) time.Time { return Base.Add(d) }

	// DHCP: the phone asks for its lease with a hostname; the router acks.
	c.UDP(at(AtDHCP), Phone.MAC, bcast, netip.IPv4Unspecified(), netip.MustParseAddr("255.255.255.255"), 68, 67,
		DHCPv4(1, Phone.MAC, netip.Addr{}, opt(53, 3), opt(12, []byte("alice-iphone")...), opt(50, Phone.IP.AsSlice()...), opt(55, 1, 3, 6, 15, 119, 252), opt(60, []byte("apple-ios")...)))
	c.UDP(at(AtDHCP+100*time.Millisecond), Router.MAC, Phone.MAC, Router.IP, Phone.IP, 67, 68,
		DHCPv4(2, Phone.MAC, Phone.IP, opt(53, 5), opt(51, 0, 1, 0x51, 0x80), opt(54, Router.IP.AsSlice()...)))
	c.ARP(at(AtDHCP+time.Second), Phone)

	// The printer announces itself over mDNS.
	c.UDP(at(2*time.Second), Printer.MAC, mdnsMAC, Printer.IP, netip.MustParseAddr("224.0.0.251"), 5353, 5353, c.dnsMsg(dnsmessage.Header{Response: true, Authoritative: true}, nil, func(b *dnsmessage.Builder) {
		must(t, b.PTRResource(rr("_ipp._tcp.local.", dnsmessage.TypePTR, 4500), dnsmessage.PTRResource{PTR: name("Office Printer._ipp._tcp.local.")}))
		must(t, b.SRVResource(rr("Office Printer._ipp._tcp.local.", dnsmessage.TypeSRV, 120), dnsmessage.SRVResource{Port: 631, Target: name("BRN001BA9.local.")}))
		must(t, b.TXTResource(rr("Office Printer._ipp._tcp.local.", dnsmessage.TypeTXT, 4500), dnsmessage.TXTResource{TXT: []string{"ty=Brother HL-L2350DW", "pdl=application/pdf"}}))
		must(t, b.AResource(rr("BRN001BA9.local.", dnsmessage.TypeA, 120), dnsmessage.AResource{A: Printer.IP.As4()}))
	}))

	// The TV: an IPv6 neighbour advertisement and an SSDP notify.
	c.NA(at(3*time.Second), TV)
	c.UDP(at(3*time.Second+500*time.Millisecond), TV.MAC, ssdpMAC, TV.IP, netip.MustParseAddr("239.255.255.250"), 1900, 1900,
		[]byte("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: urn:dial-multiscreen-org:service:dial:1\r\nNTS: ssdp:alive\r\nSERVER: Linux/4.9 UPnP/1.0 Chromecast/1.56\r\nUSN: uuid:tv-1234::urn:dial-multiscreen-org:service:dial:1\r\nLOCATION: http://192.168.1.50:8008/ssdp/device-desc.xml\r\n\r\n"))

	// The phone resolves www.example.com (CNAME + A) and holds a TLS
	// connection open across two minutes.
	c.DNSExchange(at(AtDNS), Phone, 41000, 0x1001, "www.example.com.", dnsmessage.TypeA, func(b *dnsmessage.Builder) {
		must(t, b.CNAMEResource(rr("www.example.com.", dnsmessage.TypeCNAME, 300), dnsmessage.CNAMEResource{CNAME: name("edge.example.net.")}))
		must(t, b.AResource(rr("edge.example.net.", dnsmessage.TypeA, 300), dnsmessage.AResource{A: ExampleIP.As4()}))
	})
	hello := ClientHello(t, "www.example.com", "h2", "http/1.1")
	cli := netip.AddrPortFrom(Phone.IP, 50000)
	srv := netip.AddrPortFrom(ExampleIP, 443)
	conn := c.TCPConn(Phone.MAC, Router.MAC, cli, srv)
	conn.Open(at(AtTLSOpen))
	conn.Send(at(AtTLSOpen+30*time.Millisecond), true, hello[:200])
	conn.Send(at(AtTLSOpen+31*time.Millisecond), true, hello[200:])
	// Then 3 KB up and 56 KB down, spread over the connection's life.
	for i := range 40 {
		ts := at(AtTLSOpen + time.Second + time.Duration(i)*3*time.Second)
		conn.Send(ts, false, make([]byte, 1400-40))
		if i < 3 {
			conn.Send(ts.Add(time.Millisecond), true, make([]byte, 1000-40-len(hello)/3))
		}
	}
	conn.Close(at(AtTLSClose))

	// QUIC to quic.example.org, ClientHello split over two Initials.
	c.DNSExchange(at(AtQUIC), Phone, 41001, 0x1002, "quic.example.org.", dnsmessage.TypeA, func(b *dnsmessage.Builder) {
		must(t, b.AResource(rr("quic.example.org.", dnsmessage.TypeA, 60), dnsmessage.AResource{A: QUICIP.As4()}))
	})
	qhello := ClientHello(t, "quic.example.org", "h3")
	hs := qhello[5:]
	mid := len(hs) / 2
	dcid := []byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4}
	qcli := netip.AddrPortFrom(Phone.IP, 51000)
	c.UDP(at(AtQUIC+50*time.Millisecond), Phone.MAC, Router.MAC, qcli.Addr(), QUICIP, qcli.Port(), 443, decode.SealInitial(decode.QUICv1, dcid, 0, decode.CryptoFrame(uint64(mid), hs[mid:])))
	c.UDP(at(AtQUIC+51*time.Millisecond), Phone.MAC, Router.MAC, qcli.Addr(), QUICIP, qcli.Port(), 443, decode.SealInitial(decode.QUICv1, dcid, 1, decode.CryptoFrame(0, hs[:mid])))
	c.UDP(at(AtQUIC+80*time.Millisecond), Router.MAC, Phone.MAC, QUICIP, qcli.Addr(), 443, qcli.Port(), make([]byte, 1200))

	// The TV fetches over plain HTTP.
	c.DNSExchange(at(AtHTTP), TV, 42000, 0x2001, "plain.example.net.", dnsmessage.TypeA, func(b *dnsmessage.Builder) {
		must(t, b.AResource(rr("plain.example.net.", dnsmessage.TypeA, 30), dnsmessage.AResource{A: PlainIP.As4()}))
	})
	h := c.TCPConn(TV.MAC, Router.MAC, netip.AddrPortFrom(TV.IP, 43000), netip.AddrPortFrom(PlainIP, 80))
	h.Open(at(AtHTTP + 20*time.Millisecond))
	h.Send(at(AtHTTP+40*time.Millisecond), true, []byte("GET /feed HTTP/1.1\r\nHost: plain.example.net\r\nUser-Agent: CrKey/1.56\r\n\r\n"))
	h.Send(at(AtHTTP+60*time.Millisecond), false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	h.Close(at(AtHTTP + 100*time.Millisecond))

	// An NXDOMAIN, and a query nobody answers.
	c.DNSExchange(at(AtNXDOMAIN), Phone, 41002, 0x1003, "nope.invalid.", dnsmessage.TypeA, nil)
	c.UDP(at(AtNXDOMAIN+time.Second), Phone.MAC, Router.MAC, Phone.IP, Router.IP, 41003, 53,
		c.dnsMsg(dnsmessage.Header{ID: 0x1004, RecursionDesired: true}, []dnsmessage.Question{{Name: name("lost.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}, nil))

	// A Windows desktop claims its NetBIOS name and answers LLMNR.
	c.UDP(at(60*time.Second), Desktop.MAC, bcast, Desktop.IP, netip.MustParseAddr("192.168.1.255"), 137, 137, NBNSRegistration("DESKTOP-1", 0x00, Desktop.IP))
	c.UDP(at(61*time.Second), Desktop.MAC, Phone.MAC, Desktop.IP, Phone.IP, 5355, 52000, c.dnsMsg(dnsmessage.Header{ID: 9, Response: true},
		[]dnsmessage.Question{{Name: name("desktop-1."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}, func(b *dnsmessage.Builder) {
			must(t, b.AResource(rr("desktop-1.", dnsmessage.TypeA, 30), dnsmessage.AResource{A: Desktop.IP.As4()}))
		}))

	// The switch advertises itself.
	c.Raw(at(70*time.Second), Switch.MAC, lldpMAC, 0x88cc, LLDPDU("00:1b:21:aa:00:01", "port-7", "core-switch"))
	return c
}

var (
	bcast   = mac("ff:ff:ff:ff:ff:ff")
	mdnsMAC = mac("01:00:5e:00:00:fb")
	ssdpMAC = mac("01:00:5e:7f:ff:fa")
	lldpMAC = mac("01:80:c2:00:00:0e")
)

// WriteFile writes the capture as a pcap file in a temp dir and returns
// its path.
func (c *Capture) WriteFile() string {
	path := filepath.Join(c.t.TempDir(), "capture.pcap")
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	must(c.t, w.WriteFileHeader(65536, layers.LinkTypeEthernet))
	for _, f := range c.frames {
		must(c.t, w.WritePacket(gopacket.CaptureInfo{Timestamp: f.ts, CaptureLength: len(f.data), Length: len(f.data)}, f.data))
	}
	must(c.t, os.WriteFile(path, buf.Bytes(), 0o644))
	return path
}

// Frames returns the frames in order with their timestamps.
func (c *Capture) Frames() ([]time.Time, [][]byte) {
	ts := make([]time.Time, len(c.frames))
	data := make([][]byte, len(c.frames))
	for i, f := range c.frames {
		ts[i], data[i] = f.ts, f.data
	}
	return ts, data
}

func (c *Capture) add(ts time.Time, ls ...gopacket.SerializableLayer) {
	buf := gopacket.NewSerializeBuffer()
	must(c.t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...))
	c.frames = append(c.frames, frame{ts, append([]byte(nil), buf.Bytes()...)})
}

func eth(src, dst net.HardwareAddr, et layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{SrcMAC: src, DstMAC: dst, EthernetType: et}
}

func ipLayer(src, dst netip.Addr, proto layers.IPProtocol) (gopacket.SerializableLayer, gopacket.NetworkLayer, layers.EthernetType) {
	if src.Is4() {
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: proto, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
		return ip, ip, layers.EthernetTypeIPv4
	}
	ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: proto, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
	return ip, ip, layers.EthernetTypeIPv6
}

// UDP adds one UDP datagram.
func (c *Capture) UDP(ts time.Time, smac, dmac net.HardwareAddr, src, dst netip.Addr, sport, dport uint16, payload []byte) {
	ip, nl, et := ipLayer(src, dst, layers.IPProtocolUDP)
	udp := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	_ = udp.SetNetworkLayerForChecksum(nl)
	c.add(ts, eth(smac, dmac, et), ip, udp, gopacket.Payload(payload))
}

// Raw adds a frame with an arbitrary EtherType.
func (c *Capture) Raw(ts time.Time, smac, dmac net.HardwareAddr, etherType uint16, payload []byte) {
	c.add(ts, eth(smac, dmac, layers.EthernetType(etherType)), gopacket.Payload(payload))
}

// ARP adds a gratuitous ARP reply announcing h.
func (c *Capture) ARP(ts time.Time, h Host) {
	c.add(ts, eth(h.MAC, bcast, layers.EthernetTypeARP), &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4,
		Operation: layers.ARPReply, SourceHwAddress: h.MAC, SourceProtAddress: h.IP.AsSlice(),
		DstHwAddress: bcast, DstProtAddress: h.IP.AsSlice(),
	})
}

// NA adds an unsolicited IPv6 neighbour advertisement for h.IP6.
func (c *Capture) NA(ts time.Time, h Host) {
	target := h.IP6.As16()
	icmp := append([]byte{136, 0, 0, 0, 0x20, 0, 0, 0}, target[:]...)
	icmp = append(icmp, 2, 1)
	icmp = append(icmp, h.MAC...)
	ip := &layers.IPv6{Version: 6, HopLimit: 255, NextHeader: layers.IPProtocolICMPv6, SrcIP: h.IP6.AsSlice(), DstIP: net.ParseIP("ff02::1")}
	c.add(ts, eth(h.MAC, mac("33:33:00:00:00:01"), layers.EthernetTypeIPv6), ip, gopacket.Payload(icmp))
}

// DNSExchange adds a query from h to the router and the response built by
// fill; a nil fill answers NXDOMAIN.
func (c *Capture) DNSExchange(ts time.Time, h Host, port, id uint16, qname string, qtype dnsmessage.Type, fill func(*dnsmessage.Builder)) {
	q := []dnsmessage.Question{{Name: name(qname), Type: qtype, Class: dnsmessage.ClassINET}}
	c.UDP(ts, h.MAC, Router.MAC, h.IP, Router.IP, port, 53, c.dnsMsg(dnsmessage.Header{ID: id, RecursionDesired: true}, q, nil))
	hdr := dnsmessage.Header{ID: id, Response: true, RecursionDesired: true, RecursionAvailable: true}
	if fill == nil {
		hdr.RCode = dnsmessage.RCodeNameError
	}
	c.UDP(ts.Add(12*time.Millisecond), Router.MAC, h.MAC, Router.IP, h.IP, 53, port, c.dnsMsg(hdr, q, fill))
}

func (c *Capture) dnsMsg(hdr dnsmessage.Header, qs []dnsmessage.Question, fill func(*dnsmessage.Builder)) []byte {
	b := dnsmessage.NewBuilder(nil, hdr)
	b.EnableCompression()
	must(c.t, b.StartQuestions())
	for _, q := range qs {
		must(c.t, b.Question(q))
	}
	must(c.t, b.StartAnswers())
	if fill != nil {
		fill(&b)
	}
	out, err := b.Finish()
	must(c.t, err)
	return out
}

// TCPConn scripts one TCP connection between a LAN host and a remote
// server through the router.
type TCPConn struct {
	c          *Capture
	cmac, rmac net.HardwareAddr
	cli, srv   netip.AddrPort
	cseq, sseq uint32
}

func (c *Capture) TCPConn(clientMAC, routerMAC net.HardwareAddr, cli, srv netip.AddrPort) *TCPConn {
	return &TCPConn{c: c, cmac: clientMAC, rmac: routerMAC, cli: cli, srv: srv, cseq: 1000, sseq: 9000}
}

func (t *TCPConn) seg(ts time.Time, fromClient bool, flags func(*layers.TCP), payload []byte) {
	src, dst, smac, dmac := t.cli, t.srv, t.cmac, t.rmac
	seq, ack := t.cseq, t.sseq
	if !fromClient {
		src, dst, smac, dmac = t.srv, t.cli, t.rmac, t.cmac
		seq, ack = t.sseq, t.cseq
	}
	ip, nl, et := ipLayer(src.Addr(), dst.Addr(), layers.IPProtocolTCP)
	tcp := &layers.TCP{SrcPort: layers.TCPPort(src.Port()), DstPort: layers.TCPPort(dst.Port()), Seq: seq, Ack: ack, Window: 65535}
	flags(tcp)
	_ = tcp.SetNetworkLayerForChecksum(nl)
	t.c.add(ts, eth(smac, dmac, et), ip, tcp, gopacket.Payload(payload))
	adv := uint32(len(payload))
	if tcp.SYN || tcp.FIN {
		adv++
	}
	if fromClient {
		t.cseq += adv
	} else {
		t.sseq += adv
	}
}

// Open adds the three-way handshake.
func (t *TCPConn) Open(ts time.Time) {
	t.seg(ts, true, func(p *layers.TCP) { p.SYN = true }, nil)
	t.seg(ts.Add(10*time.Millisecond), false, func(p *layers.TCP) { p.SYN, p.ACK = true, true }, nil)
	t.seg(ts.Add(20*time.Millisecond), true, func(p *layers.TCP) { p.ACK = true }, nil)
}

// Send adds a data segment.
func (t *TCPConn) Send(ts time.Time, fromClient bool, payload []byte) {
	t.seg(ts, fromClient, func(p *layers.TCP) { p.ACK, p.PSH = true, true }, payload)
}

// Close adds a FIN exchange.
func (t *TCPConn) Close(ts time.Time) {
	t.seg(ts, true, func(p *layers.TCP) { p.FIN, p.ACK = true, true }, nil)
	t.seg(ts.Add(10*time.Millisecond), false, func(p *layers.TCP) { p.FIN, p.ACK = true, true }, nil)
	t.seg(ts.Add(20*time.Millisecond), true, func(p *layers.TCP) { p.ACK = true }, nil)
}

// ClientHello returns a ClientHello record produced by crypto/tls.
func ClientHello(t TB, sni string, alpn ...string) []byte {
	t.Helper()
	cl, sv := net.Pipe()
	defer sv.Close()
	go func() {
		c := tls.Client(cl, &tls.Config{ServerName: sni, NextProtos: alpn, InsecureSkipVerify: true}) //nolint:gosec // fixture
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_ = c.Handshake()
		cl.Close()
	}()
	_ = sv.SetReadDeadline(time.Now().Add(5 * time.Second))
	var buf bytes.Buffer
	tmp := make([]byte, 8192)
	for {
		n, err := sv.Read(tmp)
		buf.Write(tmp[:n])
		if _, perr := decode.ParseTLSRecords(buf.Bytes()); perr == nil {
			return buf.Bytes()
		}
		if err != nil {
			t.Fatalf("capturing ClientHello: %v", err)
		}
	}
}

// DHCPv4 builds a BOOTP message with the given options.
func DHCPv4(op byte, chaddr net.HardwareAddr, yiaddr netip.Addr, opts ...[]byte) []byte {
	b := make([]byte, 240)
	b[0], b[1], b[2] = op, 1, 6
	binary.BigEndian.PutUint32(b[4:], 0x12345678)
	if yiaddr.IsValid() {
		copy(b[16:20], yiaddr.AsSlice())
	}
	copy(b[28:], chaddr)
	binary.BigEndian.PutUint32(b[236:], 0x63825363)
	for _, o := range opts {
		b = append(b, o...)
	}
	return append(b, 255)
}

func opt(code byte, v ...byte) []byte { return append([]byte{code, byte(len(v))}, v...) }

// NBNSRegistration builds a NetBIOS name registration request.
func NBNSRegistration(nb string, suffix byte, ip netip.Addr) []byte {
	raw := []byte(nb)
	for len(raw) < 15 {
		raw = append(raw, ' ')
	}
	raw = append(raw[:15], suffix)
	enc := make([]byte, 0, 34)
	enc = append(enc, 32)
	for _, ch := range raw {
		enc = append(enc, 'A'+ch>>4, 'A'+ch&0xf)
	}
	enc = append(enc, 0)
	msg := []byte{0x80, 0x01, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 1}
	msg = append(msg, enc...)
	msg = append(msg, 0, 0x20, 0, 1, 0xc0, 12, 0, 0x20, 0, 1, 0, 0, 0x0e, 0x10, 0, 6, 0, 0)
	return append(msg, ip.AsSlice()...)
}

// LLDPDU builds a minimal LLDP PDU.
func LLDPDU(chassisMAC, port, sysName string) []byte {
	tlv := func(t uint16, v []byte) []byte {
		return append(binary.BigEndian.AppendUint16(nil, t<<9|uint16(len(v))), v...)
	}
	var b []byte
	b = append(b, tlv(1, append([]byte{4}, mac(chassisMAC)...))...)
	b = append(b, tlv(2, append([]byte{7}, port...))...)
	b = append(b, tlv(3, []byte{0, 120})...)
	b = append(b, tlv(5, []byte(sysName))...)
	return append(b, tlv(0, nil)...)
}

func name(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }

func rr(n string, t dnsmessage.Type, ttl uint32) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{Name: name(n), Type: t, Class: dnsmessage.ClassINET, TTL: ttl}
}

func must(t TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// FlowBytes sums IP lengths between two endpoints, decoding the frames with
// gopacket: an independent count to check the sensor's against.
func (c *Capture) FlowBytes(a, b netip.AddrPort) (aToB, bToA uint64) {
	for _, f := range c.frames {
		p := gopacket.NewPacket(f.data, layers.LayerTypeEthernet, gopacket.Default)
		var src, dst netip.AddrPort
		var n int
		if ip4, ok := p.NetworkLayer().(*layers.IPv4); ok {
			n = int(ip4.Length)
			sa, _ := netip.AddrFromSlice(ip4.SrcIP.To4())
			da, _ := netip.AddrFromSlice(ip4.DstIP.To4())
			src, dst = netip.AddrPortFrom(sa, 0), netip.AddrPortFrom(da, 0)
		} else if ip6, ok := p.NetworkLayer().(*layers.IPv6); ok {
			n = 40 + int(ip6.Length)
			sa, _ := netip.AddrFromSlice(ip6.SrcIP)
			da, _ := netip.AddrFromSlice(ip6.DstIP)
			src, dst = netip.AddrPortFrom(sa, 0), netip.AddrPortFrom(da, 0)
		} else {
			continue
		}
		switch l4 := p.TransportLayer().(type) {
		case *layers.TCP:
			src, dst = netip.AddrPortFrom(src.Addr(), uint16(l4.SrcPort)), netip.AddrPortFrom(dst.Addr(), uint16(l4.DstPort))
		case *layers.UDP:
			src, dst = netip.AddrPortFrom(src.Addr(), uint16(l4.SrcPort)), netip.AddrPortFrom(dst.Addr(), uint16(l4.DstPort))
		}
		switch {
		case src == a && dst == b:
			aToB += uint64(n)
		case src == b && dst == a:
			bToA += uint64(n)
		}
	}
	return aToB, bToA
}
