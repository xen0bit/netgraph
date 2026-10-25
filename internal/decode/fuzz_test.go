package decode

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// Each Fuzz target asserts only that a parser terminates without panicking
// on arbitrary bytes; correctness is the table tests' job. Seeds are valid
// messages so the fuzzer starts from deep inside each format.

var fuzzSrc = netip.MustParseAddr("192.168.1.2")

func FuzzDNS(f *testing.F) {
	f.Add(buildDNS(f, dnsmessage.Header{Response: true}, []dnsmessage.Question{{Name: mustName("a.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		func(b *dnsmessage.Builder) {
			must(f, b.CNAMEResource(rh("a.example.", dnsmessage.TypeCNAME, 1), dnsmessage.CNAMEResource{CNAME: mustName("b.example.")}))
			must(f, b.SRVResource(rh("_x._tcp.example.", dnsmessage.TypeSRV, 1), dnsmessage.SRVResource{Port: 1, Target: mustName("b.example.")}))
			must(f, b.TXTResource(rh("b.example.", dnsmessage.TypeTXT, 1), dnsmessage.TXTResource{TXT: []string{"k=v"}}))
		}))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseDNS(b)
		if err != nil || m == nil {
			return
		}
		Answers(m)
		MDNS(m, fuzzSrc, "")
		LLMNR(m, fuzzSrc, "")
		NBNS(m, fuzzSrc, "")
	})
}

func FuzzDHCPv4(f *testing.F) {
	f.Add(dhcp4Packet(1, []byte{12, 3, 'a', 'b', 'c'}, []byte{81, 6, 4, 0, 0, 1, 'a', 0}))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DHCPv4(b) })
}

func FuzzDHCPv6(f *testing.F) {
	f.Add(append([]byte{1, 0, 0, 1}, opt6(39, append([]byte{0}, encodeName("x.lan")...))...))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DHCPv6(b, "") })
}

func FuzzL2(f *testing.F) {
	f.Add([]byte{0, 1, 8, 0, 6, 4, 0, 1, 1, 2, 3, 4, 5, 6, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2})
	f.Add(append(lldpTLV(1, []byte{4, 1, 2, 3, 4, 5, 6}), lldpTLV(8, []byte{5, 1, 1, 2, 3, 4})...))
	f.Fuzz(func(t *testing.T, b []byte) {
		ARP(b)
		NDP(b, fuzzSrc)
		_, _ = LLDP(b, "")
		SSDP(b, fuzzSrc, "")
		HTTPRequest(b)
	})
}

func FuzzTLS(f *testing.F) {
	f.Add(buildHello("fuzz.example", "h2"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseTLSRecords(b)
		_, _ = ParseHandshake(b, 'q')
	})
}

func FuzzQUIC(f *testing.F) {
	hello := buildHello("fuzz.example", "h3")
	f.Add(SealInitial(QUICv1, []byte{9, 9, 9, 9, 9, 9, 9, 9}, 0, CryptoFrame(0, hello[5:])))
	f.Fuzz(func(t *testing.T, b []byte) {
		if ini, err := ParseQUICInitial(b); err == nil {
			var cs CryptoStream
			cs.Add(ini.Crypto)
			_, _ = ParseHandshake(cs.Prefix(), 'q')
		}
		_, _ = cryptoFrames(b)
	})
}

// Fuzz decrypted payloads directly: the AEAD makes ParseQUICInitial's frame
// parser unreachable from random datagrams.
func FuzzQUICFrames(f *testing.F) {
	f.Add(append(CryptoFrame(5, []byte("hello")), 0x02, 1, 0, 0, 0))
	f.Fuzz(func(t *testing.T, b []byte) {
		frags, _ := cryptoFrames(b)
		var cs CryptoStream
		cs.Add(frags)
		cs.Prefix()
	})
}
