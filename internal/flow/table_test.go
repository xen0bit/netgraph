package flow

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

var (
	t0     = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	client = netip.MustParseAddrPort("192.168.1.10:50000")
	server = netip.MustParseAddrPort("93.184.216.34:443")
	cMAC   = [6]byte{0x3c, 0x22, 0xfb, 1, 2, 3}
	rMAC   = [6]byte{0x02, 0, 0, 0, 0, 1}
)

type recorder struct{ flows []wire.Flow }

func (r *recorder) emit(f *wire.Flow) { r.flows = append(r.flows, *f) }

func pkt(at time.Duration, src, dst netip.AddrPort, flags uint8, n int, payload []byte) *Packet {
	mac := cMAC
	if src == server {
		mac = rMAC
	}
	return &Packet{TS: t0.Add(at), Proto: ProtoTCP, Src: src, Dst: dst, SrcMAC: mac, Len: n, TCPFlags: flags, Payload: payload}
}

func TestIntervalsAndClose(t *testing.T) {
	var r recorder
	tb := New(Config{ActiveTimeout: 10 * time.Second}, r.emit)
	// The SYN-ACK arrives first (capture started mid-handshake): the
	// initiator must still be the client.
	tb.Add(pkt(0, server, client, SYN|ACK, 60, nil))
	tb.Add(pkt(time.Second, client, server, ACK, 1000, nil))
	tb.Add(pkt(2*time.Second, server, client, ACK, 5000, nil))
	tb.Expire(t0.Add(10 * time.Second)) // active timeout: interval 1
	tb.Expire(t0.Add(20 * time.Second)) // quiet interval: heartbeat for open TCP
	tb.Add(pkt(25*time.Second, client, server, FIN|ACK, 40, nil))
	tb.Add(pkt(25500*time.Millisecond, server, client, FIN|ACK, 40, nil))
	tb.Expire(t0.Add(26 * time.Second)) // within linger
	tb.Expire(t0.Add(28 * time.Second)) // linger over: final

	if len(r.flows) != 3 {
		t.Fatalf("got %d records: %+v", len(r.flows), r.flows)
	}
	a, hb, fin := r.flows[0], r.flows[1], r.flows[2]
	if a.Src != client.Addr() || a.DstPort != 443 || a.BytesOut != 1000 || a.BytesIn != 5060 || a.Final {
		t.Errorf("interval 1 = %+v", a)
	}
	if a.SrcMAC != "3c:22:fb:01:02:03" || a.DstMAC != "02:00:00:00:00:01" {
		t.Errorf("macs = %s %s", a.SrcMAC, a.DstMAC)
	}
	if hb.BytesOut != 0 || hb.BytesIn != 0 || !hb.Start.Equal(t0.Add(10*time.Second)) || !hb.End.Equal(t0.Add(20*time.Second)) {
		t.Errorf("heartbeat = %+v", hb)
	}
	if !fin.Final || fin.EndReason != "fin" || fin.BytesOut != 40 || fin.BytesIn != 40 || !fin.FirstSeen.Equal(t0) || fin.ID != a.ID {
		t.Errorf("final = %+v", fin)
	}
	if tb.Len() != 0 {
		t.Errorf("table still holds %d flows", tb.Len())
	}
}

func TestIdleUDPAndNoHeartbeat(t *testing.T) {
	var r recorder
	tb := New(Config{ActiveTimeout: 10 * time.Second, UDPIdle: 30 * time.Second}, r.emit)
	c := netip.MustParseAddrPort("192.168.1.10:40000")
	dns := netip.MustParseAddrPort("192.168.1.1:53")
	// Response seen first: the server port decides the direction.
	tb.Add(&Packet{TS: t0, Proto: ProtoUDP, Src: dns, Dst: c, Len: 120})
	tb.Expire(t0.Add(10 * time.Second))
	tb.Expire(t0.Add(20 * time.Second)) // silent UDP: nothing exported
	tb.Expire(t0.Add(31 * time.Second))
	if len(r.flows) != 2 {
		t.Fatalf("got %+v", r.flows)
	}
	if r.flows[0].Src != c.Addr() || r.flows[0].BytesIn != 120 || r.flows[0].App != "dns" {
		t.Errorf("first = %+v", r.flows[0])
	}
	if f := r.flows[1]; !f.Final || f.EndReason != "idle" || !f.End.Equal(t0) {
		t.Errorf("final = %+v", f)
	}
}

func TestEviction(t *testing.T) {
	var r recorder
	tb := New(Config{MaxFlows: 2}, r.emit)
	for i := range 3 {
		src := netip.AddrPortFrom(client.Addr(), uint16(50000+i))
		tb.Add(pkt(time.Duration(i)*time.Second, src, server, SYN, 60, nil))
	}
	if tb.Len() != 2 || tb.Evicted() != 1 || len(r.flows) != 1 || r.flows[0].EndReason != "evict" || r.flows[0].SrcPort != 50000 {
		t.Fatalf("len=%d evicted=%d flows=%+v", tb.Len(), tb.Evicted(), r.flows)
	}
}

func TestPortReuseStartsNewFlow(t *testing.T) {
	var r recorder
	tb := New(Config{}, r.emit)
	tb.Add(pkt(0, client, server, SYN, 60, nil))
	tb.Add(pkt(time.Second, client, server, RST, 40, nil))
	tb.Add(pkt(1500*time.Millisecond, client, server, SYN, 60, nil))
	if len(r.flows) != 1 || tb.Len() != 1 {
		t.Fatalf("flows=%+v len=%d", r.flows, tb.Len())
	}
}

// The table learns SNI from a real ClientHello split across segments.
func TestTLSInspection(t *testing.T) {
	c, s := net.Pipe()
	go func() {
		tc := tls.Client(c, &tls.Config{ServerName: "split.example.com", NextProtos: []string{"h2"}, InsecureSkipVerify: true})
		_ = tc.Handshake()
	}()
	var hello bytes.Buffer
	buf := make([]byte, 8192)
	_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := s.Read(buf)
	hello.Write(buf[:n])
	s.Close()

	var r recorder
	tb := New(Config{}, r.emit)
	tb.Add(pkt(0, client, server, SYN, 60, nil))
	raw := hello.Bytes()
	seq := uint32(1000)
	for i, chunk := range [][]byte{raw[:100], raw[:100], raw[100:300], raw[300:]} { // includes a retransmission
		p := pkt(time.Duration(i+1)*time.Millisecond, client, server, ACK|PSH, 40+len(chunk), chunk)
		if i == 1 {
			p.Seq = 1000
		} else {
			p.Seq = seq
			seq += uint32(len(chunk))
		}
		if i == 0 {
			seq = 1100
		}
		tb.Add(p)
	}
	tb.Flush(t0.Add(time.Second), "shutdown")
	if len(r.flows) != 1 {
		t.Fatalf("got %+v", r.flows)
	}
	if f := r.flows[0]; f.App != "tls" || f.SNI != "split.example.com" || f.ALPN != "h2" || len(f.JA4) != 36 {
		t.Fatalf("flow = %+v", f)
	}
}

func TestHTTPInspection(t *testing.T) {
	var r recorder
	tb := New(Config{}, r.emit)
	web := netip.MustParseAddrPort("10.0.0.5:8080")
	req := []byte("GET / HTTP/1.1\r\nHost: plain.lab\r\nUser-Agent: test/1\r\n\r\n")
	tb.Add(&Packet{TS: t0, Proto: ProtoTCP, Src: client, Dst: web, TCPFlags: SYN, Len: 60})
	tb.Add(&Packet{TS: t0, Proto: ProtoTCP, Src: client, Dst: web, TCPFlags: ACK | PSH, Len: 100, Seq: 1, Payload: req})
	tb.Flush(t0, "shutdown")
	if f := r.flows[0]; f.App != "http" || f.HTTPHost != "plain.lab" || f.UserAgent != "test/1" {
		t.Fatalf("flow = %+v", f)
	}
}

func BenchmarkAdd(b *testing.B) {
	tb := New(Config{}, func(*wire.Flow) {})
	p := pkt(0, client, server, ACK, 1500, nil)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		p.Src = netip.AddrPortFrom(client.Addr(), uint16(i%4096))
		tb.Add(p)
	}
}

// A full table must fit a router's memory budget with room to spare: the
// sensor's default soft limit is 128 MiB.
func TestTableMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a full table")
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	tb := New(Config{MaxFlows: 65536}, func(*wire.Flow) {})
	for i := range 65536 {
		src := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), uint16(i))
		tb.Add(&Packet{TS: t0, Proto: ProtoTCP, Src: src, Dst: server, TCPFlags: SYN, Len: 60})
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	used := after.HeapAlloc - before.HeapAlloc
	t.Logf("65536 flows: %.1f MiB (%d B/flow)", float64(used)/(1<<20), used/65536)
	if tb.Len() != 65536 || used > 64<<20 {
		t.Fatalf("len=%d, heap grew %d MiB", tb.Len(), used>>20)
	}
	runtime.KeepAlive(tb)
}
