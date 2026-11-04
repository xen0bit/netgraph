package sources

import (
	"encoding/binary"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xen0bit/netgraph/internal/wire"
)

func tcpFrame(smac, dmac string, src, dst string, sport, dport uint16, flags byte) []byte {
	mac := func(s string) []byte {
		out := make([]byte, 0, 6)
		for _, p := range strings.Split(s, ":") {
			v := byte(0)
			for _, c := range p {
				v = v<<4 | byte(strings.IndexRune("0123456789abcdef", c))
			}
			out = append(out, v)
		}
		return out
	}
	b := append(mac(dmac), mac(smac)...)
	b = be16(b, 0x0800)
	ip := make([]byte, 20)
	ip[0], ip[9] = 0x45, 6
	binary.BigEndian.PutUint16(ip[2:], 40)
	copy(ip[12:], netip.MustParseAddr(src).AsSlice())
	copy(ip[16:], netip.MustParseAddr(dst).AsSlice())
	b = append(b, ip...)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp, sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	tcp[12], tcp[13] = 0x50, flags
	return append(b, tcp...)
}

func headerRecord(frame []byte, frameLen uint32) []byte {
	body := be32(nil, sflowEthernet)
	body = be32(body, frameLen)
	body = be32(body, 0)
	body = be32(body, uint32(len(frame)))
	body = append(body, frame...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	rec := be32(nil, sflowRawHeader)
	rec = be32(rec, uint32(len(body)))
	return append(rec, body...)
}

func flowSample(rate uint32, records ...[]byte) []byte {
	body := be32(nil, 1) // sequence
	body = be32(body, 3) // source
	body = be32(body, rate)
	body = be32(body, 1000) // pool
	body = be32(body, 0)    // drops
	body = be32(body, 1)    // input
	body = be32(body, 2)    // output
	body = be32(body, uint32(len(records)))
	for _, r := range records {
		body = append(body, r...)
	}
	out := be32(nil, sflowFlowSample)
	out = be32(out, uint32(len(body)))
	return append(out, body...)
}

func sflowDatagram(samples ...[]byte) []byte {
	b := be32(nil, 5)
	b = be32(b, 1) // agent is IPv4
	b = append(b, 192, 168, 1, 1)
	b = be32(b, 0) // sub agent
	b = be32(b, 1) // sequence
	b = be32(b, 1000)
	b = be32(b, uint32(len(samples)))
	for _, s := range samples {
		b = append(b, s...)
	}
	return b
}

func TestSFlowSample(t *testing.T) {
	frame := tcpFrame("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "192.168.1.23", "93.184.216.34", 40000, 443, 0x18)
	got, err := ParseSFlow(sflowDatagram(flowSample(512, headerRecord(frame, 1400))), rx)
	if err != nil || len(got) != 1 {
		t.Fatalf("%+v, %v", got, err)
	}
	f := got[0]
	if f.Src.String() != "192.168.1.23" || f.Dst.String() != "93.184.216.34" || f.SrcPort != 40000 || f.DstPort != 443 || f.Proto != 6 || f.TCPFlags != 0x18 {
		t.Errorf("%+v", f)
	}
	if f.BytesOut != 1400*512 || f.PktsOut != 512 {
		t.Errorf("not scaled by the sampling rate: %+v", f)
	}
	if f.SrcMAC != "aa:bb:cc:00:00:01" || f.DstMAC != "aa:bb:cc:00:00:02" {
		t.Errorf("macs %+v", f)
	}
}

func TestSFlowExpandedSample(t *testing.T) {
	frame := tcpFrame("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "192.168.1.23", "93.184.216.34", 40000, 443, 0)
	body := be32(nil, 1) // sequence
	body = be32(body, 0) // source type
	body = be32(body, 3) // source index
	body = be32(body, 64)
	for range 6 { // pool, drops, input format and value, output format and value
		body = be32(body, 0)
	}
	body = be32(body, 1)
	body = append(body, headerRecord(frame, 100)...)
	s := be32(nil, sflowExpandedFlowSample)
	s = be32(s, uint32(len(body)))
	got, err := ParseSFlow(sflowDatagram(append(s, body...)), rx)
	if err != nil || len(got) != 1 || got[0].BytesOut != 6400 {
		t.Fatalf("%+v, %v", got, err)
	}
}

func TestSFlowIPDataRecord(t *testing.T) {
	body := be32(nil, 900) // length
	body = be32(body, 6)
	body = append(body, 192, 168, 1, 23, 93, 184, 216, 34)
	body = be32(body, 40000)
	body = be32(body, 443)
	body = be32(body, 0x12)
	body = be32(body, 0)
	rec := be32(be32(nil, sflowIPv4Data), uint32(len(body)))
	got, err := ParseSFlow(sflowDatagram(flowSample(10, append(rec, body...))), rx)
	if err != nil || len(got) != 1 {
		t.Fatalf("%+v, %v", got, err)
	}
	if f := got[0]; f.BytesOut != 9000 || f.DstPort != 443 || f.SrcPort != 40000 || f.TCPFlags != 0x12 {
		t.Errorf("%+v", f)
	}
}

// A sample of the reply is the same connection, read the same way, MACs included.
func TestSFlowReplyJoinsConnection(t *testing.T) {
	out := tcpFrame("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "192.168.1.23", "93.184.216.34", 40000, 443, 0x10)
	back := tcpFrame("aa:bb:cc:00:00:02", "aa:bb:cc:00:00:01", "93.184.216.34", "192.168.1.23", 443, 40000, 0x10)
	got, err := ParseSFlow(sflowDatagram(flowSample(100, headerRecord(out, 100)), flowSample(100, headerRecord(back, 1000))), rx)
	if err != nil || len(got) != 2 {
		t.Fatalf("%+v, %v", got, err)
	}
	if got[0].ID != got[1].ID {
		t.Fatal("two directions, two connections")
	}
	var s sampleTotals
	s.add(got[0])
	s.add(got[1])
	evs := s.drain()
	if len(evs) != 1 {
		t.Fatalf("%+v", evs)
	}
	f := evs[0].Flow
	if f.BytesOut != 10_000 || f.BytesIn != 100_000 || f.Src.String() != "192.168.1.23" || f.SrcMAC != "aa:bb:cc:00:00:01" || f.DstMAC != "aa:bb:cc:00:00:02" {
		t.Errorf("%+v", f)
	}
}

// Found with real Open vSwitch sFlow: a server on 8081 split each connection in two.
func TestOrientUnregisteredServerPort(t *testing.T) {
	back := wire.Flow{Proto: 6, Src: netip.MustParseAddr("10.78.0.2"), SrcPort: 8081, Dst: netip.MustParseAddr("10.78.0.1"), DstPort: 52000, BytesOut: 900}
	orient(&back)
	if back.Src.String() != "10.78.0.1" || back.DstPort != 8081 || back.BytesIn != 900 || back.BytesOut != 0 {
		t.Errorf("%+v", back)
	}
	both := wire.Flow{Proto: 6, Src: netip.MustParseAddr("10.78.0.2"), SrcPort: 40000, Dst: netip.MustParseAddr("10.78.0.1"), DstPort: 52000, BytesOut: 900}
	orient(&both)
	if both.SrcPort != 40000 || both.BytesOut != 900 {
		t.Errorf("two client-range ports were guessed at: %+v", both)
	}
	forward := wire.Flow{Proto: 6, Src: netip.MustParseAddr("10.78.0.1"), SrcPort: 52000, Dst: netip.MustParseAddr("10.78.0.2"), DstPort: 8081, BytesOut: 5}
	orient(&forward)
	if forward.SrcPort != 52000 || forward.BytesOut != 5 {
		t.Errorf("%+v", forward)
	}
}

func TestSFlowGroupAddressIsNobodys(t *testing.T) {
	frame := tcpFrame("aa:bb:cc:00:00:01", "ff:ff:ff:ff:ff:ff", "192.168.1.23", "192.168.1.255", 40000, 40001, 0)
	got, _ := ParseSFlow(sflowDatagram(flowSample(1, headerRecord(frame, 64))), rx)
	if len(got) != 1 || got[0].DstMAC != "" {
		t.Errorf("%+v", got)
	}
}

func TestSFlowIgnoresCountersAndOtherVersions(t *testing.T) {
	counter := be32(nil, 2)
	counter = be32(counter, 4)
	counter = be32(counter, 0)
	if got, err := ParseSFlow(sflowDatagram(counter), rx); err != nil || len(got) != 0 {
		t.Errorf("%+v, %v", got, err)
	}
	if _, err := ParseSFlow(be32(be32(nil, 4), 1), rx); err == nil {
		t.Error("read sFlow v4")
	}
}

func TestSFlowClaimedLengthsAreBounded(t *testing.T) {
	d := sflowDatagram(flowSample(1, headerRecord(tcpFrame("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "10.0.0.1", "10.0.0.2", 1, 2, 0), 64)))
	// A count far beyond what's there, and a sample longer than the datagram.
	huge := append([]byte(nil), d...)
	binary.BigEndian.PutUint32(huge[24:], 0xffffffff)
	if _, err := ParseSFlow(huge, rx); err != nil {
		t.Errorf("count: %v", err)
	}
	long := append([]byte(nil), d...)
	binary.BigEndian.PutUint32(long[32:], 0xffffffff)
	if got, err := ParseSFlow(long, rx); err == nil || len(got) != 0 {
		t.Errorf("%+v, %v", got, err)
	}
}

func FuzzParseSFlow(f *testing.F) {
	frame := tcpFrame("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "192.168.1.23", "93.184.216.34", 40000, 443, 0x18)
	f.Add(sflowDatagram(flowSample(512, headerRecord(frame, 1400))))
	f.Add(sflowDatagram())
	f.Fuzz(func(t *testing.T, b []byte) {
		flows, _ := ParseSFlow(b, rx)
		var s sampleTotals
		for _, fl := range flows {
			if !fl.Src.IsValid() || !fl.Dst.IsValid() || fl.Start.After(fl.End) {
				t.Fatalf("%+v", fl)
			}
			s.add(fl)
		}
		s.drain()
	})
}

// tshark is the independent check that these datagrams are what the format says, so the
// parser's tests aren't only agreeing with themselves.
func TestSFlowDatagramAgreesWithTshark(t *testing.T) {
	tshark, err := exec.LookPath("tshark")
	if err != nil {
		t.Skip("no tshark")
	}
	frame := tcpFrame("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "192.168.1.23", "93.184.216.34", 40000, 443, 0x18)
	d := sflowDatagram(flowSample(512, headerRecord(frame, 1400)))
	// A pcap holding it as UDP to 6343.
	udp := be16(be16(be16(be16(nil, 6343), 6343), uint16(8+len(d))), 0)
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:], uint16(20+8+len(d)))
	copy(ip[12:], []byte{192, 168, 1, 1})
	copy(ip[16:], []byte{192, 168, 1, 2})
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(ip[10:], ^uint16(sum))
	pkt := append(make([]byte, 12), 8, 0)
	pkt = append(append(append(pkt, ip...), udp...), d...)
	pcap := binary.LittleEndian.AppendUint32(nil, 0xa1b2c3d4)
	pcap = binary.LittleEndian.AppendUint16(pcap, 2)
	pcap = binary.LittleEndian.AppendUint16(pcap, 4)
	pcap = append(pcap, make([]byte, 8)...)
	pcap = binary.LittleEndian.AppendUint32(pcap, 65535)
	pcap = binary.LittleEndian.AppendUint32(pcap, 1)
	pcap = binary.LittleEndian.AppendUint32(pcap, 1)
	pcap = binary.LittleEndian.AppendUint32(pcap, 0)
	pcap = binary.LittleEndian.AppendUint32(pcap, uint32(len(pkt)))
	pcap = binary.LittleEndian.AppendUint32(pcap, uint32(len(pkt)))
	pcap = append(pcap, pkt...)
	path := filepath.Join(t.TempDir(), "s.pcap")
	if err := os.WriteFile(path, pcap, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(tshark, "-r", path, "-d", "udp.port==6343,sflow", "-T", "fields",
		"-e", "sflow.sampling_rate", "-e", "sflow_245.header.frame_length", "-e", "sflow_245.sampling_rate").CombinedOutput()
	if err != nil {
		// Field names vary between versions: fall back to the decoded text.
		out, err = exec.Command(tshark, "-r", path, "-d", "udp.port==6343,sflow", "-V").CombinedOutput()
		if err != nil {
			t.Fatalf("tshark: %v\n%s", err, out)
		}
	}
	if !strings.Contains(string(out), "512") {
		t.Errorf("tshark doesn't read a sampling rate of 512:\n%s", out)
	}
	verbose, err := exec.Command(tshark, "-r", path, "-d", "udp.port==6343,sflow", "-V").CombinedOutput()
	if err != nil {
		t.Fatalf("tshark: %v\n%s", err, verbose)
	}
	for _, want := range []string{"93.184.216.34", "Dst Port: 443", "Src Port: 40000"} {
		if !strings.Contains(string(verbose), want) {
			t.Errorf("tshark doesn't find %q in the sample:\n%s", want, verbose)
		}
	}
	if strings.Contains(string(verbose), "Malformed") {
		t.Errorf("tshark calls it malformed:\n%s", verbose)
	}
}

func TestSFlowCollector(t *testing.T) {
	frame := tcpFrame("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "192.168.1.23", "93.184.216.34", 40000, 443, 0x18)
	testCollector(t, sflowDatagram(flowSample(10, headerRecord(frame, 100))), func(ready func(string), allow []netip.Prefix, sink Sink) runner {
		return &SFlow{Listen: "127.0.0.1:0", Allow: allow, Sink: sink, Ready: ready}
	}, func(evs []wire.Event) bool {
		for _, e := range evs {
			if e.Type == wire.TypeFlow && e.Flow.BytesOut >= 1000 {
				return true
			}
		}
		return false
	})
}
