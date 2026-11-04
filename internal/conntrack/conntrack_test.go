package conntrack

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type endian interface {
	binary.ByteOrder
	binary.AppendByteOrder
}

var t0 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func attr(order endian, typ uint16, v []byte) []byte {
	b := order.AppendUint16(nil, uint16(4+len(v)))
	b = order.AppendUint16(b, typ)
	b = append(b, v...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func tuple(order endian, src, dst string, sport, dport uint16, proto uint8) []byte {
	s, d := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	st, dt := uint16(ctaIPv4Src), uint16(ctaIPv4Dst)
	if s.Is6() {
		st, dt = ctaIPv6Src, ctaIPv6Dst
	}
	return concat(
		attr(order, ctaTupleIP|0x8000, concat(attr(order, st, s.AsSlice()), attr(order, dt, d.AsSlice()))),
		attr(order, ctaTupleProto|0x8000, concat(
			attr(order, ctaProtoNum, []byte{proto}),
			attr(order, ctaProtoSrcPort, binary.BigEndian.AppendUint16(nil, sport)),
			attr(order, ctaProtoDstPort, binary.BigEndian.AppendUint16(nil, dport)),
		)),
	)
}

func counters(order endian, pkts, bytes uint64) []byte {
	return concat(
		attr(order, ctaCountPackets, binary.BigEndian.AppendUint64(nil, pkts)),
		attr(order, ctaCountBytes, binary.BigEndian.AppendUint64(nil, bytes)),
	)
}

func message(order endian, typ uint16, body []byte) []byte {
	b := order.AppendUint32(nil, uint32(nlmsgHeader+len(body)))
	b = order.AppendUint16(b, typ)
	b = append(b, make([]byte, 10)...)
	return append(b, body...)
}

func natEntry(order endian) []byte {
	body := append([]byte{2, 0, 0, 0}, concat(
		attr(order, ctaTupleOrig|0x8000, tuple(order, "192.168.1.23", "93.184.216.34", 40000, 443, 6)),
		attr(order, ctaTupleReply|0x8000, tuple(order, "93.184.216.34", "203.0.113.9", 443, 40000, 6)),
		attr(order, ctaStatus, binary.BigEndian.AppendUint32(nil, statusHWOffload|1<<3)),
		attr(order, ctaCountersOrig|0x8000, counters(order, 10, 1500)),
		attr(order, ctaCountersReply|0x8000, counters(order, 20, 30000)),
		attr(order, ctaID, binary.BigEndian.AppendUint32(nil, 77)),
	)...)
	return message(order, msgCTNew, body)
}

// Both byte orders, because netlink framing is the host's: routers include big-endian MIPS.
func TestParseEitherEndian(t *testing.T) {
	for _, order := range []endian{binary.LittleEndian, binary.BigEndian} {
		b := concat(natEntry(order), message(order, nlmsgDone, make([]byte, 4)))
		got, done, err := Parse(b, order, nil)
		if err != nil || !done || len(got) != 1 {
			t.Fatalf("%v: %+v, done %v, err %v", order, got, done, err)
		}
		e := got[0]
		if e.OrigSrc.String() != "192.168.1.23" || e.ReplySrc.String() != "93.184.216.34" || e.ReplyDst.String() != "203.0.113.9" ||
			e.OrigSport != 40000 || e.ReplySport != 443 || e.Proto != 6 || e.ID != 77 {
			t.Errorf("%+v", e)
		}
		if !e.Counted || e.BytesOrig != 1500 || e.PktsOrig != 10 || e.BytesReply != 30000 || e.PktsReply != 20 {
			t.Errorf("counters %+v", e)
		}
		if !e.Offloaded() {
			t.Error("offload not read")
		}
	}
}

func TestParseKernelError(t *testing.T) {
	o := binary.LittleEndian
	if _, _, err := Parse(message(o, nlmsgError, o.AppendUint32(nil, uint32(0xffffffff))), o, nil); !errors.Is(err, ErrKernel) {
		t.Errorf("err %v", err)
	}
	// An error message with a zero errno is an acknowledgement.
	if _, done, err := Parse(message(o, nlmsgError, make([]byte, 4)), o, nil); err != nil || !done {
		t.Errorf("done %v, err %v", done, err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(natEntry(binary.LittleEndian))
	f.Add(natEntry(binary.BigEndian))
	f.Add(message(binary.LittleEndian, nlmsgDone, nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, o := range []endian{binary.LittleEndian, binary.BigEndian} {
			got, _, _ := Parse(b, o, nil)
			if len(got) > MaxEntries {
				t.Fatal(len(got))
			}
			for _, e := range got {
				if !e.OrigSrc.IsValid() || !e.ReplySrc.IsValid() {
					t.Fatalf("%+v", e)
				}
			}
			tr := Tracker{Mode: All}
			tr.Update(got, true, t0)
			tr.Close(t0)
		}
	})
}

func entry(bytes uint64, status uint32) Entry {
	return Entry{
		Proto: 6, ID: 1, Counted: true, Status: status,
		OrigSrc: netip.MustParseAddr("192.168.1.23"), OrigDst: netip.MustParseAddr("203.0.113.9"), OrigSport: 40000, OrigDport: 8443,
		ReplySrc: netip.MustParseAddr("192.168.1.50"), ReplyDst: netip.MustParseAddr("192.168.1.23"), ReplySport: 443, ReplyDport: 40000,
		BytesOrig: bytes, PktsOrig: bytes / 100, BytesReply: bytes * 2, PktsReply: bytes / 50,
	}
}

func TestTrackerAllReportsChanges(t *testing.T) {
	tr := Tracker{Mode: All}
	// The first read's totals are from before the sensor started, so aren't "now".
	if got := tr.Update([]Entry{entry(1000, 0)}, true, t0); len(got) != 0 {
		t.Fatalf("history reported: %+v", got)
	}
	got := tr.Update([]Entry{entry(1500, 0)}, true, t0.Add(10*time.Second))
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	f := got[0]
	if f.BytesOut != 500 || f.BytesIn != 1000 || f.PktsOut != 5 || !f.Start.Equal(t0) || !f.End.Equal(t0.Add(10*time.Second)) {
		t.Errorf("%+v", f)
	}
	// Past a port forward, the far side is who really answered.
	if f.Src.String() != "192.168.1.23" || f.SrcPort != 40000 || f.Dst.String() != "192.168.1.50" || f.DstPort != 443 {
		t.Errorf("ends %+v", f)
	}
	if f.ID>>63 != 1 {
		t.Errorf("id %x could collide with the flow table's", f.ID)
	}
	// Quiet: nothing to say.
	if got := tr.Update([]Entry{entry(1500, 0)}, true, t0.Add(20*time.Second)); len(got) != 0 {
		t.Errorf("%+v", got)
	}
	// A new connection after the first read did all of its traffic while we watched.
	other := entry(700, 0)
	other.ID = 2
	got = tr.Update([]Entry{entry(1500, 0), other}, true, t0.Add(30*time.Second))
	if len(got) != 1 || got[0].BytesOut != 700 {
		t.Errorf("%+v", got)
	}
}

func TestTrackerEndsAfterMissingTwice(t *testing.T) {
	tr := Tracker{Mode: All}
	tr.Update(nil, true, t0)
	first := tr.Update([]Entry{entry(100, 0)}, true, t0.Add(time.Second))
	if len(first) != 1 {
		t.Fatal(first)
	}
	if got := tr.Update(nil, true, t0.Add(2*time.Second)); len(got) != 0 {
		t.Errorf("one miss ended it: %+v", got)
	}
	// An incomplete read says nothing about what's gone.
	if got := tr.Update(nil, false, t0.Add(3*time.Second)); len(got) != 0 {
		t.Errorf("incomplete read ended it: %+v", got)
	}
	got := tr.Update(nil, true, t0.Add(4*time.Second))
	if len(got) != 1 || !got[0].Final || got[0].EndReason != "conntrack" || got[0].ID != first[0].ID || got[0].BytesOut != 0 {
		t.Errorf("%+v", got)
	}
	if got := tr.Close(t0.Add(5 * time.Second)); len(got) != 0 {
		t.Errorf("ended twice: %+v", got)
	}
}

// Offload is the point of running beside a capture: what's not offloaded was captured, and
// so was what an offloaded connection did before it left the CPU.
func TestTrackerOffloadedOnly(t *testing.T) {
	tr := Tracker{Mode: Offloaded}
	tr.Update(nil, true, t0)
	if got := tr.Update([]Entry{entry(1000, 0)}, true, t0.Add(time.Second)); len(got) != 0 {
		t.Fatalf("not offloaded, but reported: %+v", got)
	}
	if got := tr.Update([]Entry{entry(2000, statusOffload)}, true, t0.Add(2*time.Second)); len(got) != 0 {
		t.Fatalf("counted what capture saw: %+v", got)
	}
	got := tr.Update([]Entry{entry(2600, statusHWOffload)}, true, t0.Add(3*time.Second))
	if len(got) != 1 || got[0].BytesOut != 600 {
		t.Errorf("%+v", got)
	}
}

func TestTrackerCounterReset(t *testing.T) {
	tr := Tracker{Mode: All}
	tr.Update([]Entry{entry(1000, 0)}, true, t0)
	if got := tr.Update([]Entry{entry(10, 0)}, true, t0.Add(time.Second)); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
	got := tr.Update([]Entry{entry(30, 0)}, true, t0.Add(2*time.Second))
	if len(got) != 1 || got[0].BytesOut != 20 {
		t.Errorf("%+v", got)
	}
}

func TestTrackerNoCounters(t *testing.T) {
	tr := Tracker{Mode: All}
	tr.Update(nil, true, t0)
	e := entry(0, 0)
	e.Counted, e.PktsOrig, e.PktsReply = false, 0, 0
	got := tr.Update([]Entry{e}, true, t0.Add(time.Second))
	if len(got) != 1 || got[0].BytesOut != 0 {
		t.Fatalf("a connection with no counters should show once: %+v", got)
	}
	if got := tr.Update([]Entry{e}, true, t0.Add(2*time.Second)); len(got) != 0 {
		t.Errorf("said again: %+v", got)
	}
}

func TestTrackerIgnoresOwnAndLoopback(t *testing.T) {
	loop := entry(100, 0)
	loop.OrigSrc = netip.MustParseAddr("127.0.0.1")
	tr := Tracker{Mode: All, Ignore: func(src, _ netip.AddrPort) bool { return src.Port() == 40000 }}
	tr.Update(nil, true, t0)
	mine := entry(100, 0)
	mine.ID = 5
	if got := tr.Update([]Entry{loop, mine}, true, t0.Add(time.Second)); len(got) != 0 {
		t.Errorf("%+v", got)
	}
}

func TestParseMode(t *testing.T) {
	for _, s := range []string{"off", "offloaded", "all"} {
		if _, ok := ParseMode(s); !ok {
			t.Error(s)
		}
	}
	if _, ok := ParseMode("some"); ok {
		t.Error("accepted nonsense")
	}
}
