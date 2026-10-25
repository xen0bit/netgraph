package capture

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

var t0 = time.Date(2026, 10, 25, 12, 0, 0, 123456789, time.UTC)

// pcapgo writes the fixtures: an independent implementation of both
// formats to read back.
func fixtures(t *testing.T) map[string][]byte {
	frames := [][]byte{{1, 2, 3, 4}, bytes.Repeat([]byte{9}, 1500)}
	out := map[string][]byte{}

	var us bytes.Buffer
	w := pcapgo.NewWriter(&us)
	_ = w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	for i, f := range frames {
		_ = w.WritePacket(gopacket.CaptureInfo{Timestamp: t0.Add(time.Duration(i) * time.Second), CaptureLength: len(f), Length: len(f)}, f)
	}
	out["pcap-us"] = us.Bytes()

	var ns bytes.Buffer
	w = pcapgo.NewWriterNanos(&ns)
	_ = w.WriteFileHeader(65536, layers.LinkTypeRaw)
	for i, f := range frames {
		_ = w.WritePacket(gopacket.CaptureInfo{Timestamp: t0.Add(time.Duration(i) * time.Second), CaptureLength: len(f), Length: len(f)}, f)
	}
	out["pcap-ns"] = ns.Bytes()

	var ng bytes.Buffer
	nw, err := pcapgo.NewNgWriter(&ng, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range frames {
		_ = nw.WritePacket(gopacket.CaptureInfo{Timestamp: t0.Add(time.Duration(i) * time.Second), CaptureLength: len(f), Length: len(f), InterfaceIndex: 0}, f)
	}
	_ = nw.Flush()
	out["pcapng"] = ng.Bytes()
	return out
}

func TestReadFormats(t *testing.T) {
	for name, data := range fixtures(t) {
		r, err := NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for i := range 2 {
			d, ts, err := r.ReadPacket()
			if err != nil {
				t.Fatalf("%s packet %d: %v", name, i, err)
			}
			want := t0.Add(time.Duration(i) * time.Second)
			if name == "pcap-us" {
				want = want.Truncate(time.Microsecond)
			}
			if !ts.Equal(want) || (i == 0 && !bytes.Equal(d, []byte{1, 2, 3, 4})) || (i == 1 && len(d) != 1500) {
				t.Fatalf("%s packet %d: ts %v len %d", name, i, ts, len(d))
			}
		}
		if _, _, err := r.ReadPacket(); err != io.EOF {
			t.Fatalf("%s: end: %v", name, err)
		}
		wantLink := LinkEthernet
		if name == "pcap-ns" {
			wantLink = LinkRaw
		}
		if r.LinkType() != wantLink {
			t.Fatalf("%s: link %d", name, r.LinkType())
		}
	}
}

func TestTruncatedFileEndsCleanly(t *testing.T) {
	data := fixtures(t)["pcap-us"]
	r, _ := NewReader(bytes.NewReader(data[:len(data)-100]))
	if _, _, err := r.ReadPacket(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ReadPacket(); err != io.EOF {
		t.Fatalf("got %v, want EOF", err)
	}
	if _, err := NewReader(bytes.NewReader([]byte("not a capture file"))); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestBigEndianPcap(t *testing.T) {
	var b bytes.Buffer
	hdr := make([]byte, 24)
	binary.BigEndian.PutUint32(hdr, 0xa1b2c3d4)
	binary.BigEndian.PutUint32(hdr[20:], 1)
	b.Write(hdr)
	rec := make([]byte, 16)
	binary.BigEndian.PutUint32(rec, uint32(t0.Unix()))
	binary.BigEndian.PutUint32(rec[4:], 5)
	binary.BigEndian.PutUint32(rec[8:], 2)
	b.Write(rec)
	b.Write([]byte{7, 8})
	r, err := NewReader(&b)
	if err != nil {
		t.Fatal(err)
	}
	d, ts, err := r.ReadPacket()
	if err != nil || !bytes.Equal(d, []byte{7, 8}) || ts.Nanosecond() != 5000 {
		t.Fatalf("%v %v %v", d, ts, err)
	}
}

func FuzzReader(f *testing.F) {
	for _, d := range fixtures(&testing.T{}) {
		f.Add(d)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := NewReader(bytes.NewReader(b))
		if err != nil {
			return
		}
		for range 100 {
			if _, _, err := r.ReadPacket(); err != nil {
				return
			}
		}
	})
}
