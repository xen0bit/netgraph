//go:build experimental

package main

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/xen0bit/netgraph/internal/capture"
)

func hello() []byte {
	name := []byte("outer.example")
	entry := append([]byte{0, byte(len(name) >> 8), byte(len(name))}, name...)
	list := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	exts := append([]byte{0, 0, byte(len(list) >> 8), byte(len(list))}, list...)
	payload := []byte("inner")
	// outer, HKDF-SHA256 + AES-128-GCM, config 7, an empty enc, the payload
	data := []byte{0, 0, 1, 0, 1, 7, 0, 0, 0, byte(len(payload))}
	data = append(data, payload...)
	exts = append(exts, 0xfe, 0x0d, byte(len(data)>>8), byte(len(data)))
	exts = append(exts, data...)
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := []byte{0x16, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(rec[3:], uint16(len(hs)))
	return append(rec, hs...)
}

func TestInspectFrame(t *testing.T) {
	ip := layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: []byte{10, 0, 0, 2}, DstIP: []byte{203, 0, 113, 9}}
	tcp := layers.TCP{SrcPort: 50000, DstPort: 443, Seq: 1, SYN: true}
	if err := tcp.SetNetworkLayerForChecksum(&ip); err != nil {
		t.Fatal(err)
	}
	eth := layers.Ethernet{SrcMAC: []byte{1, 2, 3, 4, 5, 6}, DstMAC: []byte{6, 5, 4, 3, 2, 1}, EthernetType: layers.EthernetTypeIPv4}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload(hello())); err != nil {
		t.Fatal(err)
	}
	r, ok := inspectFrame(buf.Bytes(), capture.LinkEthernet, time.Now())
	if !ok || !r.Obs.ECH || r.Obs.OuterSNI != "outer.example" || r.Obs.PayloadLen != 5 || r.Src != "10.0.0.2" {
		t.Fatalf("result = %+v ok=%v", r, ok)
	}
}
