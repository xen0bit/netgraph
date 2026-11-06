package ech

import (
	"encoding/binary"
	"testing"
)

func clientHello(sni string, ech bool) []byte {
	var exts []byte
	if sni != "" {
		name := []byte(sni)
		entry := append([]byte{0, byte(len(name) >> 8), byte(len(name))}, name...)
		list := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
		exts = append(exts, 0, 0, byte(len(list)>>8), byte(len(list)))
		exts = append(exts, list...)
	}
	if ech {
		payload := []byte("inner")
		data := []byte{0, 0x00, 0x01, 0x00, 0x01, 0x07, 0, 0, byte(len(payload))}
		data = append(data, payload...)
		exts = append(exts, 0xfe, 0x0d, byte(len(data)>>8), byte(len(data)))
		exts = append(exts, data...)
	}
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                // session id length
	body = append(body, 0, 2, 0x13, 0x01) // cipher suites
	body = append(body, 1, 0)             // compression methods
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := []byte{0x16, 0x03, 0x01, 0, 0}
	binary.BigEndian.PutUint16(rec[3:], uint16(len(hs)))
	return append(rec, hs...)
}

func TestInspectECH(t *testing.T) {
	o, ok, err := Inspect(clientHello("public.example", true))
	if err != nil || !ok {
		t.Fatalf("inspect = %+v %v %v", o, ok, err)
	}
	if o.OuterSNI != "public.example" || !o.ECH || o.ConfigID != 7 || o.PayloadLen != 5 {
		t.Fatalf("observation = %+v", o)
	}
}

func TestInspectWithoutECH(t *testing.T) {
	o, ok, err := Inspect(clientHello("plain.example", false))
	if err != nil || ok || o.ECH {
		t.Fatalf("inspect = %+v %v %v", o, ok, err)
	}
	if _, _, err := Inspect([]byte("not tls")); err != ErrNoClientHello {
		t.Fatalf("err = %v", err)
	}
}
