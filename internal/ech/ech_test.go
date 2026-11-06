package ech

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
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
		// outer type, HKDF-SHA256 + AES-128-GCM, config 7, a 32-byte X25519
		// enc and the encrypted inner hello, each with a 16-bit length.
		enc := make([]byte, 32)
		payload := make([]byte, 200)
		data := []byte{0, 0x00, 0x01, 0x00, 0x01, 0x07, 0, byte(len(enc))}
		data = append(data, enc...)
		data = append(data, byte(len(payload)>>8), byte(len(payload)))
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
	if o.OuterSNI != "public.example" || !o.ECH || o.ConfigID != 7 || o.PayloadLen != 200 {
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

// A ClientHello from Go's own TLS stack, offering ECH, parses: outer name,
// config ID and the length of the encrypted inner hello.
func TestInspectRealECHHello(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// ECHConfig (RFC 9849 §4): version, length, then the contents.
	var c []byte
	c = append(c, 42)         // config_id
	c = append(c, 0x00, 0x20) // KEM: DHKEM(X25519, HKDF-SHA256)
	pub := key.PublicKey().Bytes()
	c = append(c, byte(len(pub)>>8), byte(len(pub)))
	c = append(c, pub...)
	c = append(c, 0, 4, 0x00, 0x01, 0x00, 0x01) // HKDF-SHA256, AES-128-GCM
	c = append(c, 0)                            // maximum_name_length
	name := "public.example"
	c = append(c, byte(len(name)))
	c = append(c, name...)
	c = append(c, 0, 0) // extensions
	cfg := append([]byte{0xfe, 0x0d, byte(len(c) >> 8), byte(len(c))}, c...)
	list := append([]byte{byte(len(cfg) >> 8), byte(len(cfg))}, cfg...)

	client, server := net.Pipe()
	defer server.Close()
	go func() {
		conn := tls.Client(client, &tls.Config{ServerName: "secret.example", MinVersion: tls.VersionTLS13,
			EncryptedClientHelloConfigList: list})
		_ = conn.Handshake()
		client.Close()
	}()
	buf := make([]byte, 16<<10)
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.ReadAtLeast(server, buf, 5)
	if err != nil {
		t.Fatal(err)
	}
	for n < 5+int(binary.BigEndian.Uint16(buf[3:5])) {
		m, err := server.Read(buf[n:])
		if err != nil {
			t.Fatal(err)
		}
		n += m
	}
	o, ok, err := Inspect(buf[:n])
	if err != nil || !ok {
		t.Fatalf("inspect = %+v %v %v", o, ok, err)
	}
	if o.OuterSNI != "public.example" || o.ECHType != 0 || o.ConfigID != 42 || o.PayloadLen < 100 {
		t.Fatalf("observation = %+v", o)
	}
}
