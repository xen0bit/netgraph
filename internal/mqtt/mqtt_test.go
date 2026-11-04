package mqtt

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// broker accepts one connection, answers like a broker and records what it gets.
type testBroker struct {
	l        net.Listener
	connects chan []byte
	publish  chan [2]string
	retained chan bool
	refuse   byte
	pings    chan struct{}
}

func newBroker(t *testing.T, refuse byte) *testBroker {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &testBroker{l: l, connects: make(chan []byte, 4), publish: make(chan [2]string, 16), retained: make(chan bool, 16), refuse: refuse, pings: make(chan struct{}, 16)}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go b.serve(c)
		}
	}()
	return b
}

func (b *testBroker) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		typ, flags, body, err := ReadPacket(r)
		if err != nil {
			return
		}
		switch typ {
		case typeConnect:
			b.connects <- body
			_, _ = c.Write([]byte{typeConnack << 4, 2, 0, b.refuse})
		case typePublish:
			n := int(body[0])<<8 | int(body[1])
			b.publish <- [2]string{string(body[2 : 2+n]), string(body[2+n:])}
			b.retained <- flags&1 == 1
		case typePingReq:
			b.pings <- struct{}{}
			_, _ = c.Write([]byte{typePingRes << 4, 0})
		case typeDisconn:
			return
		}
	}
}

func TestPublishes(t *testing.T) {
	b := newBroker(t, 0)
	c, err := Dial(context.Background(), Options{Addr: b.l.Addr().String(), ClientID: "ng", Username: "u", Password: "p", WillTopic: "s", WillBody: []byte("off"), WillRetain: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn := <-b.connects
	for _, want := range []string{"MQTT", "ng", "u", "p", "off"} {
		if !bytes.Contains(conn, []byte(want)) {
			t.Errorf("connect lacks %q: %q", want, conn)
		}
	}
	if err := c.Publish("a/b", []byte("hello"), true); err != nil {
		t.Fatal(err)
	}
	if got := <-b.publish; got != [2]string{"a/b", "hello"} {
		t.Errorf("got %v", got)
	}
	if !<-b.retained {
		t.Error("not retained")
	}
	// Past 127 bytes the length takes two bytes.
	long := strings.Repeat("x", 1000)
	if err := c.Publish("l", []byte(long), false); err != nil {
		t.Fatal(err)
	}
	if got := <-b.publish; got[1] != long {
		t.Errorf("long body: %d bytes", len(got[1]))
	}
	if <-b.retained {
		t.Error("retained")
	}
}

func TestBrokerRefuses(t *testing.T) {
	b := newBroker(t, 4)
	_, err := Dial(context.Background(), Options{Addr: b.l.Addr().String(), ClientID: "ng"})
	if err == nil || !strings.Contains(err.Error(), "bad user name or password") {
		t.Errorf("got %v", err)
	}
}

func TestPingsAndNoticesTheEnd(t *testing.T) {
	b := newBroker(t, 0)
	c, err := Dial(context.Background(), Options{Addr: b.l.Addr().String(), ClientID: "ng", KeepAlive: 40 * time.Millisecond, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-b.pings:
	case <-time.After(5 * time.Second):
		t.Fatal("no ping")
	}
	b.l.Close()
	c.conn.Close()
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the end went unnoticed")
	}
	if err := c.Publish("a", nil, false); err == nil {
		t.Error("a publish on a dead connection worked")
	}
}

// A broker that sends a huge length must not get memory for it.
func TestOversizedPacketRefused(t *testing.T) {
	for _, in := range [][]byte{
		{typeConnack << 4, 0xff, 0xff, 0xff, 0x7f},
		{typeConnack << 4, 0xff, 0xff, 0xff, 0xff, 0x01},
		{typeConnack << 4, 0x80},
	} {
		if _, _, _, err := ReadPacket(bufio.NewReader(bytes.NewReader(in))); err == nil {
			t.Errorf("%x was accepted", in)
		}
	}
}

func FuzzReadPacket(f *testing.F) {
	f.Add([]byte{typeConnack << 4, 2, 0, 0})
	f.Add([]byte{typePublish << 4, 5, 0, 1, 'a', 'b', 'c'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, in []byte) {
		r := bufio.NewReader(bytes.NewReader(in))
		for range 16 {
			_, _, body, err := ReadPacket(r)
			if err != nil {
				return
			}
			if len(body) > maxInbound {
				t.Fatalf("%d bytes", len(body))
			}
		}
	})
}
