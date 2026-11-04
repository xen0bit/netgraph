// Package mqtt is a small MQTT 3.1.1 publisher: connect, publish, keep alive. It
// only ever publishes, so all it reads from a broker is acknowledgements, and
// netgraph takes no dependency for a protocol this small.
//
// A broker is a remote party. Everything read from it is bounded, and an oversized
// or malformed packet ends the connection.
package mqtt

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Packet types.
const (
	typeConnect = 1
	typeConnack = 2
	typePublish = 3
	typePuback  = 4
	typePingReq = 12
	typePingRes = 13
	typeDisconn = 14
)

// maxInbound is the largest packet a publisher should ever be sent: every
// acknowledgement it asks for is a few bytes, and it subscribes to nothing.
const maxInbound = 4096

// Options configure a connection.
type Options struct {
	Addr       string // host:port
	TLS        *tls.Config
	ClientID   string
	Username   string
	Password   string
	KeepAlive  time.Duration // default 60s
	Timeout    time.Duration // for connecting and for each write; default 15s
	WillTopic  string        // published by the broker if this connection dies
	WillBody   []byte
	WillRetain bool
}

// Client is one connection. It doesn't reconnect: Done closes when the connection
// ends, and the caller decides what to do.
type Client struct {
	opts Options
	conn net.Conn
	mu   sync.Mutex // serialises writes
	done chan struct{}
	once sync.Once
	err  error
}

// Dial connects and completes the MQTT handshake.
func Dial(ctx context.Context, o Options) (*Client, error) {
	if o.KeepAlive <= 0 {
		o.KeepAlive = 60 * time.Second
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	d := net.Dialer{Timeout: o.Timeout}
	var conn net.Conn
	var err error
	if o.TLS != nil {
		conn, err = (&tls.Dialer{NetDialer: &d, Config: o.TLS}).DialContext(ctx, "tcp", o.Addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", o.Addr)
	}
	if err != nil {
		return nil, err
	}
	c := &Client{opts: o, conn: conn, done: make(chan struct{})}
	if err := c.handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	go c.readLoop()
	go c.pingLoop()
	return c, nil
}

func (c *Client) handshake() error {
	pkt, err := connectPacket(c.opts)
	if err != nil {
		return err
	}
	_ = c.conn.SetDeadline(time.Now().Add(c.opts.Timeout))
	if _, err := c.conn.Write(pkt); err != nil {
		return err
	}
	typ, _, body, err := ReadPacket(bufio.NewReader(c.conn))
	if err != nil {
		return fmt.Errorf("reading connack: %w", err)
	}
	if typ != typeConnack || len(body) != 2 {
		return fmt.Errorf("the broker answered with packet type %d", typ)
	}
	if body[1] != 0 {
		return fmt.Errorf("the broker refused the connection: %s", connackReason(body[1]))
	}
	_ = c.conn.SetDeadline(time.Time{})
	return nil
}

func connackReason(code byte) string {
	switch code {
	case 1:
		return "unacceptable protocol version"
	case 2:
		return "client identifier rejected"
	case 3:
		return "server unavailable"
	case 4:
		return "bad user name or password"
	case 5:
		return "not authorised"
	}
	return fmt.Sprintf("code %d", code)
}

func appendString(b []byte, s []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

// A string or topic in MQTT has a 16-bit length.
const maxString = 65535

func connectPacket(o Options) ([]byte, error) {
	if len(o.ClientID) > maxString || len(o.Username) > maxString || len(o.Password) > maxString || len(o.WillTopic) > maxString || len(o.WillBody) > maxString {
		return nil, errors.New("mqtt: a connect field is too long")
	}
	body := appendString(nil, []byte("MQTT"))
	body = append(body, 4) // protocol level: 3.1.1
	flags := byte(0x02)    // clean session
	if o.WillTopic != "" {
		flags |= 0x04
		if o.WillRetain {
			flags |= 0x20
		}
	}
	if o.Username != "" {
		flags |= 0x80
		if o.Password != "" {
			flags |= 0x40
		}
	}
	body = append(body, flags)
	body = binary.BigEndian.AppendUint16(body, uint16(o.KeepAlive/time.Second))
	body = appendString(body, []byte(o.ClientID))
	if o.WillTopic != "" {
		body = appendString(body, []byte(o.WillTopic))
		body = appendString(body, o.WillBody)
	}
	if o.Username != "" {
		body = appendString(body, []byte(o.Username))
		if o.Password != "" {
			body = appendString(body, []byte(o.Password))
		}
	}
	return frame(typeConnect<<4, body)
}

// maxRemaining is the most the protocol's length field can say.
const maxRemaining = 268435455

func frame(first byte, body []byte) ([]byte, error) {
	if len(body) > maxRemaining {
		return nil, errors.New("mqtt: packet too large")
	}
	out := []byte{first}
	n := len(body)
	for {
		b := byte(n % 128)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			break
		}
	}
	return append(out, body...), nil
}

// ReadPacket reads one packet: its type, flags and body. A packet longer than a
// publisher can have asked for is an error, before anything is allocated for it.
func ReadPacket(r io.ByteReader) (typ, flags byte, body []byte, err error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, 0, nil, err
	}
	n, mul := 0, 1
	for i := 0; ; i++ {
		if i == 4 {
			return 0, 0, nil, errors.New("mqtt: malformed length")
		}
		b, err := r.ReadByte()
		if err != nil {
			return 0, 0, nil, err
		}
		n += int(b&0x7f) * mul
		mul *= 128
		if b&0x80 == 0 {
			break
		}
	}
	if n > maxInbound {
		return 0, 0, nil, fmt.Errorf("mqtt: a %d-byte packet from the broker", n)
	}
	body = make([]byte, n)
	for i := range body {
		if body[i], err = r.ReadByte(); err != nil {
			return 0, 0, nil, err
		}
	}
	return first >> 4, first & 0x0f, body, nil
}

// Publish sends at QoS 0, which is all a state that's republished needs.
func (c *Client) Publish(topic string, body []byte, retain bool) error {
	if topic == "" || len(topic) > maxString {
		return errors.New("mqtt: bad topic")
	}
	first := byte(typePublish << 4)
	if retain {
		first |= 1
	}
	pkt := appendString(make([]byte, 0, len(topic)+len(body)+2), []byte(topic))
	pkt = append(pkt, body...)
	out, err := frame(first, pkt)
	if err != nil {
		return err
	}
	return c.write(out)
}

func (c *Client) write(b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return c.Err()
	default:
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.opts.Timeout))
	if _, err := c.conn.Write(b); err != nil {
		c.stop(err)
		return err
	}
	return nil
}

// readLoop watches for the connection ending. Nothing a publisher is sent needs
// acting on, but a silent broker must be noticed: it should answer every ping.
func (c *Client) readLoop() {
	r := bufio.NewReader(c.conn)
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.opts.KeepAlive + c.opts.Timeout))
		if _, _, _, err := ReadPacket(r); err != nil {
			c.stop(err)
			return
		}
	}
}

func (c *Client) pingLoop() {
	t := time.NewTicker(c.opts.KeepAlive * 3 / 4)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			if err := c.write([]byte{typePingReq << 4, 0}); err != nil {
				return
			}
		}
	}
}

func (c *Client) stop(err error) {
	c.once.Do(func() {
		c.err = err
		close(c.done)
		c.conn.Close()
	})
}

// Done closes when the connection has ended.
func (c *Client) Done() <-chan struct{} { return c.done }

// Err says why it ended, once Done is closed.
func (c *Client) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}

// Close says goodbye, so the broker doesn't publish the will.
func (c *Client) Close() {
	_ = c.write([]byte{typeDisconn << 4, 0})
	c.stop(errors.New("closed"))
}
