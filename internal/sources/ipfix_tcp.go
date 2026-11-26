package sources

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

const (
	// IPFIX's length field is 16 bits, so a message cannot be larger. One
	// connection holds at most one message at a time.
	maxIPFIXMessage  = 65535
	maxIPFIXTCPConns = 64
	ipfixTCPIdle     = 2 * time.Minute
)

var errIPFIXLength = errors.New("ipfix-tcp: bad message length")

// IPFIXTCP accepts IPFIX messages over TCP. Templates belong to the connection that
// announced them, so each gets its own. As with the UDP collector, Allow is required:
// it says which exporters to believe.
type IPFIXTCP struct {
	Listen string
	Allow  []netip.Prefix
	Local  []netip.Prefix
	Sink   Sink
	Log    *slog.Logger
	// Ready, if set, is told the address once it's listening.
	Ready func(addr string)
}

// Run listens until ctx ends. At most maxIPFIXTCPConns connections are handled at
// once; more are refused rather than remembered.
func (i *IPFIXTCP) Run(ctx context.Context) error {
	if len(i.Allow) == 0 {
		return fmt.Errorf("ipfix-tcp: needs addresses to accept exports from")
	}
	if i.Log == nil {
		i.Log = slog.Default()
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", i.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	if i.Ready != nil {
		i.Ready(ln.Addr().String())
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	slots := make(chan struct{}, maxIPFIXTCPConns)
	var busy spamLimit
	for {
		conn, err := ln.Accept()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		ua, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			conn.Close()
			continue
		}
		from := ua.AddrPort().Addr().Unmap()
		if !allowed(i.Allow, from) {
			conn.Close()
			busy.note(i.Log, time.Now(), "ipfix-tcp: a connection from an address not allowed")
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			busy.note(i.Log, time.Now(), "ipfix-tcp: too many connections")
			continue
		}
		go func() {
			defer func() {
				conn.Close()
				<-slots
			}()
			i.handle(ctx, conn, from)
		}()
	}
}

func (i *IPFIXTCP) handle(ctx context.Context, conn net.Conn, from netip.Addr) {
	pub := newPublisher("ipfix-tcp-"+from.String(), i.Local, i.Sink, i.Log)
	r := bufio.NewReaderSize(conn, 64<<10)
	var tmpl Templates
	var evs []wire.Event
	for {
		if ctx.Err() != nil {
			pub.send(context.WithoutCancel(ctx), evs)
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(ipfixTCPIdle))
		msg, err := readIPFIXMessage(r)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					// A quiet exporter: close the connection, not the listener.
				} else {
					i.Log.Debug("ipfix-tcp: a connection ended", "from", from, "err", err)
				}
			}
			pub.send(context.WithoutCancel(ctx), evs)
			return
		}
		flows, err := ParseNetFlow(msg, &tmpl, time.Now())
		if err != nil {
			i.Log.Debug("ipfix-tcp: a message didn't parse", "from", from, "err", err)
		}
		for n := range flows {
			f := flows[n]
			evs = append(evs, wire.Event{Type: wire.TypeFlow, TS: f.End, Flow: &f})
		}
		// TCP exporters usually send several messages without pausing; send what
		// this one said, without waiting for a full batch that may never come.
		if len(evs) > 0 {
			pub.send(ctx, evs)
			evs = nil
		}
	}
}

// readIPFIXMessage reads one framed message. IPFIX-over-TCP normally begins with the
// message's own version and length fields; some exporters put a two-byte length in
// front instead. Both are accepted, and nothing is allocated for a length that cannot
// be a message.
func readIPFIXMessage(r *bufio.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:2]); err != nil {
		return nil, err
	}
	first := binary.BigEndian.Uint16(hdr[:2])
	if first == 10 { // the message starts here: the length is its third field
		if _, err := io.ReadFull(r, hdr[2:]); err != nil {
			return nil, err
		}
		length := int(binary.BigEndian.Uint16(hdr[2:]))
		if length < 16 || length > maxIPFIXMessage {
			return nil, errIPFIXLength
		}
		msg := make([]byte, length)
		copy(msg, hdr[:4])
		if _, err := io.ReadFull(r, msg[4:]); err != nil {
			return nil, err
		}
		return msg, nil
	}
	length := int(first)
	if length < 16 || length > maxIPFIXMessage {
		return nil, errIPFIXLength
	}
	msg := make([]byte, length)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	if len(msg) < 2 || binary.BigEndian.Uint16(msg) != 10 {
		return nil, fmt.Errorf("ipfix-tcp: message is not IPFIX")
	}
	return msg, nil
}
