package sources

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

const (
	// A syslog datagram is tiny; anything larger is cut off rather than read into
	// memory. The extra byte is how an oversized datagram is noticed.
	maxSyslogDatagram = 8 << 10
	maxSyslogLines    = 64
	syslogFlush       = 2 * time.Second
)

// SyslogConfig is a UDP syslog receiver for a DNS server's log. Allow is required:
// UDP has no login, so it says whose messages to believe. Format is the parser to
// hand each message to: dnsmasq (also Pi-hole), adguard, unbound or bind.
type SyslogConfig struct {
	Addr   string
	Allow  []netip.Prefix
	Format string
	Local  []netip.Prefix
	Log    *slog.Logger
	// Ready, if set, is told the address once it's listening.
	Ready func(addr string)
}

// RunSyslog listens for syslog lines until ctx ends. It strips each message's RFC 3164
// or RFC 5424 header and gives the rest to the same parser the DNS log follower uses,
// publishing lookups through publish the way a sensor would.
func RunSyslog(ctx context.Context, cfg SyslogConfig, publish Sink) error {
	if len(cfg.Allow) == 0 {
		return fmt.Errorf("syslog: needs addresses to accept messages from")
	}
	if !ValidDNSLogFormat(cfg.Format) {
		return fmt.Errorf("syslog: format %q", cfg.Format)
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	conn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", cfg.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if cfg.Ready != nil {
		cfg.Ready(conn.LocalAddr().String())
	}
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	pub := newPublisher("syslog", cfg.Local, publish, cfg.Log)
	parser := newLogParser(cfg.Format, false)
	var refused, bad spamLimit
	buf := make([]byte, maxSyslogDatagram+1)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(syslogFlush))
		n, addr, err := conn.ReadFrom(buf)
		now := time.Now()
		if ctx.Err() != nil {
			pub.send(context.WithoutCancel(ctx), parser.Close())
			return nil
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				pub.send(ctx, parser.Tick())
				continue
			}
			return err
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		from := ua.AddrPort().Addr().Unmap()
		if !allowed(cfg.Allow, from) {
			refused.note(cfg.Log, now, "syslog: a datagram from an address not allowed")
			continue
		}
		if n > maxSyslogDatagram {
			bad.note(cfg.Log, now, "syslog: an oversized datagram was dropped", "from", from)
			continue
		}
		var evs []wire.Event
		lines := strings.Split(string(buf[:n]), "\n")
		for i, line := range lines {
			if i >= maxSyslogLines {
				bad.note(cfg.Log, now, "syslog: a datagram held too many lines", "from", from)
				break
			}
			line = strings.TrimRight(line, "\r")
			if line == "" {
				continue
			}
			ts, msg := stripLogHeader(line, now)
			evs = append(evs, parser.Message(msg, ts)...)
		}
		evs = append(evs, parser.Tick()...)
		pub.send(ctx, evs)
	}
}

// spamLimit logs the first occurrence of a repeated problem, then at most once a
// minute, with how many were held back. It keeps a bad sender from filling the log.
type spamLimit struct {
	last    time.Time
	dropped int
}

func (s *spamLimit) note(log *slog.Logger, now time.Time, msg string, args ...any) {
	if !s.last.IsZero() && now.Sub(s.last) < time.Minute {
		s.dropped++
		return
	}
	if s.dropped > 0 {
		args = append(args, "suppressed", s.dropped)
	}
	log.Debug(msg, args...)
	s.last, s.dropped = now, 0
}
