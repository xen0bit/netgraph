package dnsserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxMessage is the largest DNS message over TCP (and so anywhere).
const maxMessage = 65535

// upstreamTimeout bounds one exchange with one upstream.
const upstreamTimeout = 4 * time.Second

// Upstream is a resolver lookups are forwarded to.
type Upstream interface {
	// Exchange sends one query and returns the answer.
	Exchange(ctx context.Context, q []byte) ([]byte, error)
	// Name is the scheme and host: never the path or query, which can
	// hold an account's ID (NextDNS, ControlD).
	Name() string
}

// ParseUpstream reads one upstream:
//
//	udp://1.1.1.1            plain DNS (53), over TCP when the answer is truncated
//	tcp://1.1.1.1:53         plain DNS over TCP
//	tls://1.1.1.1:853#cloudflare-dns.com   DNS over TLS; after # the name its certificate must have
//	https://dns.quad9.net/dns-query        DNS over HTTPS (RFC 8484)
//
// A bare address is udp://. A host name is resolved by the system's resolver:
// if that is this server, give an address (and the TLS name after #).
func ParseUpstream(s string) (Upstream, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		s = "udp://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("an upstream is not a URL") // the URL itself may hold a secret
	}
	switch u.Scheme {
	case "udp", "tcp", "tls":
		port := "53"
		if u.Scheme == "tls" {
			port = "853"
		}
		host := u.Host
		if u.Port() == "" {
			host = net.JoinHostPort(strings.Trim(u.Hostname(), "[]"), port)
		}
		if u.Hostname() == "" {
			return nil, fmt.Errorf("%s upstream has no host", u.Scheme)
		}
		if u.Scheme == "tls" {
			sni := u.Fragment
			if sni == "" {
				sni = u.Hostname()
			}
			return &streamUpstream{addr: host, tls: &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12}, name: "tls://" + host}, nil
		}
		if u.Scheme == "tcp" {
			return &streamUpstream{addr: host, name: "tcp://" + host}, nil
		}
		return &udpUpstream{addr: host, tcp: &streamUpstream{addr: host, name: "tcp://" + host}, name: "udp://" + host}, nil
	case "https":
		if u.Host == "" {
			return nil, errors.New("https upstream has no host")
		}
		return &dohUpstream{url: u.String(), name: "https://" + u.Host,
			client: &http.Client{Timeout: upstreamTimeout, Transport: &http.Transport{
				Proxy: nil, ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 4, IdleConnTimeout: 90 * time.Second,
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			}}}, nil
	}
	return nil, fmt.Errorf("upstream scheme %q is not udp, tcp, tls or https", u.Scheme)
}

// ReadUpstreams reads a file of upstreams, one a line; a line starting with #
// is a comment. The
// file is where they belong rather than a flag: a DoH URL can hold an
// account's ID, and flags show in a process list.
func ReadUpstreams(path string) ([]Upstream, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseUpstreams(string(b))
}

// ParseUpstreams reads upstreams from text, one a line or separated by commas.
func ParseUpstreams(text string) ([]Upstream, error) {
	var out []Upstream
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		// A comment is a line starting with #, or what follows " #": a # with
		// no space before it names a TLS server (tls://1.1.1.1#one.one.one.one).
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		for _, f := range strings.Split(line, ",") {
			if f = strings.TrimSpace(f); f == "" {
				continue
			}
			u, err := ParseUpstream(f)
			if err != nil {
				return nil, err
			}
			out = append(out, u)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no upstream resolvers")
	}
	return out, nil
}

type udpUpstream struct {
	addr, name string
	tcp        *streamUpstream
}

func (u *udpUpstream) Name() string { return u.name }

func (u *udpUpstream) Exchange(ctx context.Context, q []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", u.addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, maxMessage)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		a := buf[:n]
		// A connected UDP socket only hears its peer; still, an answer must
		// be to this question.
		if n < 12 || a[0] != q[0] || a[1] != q[1] {
			continue
		}
		if a[2]&0x02 != 0 { // TC: too big for UDP, ask again over TCP
			return u.tcp.Exchange(ctx, q)
		}
		return bytes.Clone(a), nil
	}
}

// streamUpstream is DNS over TCP, or over TLS.
type streamUpstream struct {
	addr, name string
	tls        *tls.Config
}

func (u *streamUpstream) Name() string { return u.name }

func (u *streamUpstream) Exchange(ctx context.Context, q []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	var c net.Conn
	var err error
	if u.tls != nil {
		d := tls.Dialer{Config: u.tls}
		c, err = d.DialContext(ctx, "tcp", u.addr)
	} else {
		var d net.Dialer
		c, err = d.DialContext(ctx, "tcp", u.addr)
	}
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	return exchangeStream(c, q)
}

// exchangeStream writes one length-prefixed query and reads one answer.
func exchangeStream(c io.ReadWriter, q []byte) ([]byte, error) {
	if len(q) > maxMessage {
		return nil, errors.New("query too long")
	}
	msg := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(msg, uint16(len(q)))
	copy(msg[2:], q)
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	a := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, a); err != nil {
		return nil, err
	}
	if len(a) < 12 || a[0] != q[0] || a[1] != q[1] {
		return nil, errors.New("answer to another question")
	}
	return a, nil
}

type dohUpstream struct {
	url, name string
	client    *http.Client
}

func (u *dohUpstream) Name() string { return u.name }

func (u *dohUpstream) Exchange(ctx context.Context, q []byte) ([]byte, error) {
	// RFC 8484 asks for ID 0, which caches better; the caller's ID is put back.
	id0 := bytes.Clone(q)
	id0[0], id0[1] = 0, 0
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(id0))
	if err != nil {
		return nil, errors.New("bad DoH request") // the URL may hold a secret
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := u.client.Do(req)
	if err != nil {
		// An http client's error quotes the URL, and the URL may hold an
		// account's ID: say only what kind of failure it was.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("%s: %w", u.name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", u.name, resp.StatusCode)
	}
	a, err := io.ReadAll(io.LimitReader(resp.Body, maxMessage+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", u.name, err)
	}
	if len(a) < 12 || len(a) > maxMessage {
		return nil, fmt.Errorf("%s: not a DNS answer", u.name)
	}
	a[0], a[1] = q[0], q[1]
	return a, nil
}

// pool tries upstreams in order, skipping for a while one that just failed,
// unless every one has.
type pool struct {
	ups   []Upstream
	state []upState
}

type upState struct {
	mu        sync.Mutex
	downUntil time.Time
	answered  atomic.Uint64
	failed    atomic.Uint64
	latency   atomic.Int64 // microseconds, smoothed
}

const upstreamBackoff = 30 * time.Second

func newPool(ups []Upstream) *pool {
	return &pool{ups: ups, state: make([]upState, len(ups))}
}

func (p *pool) exchange(ctx context.Context, q []byte) ([]byte, error) {
	now := time.Now()
	order := make([]int, 0, len(p.ups))
	var down []int
	for i := range p.ups {
		p.state[i].mu.Lock()
		if now.Before(p.state[i].downUntil) {
			down = append(down, i)
		} else {
			order = append(order, i)
		}
		p.state[i].mu.Unlock()
	}
	order = append(order, down...)
	var errs []error
	for _, i := range order {
		if ctx.Err() != nil {
			break
		}
		st := &p.state[i]
		t0 := time.Now()
		a, err := p.ups[i].Exchange(ctx, q)
		if err == nil {
			st.answered.Add(1)
			us := time.Since(t0).Microseconds()
			if old := st.latency.Load(); old == 0 {
				st.latency.Store(us)
			} else {
				st.latency.Store((old*7 + us) / 8)
			}
			st.mu.Lock()
			st.downUntil = time.Time{}
			st.mu.Unlock()
			return a, nil
		}
		st.failed.Add(1)
		st.mu.Lock()
		st.downUntil = time.Now().Add(upstreamBackoff)
		st.mu.Unlock()
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		return nil, ctx.Err()
	}
	return nil, errors.Join(errs...)
}
