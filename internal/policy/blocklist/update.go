package blocklist

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// FetchResult is one conditional update attempt.
type FetchResult struct {
	Body         []byte
	ETag         string
	LastModified string
	NotModified  bool
	URL          string
}

// Fetcher retrieves blocklists with bounded size, time and redirects. By
// default it refuses private, loopback and link-local targets so a URL set by
// an operator cannot turn the server into an SSRF proxy.
type Fetcher struct {
	Client       *http.Client
	MaxBytes     int64
	AllowPrivate bool
	AllowHTTP    bool
	UserAgent    string
}

func (f *Fetcher) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	// The address is checked where the connection is made, not when the URL is
	// read: a name can resolve differently a moment later, and a redirect can
	// point anywhere.
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		if f.AllowPrivate {
			return nil
		}
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("blocklist fetch: unexpected address %q", address)
		}
		if isPrivate(ap.Addr().Unmap()) {
			return errPrivate
		}
		return nil
	}}
	tr := &http.Transport{
		Proxy:                  nil, // a proxy would make the dial check meaningless
		DialContext:            dialer.DialContext,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  20 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if req.URL.Scheme != "https" && !(f.AllowHTTP && req.URL.Scheme == "http") {
				return fmt.Errorf("redirect to %s is not https", req.URL.Scheme)
			}
			return nil
		},
	}
}

var errPrivate = errors.New("blocklist URL points at a private, loopback or link-local address")

// Fetch retrieves url, sending the conditional headers when supplied. A
// response over MaxBytes is an error, not a silently truncated list.
func (f *Fetcher) Fetch(ctx context.Context, rawURL, etag, lastModified string) (*FetchResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" && !(f.AllowHTTP && u.Scheme == "http") {
		return nil, fmt.Errorf("blocklist URL must be https")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("blocklist URL has no host")
	}
	if a, err := netip.ParseAddr(u.Hostname()); err == nil && !f.AllowPrivate && isPrivate(a.Unmap()) {
		return nil, errPrivate
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", firstNonEmpty(f.UserAgent, "netgraph-blocklist/1"))
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}
	resp, err := f.client().Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // an http client's error quotes the whole URL
		}
		return nil, fmt.Errorf("blocklist fetch from %s: %w", u.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return &FetchResult{NotModified: true, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"), URL: u.String()}, nil
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("blocklist fetch from %s: %s", u.Host, resp.Status)
	}
	max := f.MaxBytes
	if max <= 0 {
		max = 32 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("blocklist from %s is larger than %d bytes", u.Host, max)
	}
	return &FetchResult{
		Body: body, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"), URL: u.String(),
	}, nil
}

func isPrivate(a netip.Addr) bool {
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsUnspecified() || a.IsMulticast() || cgnat.Contains(a)
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}
