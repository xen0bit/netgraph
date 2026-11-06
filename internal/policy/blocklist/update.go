package blocklist

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
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
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if req.URL.Scheme != "https" && !f.AllowHTTP {
				return fmt.Errorf("redirect to %s is not https", req.URL.Scheme)
			}
			return nil
		},
	}
}

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
	if err := f.checkHost(ctx, u.Hostname()); err != nil {
		return nil, err
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
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return &FetchResult{NotModified: true, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"), URL: u.String()}, nil
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("blocklist %s: %s", u, resp.Status)
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
		return nil, fmt.Errorf("blocklist %s is larger than %d bytes", u, max)
	}
	return &FetchResult{
		Body: body, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"), URL: u.String(),
	}, nil
}

func (f *Fetcher) checkHost(ctx context.Context, host string) error {
	if f.AllowPrivate {
		return nil
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if isPrivate(a) {
			return fmt.Errorf("blocklist URL points at a private address")
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, a := range ips {
		if isPrivate(a.Unmap()) {
			return fmt.Errorf("blocklist URL resolves to a private address")
		}
	}
	return nil
}

func isPrivate(a netip.Addr) bool {
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified()
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}
