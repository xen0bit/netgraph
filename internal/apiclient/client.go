// Package apiclient is the HTTP client for netgraph's API. It implements
// model.Backend, and works under GOOS=js too, where net/http uses the
// browser's fetch, which is how the WASM web UI talks to its server.
package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

// Client queries a netgraph server.
type Client struct {
	Base  string // e.g. "https://netgraph.lan:8443"; "" means same origin (WASM)
	Token string
	HTTP  *http.Client
}

var _ model.Backend = (*Client)(nil)

// NewClient returns a client for base.
func NewClient(base, token string) *Client {
	return &Client{Base: strings.TrimRight(base, "/"), Token: token, HTTP: &http.Client{Timeout: 2 * time.Minute}}
}

// Error is a non-2xx response.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("server: %d %s", e.Status, e.Message) }

// Get fetches path with query parameters and returns the raw body.
func (c *Client) Get(ctx context.Context, path string, q url.Values) ([]byte, error) {
	u := c.Base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		var e struct{ Error string }
		_ = json.Unmarshal(body, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(body))
		}
		return nil, &Error{Status: resp.StatusCode, Message: e.Error}
	}
	return body, nil
}

func (c *Client) getJSON(ctx context.Context, path string, q url.Values, v any) error {
	body, err := c.Get(ctx, path, q)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

func (c *Client) Summary(ctx context.Context, f model.Filter) (*model.Summary, error) {
	var v model.Summary
	return &v, c.getJSON(ctx, "/api/v1/summary", f.Values(), &v)
}

func (c *Client) Devices(ctx context.Context, f model.Filter) ([]model.Device, error) {
	var v []model.Device
	return v, c.getJSON(ctx, "/api/v1/devices", f.Values(), &v)
}

func (c *Client) Flows(ctx context.Context, f model.Filter) ([]model.Flow, error) {
	var v []model.Flow
	return v, c.getJSON(ctx, "/api/v1/flows", f.Values(), &v)
}

func (c *Client) DNS(ctx context.Context, f model.Filter) ([]model.DNSQuery, error) {
	var v []model.DNSQuery
	return v, c.getJSON(ctx, "/api/v1/dns", f.Values(), &v)
}

func (c *Client) Facts(ctx context.Context, f model.Filter) ([]model.Fact, error) {
	var v []model.Fact
	return v, c.getJSON(ctx, "/api/v1/facts", f.Values(), &v)
}

func (c *Client) Timeseries(ctx context.Context, f model.Filter, step time.Duration) (*model.Timeseries, error) {
	q := f.Values()
	if step > 0 {
		q.Set("step", step.String())
	}
	var v model.Timeseries
	return &v, c.getJSON(ctx, "/api/v1/timeseries", q, &v)
}

func (c *Client) Graph(ctx context.Context, f model.Filter, o model.GraphOptions) (*model.Graph, error) {
	q := f.Values()
	for k, v := range o.Values() {
		q.Set(k, v)
	}
	var v model.Graph
	return &v, c.getJSON(ctx, "/api/v1/graph", q, &v)
}

// GraphFormat fetches the graph rendered by the server: "d2", "svg" or "txt".
func (c *Client) GraphFormat(ctx context.Context, f model.Filter, o model.GraphOptions, format, theme string) ([]byte, error) {
	q := f.Values()
	for k, v := range o.Values() {
		q.Set(k, v)
	}
	q.Set("format", format)
	if theme != "" {
		q.Set("theme", theme)
	}
	return c.Get(ctx, "/api/v1/graph", q)
}

func (c *Client) Entity(ctx context.Context, id string, f model.Filter) (*model.EntityDetail, error) {
	q := f.Values()
	q.Set("id", id)
	var v model.EntityDetail
	if err := c.getJSON(ctx, "/api/v1/entity", q, &v); err != nil {
		var e *Error
		if errors.As(err, &e) && e.Status == http.StatusNotFound {
			return nil, fmt.Errorf("%s: not found", id)
		}
		return nil, err
	}
	return &v, nil
}

func (c *Client) Sensors(ctx context.Context) ([]model.Sensor, error) {
	var v []model.Sensor
	return v, c.getJSON(ctx, "/api/v1/sensors", nil, &v)
}

// Version returns the server's version.
func (c *Client) Version(ctx context.Context) (string, error) {
	var v struct{ Version string }
	err := c.getJSON(ctx, "/api/v1/version", nil, &v)
	return v.Version, err
}
