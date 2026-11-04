// Package apiclient is the HTTP client for netgraph's API. It implements
// model.Backend, and works under GOOS=js too, where net/http uses the
// browser's fetch, which is how the WASM web UI talks to its server.
package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy"
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
	return c.do(ctx, http.MethodGet, path, q, nil)
}

// SetDeviceLabel names a device by hand; an empty label clears the name.
func (c *Client) SetDeviceLabel(ctx context.Context, mac, label string) error {
	body, err := json.Marshal(map[string]string{"label": label})
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPut, "/api/v1/devices/"+url.PathEscape(mac)+"/label", nil, body)
	return err
}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, payload []byte) ([]byte, error) {
	u := c.Base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
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
	const maxBody = 256 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("response larger than %d bytes", maxBody)
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

func (c *Client) Destinations(ctx context.Context, f model.Filter) ([]model.Destination, error) {
	var v []model.Destination
	return v, c.getJSON(ctx, "/api/v1/destinations", f.Values(), &v)
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

func (c *Client) Search(ctx context.Context, q string, limit int) ([]model.SearchResult, error) {
	var v []model.SearchResult
	return v, c.getJSON(ctx, "/api/v1/search", url.Values{"q": {q}, "limit": {strconv.Itoa(limit)}}, &v)
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

func (c *Client) WiFi(ctx context.Context, f model.Filter) ([]model.WiFiNetwork, error) {
	var v []model.WiFiNetwork
	return v, c.getJSON(ctx, "/api/v1/wifi", f.Values(), &v)
}

func (c *Client) Anomalies(ctx context.Context, f model.Filter) (*model.AnomalyReport, error) {
	var v model.AnomalyReport
	if err := c.getJSON(ctx, "/api/v1/anomalies", f.Values(), &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// Version returns the server's version.
func (c *Client) Version(ctx context.Context) (string, error) {
	var v struct{ Version string }
	err := c.getJSON(ctx, "/api/v1/version", nil, &v)
	return v.Version, err
}

func (c *Client) Frame(ctx context.Context, f model.Filter) (*model.Frame, error) {
	q := f.Values()
	if d := f.To.Sub(f.From); d > 0 {
		q.Set("lookback", d.String())
	}
	var v model.Frame
	err := c.getJSON(ctx, "/api/v1/frame", q, &v)
	return &v, err
}

func (c *Client) Story(ctx context.Context, id string, f model.Filter) (*model.Story, error) {
	q := f.Values()
	q.Set("entity", id)
	var v model.Story
	err := c.getJSON(ctx, "/api/v1/story", q, &v)
	return &v, err
}

func (c *Client) Timeline(ctx context.Context, f model.Filter, tq model.TimelineQuery) (*model.TimelinePage, error) {
	q := f.Values()
	if tq.Entity != "" {
		q.Set("entity", tq.Entity)
	}
	if len(tq.Kinds) > 0 {
		q.Set("kinds", strings.Join(tq.Kinds, ","))
	}
	if tq.Cursor != "" {
		q.Set("cursor", tq.Cursor)
	}
	if tq.Limit > 0 {
		q.Set("limit", strconv.Itoa(tq.Limit))
	}
	var v model.TimelinePage
	err := c.getJSON(ctx, "/api/v1/timeline", q, &v)
	return &v, err
}

func (c *Client) Diff(ctx context.Context, a, b model.Filter, scope string) (*model.Diff, error) {
	q := url.Values{}
	q.Set("at_a", strconv.FormatInt(a.To.UnixMilli(), 10))
	q.Set("at_b", strconv.FormatInt(b.To.UnixMilli(), 10))
	lb := a.To.Sub(a.From)
	if lb > 0 {
		q.Set("lookback", lb.String())
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	var v model.Diff
	err := c.getJSON(ctx, "/api/v1/diff", q, &v)
	return &v, err
}

// WhatIf sends a proposed policy for a read-only blast-radius simulation.
func (c *Client) WhatIf(ctx context.Context, p *policy.Policy, f model.Filter, scope string) (*model.WhatIfResult, error) {
	body, err := json.Marshal(map[string]any{"policy": p, "from": f.From, "to": f.To})
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if scope != "" {
		q.Set("scope", scope)
	}
	b, err := c.do(ctx, http.MethodPost, "/api/v1/whatif", q, body)
	if err != nil {
		return nil, err
	}
	var v model.WhatIfResult
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// Ask sends a question to the server's grounded intent engine.
func (c *Client) Ask(ctx context.Context, question string, f model.Filter) (*model.Answer, error) {
	body, err := json.Marshal(map[string]any{"q": question, "from": f.From, "to": f.To})
	if err != nil {
		return nil, err
	}
	b, err := c.do(ctx, http.MethodPost, "/api/v1/ask", nil, body)
	if err != nil {
		return nil, err
	}
	var v model.Answer
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (c *Client) Exposure(ctx context.Context, f model.Filter) (*model.ExposureReport, error) {
	var v model.ExposureReport
	err := c.getJSON(ctx, "/api/v1/exposure", f.Values(), &v)
	return &v, err
}

func (c *Client) Coverage(ctx context.Context, f model.Filter) (*model.CoverageReport, error) {
	var v model.CoverageReport
	err := c.getJSON(ctx, "/api/v1/coverage", f.Values(), &v)
	return &v, err
}

func (c *Client) Airspace(ctx context.Context, f model.Filter) (*model.AirspaceReport, error) {
	var v model.AirspaceReport
	err := c.getJSON(ctx, "/api/v1/airspace", f.Values(), &v)
	return &v, err
}

func (c *Client) Weather(ctx context.Context, f model.Filter) (*model.WeatherReport, error) {
	var v model.WeatherReport
	err := c.getJSON(ctx, "/api/v1/weather", f.Values(), &v)
	return &v, err
}
