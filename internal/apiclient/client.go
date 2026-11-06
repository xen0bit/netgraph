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

	"github.com/xen0bit/netgraph/internal/backup"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy"
	"github.com/xen0bit/netgraph/internal/purpose"
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

// LearnPolicy asks the server to propose a policy for a device.
func (c *Client) LearnPolicy(ctx context.Context, device string, f model.Filter) (*policy.Learned, error) {
	q := url.Values{"device": {device}, "from": {f.From.Format(time.RFC3339Nano)}, "to": {f.To.Format(time.RFC3339Nano)}}
	b, err := c.do(ctx, http.MethodGet, "/api/v1/policy/learn", q, nil)
	if err != nil {
		return nil, err
	}
	var v policy.Learned
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// ExportPolicy asks the server for a firewall's configuration.
func (c *Client) ExportPolicy(ctx context.Context, p *policy.Policy, format string, f model.Filter) (*policy.Exported, error) {
	body, err := json.Marshal(map[string]any{"policy": p, "format": format, "from": f.From, "to": f.To})
	if err != nil {
		return nil, err
	}
	b, err := c.do(ctx, http.MethodPost, "/api/v1/policy/export", nil, body)
	if err != nil {
		return nil, err
	}
	var v policy.Exported
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// Ask sends a question to the server's grounded intent engine.
func (c *Client) Ask(ctx context.Context, question string, f model.Filter) (*model.Answer, error) {
	_, offset := time.Now().Zone()
	body, err := json.Marshal(map[string]any{"q": question, "from": f.From, "to": f.To, "tz": offset / 60})
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

// Quality reports how the network is doing.
func (c *Client) Quality(ctx context.Context, f model.Filter) (*model.Quality, error) {
	var v model.Quality
	err := c.getJSON(ctx, "/api/v1/quality", f.Values(), &v)
	return &v, err
}

func (c *Client) Weather(ctx context.Context, f model.Filter) (*model.WeatherReport, error) {
	var v model.WeatherReport
	err := c.getJSON(ctx, "/api/v1/weather", f.Values(), &v)
	return &v, err
}

func (c *Client) CreateAnnotation(ctx context.Context, a model.Annotation) (*model.Annotation, error) {
	body, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	b, err := c.do(ctx, http.MethodPost, "/api/v1/annotations", nil, body)
	if err != nil {
		return nil, err
	}
	var v model.Annotation
	return &v, json.Unmarshal(b, &v)
}

func (c *Client) CreateBookmark(ctx context.Context, b model.Bookmark) (*model.Bookmark, error) {
	body, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	bdy, err := c.do(ctx, http.MethodPost, "/api/v1/bookmarks", nil, body)
	if err != nil {
		return nil, err
	}
	var v model.Bookmark
	return &v, json.Unmarshal(bdy, &v)
}

func (c *Client) Incidents(ctx context.Context, status string, limit int) ([]model.Incident, error) {
	q := url.Values{}
	if status != "" {
		q.Set("status", status)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var v []model.Incident
	err := c.getJSON(ctx, "/api/v1/incidents", q, &v)
	return v, err
}

func (c *Client) IncidentDetail(ctx context.Context, id int64) (*model.IncidentDetail, error) {
	var v model.IncidentDetail
	err := c.getJSON(ctx, "/api/v1/incidents/"+strconv.FormatInt(id, 10), nil, &v)
	return &v, err
}

func (c *Client) IncidentAutopsy(ctx context.Context, id int64) (*model.Autopsy, error) {
	var v model.Autopsy
	err := c.getJSON(ctx, "/api/v1/incidents/"+strconv.FormatInt(id, 10)+"/autopsy", nil, &v)
	return &v, err
}

func (c *Client) UpdateIncident(ctx context.Context, id int64, status, title, summary, note, author string) (*model.Incident, error) {
	body, err := json.Marshal(map[string]string{"status": status, "title": title, "summary": summary, "note": note, "author": author})
	if err != nil {
		return nil, err
	}
	b, err := c.do(ctx, http.MethodPatch, "/api/v1/incidents/"+strconv.FormatInt(id, 10), nil, body)
	if err != nil {
		return nil, err
	}
	var v model.Incident
	return &v, json.Unmarshal(b, &v)
}

func (c *Client) DeleteIncident(ctx context.Context, id int64) error {
	_, err := c.do(ctx, http.MethodDelete, "/api/v1/incidents/"+strconv.FormatInt(id, 10), nil, nil)
	return err
}

func (c *Client) ExportIncident(ctx context.Context, id int64) ([]byte, error) {
	return c.Get(ctx, "/api/v1/incidents/"+strconv.FormatInt(id, 10)+"/export", nil)
}

// Policies lists saved policies.
func (c *Client) Policies(ctx context.Context) ([]policy.Summary, error) {
	var v []policy.Summary
	err := c.getJSON(ctx, "/api/v1/policies", nil, &v)
	return v, err
}

// Policy loads one saved policy.
func (c *Client) Policy(ctx context.Context, id string) (*policy.Policy, error) {
	var v policy.Policy
	if err := c.getJSON(ctx, "/api/v1/policies/"+url.PathEscape(id), nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// ActivePolicy loads the active policy, or nil when none is active.
func (c *Client) ActivePolicy(ctx context.Context) (*policy.Policy, error) {
	var v policy.Policy
	if err := c.getJSON(ctx, "/api/v1/policies/active", nil, &v); err != nil {
		if e, ok := err.(*Error); ok && e.Status == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &v, nil
}

// SavePolicy creates or replaces a policy.
func (c *Client) SavePolicy(ctx context.Context, p *policy.Policy) (*policy.Policy, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	method, path := http.MethodPost, "/api/v1/policies"
	if p.ID != "" {
		method, path = http.MethodPut, "/api/v1/policies/"+url.PathEscape(p.ID)
	}
	b, err := c.do(ctx, method, path, nil, body)
	if err != nil {
		return nil, err
	}
	var v policy.Policy
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// DeletePolicy removes a policy.
func (c *Client) DeletePolicy(ctx context.Context, id string) error {
	_, err := c.do(ctx, http.MethodDelete, "/api/v1/policies/"+url.PathEscape(id), nil, nil)
	return err
}

// ActivatePolicy makes one policy active.
func (c *Client) ActivatePolicy(ctx context.Context, id string) error {
	_, err := c.do(ctx, http.MethodPost, "/api/v1/policies/"+url.PathEscape(id)+"/activate", nil, nil)
	return err
}

// ExplainPolicy explains one connection against a policy.
func (c *Client) ExplainPolicy(ctx context.Context, p *policy.Policy, conn policy.Conn) (*policy.Explanation, error) {
	body, err := json.Marshal(map[string]any{"policy": p, "conn": conn})
	if err != nil {
		return nil, err
	}
	b, err := c.do(ctx, http.MethodPost, "/api/v1/policy/explain", nil, body)
	if err != nil {
		return nil, err
	}
	var v policy.Explanation
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// Blocklists lists configured blocklists.
func (c *Client) Blocklists(ctx context.Context) ([]model.Blocklist, error) {
	var v []model.Blocklist
	err := c.getJSON(ctx, "/api/v1/blocklists", nil, &v)
	return v, err
}

// Blocklist loads one blocklist.
func (c *Client) Blocklist(ctx context.Context, id int64) (*model.Blocklist, error) {
	var v model.Blocklist
	if err := c.getJSON(ctx, fmt.Sprintf("/api/v1/blocklists/%d", id), nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// SaveBlocklist creates or replaces a blocklist.
func (c *Client) SaveBlocklist(ctx context.Context, b *model.Blocklist) (*model.Blocklist, error) {
	body, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	method, path := http.MethodPost, "/api/v1/blocklists"
	if b.ID != 0 {
		method, path = http.MethodPut, fmt.Sprintf("/api/v1/blocklists/%d", b.ID)
	}
	out, err := c.do(ctx, method, path, nil, body)
	if err != nil {
		return nil, err
	}
	var v model.Blocklist
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// DeleteBlocklist removes a blocklist.
func (c *Client) DeleteBlocklist(ctx context.Context, id int64) error {
	_, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/blocklists/%d", id), nil, nil)
	return err
}

// BlocklistEntries lists a blocklist's entries.
func (c *Client) BlocklistEntries(ctx context.Context, id int64, enabledOnly bool) ([]model.BlocklistEntry, error) {
	q := url.Values{}
	if enabledOnly {
		q.Set("enabled", "1")
	}
	var v []model.BlocklistEntry
	err := c.getJSON(ctx, fmt.Sprintf("/api/v1/blocklists/%d/entries", id), q, &v)
	return v, err
}

// ImportBlocklist replaces a blocklist's entries with parsed text.
func (c *Client) ImportBlocklist(ctx context.Context, id int64, text, format string) (*model.Blocklist, error) {
	body, err := json.Marshal(map[string]string{"text": text, "format": format})
	if err != nil {
		return nil, err
	}
	out, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/blocklists/%d/import", id), nil, body)
	if err != nil {
		return nil, err
	}
	var v model.Blocklist
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// UpdateBlocklist fetches a blocklist's URL now.
func (c *Client) UpdateBlocklist(ctx context.Context, id int64, allowPrivate, allowHTTP bool) (*model.Blocklist, error) {
	body, _ := json.Marshal(map[string]bool{"allow_private": allowPrivate, "allow_http": allowHTTP})
	out, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/blocklists/%d/update", id), nil, body)
	if err != nil {
		return nil, err
	}
	var v model.Blocklist
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// SetBlocklistEntry enables or disables one entry.
func (c *Client) SetBlocklistEntry(ctx context.Context, id, entry int64, enabled bool) error {
	body, _ := json.Marshal(map[string]bool{"enabled": enabled})
	_, err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/api/v1/blocklists/%d/entries/%d", id, entry), nil, body)
	return err
}

// RuleGroups lists blocklist groups.
func (c *Client) RuleGroups(ctx context.Context) ([]model.RuleGroup, error) {
	var v []model.RuleGroup
	err := c.getJSON(ctx, "/api/v1/rule-groups", nil, &v)
	return v, err
}

// SaveRuleGroup creates or replaces a group.
func (c *Client) SaveRuleGroup(ctx context.Context, g *model.RuleGroup) (*model.RuleGroup, error) {
	body, _ := json.Marshal(g)
	out, err := c.do(ctx, http.MethodPost, "/api/v1/rule-groups", nil, body)
	if err != nil {
		return nil, err
	}
	var v model.RuleGroup
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// Profiles lists policy profiles.
func (c *Client) Profiles(ctx context.Context) ([]model.Profile, error) {
	var v []model.Profile
	err := c.getJSON(ctx, "/api/v1/profiles", nil, &v)
	return v, err
}

// Profile loads one profile.
func (c *Client) Profile(ctx context.Context, id int64) (*model.Profile, error) {
	var v model.Profile
	if err := c.getJSON(ctx, fmt.Sprintf("/api/v1/profiles/%d", id), nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// SaveProfile creates or replaces a profile.
func (c *Client) SaveProfile(ctx context.Context, p *model.Profile) (*model.Profile, error) {
	body, _ := json.Marshal(p)
	method, path := http.MethodPost, "/api/v1/profiles"
	if p.ID != 0 {
		method, path = http.MethodPut, fmt.Sprintf("/api/v1/profiles/%d", p.ID)
	}
	out, err := c.do(ctx, method, path, nil, body)
	if err != nil {
		return nil, err
	}
	var v model.Profile
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// DeleteProfile removes a profile.
func (c *Client) DeleteProfile(ctx context.Context, id int64) error {
	_, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/profiles/%d", id), nil, nil)
	return err
}

// ActivateProfile makes one profile active.
func (c *Client) ActivateProfile(ctx context.Context, id int64) error {
	_, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/profiles/%d/activate", id), nil, nil)
	return err
}

// EvaluateProfile applies network triggers now.
func (c *Client) EvaluateProfile(ctx context.Context) (*model.Profile, error) {
	out, err := c.do(ctx, http.MethodPost, "/api/v1/profiles/evaluate", nil, []byte("{}"))
	if err != nil {
		return nil, err
	}
	var v struct {
		Profile *model.Profile `json:"profile"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, err
	}
	return v.Profile, nil
}

// NetworkContext returns the current network signature.
func (c *Client) NetworkContext(ctx context.Context) (*model.NetworkContext, error) {
	var v model.NetworkContext
	if err := c.getJSON(ctx, "/api/v1/network", nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// NetworkTriggers lists network triggers.
func (c *Client) NetworkTriggers(ctx context.Context) ([]model.NetworkTrigger, error) {
	var v []model.NetworkTrigger
	err := c.getJSON(ctx, "/api/v1/network-triggers", nil, &v)
	return v, err
}

// SaveNetworkTrigger creates or replaces a trigger.
func (c *Client) SaveNetworkTrigger(ctx context.Context, t *model.NetworkTrigger) (*model.NetworkTrigger, error) {
	body, _ := json.Marshal(t)
	out, err := c.do(ctx, http.MethodPost, "/api/v1/network-triggers", nil, body)
	if err != nil {
		return nil, err
	}
	var v model.NetworkTrigger
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// DeleteNetworkTrigger removes a trigger.
func (c *Client) DeleteNetworkTrigger(ctx context.Context, id int64) error {
	_, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/network-triggers/%d", id), nil, nil)
	return err
}

// Decisions lists policy decisions.
func (c *Client) Decisions(ctx context.Context, status string) ([]model.PolicyDecision, error) {
	q := url.Values{}
	if status != "" {
		q.Set("status", status)
	}
	var v []model.PolicyDecision
	err := c.getJSON(ctx, "/api/v1/decisions", q, &v)
	return v, err
}

// ScanDecisions records would-ask decisions for a window.
func (c *Client) ScanDecisions(ctx context.Context, f model.Filter, limit int) (int, error) {
	body, _ := json.Marshal(map[string]any{"from": f.From, "to": f.To, "limit": limit})
	out, err := c.do(ctx, http.MethodPost, "/api/v1/decisions/scan", nil, body)
	if err != nil {
		return 0, err
	}
	var v struct {
		Created int `json:"created"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return 0, err
	}
	return v.Created, nil
}

// DecideDecision answers a decision.
func (c *Client) DecideDecision(ctx context.Context, id int64, action, by, note string) error {
	body, _ := json.Marshal(map[string]string{"by": by, "note": note})
	_, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/decisions/%d/%s", id, action), nil, body)
	return err
}

// ResetDecision reopens a decision.
func (c *Client) ResetDecision(ctx context.Context, id int64) error {
	_, err := c.do(ctx, http.MethodPost, fmt.Sprintf("/api/v1/decisions/%d/reset", id), nil, []byte("{}"))
	return err
}

// AuditPolicy asks the server to audit a policy.
func (c *Client) AuditPolicy(ctx context.Context, p *policy.Policy) (*policy.AuditReport, error) {
	path := "/api/v1/policy/audit"
	if p != nil && p.ID != "" {
		path += "?id=" + url.QueryEscape(p.ID)
	}
	body, err := c.Get(ctx, path, nil)
	if err != nil {
		return nil, err
	}
	var v policy.AuditReport
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// ConnectionGroups folds connections by device, app, domain, host or
// destination.
func (c *Client) ConnectionGroups(ctx context.Context, f model.Filter, group string) ([]model.ConnectionGroup, error) {
	q := f.Values()
	q.Set("group", group)
	var v []model.ConnectionGroup
	err := c.getJSON(ctx, "/api/v1/connections", q, &v)
	return v, err
}

// Purposes lists purpose metadata, optionally for one host.
func (c *Client) Purposes(ctx context.Context, host string) ([]model.Purpose, error) {
	q := url.Values{}
	if host != "" {
		q.Set("host", host)
	}
	var v []model.Purpose
	err := c.getJSON(ctx, "/api/v1/purposes", q, &v)
	return v, err
}

// ImportPurpose uploads one application's purpose manifest.
func (c *Client) ImportPurpose(ctx context.Context, m *purpose.Manifest) (int, error) {
	body, _ := json.Marshal(m)
	out, err := c.do(ctx, http.MethodPost, "/api/v1/purposes", nil, body)
	if err != nil {
		return 0, err
	}
	var v struct {
		Imported int `json:"imported"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return 0, err
	}
	return v.Imported, nil
}

// DeletePurpose removes one purpose entry.
func (c *Client) DeletePurpose(ctx context.Context, id int64) error {
	_, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/purposes/%d", id), nil, nil)
	return err
}

// ExportBundle downloads the server's policy configuration bundle.
func (c *Client) ExportBundle(ctx context.Context) (*backup.Bundle, error) {
	body, err := c.Get(ctx, "/api/v1/policy/bundle", nil)
	if err != nil {
		return nil, err
	}
	return backup.Parse(bytes.NewReader(body))
}

// ImportBundle uploads a policy configuration bundle.
func (c *Client) ImportBundle(ctx context.Context, b *backup.Bundle) (map[string]int, error) {
	raw, err := backup.Marshal(b)
	if err != nil {
		return nil, err
	}
	out, err := c.do(ctx, http.MethodPost, "/api/v1/policy/bundle", nil, raw)
	if err != nil {
		return nil, err
	}
	var v struct {
		Imported map[string]int `json:"imported"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, err
	}
	return v.Imported, nil
}

// Agents lists host agents the server has heard from.
func (c *Client) Agents(ctx context.Context) ([]model.Agent, error) {
	var v []model.Agent
	err := c.getJSON(ctx, "/api/v1/agents", nil, &v)
	return v, err
}

// AgentProcesses lists one agent's processes.
func (c *Client) AgentProcesses(ctx context.Context, name string, limit int) ([]model.AgentProcess, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var v []model.AgentProcess
	err := c.getJSON(ctx, "/api/v1/agents/"+url.PathEscape(name)+"/processes", q, &v)
	return v, err
}

// AgentConnections lists one agent's attributed connections.
func (c *Client) AgentConnections(ctx context.Context, name string, limit int) ([]model.AgentConnection, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var v []model.AgentConnection
	err := c.getJSON(ctx, "/api/v1/agents/"+url.PathEscape(name)+"/connections", q, &v)
	return v, err
}
