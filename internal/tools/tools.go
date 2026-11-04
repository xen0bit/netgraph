// Package tools is what an AI assistant may do with netgraph: read, and nothing else.
// The MCP server and the optional LLM mode both use this one list, so a tool added
// here is available to both, and a tool that writes can't get in by accident: the
// Backend it's given has no method that writes.
//
// Every result is bounded, because it goes into someone's model context, and marked
// as data, because hostnames and the like were chosen by whoever's on the network.
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

// Backend is everything a tool can reach. It is reads only, by construction.
type Backend interface {
	Summary(ctx context.Context, f model.Filter) (*model.Summary, error)
	Devices(ctx context.Context, f model.Filter) ([]model.Device, error)
	Flows(ctx context.Context, f model.Filter) ([]model.Flow, error)
	Destinations(ctx context.Context, f model.Filter) ([]model.Destination, error)
	DNS(ctx context.Context, f model.Filter) ([]model.DNSQuery, error)
	Entity(ctx context.Context, id string, f model.Filter) (*model.EntityDetail, error)
	Sensors(ctx context.Context) ([]model.Sensor, error)
	Anomalies(ctx context.Context, f model.Filter) (*model.AnomalyReport, error)
	Search(ctx context.Context, q string, limit int) ([]model.SearchResult, error)
	Story(ctx context.Context, id string, f model.Filter) (*model.Story, error)
	Diff(ctx context.Context, a, b model.Filter, scope string) (*model.Diff, error)
	Quality(ctx context.Context, f model.Filter) (*model.Quality, error)
}

// MaxResult is the most one tool call returns, in bytes. Past it the list is cut, and
// says so.
const MaxResult = 64 << 10

// maxRows is the most rows a tool asks for.
const maxRows = 100

// Tool is one read.
type Tool struct {
	Name        string
	Description string
	Params      []Param
	run         func(ctx context.Context, b Backend, a args) (any, error)
}

// Param is one argument of a tool.
type Param struct {
	Name, Description string
	Required          bool
}

// Window arguments, on every tool that reads a time range.
var windowParams = []Param{
	{Name: "from", Description: "start of the window: RFC 3339, or relative as -24h. Default: 24 hours ago."},
	{Name: "to", Description: "end of the window, exclusive: RFC 3339, or relative. Default: now."},
}

func withWindow(p ...Param) []Param { return append(p, windowParams...) }

// List is every tool.
var List = []Tool{
	{
		Name: "search", Description: "Find devices, addresses, names and networks by key or name. Start here when you have a name; a result's id is what the other tools take.",
		Params: []Param{{Name: "q", Description: "what to look for", Required: true}},
		run: func(ctx context.Context, b Backend, a args) (any, error) {
			if a.get("q") == "" {
				return nil, errors.New("q is required")
			}
			return b.Search(ctx, a.get("q"), 20)
		},
	},
	{
		Name: "summary", Description: "Totals for a window: devices, connections, lookups, bytes each way.",
		Params: withWindow(),
		run: func(ctx context.Context, b Backend, a args) (any, error) {
			f, err := a.filter()
			if err != nil {
				return nil, err
			}
			return b.Summary(ctx, f)
		},
	},
	{
		Name: "devices", Description: "Devices active in a window, busiest first, with what's known of each: type, owner, vendor, addresses, names, bytes. Filter with device: a name, a MAC, type:printer, owner:alice or group:iot.",
		Params: withWindow(Param{Name: "device", Description: "a name, MAC, type:printer, owner:alice or group:iot"}),
		run: func(ctx context.Context, b Backend, a args) (any, error) {
			f, err := a.filter()
			if err != nil {
				return nil, err
			}
			f.Limit = maxRows
			return b.Devices(ctx, f)
		},
	},
	{
		Name: "connections", Description: "Connections in a window, busiest first: client, server, port, application, bytes each way, and whether it was open when the window began.",
		Params: withWindow(Param{Name: "device", Description: "only this device"}, Param{Name: "domain", Description: "only this name; a glob like *.example.com"}, Param{Name: "ip", Description: "only this address or CIDR"}, Param{Name: "port", Description: "only this server port"}),
		run: func(ctx context.Context, b Backend, a args) (any, error) {
			f, err := a.filter()
			if err != nil {
				return nil, err
			}
			f.Limit = maxRows
			return b.Flows(ctx, f)
		},
	},
	{
		Name: "destinations", Description: "What was reached in a window, by name, busiest first.",
		Params: withWindow(Param{Name: "device", Description: "only this device"}),
		run: func(ctx context.Context, b Backend, a args) (any, error) {
			f, err := a.filter()
			if err != nil {
				return nil, err
			}
			f.Limit = maxRows
			return b.Destinations(ctx, f)
		},
	},
	{
		Name: "dns", Description: "DNS lookups in a window, newest first, with their answers.",
		Params: withWindow(Param{Name: "device", Description: "only this device"}, Param{Name: "domain", Description: "only this name; a glob like *.example.com"}),
		run: func(ctx context.Context, b Backend, a args) (any, error) {
			f, err := a.filter()
			if err != nil {
				return nil, err
			}
			f.Limit = maxRows
			return b.DNS(ctx, f)
		},
	},
	{
		Name: "entity", Description: "Everything recorded about one entity in a window: its details, relationships and connections. For a device, also why it's thought to be what it is.",
		Params: withWindow(Param{Name: "id", Description: "an id from search", Required: true}),
		run: func(ctx context.Context, b Backend, a args) (any, error) {
			f, err := a.filter()
			if err != nil {
				return nil, err
			}
			if a.get("id") == "" {
				return nil, errors.New("id is required")
			}
			return b.Entity(ctx, a.get("id"), f)
		},
	},
	{
		Name: "story", Description: "One entity's life over a window as a sequence of intervals, each with evidence.",
		Params: withWindow(Param{Name: "id", Description: "an id from search", Required: true}),
		run: func(ctx context.Context, b Backend, a args) (any, error) {
			f, err := a.filter()
			if err != nil {
				return nil, err
			}
			if a.get("id") == "" {
				return nil, errors.New("id is required")
			}
			return b.Story(ctx, a.get("id"), f)
		},
	},
	{
		Name: "anomalies", Description: "Run the anomaly checks over a window: new devices, odd destinations, upload spikes, beacons, DNS tunnels, scans and more. This can take a while over a long window.",
		Params: withWindow(Param{Name: "device", Description: "only this device"}),
		run: func(ctx context.Context, b Backend, a args) (any, error) {
			f, err := a.filter()
			if err != nil {
				return nil, err
			}
			return b.Anomalies(ctx, f)
		},
	},
	{
		Name: "diff", Description: "What changed between two moments: entities and connections added, removed, or much busier or quieter. Each moment is the 5 minutes before it, unless lookback says otherwise.",
		Params: []Param{{Name: "a", Description: "the earlier moment: RFC 3339, or relative as -1h", Required: true}, {Name: "b", Description: "the later moment. Default: now."}, {Name: "lookback", Description: "how much before each moment counts, as 15m. Default 5m."}},
		run: func(ctx context.Context, b Backend, a args) (any, error) {
			return runDiff(ctx, b, a)
		},
	},
	{
		Name: "quality", Description: "How the network is doing: delay upstream and on the local network, packet loss, DNS, outages, and a plain verdict on whether trouble looks local or upstream. It measures delay and loss, not speed.",
		Params: withWindow(Param{Name: "device", Description: "only this device"}),
		run: func(ctx context.Context, b Backend, a args) (any, error) {
			f, err := a.filter()
			if err != nil {
				return nil, err
			}
			return b.Quality(ctx, f)
		},
	},
	{
		Name: "sensors", Description: "The sensors reporting to this server, when each last reported and what it watches. If a window looks empty, check this first.",
		run: func(ctx context.Context, b Backend, _ args) (any, error) { return b.Sensors(ctx) },
	},
}

// Find returns a tool by name.
func Find(name string) *Tool {
	i := slices.IndexFunc(List, func(t Tool) bool { return t.Name == name })
	if i < 0 {
		return nil
	}
	return &List[i]
}

// Schema is the tool's arguments as JSON Schema.
func (t *Tool) Schema() map[string]any {
	props := map[string]any{}
	required := []string{}
	for _, p := range t.Params {
		props[p.Name] = map[string]any{"type": "string", "description": p.Description}
		if p.Required {
			required = append(required, p.Name)
		}
	}
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}

// Result is what a call returned, ready to hand to a model.
type Result struct {
	Text      string
	Truncated bool
}

// Call runs a tool. raw holds its arguments as a JSON object, and a model wrote it,
// so it's checked like any other input.
func (t *Tool) Call(ctx context.Context, b Backend, raw json.RawMessage, now time.Time) (Result, error) {
	a := args{now: now, vals: map[string]string{}}
	if len(raw) > 0 && string(raw) != "null" {
		var in map[string]any
		if err := json.Unmarshal(raw, &in); err != nil {
			return Result{}, errors.New("arguments must be a JSON object")
		}
		for k, v := range in {
			if !slices.ContainsFunc(t.Params, func(p Param) bool { return p.Name == k }) {
				return Result{}, fmt.Errorf("%s takes no argument %q", t.Name, k)
			}
			switch x := v.(type) {
			case string:
				a.vals[k] = x
			case float64:
				a.vals[k] = strconv.FormatFloat(x, 'f', -1, 64)
			case nil:
			default:
				return Result{}, fmt.Errorf("%s must be a string", k)
			}
		}
	}
	out, err := t.run(ctx, b, a)
	if err != nil {
		return Result{}, err
	}
	return Render(out)
}

// Render makes a result fit. A list that's too long loses rows from the end, its
// least important, and stays valid JSON.
func Render(v any) (Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return Result{}, err
	}
	if len(b) <= MaxResult {
		return Result{Text: string(b)}, nil
	}
	var list []json.RawMessage
	if json.Unmarshal(b, &list) == nil && len(list) > 0 {
		total := len(list)
		size := 0
		keep := 0
		for keep < len(list) && size+len(list[keep])+1 <= MaxResult-200 {
			size += len(list[keep]) + 1
			keep++
		}
		out, err := json.Marshal(map[string]any{"rows": list[:keep], "truncated": fmt.Sprintf("showing %d of %d rows; narrow the window or filter for the rest", keep, total)})
		return Result{Text: string(out), Truncated: true}, err
	}
	// Not a list, and too big to cut sensibly: say so rather than return half of it.
	out, err := json.Marshal(map[string]string{"truncated": fmt.Sprintf("the answer is %d bytes, over the %d limit; narrow the window or filter", len(b), MaxResult)})
	return Result{Text: string(out), Truncated: true}, err
}

type args struct {
	now  time.Time
	vals map[string]string
}

func (a args) get(k string) string { return strings.TrimSpace(a.vals[k]) }

func (a args) time(k string, def time.Time) (time.Time, error) {
	v := a.get(k)
	if v == "" {
		return def, nil
	}
	t, err := model.ParseTime(v, a.now)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", k, err)
	}
	return t, nil
}

func (a args) filter() (model.Filter, error) {
	var f model.Filter
	var err error
	if f.To, err = a.time("to", a.now); err != nil {
		return f, err
	}
	if f.From, err = a.time("from", f.To.Add(-24*time.Hour)); err != nil {
		return f, err
	}
	if !f.From.Before(f.To) {
		return f, errors.New("from must be before to")
	}
	q := map[string][]string{}
	for _, k := range []string{"device", "domain", "ip", "port"} {
		if v := a.get(k); v != "" {
			q[k] = []string{v}
		}
	}
	if len(q) > 0 {
		narrow, err := model.ParseFilter(q, a.now)
		if err != nil {
			return f, err
		}
		narrow.From, narrow.To = f.From, f.To
		f = narrow
	}
	return f, nil
}

func runDiff(ctx context.Context, b Backend, a args) (any, error) {
	if a.get("a") == "" {
		return nil, errors.New("a is required")
	}
	first, err := a.time("a", a.now)
	if err != nil {
		return nil, err
	}
	second, err := a.time("b", a.now)
	if err != nil {
		return nil, err
	}
	back := 5 * time.Minute
	if v := a.get("lookback"); v != "" {
		if back, err = model.ParseDuration(v); err != nil || back <= 0 {
			return nil, errors.New("lookback: want a duration like 15m")
		}
	}
	return b.Diff(ctx, model.Filter{From: first.Add(-back), To: first}, model.Filter{From: second.Add(-back), To: second}, "")
}
