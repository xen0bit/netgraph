// Package model holds the types the netgraph server answers queries with,
// shared by everything that asks: the HTTP API and its client, the CLI, the
// TUI and the WASM web UI. It has no dependencies beyond the standard
// library, so the WASM build can use it.
package model

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Backend answers queries over a time window. The SQLite query engine and
// the HTTP API client both implement it, so the CLI and TUI work the same
// against a local database file or a remote server.
type Backend interface {
	Summary(ctx context.Context, f Filter) (*Summary, error)
	Devices(ctx context.Context, f Filter) ([]Device, error)
	Flows(ctx context.Context, f Filter) ([]Flow, error)
	DNS(ctx context.Context, f Filter) ([]DNSQuery, error)
	Facts(ctx context.Context, f Filter) ([]Fact, error)
	Timeseries(ctx context.Context, f Filter, step time.Duration) (*Timeseries, error)
	Graph(ctx context.Context, f Filter, o GraphOptions) (*Graph, error)
	Entity(ctx context.Context, id string, f Filter) (*EntityDetail, error)
	Sensors(ctx context.Context) ([]Sensor, error)
	WiFi(ctx context.Context, f Filter) ([]WiFiNetwork, error)
}

// Filter selects what a query covers. The window is half-open: [From, To).
// The other fields narrow it; empty means no restriction. Device, Domain and
// Host accept shell globs (*, ?), matched case-insensitively.
type Filter struct {
	From, To time.Time

	Device string // MAC, hostname or label of the local device
	IP     string // address or CIDR, either side of a flow
	Domain string // DNS name, SNI or HTTP host
	Port   int    // remote port
	Proto  string // tcp, udp, icmp, or a protocol number
	App    string // tls, quic, http, dns, ...

	Multicast bool // include multicast/broadcast traffic
	Limit     int  // maximum rows; 0 means the endpoint's default
}

// Precision tells how exactly a result honours the window edges.
const (
	PrecisionExact = "exact" // from raw records: edges at the window boundaries are prorated
	PrecisionHour  = "hour"  // from hourly rollups: windows are widened to whole hours
)

// Summary is a window's headline numbers.
type Summary struct {
	FromMS     int64  `json:"from"`
	ToMS       int64  `json:"to"`
	Precision  string `json:"precision"`
	Devices    int    `json:"devices"`
	Flows      int    `json:"flows"`
	DNSQueries int    `json:"dns_queries"`
	Domains    int    `json:"domains"`
	RemoteIPs  int    `json:"remote_ips"`
	BytesOut   uint64 `json:"bytes_out"`
	BytesIn    uint64 `json:"bytes_in"`
	PeakConns  int    `json:"peak_connections"`
	OldestData int64  `json:"oldest_data,omitempty"` // ms; what the database still holds
	NewestData int64  `json:"newest_data,omitempty"` // ms
	RawFrom    int64  `json:"raw_from,omitempty"`    // ms; earliest exact data
}

// Device is a local machine, identified by MAC.
type Device struct {
	ID           string   `json:"id"` // "device:<mac>"
	MAC          string   `json:"mac"`
	Label        string   `json:"label"`
	Vendor       string   `json:"vendor,omitempty"`
	VendorShort  string   `json:"vendor_short,omitempty"` // "Apple" for "Apple, Inc."
	Randomized   bool     `json:"randomized,omitempty"`
	Role         string   `json:"role,omitempty"` // router, ...
	IPs          []string `json:"ips,omitempty"`
	Hostnames    []string `json:"hostnames,omitempty"`
	Services     []string `json:"services,omitempty"`
	Fingerprints []string `json:"fingerprints,omitempty"`
	UserAgents   []string `json:"user_agents,omitempty"`
	FirstSeen    int64    `json:"first_seen"` // ms, ever
	LastSeen     int64    `json:"last_seen"`  // ms, ever
	ActiveFrom   int64    `json:"active_from,omitempty"`
	ActiveTo     int64    `json:"active_to,omitempty"`
	Flows        int      `json:"flows"`
	DNSQueries   int      `json:"dns_queries"`
	BytesOut     uint64   `json:"bytes_out"`
	BytesIn      uint64   `json:"bytes_in"`
	Remotes      int      `json:"remotes"`
}

// Flow states relative to the window.
const (
	StateCarried = "carried" // opened before the window, still open at its start
	StateOpened  = "opened"  // opened inside the window
)

// Flow is one connection's activity inside the window.
type Flow struct {
	Key        string `json:"key"`
	Proto      string `json:"proto"`
	ClientIP   string `json:"client_ip"`
	ClientPort int    `json:"client_port"`
	ClientMAC  string `json:"client_mac,omitempty"`
	Device     string `json:"device,omitempty"` // device ID
	DeviceName string `json:"device_name,omitempty"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	Direction  string `json:"direction"` // out, in, local, external
	App        string `json:"app,omitempty"`
	Name       string `json:"name,omitempty"` // best name: SNI, HTTP host, then DNS
	SNI        string `json:"sni,omitempty"`
	HTTPHost   string `json:"http_host,omitempty"`
	QName      string `json:"qname,omitempty"`
	ALPN       string `json:"alpn,omitempty"`
	JA4        string `json:"ja4,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	FirstSeen  int64  `json:"first_seen"` // ms; when the connection opened
	LastSeen   int64  `json:"last_seen"`  // ms; its last record
	State      string `json:"state"`
	Closed     bool   `json:"closed"` // it ended inside the window
	EndReason  string `json:"end_reason,omitempty"`
	BytesOut   uint64 `json:"bytes_out"` // inside the window
	BytesIn    uint64 `json:"bytes_in"`
	PktsOut    uint64 `json:"pkts_out"`
	PktsIn     uint64 `json:"pkts_in"`
}

// DNSQuery is one lookup.
type DNSQuery struct {
	TS         int64       `json:"ts"`
	ClientIP   string      `json:"client_ip"`
	Device     string      `json:"device,omitempty"`
	DeviceName string      `json:"device_name,omitempty"`
	Server     string      `json:"server"`
	QName      string      `json:"qname"`
	QType      string      `json:"qtype"`
	RCode      string      `json:"rcode"`
	LatencyMS  float64     `json:"latency_ms,omitempty"`
	Answers    []DNSAnswer `json:"answers,omitempty"`
}

// DNSAnswer is one answer record.
type DNSAnswer struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Data    string `json:"data"`
	TTL     uint32 `json:"ttl"`
	Expires int64  `json:"expires"` // ms
}

// Fact is a relationship observed over an interval: "this device had this
// address from A to B".
type Fact struct {
	Rel       string            `json:"rel"`
	Src       string            `json:"src"` // entity IDs
	SrcLabel  string            `json:"src_label,omitempty"`
	Dst       string            `json:"dst"`
	DstLabel  string            `json:"dst_label,omitempty"`
	FirstSeen int64             `json:"first_seen"`
	LastSeen  int64             `json:"last_seen"`
	Count     int               `json:"count"`
	Source    string            `json:"source,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
}

// Fact relations.
const (
	RelHasIP       = "has_ip"      // device -> ip
	RelHostname    = "hostname"    // device -> hostname
	RelVendor      = "vendor"      // device -> vendor
	RelAnnounces   = "announces"   // device -> service (mDNS/DNS-SD)
	RelFingerprint = "fingerprint" // device -> fingerprint (DHCP, JA4)
	RelUserAgent   = "user_agent"  // device -> useragent
	RelUPnP        = "upnp"        // device -> upnp descriptor
	RelResolvesTo  = "resolves_to" // domain -> ip, valid for the answer's TTL
	RelCNAME       = "cname"       // domain -> domain
	RelServes      = "serves"      // ip -> domain (from SNI / HTTP host)
	RelQueried     = "queried"     // device -> domain (graph only)
	RelConnects    = "connects"    // device -> ip/domain (graph only)
	RelNeighbor    = "neighbor"    // device -> lldp descriptor
	RelBroadcasts  = "broadcasts"  // access point -> ssid
	RelProbes      = "probes"      // device -> ssid
	RelAssociates  = "associates"  // device -> access point
	RelHandshake   = "handshake"   // device -> access point (4-way handshake)
)

// Entity kinds; an entity ID is "<kind>:<key>".
const (
	KindDevice      = "device"
	KindIP          = "ip"
	KindDomain      = "domain"
	KindHostname    = "hostname"
	KindVendor      = "vendor"
	KindService     = "service"
	KindFingerprint = "fingerprint"
	KindUserAgent   = "useragent"
	KindUPnP        = "upnp"
	KindLLDP        = "lldp"
	KindSSID        = "ssid"
)

// EntityID builds an entity ID.
func EntityID(kind, key string) string { return kind + ":" + key }

// SplitEntityID splits an entity ID into kind and key.
func SplitEntityID(id string) (kind, key string, ok bool) {
	return strings.Cut(id, ":")
}

// Timeseries is traffic per step across the window.
type Timeseries struct {
	StepMS    int64    `json:"step"`
	Precision string   `json:"precision"`
	Buckets   []Bucket `json:"buckets"`
}

// Bucket is one step of a timeseries.
type Bucket struct {
	TS         int64  `json:"ts"` // ms, bucket start
	BytesOut   uint64 `json:"bytes_out"`
	BytesIn    uint64 `json:"bytes_in"`
	FlowsNew   int    `json:"flows_new"`
	DNSQueries int    `json:"dns_queries"`
	Devices    int    `json:"devices"`
}

// GraphOptions shape a graph.
type GraphOptions struct {
	// Collapse folds remote addresses into the names they were reached
	// by, so a device connects to "www.example.com" rather than to three
	// CDN addresses. Unnamed addresses stay as address nodes.
	Collapse bool `json:"collapse"`
	// TopN keeps each device's N busiest destinations (0: default 15,
	// negative: all).
	TopN int `json:"top_n"`
	// Identity adds identity nodes (hostnames, services, fingerprints,
	// vendors) around each device instead of only listing them on it.
	Identity bool `json:"identity"`
	// DNS adds device -> domain edges for lookups and domain -> address
	// edges for answers.
	DNS bool `json:"dns"`
}

// DefaultGraphOptions is what the UIs start from.
var DefaultGraphOptions = GraphOptions{Collapse: true, TopN: 15, DNS: true}

// Values encodes graph options as query parameters.
func (o GraphOptions) Values() map[string]string {
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	return map[string]string{"collapse": b(o.Collapse), "identity": b(o.Identity), "dns": b(o.DNS), "top": strconv.Itoa(o.TopN)}
}

// ParseGraphOptions decodes query parameters over DefaultGraphOptions.
func ParseGraphOptions(q url.Values) GraphOptions {
	o := DefaultGraphOptions
	flag := func(k string, def bool) bool {
		switch q.Get(k) {
		case "1", "true", "yes":
			return true
		case "0", "false", "no":
			return false
		}
		return def
	}
	o.Collapse = flag("collapse", o.Collapse)
	o.Identity = flag("identity", o.Identity)
	o.DNS = flag("dns", o.DNS)
	if n, err := strconv.Atoi(q.Get("top")); err == nil {
		o.TopN = n
	}
	return o
}

// Graph is a window's entities and relationships.
type Graph struct {
	FromMS    int64  `json:"from"`
	ToMS      int64  `json:"to"`
	Precision string `json:"precision"`
	Nodes     []Node `json:"nodes"`
	Edges     []Edge `json:"edges"`
	Truncated bool   `json:"truncated,omitempty"` // TopN dropped destinations
}

// Node is one entity in a graph.
type Node struct {
	ID       string            `json:"id"`
	Kind     string            `json:"kind"`
	Label    string            `json:"label"`
	Sub      string            `json:"sub,omitempty"` // second line: vendor, address, ...
	Local    bool              `json:"local,omitempty"`
	BytesOut uint64            `json:"bytes_out,omitempty"`
	BytesIn  uint64            `json:"bytes_in,omitempty"`
	Attrs    map[string]string `json:"attrs,omitempty"`
}

// Edge is one relationship in a graph, aggregated over the window.
type Edge struct {
	From      string            `json:"from"`
	To        string            `json:"to"`
	Rel       string            `json:"rel"`
	Count     int               `json:"count,omitempty"` // connections, lookups, observations
	BytesOut  uint64            `json:"bytes_out,omitempty"`
	BytesIn   uint64            `json:"bytes_in,omitempty"`
	Carried   int               `json:"carried,omitempty"` // connections open at the window's start
	Opened    int               `json:"opened,omitempty"`  // connections opened inside it
	Closed    int               `json:"closed,omitempty"`  // connections that ended inside it
	Peak      int               `json:"peak,omitempty"`    // most simultaneous connections
	Ports     []string          `json:"ports,omitempty"`   // "443/tcp"
	TTL       uint32            `json:"ttl,omitempty"`     // DNS answers
	FirstSeen int64             `json:"first_seen,omitempty"`
	LastSeen  int64             `json:"last_seen,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
}

// EntityDetail is everything known about one entity in a window.
type EntityDetail struct {
	ID        string            `json:"id"`
	Kind      string            `json:"kind"`
	Key       string            `json:"key"`
	Label     string            `json:"label"`
	FirstSeen int64             `json:"first_seen"`
	LastSeen  int64             `json:"last_seen"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	Device    *Device           `json:"device,omitempty"`
	Facts     []Fact            `json:"facts,omitempty"`
	Flows     []Flow            `json:"flows,omitempty"`
	DNS       []DNSQuery        `json:"dns,omitempty"`
	Timeline  []TimelineEvent   `json:"timeline,omitempty"`
}

// TimelineEvent is one dated line in an entity's story.
type TimelineEvent struct {
	TS     int64  `json:"ts"`
	Type   string `json:"type"` // dhcp, mdns, dns, flow-open, flow-close, binding, ...
	Detail string `json:"detail"`
}

// Sensor is a sensor the server has heard from.
type Sensor struct {
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	FirstSeen  int64          `json:"first_seen"`
	LastSeen   int64          `json:"last_seen"`
	Interfaces []string       `json:"interfaces,omitempty"`
	Stats      map[string]any `json:"stats,omitempty"`
}

// WiFiNetwork is one SSID an access point was seen broadcasting. It exists
// only when a monitor-mode sensor with Wi-Fi support has reported it.
type WiFiNetwork struct {
	BSSID     string `json:"bssid"`
	SSID      string `json:"ssid"`
	Security  string `json:"security,omitempty"`
	Channel   int    `json:"channel,omitempty"`
	Clients   int    `json:"clients"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
}

// Values encodes f as URL query parameters.
func (f Filter) Values() url.Values {
	v := url.Values{}
	if !f.From.IsZero() {
		v.Set("from", strconv.FormatInt(f.From.UnixMilli(), 10))
	}
	if !f.To.IsZero() {
		v.Set("to", strconv.FormatInt(f.To.UnixMilli(), 10))
	}
	set := func(k, s string) {
		if s != "" {
			v.Set(k, s)
		}
	}
	set("device", f.Device)
	set("ip", f.IP)
	set("domain", f.Domain)
	set("proto", f.Proto)
	set("app", f.App)
	if f.Port != 0 {
		v.Set("port", strconv.Itoa(f.Port))
	}
	if f.Multicast {
		v.Set("multicast", "1")
	}
	if f.Limit != 0 {
		v.Set("limit", strconv.Itoa(f.Limit))
	}
	return v
}

// ParseFilter decodes URL query parameters. Times may be unix
// milliseconds, RFC 3339, or relative to now ("-1h", "now").
func ParseFilter(v url.Values, now time.Time) (Filter, error) {
	var f Filter
	var err error
	if s := v.Get("from"); s != "" {
		if f.From, err = ParseTime(s, now); err != nil {
			return f, fmt.Errorf("from: %w", err)
		}
	}
	if s := v.Get("to"); s != "" {
		if f.To, err = ParseTime(s, now); err != nil {
			return f, fmt.Errorf("to: %w", err)
		}
	}
	f.Device, f.IP, f.Domain = v.Get("device"), v.Get("ip"), v.Get("domain")
	f.Proto, f.App = v.Get("proto"), v.Get("app")
	if s := v.Get("port"); s != "" {
		if f.Port, err = strconv.Atoi(s); err != nil {
			return f, fmt.Errorf("port: %w", err)
		}
	}
	f.Multicast = v.Get("multicast") == "1" || v.Get("multicast") == "true"
	if s := v.Get("limit"); s != "" {
		if f.Limit, err = strconv.Atoi(s); err != nil {
			return f, fmt.Errorf("limit: %w", err)
		}
	}
	return f, nil
}

// ParseTime parses an absolute or relative time:
//
//	now, today, yesterday
//	-15m, -2h, -7d          relative to now (d = 24h, w = 7d)
//	1761393600000           unix milliseconds
//	2026-10-25T12:00:00Z    RFC 3339
//	2026-10-25 12:00        local time
//	2026-10-25              local midnight
func ParseTime(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	switch s {
	case "now", "":
		return now, nil
	case "today":
		y, m, d := now.Date()
		return time.Date(y, m, d, 0, 0, 0, 0, now.Location()), nil
	case "yesterday":
		y, m, d := now.AddDate(0, 0, -1).Date()
		return time.Date(y, m, d, 0, 0, 0, 0, now.Location()), nil
	}
	if s[0] == '-' || s[0] == '+' {
		d, err := ParseDuration(s[1:])
		if err != nil {
			return time.Time{}, err
		}
		if s[0] == '-' {
			d = -d
		}
		return now.Add(d), nil
	}
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.UnixMilli(ms), nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		loc := now.Location()
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time %q", s)
}

// ParseDuration is time.ParseDuration plus days (d) and weeks (w).
func ParseDuration(s string) (time.Duration, error) {
	if n := len(s); n > 1 && (s[n-1] == 'd' || s[n-1] == 'w') {
		v, err := strconv.ParseFloat(s[:n-1], 64)
		if err != nil {
			return 0, err
		}
		unit := 24 * time.Hour
		if s[n-1] == 'w' {
			unit *= 7
		}
		return time.Duration(v * float64(unit)), nil
	}
	return time.ParseDuration(s)
}

// FormatBytes renders a byte count compactly: 950B, 1.2kB, 34MB, 1.1GB.
func FormatBytes(n uint64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	v := float64(n) / float64(div)
	if v >= 100 {
		return fmt.Sprintf("%.0f%cB", v, "kMGTPE"[exp])
	}
	return fmt.Sprintf("%.1f%cB", v, "kMGTPE"[exp])
}

// FormatBytesWhole is FormatBytes rounded to whole units: 950B, 1kB, 34MB.
func FormatBytesWhole(n uint64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.0f%cB", float64(n)/float64(div), "kMGTPE"[exp])
}
