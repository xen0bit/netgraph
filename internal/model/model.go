// Package model holds the types the netgraph server answers queries with,
// shared by everything that asks: the HTTP API and its client, the CLI, the
// TUI and the WASM web UI. It has no dependencies beyond the standard
// library, so the WASM build can use it.
package model

import (
	"context"
	"fmt"
	"github.com/xen0bit/netgraph/internal/wire"
	"net/netip"
	"net/url"
	"slices"
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
	Destinations(ctx context.Context, f Filter) ([]Destination, error)
	DNS(ctx context.Context, f Filter) ([]DNSQuery, error)
	Facts(ctx context.Context, f Filter) ([]Fact, error)
	Timeseries(ctx context.Context, f Filter, step time.Duration) (*Timeseries, error)
	Graph(ctx context.Context, f Filter, o GraphOptions) (*Graph, error)
	Entity(ctx context.Context, id string, f Filter) (*EntityDetail, error)
	Sensors(ctx context.Context) ([]Sensor, error)
	WiFi(ctx context.Context, f Filter) ([]WiFiNetwork, error)
	Anomalies(ctx context.Context, f Filter) (*AnomalyReport, error)
	Search(ctx context.Context, q string, limit int) ([]SearchResult, error)
	Frame(ctx context.Context, f Filter) (*Frame, error)
	Story(ctx context.Context, id string, f Filter) (*Story, error)
	Timeline(ctx context.Context, f Filter, q TimelineQuery) (*TimelinePage, error)
	Diff(ctx context.Context, a, b Filter, scope string) (*Diff, error)
	Exposure(ctx context.Context, f Filter) (*ExposureReport, error)
	Coverage(ctx context.Context, f Filter) (*CoverageReport, error)
	Airspace(ctx context.Context, f Filter) (*AirspaceReport, error)
	Weather(ctx context.Context, f Filter) (*WeatherReport, error)
	Quality(ctx context.Context, f Filter) (*Quality, error)
}

// SearchResult is an entity whose key or name matches a search: a device by
// MAC, name or label, an address, a DNS name or a network.
type SearchResult struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	Label    string `json:"label"`
	LastSeen int64  `json:"last_seen"`
}

// Filter selects what a query covers. The window is half-open: [From, To).
// The other fields narrow it; empty means no restriction. Device, Domain and
// Host accept shell globs (*, ?), matched case-insensitively.
type Filter struct {
	From, To time.Time

	Device string // MAC, hostname or label of the local device
	IP     string // address or CIDR, either side of a flow
	Domain string // DNS name, SNI or HTTP host: glob or substring
	// DomainExact and DomainSuffix are internal exact forms used by entity
	// details, which must not be truncated by a broad substring match.
	DomainExact  string
	DomainSuffix string
	// All asks the store for every matching row, for streaming exports.
	// It is not a user-facing filter and still has a hard safety ceiling.
	All   bool
	Port  int    // the server's port: the service
	Proto string // tcp, udp, icmp, or a protocol number
	App   string // tls, quic, http, dns, ...
	Dir   string // out, in, local or external
	// The remote end's network (autonomous system number) and country
	// (ISO 3166 alpha-2), from the server's ASN table.
	ASN     uint32
	Country string

	Multicast bool // include multicast/broadcast traffic
	Limit     int  // maximum rows; 0 means the endpoint's default
	Offset    int  // rows to skip, for paging
	// Sort orders flows across the whole window, before Limit: one of FlowSorts.
	// Empty is busiest first. Hourly answers keep their own order.
	Sort string
}

// FlowSorts are the columns flows can be sorted by on the server, each with
// "-" in front for descending.
var FlowSorts = []string{"first_seen", "last_seen", "bytes", "bytes_out", "bytes_in"}

// Precision tells how exactly a result honours the window edges.
const (
	PrecisionExact = "exact" // from raw records: edges at the window boundaries are prorated
	PrecisionHour  = "hour"  // from hourly rollups: windows are widened to whole hours
)

// Reel is a window's graph with each edge's traffic per step: everything a
// client needs to scrub through the window without asking again. Precision
// says what the steps were read from ("exact", "minute" or "hour").
// Unassigned counts bytes of traffic no drawn edge stands for.
type Reel struct {
	FromMS     int64        `json:"from"`
	ToMS       int64        `json:"to"`
	StepMS     int64        `json:"step"`
	Steps      int          `json:"steps"`
	Precision  string       `json:"precision"`
	Graph      *Graph       `json:"graph"`
	Series     []ReelSeries `json:"series"`
	Markers    []ReelMarker `json:"markers"`
	Unassigned uint64       `json:"unassigned,omitempty"`
}

// ReelSeries is one edge's traffic: Edge indexes Graph.Edges, and each point
// is [step index, client to server bytes, server to client bytes], in order,
// with empty steps left out.
type ReelSeries struct {
	Edge   int         `json:"edge"`
	Points [][3]uint64 `json:"points"`
}

// ReelMarker is a moment worth seeking to.
type ReelMarker struct {
	TS       int64  `json:"ts"`
	Kind     string `json:"kind"`
	Severity string `json:"severity,omitempty"`
	Title    string `json:"title"`
	Entity   string `json:"entity,omitempty"`
}

// MapPin is where a person put a node on the map, in the map's own units.
type MapPin struct {
	ID      string  `json:"id"`
	X       float64 `json:"x"`
	Y       float64 `json:"y"`
	Updated int64   `json:"updated,omitempty"`
}

// DataRange says what a server holds, so a UI can offer real times: unix
// milliseconds, zero when it holds nothing. Raw records answer exactly from
// RawFromMS on; rollups answer by the hour from RollupFromMS on.
type DataRange struct {
	FirstMS      int64 `json:"first_ms"`
	LastMS       int64 `json:"last_ms"`
	RawFromMS    int64 `json:"raw_from_ms"`
	RollupFromMS int64 `json:"rollup_from_ms"`
	NowMS        int64 `json:"now_ms"`
}

// Summary is a window's headline numbers.
type Summary struct {
	FromMS     int64  `json:"from"`
	ToMS       int64  `json:"to"`
	Precision  string `json:"precision"`
	Devices    int    `json:"devices"`
	Flows      int    `json:"flows"`
	Inbound    int    `json:"inbound"` // of Flows, opened from outside
	DNSQueries int    `json:"dns_queries"`
	Domains    int    `json:"domains"`
	RemoteIPs  int    `json:"remote_ips"`
	BytesOut   uint64 `json:"bytes_out"` // sent by devices here
	BytesIn    uint64 `json:"bytes_in"`  // received by them
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
	UserLabel    bool     `json:"user_label,omitempty"` // Label was set by hand
	AutoLabel    string   `json:"auto_label,omitempty"` // the automatic name, when UserLabel
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
	Inbound      int      `json:"inbound"`          // of Flows, opened by someone outside
	Serves       []string `json:"serves,omitempty"` // ports others connected to: "443/tcp"
	DNSQueries   int      `json:"dns_queries"`
	BytesOut     uint64   `json:"bytes_out"` // what the device sent
	BytesIn      uint64   `json:"bytes_in"`  // what it received
	Remotes      int      `json:"remotes"`

	// What kind of thing it is: a person's word if UserType, else the verdict of
	// the classifier, with its confidence. TypeWhy is only on single-device answers.
	Type           string       `json:"type,omitempty"`
	TypeConfidence string       `json:"type_confidence,omitempty"`
	UserType       bool         `json:"user_type,omitempty"`
	TypeWhy        []TypeReason `json:"type_why,omitempty"`
	Owner          string       `json:"owner,omitempty"`
	Groups         []string     `json:"groups,omitempty"`
	SameAs         string       `json:"same_as,omitempty"` // the MAC a person said this also is
}

// TypeReason is one signal behind a device's type.
type TypeReason struct {
	Signal string `json:"signal"`
	Value  string `json:"value"`
	Says   string `json:"says"`
	Weight int    `json:"weight"`
}

// DeviceProfile is what a person says about a device. A nil field is left alone;
// an empty one clears it.
type DeviceProfile struct {
	Type   *string  `json:"type,omitempty"`
	Owner  *string  `json:"owner,omitempty"`
	Groups []string `json:"groups,omitempty"` // nil is left alone; empty clears
}

// LinkReason is one thing two MACs have in common.
type LinkReason struct {
	Signal string `json:"signal"` // hostname, service, fingerprint, user_agent
	Value  string `json:"value"`
}

// DeviceLink suggests that a private MAC is a device already known under another
// address. It is a suggestion: nothing changes until a person says so.
type DeviceLink struct {
	Device     Device       `json:"device"`
	Same       Device       `json:"same"`
	Confidence string       `json:"confidence"`
	Reasons    []LinkReason `json:"reasons"`
}

// PresenceDevice is when one device was seen in a window.
type PresenceDevice struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	Type      string     `json:"type,omitempty"`
	Owner     string     `json:"owner,omitempty"`
	Intervals [][2]int64 `json:"intervals"` // half-open, ms
}

// Presence is when devices were seen. "Seen" means they moved traffic: a phone
// asleep on the network doesn't show.
type Presence struct {
	FromMS    int64            `json:"from"`
	ToMS      int64            `json:"to"`
	Precision string           `json:"precision"` // minute or hour
	GapMS     int64            `json:"gap"`       // silence shorter than this doesn't split an interval
	Devices   []PresenceDevice `json:"devices"`
}

// Home states: how far to trust what the landing page shows as "now".
const (
	HomeOK       = "ok"       // at least one sensor is reporting
	HomeQuiet    = "quiet"    // sensors exist, and none has reported lately
	HomeImported = "imported" // data, but no sensor: it came from a capture
	HomeNoData   = "no_data"  // nothing has ever arrived
)

// HomeSensor is one sensor on the landing page.
type HomeSensor struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	LastSeen   int64    `json:"last_seen"`
	Interfaces []string `json:"interfaces,omitempty"`
	Quiet      bool     `json:"quiet,omitempty"`
}

// Home is the landing page. Active and TopTalkers are as of AsOfMS, the newest
// data held, which is not now if the sensors have stopped.
type Home struct {
	State        string       `json:"state"`
	NowMS        int64        `json:"now"`
	AsOfMS       int64        `json:"as_of"`
	SinceMS      int64        `json:"since"`
	SinceClamped bool         `json:"since_clamped,omitempty"` // the absence was longer than Since covers
	Sensors      []HomeSensor `json:"sensors"`
	Active       []Device     `json:"active"`
	NewDevices   []Device     `json:"new_devices"`
	TopTalkers   []Device     `json:"top_talkers"`
	Since        *Summary     `json:"summary_since,omitempty"`
	Traffic      *Timeseries  `json:"traffic,omitempty"`
}

// PassportDay is one day of a device's traffic.
type PassportDay struct {
	TS       int64  `json:"ts"`
	Flows    int    `json:"flows"`
	BytesOut uint64 `json:"bytes_out"`
	BytesIn  uint64 `json:"bytes_in"`
}

// PassportWeek is one week of a device's traffic.
type PassportWeek struct {
	Flows        int    `json:"flows"`
	BytesOut     uint64 `json:"bytes_out"`
	BytesIn      uint64 `json:"bytes_in"`
	Destinations int    `json:"destinations"`
}

// PassportDest is what a device talked to, or was reached from, this week.
type PassportDest struct {
	Key       string `json:"key"`
	Direction string `json:"direction"`
	Flows     int    `json:"flows"`
	BytesOut  uint64 `json:"bytes_out"`
	BytesIn   uint64 `json:"bytes_in"`
	New       bool   `json:"new,omitempty"` // not seen in the week before
}

// Passport is one device's profile, from the hourly rollups.
type Passport struct {
	ID              string         `json:"id"`
	AsOfMS          int64          `json:"as_of"`
	WeekFromMS      int64          `json:"week_from"`
	LastWeekFromMS  int64          `json:"last_week_from"`
	Device          *Device        `json:"device"`
	AlsoSeenAs      []Device       `json:"also_seen_as,omitempty"`
	Hours           []uint64       `json:"hours"` // bytes this week per hour of the day, in the reader's timezone
	Days            []PassportDay  `json:"days"`
	ThisWeek        PassportWeek   `json:"this_week"`
	LastWeek        PassportWeek   `json:"last_week"`
	HasLastWeek     bool           `json:"has_last_week"` // the device existed for all of it
	NewDestinations int            `json:"new_destinations"`
	Destinations    []PassportDest `json:"destinations"`
	Story           *Story         `json:"story,omitempty"`
}

// Flow states relative to the window.
const (
	StateCarried = "carried" // opened before the window, still open at its start
	StateOpened  = "opened"  // opened inside the window
)

// Connection directions, from the local network's point of view.
const (
	DirOut      = "out"      // a device here connected to something outside
	DirIn       = "in"       // something outside connected to a device here
	DirLocal    = "local"    // both ends are here
	DirExternal = "external" // neither end is (traffic passing through)
)

// Destination is a remote end aggregated over a window: one name or address
// with its connections and traffic, for the destinations table.
type Destination struct {
	Key         string   `json:"key"`
	Kind        string   `json:"kind"` // name or ip
	Label       string   `json:"label"`
	Connections int      `json:"connections"`
	Devices     int      `json:"devices"`
	BytesOut    uint64   `json:"bytes_out"`
	BytesIn     uint64   `json:"bytes_in"`
	FirstSeen   int64    `json:"first_seen"`
	LastSeen    int64    `json:"last_seen"`
	Ports       []string `json:"ports,omitempty"`
	RemoteIPs   []string `json:"remote_ips,omitempty"`
}

// Flow is one connection's activity inside the window.
//
// Client and server are the connection's two ends as TCP or UDP sees them:
// the client opened it. Remote is whichever end is not the device: the
// server, unless the connection came in (Direction "in"), when it is the
// client. Byte and packet counters are from the device's side: BytesOut
// is what the device sent, whichever end opened the connection.
type Flow struct {
	Key        string `json:"key"`
	Proto      string `json:"proto"`
	ClientIP   string `json:"client_ip"`
	ClientPort int    `json:"client_port"`
	ServerIP   string `json:"server_ip"`
	ServerPort int    `json:"server_port"`
	DeviceMAC  string `json:"device_mac,omitempty"`
	Device     string `json:"device,omitempty"` // device ID
	DeviceName string `json:"device_name,omitempty"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	// The remote end's device, when it is one here too (Direction "local").
	PeerDevice string `json:"peer_device,omitempty"`
	PeerName   string `json:"peer_name,omitempty"`
	Direction  string `json:"direction"` // out, in, local, external
	App        string `json:"app,omitempty"`
	Name       string `json:"name,omitempty"` // best name: SNI, HTTP host, then DNS
	SNI        string `json:"sni,omitempty"`
	HTTPHost   string `json:"http_host,omitempty"`
	QName      string `json:"qname,omitempty"`
	ALPN       string `json:"alpn,omitempty"`
	JA4        string `json:"ja4,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	// The remote end's network, when the server has an ASN table.
	ASN       uint32 `json:"asn,omitempty"`
	ASOrg     string `json:"as_org,omitempty"`
	Country   string `json:"country,omitempty"`
	Continent string `json:"continent,omitempty"`
	Region    string `json:"region,omitempty"`
	City      string `json:"city,omitempty"`
	GeoOrg    string `json:"geo_org,omitempty"`
	FirstSeen int64  `json:"first_seen"` // ms; when the connection opened
	LastSeen  int64  `json:"last_seen"`  // ms; its last record
	State     string `json:"state"`
	Closed    bool   `json:"closed"` // it ended inside the window
	EndReason string `json:"end_reason,omitempty"`
	// Truncated means the sensor dropped its state (the flow table was
	// full), not that the connection closed cleanly.
	Truncated   bool   `json:"truncated,omitempty"`
	BytesOut    uint64 `json:"bytes_out"` // inside the window
	BytesIn     uint64 `json:"bytes_in"`
	PktsOut     uint64 `json:"pkts_out"`
	PktsIn      uint64 `json:"pkts_in"`
	Connections int    `json:"connections,omitempty"` // rows from hourly rollups, which keep no packet counts
}

// Inbound reports whether the connection was opened from outside to the
// device.
func (f Flow) Inbound() bool { return f.Direction == DirIn }

// Network names the remote end's network: "AS13335 CLOUDFLARENET · US",
// or "" when the server has no ASN table.
func (f Flow) Network() string {
	if f.ASN == 0 {
		return ""
	}
	s := "AS" + strconv.FormatUint(uint64(f.ASN), 10)
	if f.ASOrg != "" {
		s += " " + f.ASOrg
	}
	if f.Country != "" {
		s += " · " + f.Country
	}
	return s
}

// LocalIP is the device's end of the connection.
func (f Flow) LocalIP() string {
	if f.Inbound() {
		return f.ServerIP
	}
	return f.ClientIP
}

// Service is the server's port and protocol, "443/tcp" (or just the
// protocol, for one without ports).
func (f Flow) Service() string {
	if f.ServerPort == 0 {
		return f.Proto
	}
	return fmt.Sprintf("%d/%s", f.ServerPort, f.Proto)
}

// Ends is how a table shows the flow's client and server: devices by name
// and the other end by address, the server with its port.
//
//	laptop               93.184.215.14:443/tcp   (out)
//	198.51.100.7:51234   nas:443/tcp             (in)
func (f Flow) Ends() (client, server string) {
	dev := f.DeviceName
	if dev == "" {
		dev = f.LocalIP()
	}
	addr := func(ip string, port int) string {
		if strings.Contains(ip, ":") {
			ip = "[" + ip + "]"
		}
		if port == 0 {
			return ip
		}
		return ip + ":" + strconv.Itoa(port)
	}
	if f.Inbound() {
		return addr(f.ClientIP, f.ClientPort), addr(dev, f.ServerPort) + "/" + f.Proto
	}
	server = f.ServerIP
	if f.PeerName != "" {
		server = f.PeerName
	}
	return dev, addr(server, f.ServerPort) + "/" + f.Proto
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
	Count      int         `json:"count,omitempty"` // lookups this row stands for (hourly rollups)
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
	// An autonomous system, keyed by its number: the network a remote
	// address belongs to (label: its organisation; attrs: country).
	KindASN = "asn"
	// Graph only: the names under one registrable domain (Sites), and the
	// destinations of one device that Top N summarised.
	KindSite   = "site"
	KindSensor = "sensor"
	KindOther  = "other"
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
	// Sites groups names by registrable domain: one "time.com" node for
	// www.time.com, auth.time.com and the rest.
	Sites bool `json:"sites"`
	// Anomalies marks the nodes that the window's anomalies are about.
	Anomalies bool `json:"anomalies"`
	// Networks draws remote addresses with a known network (the server's
	// ASN table) as one node per network: a web server's visitors as
	// "AS24940 HETZNER-AS · DE", not an address each. Named destinations
	// stay names.
	Networks bool `json:"networks"`
}

// DefaultGraphOptions is what the UIs start from.
var DefaultGraphOptions = GraphOptions{Collapse: true, TopN: 15, DNS: true, Sites: true, Anomalies: true, Networks: true}

// Values encodes graph options as query parameters.
func (o GraphOptions) Values() map[string]string {
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	return map[string]string{"collapse": b(o.Collapse), "identity": b(o.Identity), "dns": b(o.DNS), "sites": b(o.Sites),
		"anomalies": b(o.Anomalies), "networks": b(o.Networks), "top": strconv.Itoa(o.TopN)}
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
	o.Sites = flag("sites", o.Sites)
	o.Anomalies = flag("anomalies", o.Anomalies)
	o.Networks = flag("networks", o.Networks)
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

	OS   string `json:"os,omitempty"`
	Arch string `json:"arch,omitempty"`
	// Status is SensorOK, SensorQuiet or SensorStruggling, and Problems says why.
	Status   string   `json:"status,omitempty"`
	Problems []string `json:"problems,omitempty"`
	// UpgradeTo is the server's version, if this sensor's is older. Nothing upgrades it:
	// a router's software is its owner's to change.
	UpgradeTo string `json:"upgrade_to,omitempty"`
	// Settable is false for a source inside the server, which has no settings to push.
	Settable bool `json:"settable,omitempty"`
	// Config is what's been asked of this sensor alone, InEffect what it last said it's
	// doing, and ConfigApplied whether that matches what's asked, fleet settings included.
	Config        *wire.SensorConfig `json:"config,omitempty"`
	InEffect      *wire.SensorConfig `json:"in_effect,omitempty"`
	ConfigApplied bool               `json:"config_applied,omitempty"`
	// TakesConfig is false for one too old to, or started with -remote-config=false.
	TakesConfig bool `json:"takes_config,omitempty"`
}

// How a sensor is doing.
const (
	SensorOK         = "ok"
	SensorQuiet      = "quiet"
	SensorStruggling = "struggling"
)

// Anomaly kinds.
const (
	AnomalyNewDevice      = "new_device"        // a device used an address on the LAN for the first time
	AnomalyNewDestination = "new_destination"   // a device reached a site it never had
	AnomalyUploadSpike    = "upload_spike"      // a device sent far more than its history
	AnomalyBeacon         = "beacon"            // a device connects somewhere on a fixed period
	AnomalyDNSFailures    = "dns_failures"      // many lookups of names that do not exist
	AnomalyDNSTunnel      = "dns_tunnel"        // many long, unique names under one site
	AnomalyRogueAP        = "rogue_ap"          // a network name with an unexpected access point
	AnomalyScan           = "scan"              // an address outside tried many ports, or one port on many hosts
	AnomalyBruteForce     = "brute_force"       // many short sessions to a login service from outside
	AnomalyNewService     = "new_service"       // a device here started serving a port to clients outside
	AnomalyInboundSurge   = "inbound_surge"     // far more connections from outside than in any recent hour
	AnomalyARPConflict    = "arp_conflict"      // two devices held one address at the same time
	AnomalyRogueDHCP      = "rogue_dhcp"        // a DHCP server that is not the router answered on the LAN
	AnomalyNameMismatch   = "name_mismatch"     // SNI/Host name was never resolved by the device
	AnomalyDeauthFlood    = "wifi_deauth_flood" // many deauthentications from one access point
	AnomalySensorSilent   = "sensor_silent"     // a sensor stopped reporting
)

// Anomaly severities, least to most.
const (
	SeverityLow    = "low"
	SeverityMedium = "medium"
	SeverityHigh   = "high"
)

// SeverityRank orders severities: 0 for unknown, then low, medium, high.
func SeverityRank(s string) int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	}
	return 0
}

// Anomaly is something in a window that stands out, from the network's own
// history or from how hosts normally behave, with the evidence for it.
type Anomaly struct {
	Kind       string            `json:"kind"`
	Severity   string            `json:"severity"`
	TS         int64             `json:"ts"`               // ms; when it started in the window
	Device     string            `json:"device,omitempty"` // device ID
	DeviceName string            `json:"device_name,omitempty"`
	Entity     string            `json:"entity,omitempty"` // what it is about: a site, address, SSID or access point ID
	Summary    string            `json:"summary"`
	Evidence   map[string]string `json:"evidence,omitempty"`
}

// Quality verdicts.
const (
	QualityGood         = "good"
	QualityUnknown      = "unknown"
	QualitySlowLocal    = "slow_local"
	QualitySlowUpstream = "slow_upstream"
	QualityLossy        = "lossy"
	QualityOutage       = "outage"
)

// PathStats is delay over some path.
type PathStats struct {
	P50MS   float64 `json:"p50_ms"`
	P95MS   float64 `json:"p95_ms"`
	Samples int     `json:"samples"`
}

// QualityPoint is one step of a window.
type QualityPoint struct {
	TS         int64   `json:"ts"`
	WANP50MS   float64 `json:"wan_p50_ms"`
	LANP50MS   float64 `json:"lan_p50_ms"`
	RetransPct float64 `json:"retrans_pct"`
}

// QualityDevice is how one device's connections are doing.
type QualityDevice struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	WAN        PathStats `json:"wan"`
	LAN        PathStats `json:"lan"`
	RetransPct float64   `json:"retrans_pct"`
}

// Outage is a stretch when nothing outward was answered.
type Outage struct {
	FromMS   int64 `json:"from"`
	ToMS     int64 `json:"to"`
	Attempts int   `json:"attempts"`
}

// Quality is how the network is doing, from what passes through it. It measures delay
// and loss, not speed.
type Quality struct {
	FromMS      int64           `json:"from"`
	ToMS        int64           `json:"to"`
	StepMS      int64           `json:"step"`
	Verdict     string          `json:"verdict"`
	Summary     string          `json:"summary"`
	WAN         PathStats       `json:"wan"`   // the way upstream
	LAN         PathStats       `json:"lan"`   // the way to devices here
	Usual       PathStats       `json:"usual"` // the WAN over the week before
	DNS         PathStats       `json:"dns"`
	DNSQueries  int             `json:"dns_queries"`
	DNSTimeouts int             `json:"dns_timeouts"`
	RetransPct  float64         `json:"retrans_pct"`
	Unanswered  int             `json:"unanswered"`
	Outages     []Outage        `json:"outages"`
	Series      []QualityPoint  `json:"series"`
	Devices     []QualityDevice `json:"devices"`
	Gaps        []string        `json:"gaps,omitempty"`
}

// AuditEntry is one change someone made through the API.
type AuditEntry struct {
	ID     int64  `json:"id"`
	TS     int64  `json:"ts"`
	Actor  string `json:"actor"`
	Role   string `json:"role"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Remote string `json:"remote,omitempty"`
}

// Finding statuses: its life from when a check first reports it.
const (
	FindingNew          = "new"
	FindingSeen         = "seen"
	FindingAcknowledged = "acknowledged"
	FindingResolved     = "resolved"  // a person's word, or a week of silence (AutoResolved)
	FindingDismissed    = "dismissed" // a person said it's fine; it won't be reported again
)

// Finding is an anomaly with a memory. Its embedded TS is LastSeen.
type Finding struct {
	Anomaly
	ID           int64  `json:"id"`
	FirstSeen    int64  `json:"first_seen"`
	LastSeen     int64  `json:"last_seen"`
	Occurrences  int    `json:"occurrences"`
	Status       string `json:"status"`
	StatusAt     int64  `json:"status_at"`
	AutoResolved bool   `json:"auto_resolved,omitempty"`
	Recurrences  int    `json:"recurrences,omitempty"` // times it came back after being resolved
	Note         string `json:"note,omitempty"`
	// On a single finding's answer only.
	Why    string `json:"why,omitempty"`
	Advice string `json:"advice,omitempty"`
	Usual  string `json:"usual,omitempty"`
}

// FindingGroup is one device's findings close together in time: probably one story.
type FindingGroup struct {
	Device     string  `json:"device"`
	DeviceName string  `json:"device_name,omitempty"`
	FromMS     int64   `json:"from"`
	ToMS       int64   `json:"to"`
	Severity   string  `json:"severity"`
	IDs        []int64 `json:"ids"`
}

// FindingQuery selects findings.
type FindingQuery struct {
	Status  string // a status, "open", or empty for all
	SinceMS int64  // last seen at or after this
	ToMS    int64  // first seen before this
	Device  string
	Limit   int
}

// FindingList is findings with what's needed to show them.
type FindingList struct {
	Findings  []Finding      `json:"findings"`
	Groups    []FindingGroup `json:"groups"`
	Counts    map[string]int `json:"counts"` // every finding by status, whatever was selected
	ScannedMS int64          `json:"scanned_at,omitempty"`
	Learning  bool           `json:"learning,omitempty"`
}

// AnomalyReport is a window's anomalies. Checks that compare with history
// need a day of it before the window; until then Learning is set and only
// the checks that need no history run.
type AnomalyReport struct {
	FromMS     int64     `json:"from"`
	ToMS       int64     `json:"to"`
	SinceMS    int64     `json:"since,omitempty"` // when the first sensor first reported
	HistoryMS  int64     `json:"history_ms,omitempty"`
	BaselineMS int64     `json:"baseline_ms,omitempty"`
	Learning   bool      `json:"learning,omitempty"`
	Anomalies  []Anomaly `json:"anomalies"`
}

// Frame is a recorded moment: a short lookback ending at AtMS, rendered as
// the network the user would have seen then.
type Frame struct {
	AtMS         int64         `json:"at"`
	FromMS       int64         `json:"from"`
	ToMS         int64         `json:"to"`
	LookbackMS   int64         `json:"lookback_ms"`
	Precision    string        `json:"precision"`
	Scope        string        `json:"scope,omitempty"`
	Summary      *Summary      `json:"summary,omitempty"`
	Devices      []Device      `json:"devices,omitempty"`
	Destinations []Destination `json:"destinations,omitempty"`
	Flows        []Flow        `json:"flows,omitempty"`
	DNS          []DNSQuery    `json:"dns,omitempty"`
	WiFi         []WiFiNetwork `json:"wifi,omitempty"`
	Sensors      []Sensor      `json:"sensors,omitempty"`
	Anomalies    []Anomaly     `json:"anomalies,omitempty"`
	Graph        *Graph        `json:"graph,omitempty"`
	Truncated    []string      `json:"truncated,omitempty"`
}

// TimelineQuery selects timeline entries. Cursor is opaque and replaces
// Offset for stable paging while ingest is running.
type TimelineQuery struct {
	Entity string
	Kinds  []string
	Cursor string
	Limit  int
}

// TimelineEntry is one rail event. Ref is "table:key", for opening the
// authoritative record.
type TimelineEntry struct {
	ID       int64             `json:"id"`
	TS       int64             `json:"ts"`
	Kind     string            `json:"kind"`
	Entity   string            `json:"entity,omitempty"`
	Related  string            `json:"related,omitempty"`
	Severity string            `json:"severity,omitempty"`
	Title    string            `json:"title"`
	Ref      string            `json:"ref,omitempty"`
	Attrs    map[string]string `json:"attrs,omitempty"`
}

// TimelinePage is one page of the event rail.
type TimelinePage struct {
	Events    []TimelineEntry `json:"events"`
	Next      string          `json:"next,omitempty"`
	Precision string          `json:"precision"`
}

// EvidenceRef points at the record behind a claim, segment or scene.
type EvidenceRef struct {
	Kind string `json:"kind"` // timeline, flow, dns, observation, fact, anomaly, sensor, note
	ID   string `json:"id"`
	TS   int64  `json:"ts,omitempty"`
	Text string `json:"text,omitempty"`
}

// StorySegment is one dated interval in an entity's story.
type StorySegment struct {
	Kind     string        `json:"kind"` // presence, fact relation, connection, incident
	FromMS   int64         `json:"from"`
	ToMS     int64         `json:"to"`
	Entity   string        `json:"entity,omitempty"`
	Label    string        `json:"label,omitempty"`
	Count    int           `json:"count,omitempty"`
	BytesOut uint64        `json:"bytes_out,omitempty"`
	BytesIn  uint64        `json:"bytes_in,omitempty"`
	Evidence []EvidenceRef `json:"evidence,omitempty"`
}

// Story is an entity's recorded life over a window.
type Story struct {
	Entity     string          `json:"entity"`
	Label      string          `json:"label,omitempty"`
	FromMS     int64           `json:"from"`
	ToMS       int64           `json:"to"`
	Segments   []StorySegment  `json:"segments"`
	Milestones []TimelineEntry `json:"milestones,omitempty"`
	Evidence   []EvidenceRef   `json:"evidence,omitempty"`
	Gaps       []string        `json:"gaps,omitempty"`
}

// DiffItem is one added, removed or changed thing between two frames.
type DiffItem struct {
	Kind     string        `json:"kind"`
	Key      string        `json:"key"`
	Label    string        `json:"label,omitempty"`
	Before   string        `json:"before,omitempty"`
	After    string        `json:"after,omitempty"`
	Evidence []EvidenceRef `json:"evidence,omitempty"`
}

// Diff compares two recorded moments.
type Diff struct {
	FromMS  int64      `json:"from"`
	ToMS    int64      `json:"to"`
	Added   []DiffItem `json:"added,omitempty"`
	Removed []DiffItem `json:"removed,omitempty"`
	Changed []DiffItem `json:"changed,omitempty"`
	Gaps    []string   `json:"gaps,omitempty"`
}

// Camera asks the Flight Recorder where to look in a scene.
type Camera struct {
	Focus    string   `json:"focus,omitempty"`
	Entities []string `json:"entities,omitempty"`
	Layer    string   `json:"layer,omitempty"`
}

// Scene is one step of an autopsy reel.
type Scene struct {
	ID        string        `json:"id"`
	AtMS      int64         `json:"at"`
	DurMS     int64         `json:"duration,omitempty"`
	Title     string        `json:"title"`
	Narrative string        `json:"narrative"`
	Camera    Camera        `json:"camera"`
	Evidence  []EvidenceRef `json:"evidence,omitempty"`
	Severity  string        `json:"severity,omitempty"`
}

// Autopsy is a deterministic reconstruction of an anomaly or incident.
type Autopsy struct {
	Anomaly   *Anomaly `json:"anomaly,omitempty"`
	Incident  int64    `json:"incident,omitempty"`
	FromMS    int64    `json:"from"`
	ToMS      int64    `json:"to"`
	Generated int64    `json:"generated"`
	Scenes    []Scene  `json:"scenes"`
	Entities  []string `json:"entities,omitempty"`
	Gaps      []string `json:"gaps,omitempty"`
}

// Incident is a saved investigation. Anomalies are ephemeral; an incident
// pins the window and evidence a person wants to keep.
type Incident struct {
	ID        int64    `json:"id"`
	OpenedMS  int64    `json:"opened"`
	UpdatedMS int64    `json:"updated"`
	StartMS   int64    `json:"start"`
	EndMS     int64    `json:"end"`
	Kind      string   `json:"kind"`
	Severity  string   `json:"severity"`
	Status    string   `json:"status"`
	Title     string   `json:"title"`
	Summary   string   `json:"summary,omitempty"`
	Entities  []string `json:"entities,omitempty"`
}

// IncidentNote is a timestamped human note on an incident.
type IncidentNote struct {
	ID         int64  `json:"id"`
	IncidentID int64  `json:"incident"`
	TS         int64  `json:"ts"`
	Author     string `json:"author,omitempty"`
	Body       string `json:"body"`
}

// IncidentDetail is an incident with its notes and pinned evidence.
type IncidentDetail struct {
	Incident
	Notes    []IncidentNote `json:"notes,omitempty"`
	Evidence []EvidenceRef  `json:"evidence,omitempty"`
}

// Impact is one connection or lookup affected by a proposed policy.
type Impact struct {
	Kind        string        `json:"kind"` // connection, dns
	Device      string        `json:"device,omitempty"`
	DeviceName  string        `json:"device_name,omitempty"`
	Zone        string        `json:"zone,omitempty"`
	Destination string        `json:"destination,omitempty"`
	Port        string        `json:"port,omitempty"`
	Direction   string        `json:"direction,omitempty"`
	BytesOut    uint64        `json:"bytes_out,omitempty"`
	BytesIn     uint64        `json:"bytes_in,omitempty"`
	Connections int           `json:"connections,omitempty"`
	Rule        string        `json:"rule,omitempty"`
	Reason      string        `json:"reason,omitempty"`
	Critical    bool          `json:"critical,omitempty"`
	Evidence    []EvidenceRef `json:"evidence,omitempty"`
}

// ImpactGroup aggregates impacts for the blast-radius tables.
type ImpactGroup struct {
	Key         string `json:"key"`
	Label       string `json:"label,omitempty"`
	Connections int    `json:"connections,omitempty"`
	BytesOut    uint64 `json:"bytes_out,omitempty"`
	BytesIn     uint64 `json:"bytes_in,omitempty"`
}

// WhatIfSummary is the headline result of a policy simulation.
type WhatIfSummary struct {
	Connections int `json:"connections"`
	Blocked     int `json:"blocked"`   // connections the policy would stop
	Essential   int `json:"essential"` // of Blocked, ones the network depends on
	Lookups     int `json:"lookups"`   // DNS lookups the policy would stop
	WouldAsk    int `json:"would_ask"` // connections an ask rule would have held
	Unknown     int `json:"unknown"`
	OutOfScope  int `json:"out_of_scope"`
	Unchanged   int `json:"unchanged"`
}

// WhatIfResult is a proposed policy evaluated against observed traffic.
type WhatIfResult struct {
	FromMS        int64         `json:"from"`
	ToMS          int64         `json:"to"`
	PolicyHash    string        `json:"policy_hash,omitempty"`
	Summary       WhatIfSummary `json:"summary"`
	Blocked       []Impact      `json:"blocked,omitempty"`
	Essential     []Impact      `json:"essential,omitempty"`
	WouldAsk      []Impact      `json:"would_ask,omitempty"`
	Unknown       []Impact      `json:"unknown,omitempty"`
	ByDevice      []ImpactGroup `json:"by_device,omitempty"`
	ByDestination []ImpactGroup `json:"by_destination,omitempty"`
	ByRule        []ImpactGroup `json:"by_rule,omitempty"`
	Gaps          []string      `json:"gaps,omitempty"`
}

// Claim is one factual sentence in an answer, with the records behind it.
type Claim struct {
	Text     string        `json:"text"`
	Evidence []EvidenceRef `json:"evidence"`
}

// ToolCall records what an answer looked at.
type ToolCall struct {
	Tool string            `json:"tool"`
	Args map[string]string `json:"args,omitempty"`
}

// Answer is a grounded response to a question. Ask drops any claim that has
// no evidence behind it.
type Answer struct {
	Question   string        `json:"question"`
	Answer     string        `json:"answer"`
	Confidence string        `json:"confidence"`
	Claims     []Claim       `json:"claims,omitempty"`
	Evidence   []EvidenceRef `json:"evidence,omitempty"`
	Plan       []ToolCall    `json:"plan,omitempty"`
	Followups  []string      `json:"followups,omitempty"`
	Gaps       []string      `json:"gaps,omitempty"`
	FromMS     int64         `json:"from,omitempty"`  // the window it answers
	ToMS       int64         `json:"to,omitempty"`    //
	Focus      string        `json:"focus,omitempty"` // the device it's about, if one
	Model      string        `json:"model,omitempty"` // which language model wrote it; empty is none
}

// ExposureFinding is one observation about what is reachable or weak.
type ExposureFinding struct {
	Kind     string        `json:"kind"`
	Severity string        `json:"severity"`
	Entity   string        `json:"entity,omitempty"`
	Label    string        `json:"label,omitempty"`
	Summary  string        `json:"summary"`
	Evidence []EvidenceRef `json:"evidence,omitempty"`
}

// ExposureReport is a read-only risk inventory, not a vulnerability scan.
type ExposureReport struct {
	FromMS   int64             `json:"from"`
	ToMS     int64             `json:"to"`
	Findings []ExposureFinding `json:"findings"`
	Gaps     []string          `json:"gaps,omitempty"`
}

// CoverageSensor is one sensor's health and observed devices.
type CoverageSensor struct {
	Name       string   `json:"name"`
	LastSeen   int64    `json:"last_seen"`
	Version    string   `json:"version,omitempty"`
	Interfaces []string `json:"interfaces,omitempty"`
	Devices    int      `json:"devices"`
	OnlyDevice int      `json:"only_device"`
}

// CoverageDevice is which sensors saw one device.
type CoverageDevice struct {
	Device  string   `json:"device"`
	Label   string   `json:"label,omitempty"`
	Sensors []string `json:"sensors"`
	OnlyOne bool     `json:"only_one,omitempty"`
}

// CoverageReport shows what each sensor can and cannot see.
type CoverageReport struct {
	FromMS  int64            `json:"from"`
	ToMS    int64            `json:"to"`
	Sensors []CoverageSensor `json:"sensors"`
	Devices []CoverageDevice `json:"devices"`
	Gaps    []string         `json:"gaps,omitempty"`
}

// AirspaceNetwork is one BSSID in the Wi-Fi airspace view.
type AirspaceNetwork struct {
	BSSID     string   `json:"bssid"`
	SSID      string   `json:"ssid"`
	Security  string   `json:"security,omitempty"`
	Channel   int      `json:"channel,omitempty"`
	Signal    int      `json:"signal,omitempty"` // dBm, as last heard by a sensor
	Band      string   `json:"band,omitempty"`   // 2.4, 5 or 6 GHz
	Clients   []string `json:"clients,omitempty"`
	FirstSeen int64    `json:"first_seen"`
	LastSeen  int64    `json:"last_seen"`
	Rogue     bool     `json:"rogue,omitempty"`
}

// AirspaceReport is the time-aware Wi-Fi view.
type AirspaceReport struct {
	FromMS   int64             `json:"from"`
	ToMS     int64             `json:"to"`
	Networks []AirspaceNetwork `json:"networks"`
	Channels []AirspaceChannel `json:"channels"`
	Gaps     []string          `json:"gaps,omitempty"`
}

// AirspaceChannel is what was heard on one channel. It counts networks, which isn't how busy
// the air is: one network can be idle and another flat out.
type AirspaceChannel struct {
	Band     string `json:"band"`
	Channel  int    `json:"channel"`
	Networks int    `json:"networks"`
	Clients  int    `json:"clients"`
	// Strongest is the loudest network here, in dBm; 0 if no sensor reported a level.
	Strongest int `json:"strongest,omitempty"`
	// Overlapping counts networks on other channels near enough to share its air: on 2.4 GHz,
	// where neighbouring channels overlap.
	Overlapping int `json:"overlapping,omitempty"`
}

// WeatherPoint is one observed or forecast bucket.
type WeatherPoint struct {
	TS       int64  `json:"ts"`
	BytesOut uint64 `json:"bytes_out"`
	BytesIn  uint64 `json:"bytes_in"`
	Flows    int    `json:"flows"`
	DNS      int    `json:"dns"`
	Devices  int    `json:"devices"`
	Lower    uint64 `json:"lower,omitempty"`
	Upper    uint64 `json:"upper,omitempty"`
	Forecast bool   `json:"forecast,omitempty"`
}

// WeatherReport is a simple, explainable traffic forecast.
type WeatherReport struct {
	FromMS int64          `json:"from"`
	ToMS   int64          `json:"to"`
	StepMS int64          `json:"step"`
	Points []WeatherPoint `json:"points"`
	Gaps   []string       `json:"gaps,omitempty"`
}

// Incident statuses.
const (
	IncidentOpen         = "open"
	IncidentAcknowledged = "acknowledged"
	IncidentResolved     = "resolved"
)

// Annotation is a human note pinned to a moment and optionally an entity.
type Annotation struct {
	ID      int64  `json:"id"`
	TS      int64  `json:"ts"`
	Entity  string `json:"entity,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Text    string `json:"text"`
	Author  string `json:"author,omitempty"`
	Created int64  `json:"created,omitempty"`
}

// Bookmark marks a moment for later.
type Bookmark struct {
	ID      int64  `json:"id"`
	TS      int64  `json:"ts"`
	Entity  string `json:"entity,omitempty"`
	Name    string `json:"name"`
	Created int64  `json:"created,omitempty"`
}

// AnomalyMute suppresses matching findings until Until (ms). Empty Kind,
// Device or Entity fields are wildcards; the API/UI normally sets all three
// for one finding.
type AnomalyMute struct {
	Kind    string `json:"kind,omitempty"`
	Device  string `json:"device,omitempty"`
	Entity  string `json:"entity,omitempty"`
	Until   int64  `json:"until"`
	Note    string `json:"note,omitempty"`
	Created int64  `json:"created,omitempty"`
}

// WiFiNetwork is one SSID an access point was seen broadcasting. It exists
// only when a monitor-mode sensor with Wi-Fi support has reported it.
type WiFiNetwork struct {
	BSSID     string `json:"bssid"`
	SSID      string `json:"ssid"`
	Security  string `json:"security,omitempty"`
	Channel   int    `json:"channel,omitempty"`
	Signal    int    `json:"signal,omitempty"` // dBm, as last heard by a sensor
	Frequency int    `json:"freq,omitempty"`   // MHz
	Clients   int    `json:"clients"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
}

// ApplyScope narrows f to a Flight Recorder scope: device:MAC, domain:name or
// ip:addr. An empty scope changes nothing.
func (f *Filter) ApplyScope(scope string) error {
	if scope == "" {
		return nil
	}
	kind, key, _ := SplitEntityID(scope)
	if key != "" {
		switch kind {
		case KindDevice:
			f.Device = key
			return nil
		case KindDomain:
			f.DomainExact = key
			return nil
		case KindIP:
			f.IP = key
			return nil
		}
	}
	return fmt.Errorf("unknown scope %q: want device:MAC, domain:name or ip:addr", scope)
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
	set("dir", f.Dir)
	set("cc", f.Country)
	if f.ASN != 0 {
		v.Set("asn", strconv.FormatUint(uint64(f.ASN), 10))
	}
	if f.Port != 0 {
		v.Set("port", strconv.Itoa(f.Port))
	}
	if f.Multicast {
		v.Set("multicast", "1")
	}
	if f.Limit != 0 {
		v.Set("limit", strconv.Itoa(f.Limit))
	}
	if f.Offset != 0 {
		v.Set("offset", strconv.Itoa(f.Offset))
	}
	if f.Sort != "" {
		v.Set("sort", f.Sort)
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
	f.Proto, f.App = strings.ToLower(v.Get("proto")), v.Get("app")
	if f.Proto != "" && !validProto(f.Proto) {
		return f, fmt.Errorf("proto: %q is not a protocol name or 0-255", f.Proto)
	}
	switch f.Dir = v.Get("dir"); f.Dir {
	case "", DirOut, DirIn, DirLocal, DirExternal:
	default:
		return f, fmt.Errorf("dir: %q is not out, in, local or external", f.Dir)
	}
	if s := v.Get("port"); s != "" {
		if f.Port, err = strconv.Atoi(s); err != nil || f.Port < 0 || f.Port > 65535 {
			return f, fmt.Errorf("port: %q is not a port number", s)
		}
	}
	if f.IP != "" {
		if _, err := netip.ParsePrefix(f.IP); err != nil {
			if _, aerr := netip.ParseAddr(f.IP); aerr != nil {
				return f, fmt.Errorf("ip: %q is not an address or CIDR", f.IP)
			}
		}
	}
	if s := v.Get("asn"); s != "" {
		if f.ASN, err = ParseASN(s); err != nil {
			return f, fmt.Errorf("asn: %w", err)
		}
	}
	if s := v.Get("cc"); s != "" {
		if f.Country, err = ParseCountry(s); err != nil {
			return f, fmt.Errorf("cc: %w", err)
		}
	}
	f.Multicast = v.Get("multicast") == "1" || v.Get("multicast") == "true"
	if s := v.Get("limit"); s != "" {
		if f.Limit, err = strconv.Atoi(s); err != nil {
			return f, fmt.Errorf("limit: %w", err)
		}
	}
	if s := v.Get("offset"); s != "" {
		if f.Offset, err = strconv.Atoi(s); err != nil || f.Offset < 0 {
			return f, fmt.Errorf("offset: %q is not a non-negative number", s)
		}
	}
	if s := v.Get("sort"); s != "" {
		if !slices.Contains(FlowSorts, strings.TrimPrefix(s, "-")) {
			return f, fmt.Errorf("sort: %q is not one of %v", s, FlowSorts)
		}
		f.Sort = s
	}
	return f, nil
}

func validProto(p string) bool {
	switch p {
	case "tcp", "udp", "icmp", "icmpv6":
		return true
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 0 && n <= 255
}

// ParseASN parses an autonomous system number, "13335" or "AS13335".
func ParseASN(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if len(s) > 2 && strings.EqualFold(s[:2], "as") {
		s = s[2:]
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("%q is not an AS number", s)
	}
	return uint32(n), nil
}

// ParseCountry parses a two-letter country code, in either case.
func ParseCountry(s string) (string, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) != 2 || s[0] < 'A' || s[0] > 'Z' || s[1] < 'A' || s[1] > 'Z' {
		return "", fmt.Errorf("%q is not a two-letter country code", s)
	}
	return s, nil
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

// At returns the report as the answer for the window [from, to). A live view's
// window moves between runs of the checks, and its response names the window
// asked for; the report itself is shared and never changed.
func (r *AnomalyReport) At(from, to int64) *AnomalyReport {
	if r == nil || (r.FromMS == from && r.ToMS == to) {
		return r
	}
	c := *r
	c.FromMS, c.ToMS = from, to
	return &c
}

// RuleGroup is a collection of blocklists or rules a person enables together.
type RuleGroup struct {
	ID             int64  `json:"id"`
	AUID           string `json:"auid"`
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	Type           string `json:"type"` // factory, remote, local
	URL            string `json:"url,omitempty"`
	Enabled        bool   `json:"enabled"`
	UpdateInterval int64  `json:"update_interval,omitempty"`
	LastSuccess    int64  `json:"last_success,omitempty"`
	LastFailure    int64  `json:"last_failure,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	InvalidEntries int    `json:"invalid_entries,omitempty"`
	Created        int64  `json:"created"`
	Modified       int64  `json:"modified"`
}

// Blocklist is one parsed source of blocked domains, hosts or addresses.
type Blocklist struct {
	ID             int64  `json:"id"`
	AUID           string `json:"auid"`
	GroupID        int64  `json:"group_id,omitempty"`
	Name           string `json:"name"`
	URL            string `json:"url,omitempty"`
	Format         string `json:"format,omitempty"`
	Enabled        bool   `json:"enabled"`
	UpdateInterval int64  `json:"update_interval,omitempty"`
	LastSuccess    int64  `json:"last_success,omitempty"`
	LastFailure    int64  `json:"last_failure,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	ETag           string `json:"etag,omitempty"`
	LastModified   string `json:"last_modified,omitempty"`
	EntryCount     int    `json:"entry_count"`
	InvalidEntries int    `json:"invalid_entries,omitempty"`
	Created        int64  `json:"created"`
	Modified       int64  `json:"modified"`
}

// BlocklistEntry is one enabled or disabled line in a blocklist.
type BlocklistEntry struct {
	ID         int64  `json:"id"`
	Blocklist  int64  `json:"blocklist_id"`
	Kind       string `json:"kind"` // domain, host, ip
	Value      string `json:"value"`
	Enabled    bool   `json:"enabled"`
	Unapproved bool   `json:"unapproved,omitempty"`
	UseCount   int64  `json:"use_count,omitempty"`
	LastUsed   int64  `json:"last_used,omitempty"`
	Notes      string `json:"notes,omitempty"`
}

// Profile is a policy context activated by a network trigger.
type Profile struct {
	ID            int64    `json:"id"`
	AUID          string   `json:"auid"`
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	Active        bool     `json:"active"`
	Mode          string   `json:"mode"` // alert, silent-allow, silent-deny
	DNSExceptions []string `json:"dns_exceptions,omitempty"`
	IsDefault     bool     `json:"is_default,omitempty"`
	Created       int64    `json:"created"`
	Modified      int64    `json:"modified"`
}

// NetworkTrigger activates or changes a profile when a signature matches.
type NetworkTrigger struct {
	ID            int64  `json:"id"`
	AUID          string `json:"auid"`
	ProfileID     int64  `json:"profile_id"`
	ProfileName   string `json:"profile_name,omitempty"`
	Signature     string `json:"signature"`
	Action        string `json:"action"` // activate, deactivate, ask, none
	Mode          string `json:"mode,omitempty"`
	Enabled       bool   `json:"enabled"`
	LastTriggered int64  `json:"last_triggered,omitempty"`
	Created       int64  `json:"created"`
	Modified      int64  `json:"modified"`
}

// NetworkContext is what netgraph currently sees as the local network.
type NetworkContext struct {
	Signature string `json:"signature"`
	SSID      string `json:"ssid,omitempty"`
	BSSID     string `json:"bssid,omitempty"`
	Router    string `json:"router,omitempty"`
	Interface string `json:"interface,omitempty"`
	Profile   string `json:"profile,omitempty"`
}

// PolicyDecision is a connection that matched an ask rule or a silent mode.
// Open means "would have asked"; it is not proof that traffic was blocked.
type PolicyDecision struct {
	ID          int64  `json:"id"`
	TS          int64  `json:"ts"`
	Device      string `json:"device,omitempty"`
	DeviceName  string `json:"device_name,omitempty"`
	FlowKey     string `json:"flow_key,omitempty"`
	Direction   string `json:"direction,omitempty"`
	Remote      string `json:"remote,omitempty"`
	Port        string `json:"port,omitempty"`
	Proto       string `json:"proto,omitempty"`
	Action      string `json:"action"` // ask, silent-allow, silent-deny
	Status      string `json:"status"` // open, allowed, denied, rule-created, expired
	RuleID      string `json:"rule_id,omitempty"`
	RuleName    string `json:"rule_name,omitempty"`
	Profile     string `json:"profile,omitempty"`
	Mode        string `json:"mode,omitempty"`
	Stalled     bool   `json:"stalled,omitempty"`
	Unconfirmed bool   `json:"unconfirmed,omitempty"`
	DecidedAt   int64  `json:"decided_at,omitempty"`
	DecidedBy   string `json:"decided_by,omitempty"`
	Note        string `json:"note,omitempty"`
	Created     int64  `json:"created"`
	Modified    int64  `json:"modified"`
}

// ConnectionGroup is connections folded by device, app, site, host or
// destination. It is the monitor's daily-use view, not a per-flow list.
type ConnectionGroup struct {
	Key          string   `json:"key"`
	Label        string   `json:"label,omitempty"`
	Kind         string   `json:"kind"` // device, app, domain, host, destination
	Devices      []string `json:"devices,omitempty"`
	DeviceNames  []string `json:"device_names,omitempty"`
	Destinations []string `json:"destinations,omitempty"`
	Ports        []string `json:"ports,omitempty"`
	RemoteIPs    []string `json:"remote_ips,omitempty"`
	Connections  int      `json:"connections"`
	BytesOut     uint64   `json:"bytes_out"`
	BytesIn      uint64   `json:"bytes_in"`
	FirstSeen    int64    `json:"first_seen"`
	LastSeen     int64    `json:"last_seen"`
	Names        []string `json:"names,omitempty"`
}

// Purpose explains what an application uses a host for. It is metadata, not
// an allow/deny decision.
type Purpose struct {
	ID               int64  `json:"id"`
	Application      string `json:"application"`
	Developer        string `json:"developer,omitempty"`
	Website          string `json:"website,omitempty"`
	Host             string `json:"host"`
	Purpose          string `json:"purpose,omitempty"`
	DenyConsequences string `json:"deny_consequences,omitempty"`
	Source           string `json:"source,omitempty"`
	Updated          int64  `json:"updated"`
}
