// Package wire is the contract between netgraph-sensor and the netgraph
// server: the event types the sensor emits and the batch encoding that
// carries them over HTTP.
//
// Events are deliberately flat facts about what was on the wire — "this MAC
// sent a DHCP request asking for hostname X", "this flow moved N bytes in this
// interval". The sensor does no correlation; that is the server's job, so it
// can be re-run and the sensor stays small.
//
// The schema is versioned (Version). A server accepts any batch whose version
// it knows; fields are only ever added, so an older server ignores fields a
// newer sensor sends.
package wire

import (
	"net/netip"
	"time"
)

// Version is the event schema version carried by every batch.
const Version = 1

// Type names an event payload. Exactly one payload pointer of Event is set,
// and it is the one Type names.
type Type string

const (
	TypeHello   Type = "hello"   // sensor identity and interfaces, on start and periodically
	TypeStats   Type = "stats"   // sensor counters, periodically
	TypeFlow    Type = "flow"    // one interval of one flow
	TypeDNS     Type = "dns"     // a DNS query and its response
	TypeBinding Type = "binding" // a MAC was seen using an IP (ARP, NDP)
	TypeDHCP    Type = "dhcp"    // a DHCPv4 or DHCPv6 message
	TypeMDNS    Type = "mdns"    // an mDNS/DNS-SD announcement or response
	TypeName    Type = "name"    // a NetBIOS or LLMNR name claim
	TypeSSDP    Type = "ssdp"    // an SSDP/UPnP announcement or response
	TypeLLDP    Type = "lldp"    // an LLDP neighbour advertisement
	TypeWiFi    Type = "wifi"    // a Wi-Fi network, client or handshake observation
)

// Event is one observation. TS is when it was observed (the packet's capture
// time, or the end of a flow interval).
type Event struct {
	Seq  uint64    `json:"seq"`
	Type Type      `json:"type"`
	TS   time.Time `json:"ts"`

	Hello   *Hello   `json:"hello,omitempty"`
	Stats   *Stats   `json:"stats,omitempty"`
	Flow    *Flow    `json:"flow,omitempty"`
	DNS     *DNS     `json:"dns,omitempty"`
	Binding *Binding `json:"binding,omitempty"`
	DHCP    *DHCP    `json:"dhcp,omitempty"`
	MDNS    *MDNS    `json:"mdns,omitempty"`
	Name    *Name    `json:"name,omitempty"`
	SSDP    *SSDP    `json:"ssdp,omitempty"`
	LLDP    *LLDP    `json:"lldp,omitempty"`
	WiFi    *WiFi    `json:"wifi,omitempty"`
}

// Hello describes the sensor and the interfaces it captures. The server uses
// the interface prefixes to decide which addresses are local, and the
// interface MACs to recognise the router itself.
type Hello struct {
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	OS         string      `json:"os"`
	Arch       string      `json:"arch"`
	Interfaces []Interface `json:"interfaces"`
	// Settings that change how flow records must be read.
	ActiveTimeout time.Duration `json:"active_timeout"`
}

type Interface struct {
	Name     string         `json:"name"`
	MAC      string         `json:"mac,omitempty"`
	Prefixes []netip.Prefix `json:"prefixes,omitempty"`
}

// Stats are cumulative counters since the sensor started.
type Stats struct {
	Uptime        time.Duration `json:"uptime"`
	Packets       uint64        `json:"packets"`
	Bytes         uint64        `json:"bytes"`
	KernelDrops   uint64        `json:"kernel_drops"`
	DecodeErrors  uint64        `json:"decode_errors"`
	FlowsActive   int           `json:"flows_active"`
	FlowsEvicted  uint64        `json:"flows_evicted"`
	EventsQueued  int           `json:"events_queued"`
	EventsDropped uint64        `json:"events_dropped"`
	BatchesSent   uint64        `json:"batches_sent"`
	SendErrors    uint64        `json:"send_errors"`
	HeapBytes     uint64        `json:"heap_bytes"`
}

// Flow is one export interval of one flow. A flow is identified by ID, which
// is unique within one sensor boot. Counters are deltas for [Start, End]; a
// long-lived flow produces one record per active-timeout interval, so summing
// the records that overlap a window gives the traffic inside it.
//
// Src is the initiator (the side that sent the first SYN, or the first packet
// of a UDP exchange); Out counts bytes from Src to Dst, In the reverse.
type Flow struct {
	ID        uint64     `json:"id"`
	Proto     uint8      `json:"proto"`
	Src       netip.Addr `json:"src"`
	SrcPort   uint16     `json:"sport,omitempty"`
	Dst       netip.Addr `json:"dst"`
	DstPort   uint16     `json:"dport,omitempty"`
	SrcMAC    string     `json:"smac,omitempty"` // MAC that sent Src's packets
	DstMAC    string     `json:"dmac,omitempty"` // MAC that sent Dst's packets
	FirstSeen time.Time  `json:"first"`          // when the flow began, not this interval
	Start     time.Time  `json:"start"`
	End       time.Time  `json:"end"`
	BytesOut  uint64     `json:"bout"`
	BytesIn   uint64     `json:"bin"`
	PktsOut   uint64     `json:"pout"`
	PktsIn    uint64     `json:"pin"`
	TCPFlags  uint8      `json:"tcpf,omitempty"` // OR of every flag seen
	Final     bool       `json:"final,omitempty"`
	EndReason string     `json:"reason,omitempty"` // fin, rst, idle, evict, shutdown

	// Application metadata, set once learned and repeated on later records.
	App       string `json:"app,omitempty"` // tls, quic, http, dns, ...
	SNI       string `json:"sni,omitempty"`
	ALPN      string `json:"alpn,omitempty"`
	JA4       string `json:"ja4,omitempty"`
	HTTPHost  string `json:"host,omitempty"`
	UserAgent string `json:"ua,omitempty"`
}

// DNS is one query and, if one was seen, its response. Unanswered queries
// are emitted with RCode "TIMEOUT".
type DNS struct {
	Client    netip.Addr `json:"client"`
	ClientMAC string     `json:"cmac,omitempty"`
	Server    netip.Addr `json:"server"`
	Proto     string     `json:"proto"` // udp, tcp
	ID        uint16     `json:"id"`
	QName     string     `json:"qname"`
	QType     string     `json:"qtype"`
	RCode     string     `json:"rcode"`
	LatencyMS float64    `json:"latency_ms,omitempty"`
	Answers   []Answer   `json:"answers,omitempty"`
}

// Answer is one resource record. Data is the address for A/AAAA, the target
// for CNAME/PTR/NS/SRV/HTTPS, and the text otherwise.
type Answer struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

// Binding says MAC was seen using IP, from ARP or NDP.
type Binding struct {
	MAC    string     `json:"mac"`
	IP     netip.Addr `json:"ip"`
	Source string     `json:"source"`           // arp, ndp
	Router bool       `json:"router,omitempty"` // NDP router advertisement
}

// DHCP is a DHCPv4 or DHCPv6 message, reduced to what identifies a device.
type DHCP struct {
	Version     int          `json:"version"` // 4 or 6
	MsgType     string       `json:"msg"`
	MAC         string       `json:"mac"`
	ClientIP    netip.Addr   `json:"ciaddr,omitzero"`
	YourIP      netip.Addr   `json:"yiaddr,omitzero"`
	RequestedIP netip.Addr   `json:"requested,omitzero"`
	ServerID    netip.Addr   `json:"server,omitzero"`
	Hostname    string       `json:"hostname,omitempty"`
	FQDN        string       `json:"fqdn,omitempty"`
	VendorClass string       `json:"vendor_class,omitempty"`
	ClientID    string       `json:"client_id,omitempty"` // hex
	ParamList   string       `json:"params,omitempty"`    // option 55 as "1,3,6,15"
	LeaseSecs   uint32       `json:"lease,omitempty"`
	Addresses   []netip.Addr `json:"addrs,omitempty"` // DHCPv6 IA addresses
}

// MDNS is what one mDNS packet said. Its records need not be about the
// sender: reflectors and sleep proxies answer for other hosts, so each
// host comes with the addresses that identify it.
type MDNS struct {
	MAC      string     `json:"mac,omitempty"`
	IP       netip.Addr `json:"ip"`
	Response bool       `json:"response"`
	Hosts    []MDNSHost `json:"hosts,omitempty"`
	Services []Service  `json:"services,omitempty"`
	Queries  []string   `json:"queries,omitempty"` // names asked about
}

// MDNSHost is a .local name and the addresses announced for it.
type MDNSHost struct {
	Name  string       `json:"name"`
	Addrs []netip.Addr `json:"addrs,omitempty"`
}

// Service is one DNS-SD service instance.
type Service struct {
	Instance string            `json:"instance"` // "Living Room._airplay._tcp.local"
	Type     string            `json:"type"`     // "_airplay._tcp"
	Target   string            `json:"target,omitempty"`
	Port     uint16            `json:"port,omitempty"`
	TXT      map[string]string `json:"txt,omitempty"`
}

// Name is a name a host claimed for itself, or that was found for it:
// NetBIOS, LLMNR, or reverse DNS.
type Name struct {
	MAC    string     `json:"mac,omitempty"`
	IP     netip.Addr `json:"ip"`
	Name   string     `json:"name"`
	Proto  string     `json:"proto"`            // nbns, llmnr, rdns
	Suffix string     `json:"suffix,omitempty"` // NetBIOS suffix, e.g. "workstation"
	Group  bool       `json:"group,omitempty"`
}

// SSDP is one UPnP discovery message.
type SSDP struct {
	MAC       string     `json:"mac,omitempty"`
	IP        netip.Addr `json:"ip"`
	Method    string     `json:"method"` // NOTIFY, M-SEARCH, RESPONSE
	Server    string     `json:"server,omitempty"`
	USN       string     `json:"usn,omitempty"`
	NT        string     `json:"nt,omitempty"` // NT or ST
	Location  string     `json:"location,omitempty"`
	UserAgent string     `json:"ua,omitempty"`
}

// LLDP is one LLDP advertisement.
type LLDP struct {
	MAC         string `json:"mac"`
	ChassisID   string `json:"chassis"`
	PortID      string `json:"port"`
	PortDesc    string `json:"port_desc,omitempty"`
	SystemName  string `json:"sys_name,omitempty"`
	SystemDesc  string `json:"sys_desc,omitempty"`
	MgmtAddress string `json:"mgmt,omitempty"`
}

// WiFi is one observation from a monitor-mode 802.11 capture. It deliberately
// carries no key material: the sensor does decryption locally and may forward
// the decrypted IP traffic as ordinary flow events.
type WiFi struct {
	Kind      string   `json:"kind"` // beacon, probe_request, association_request, handshake, data, ...
	BSSID     string   `json:"bssid,omitempty"`
	SSID      string   `json:"ssid,omitempty"`
	Client    string   `json:"client,omitempty"`
	Channel   int      `json:"channel,omitempty"`
	Frequency int      `json:"freq,omitempty"`   // MHz
	Signal    int      `json:"signal,omitempty"` // dBm
	Security  string   `json:"security,omitempty"`
	Ciphers   []string `json:"ciphers,omitempty"`
	AKMs      []string `json:"akms,omitempty"`
	Hidden    bool     `json:"hidden,omitempty"`
	Protected bool     `json:"protected,omitempty"`
	Decrypted bool     `json:"decrypted,omitempty"`
	Bytes     uint64   `json:"bytes,omitempty"`
	Reason    int      `json:"reason,omitempty"`
	// EAPOL describes a 4-way handshake message, never its nonces or MIC.
	EAPOL *EAPOL `json:"eapol,omitempty"`
	Error string `json:"error,omitempty"`
}

// EAPOL is the public shape of one 802.1X key message.
type EAPOL struct {
	Message   int    `json:"message"` // 1..4
	Version   int    `json:"version,omitempty"`
	Cipher    string `json:"cipher,omitempty"`
	Valid     bool   `json:"valid,omitempty"`
	Installed bool   `json:"installed,omitempty"`
}
