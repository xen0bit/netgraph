// Package blocklist parses and matches the blocklist formats netgraph
// accepts: hosts files, plain domain lists, AdGuard/Adblock-style domain rules
// (||example.com^, @@||example.com^), address/CIDR lists and Little
// Snitch-style .lsrules JSON. It is server-only and never touches a firewall.
package blocklist

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"unicode"
)

// Formats accepted by Parse.
const (
	FormatAuto    = "auto"
	FormatHosts   = "hosts"
	FormatDomains = "domains"
	FormatIPs     = "ips"
	FormatLSRules = "lsrules"
)

// Entry is one parsed blocklist line.
type Entry struct {
	Kind  string `json:"kind"` // domain, host, ip, or except: a domain a list exempts
	Value string `json:"value"`
	// Disabled is only set when restoring a list someone had edited; a parsed
	// feed never disables anything.
	Disabled bool `json:"disabled,omitempty"`
}

// Parsed is a blocklist document.
type Parsed struct {
	Title       string  `json:"title,omitempty"`
	Description string  `json:"description,omitempty"`
	Entries     []Entry `json:"entries"`
	Invalid     int     `json:"invalid"`
}

const (
	maxBytes   = 64 << 20
	maxEntries = 500_000
	maxLine    = 4096
	maxDomain  = 253
)

// Parse reads a blocklist. Auto detection looks at the first non-space
// character: JSON is .lsrules, otherwise the hosts/domain parser handles
// both common shapes.
func Parse(r io.Reader, format string) (*Parsed, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBytes {
		return nil, fmt.Errorf("blocklist is larger than %d bytes", maxBytes)
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = FormatAuto
	}
	if format == FormatAuto {
		trimmed := bytes.TrimSpace(b)
		if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
			format = FormatLSRules
		} else {
			format = FormatHosts
		}
	}
	switch format {
	case FormatLSRules:
		return parseLSRules(b)
	case FormatIPs:
		return parseLines(b, true, false)
	case FormatDomains:
		return parseLines(b, false, true)
	case FormatHosts:
		return parseLines(b, true, true)
	default:
		return nil, fmt.Errorf("format %q is not hosts, domains, ips, lsrules or auto", format)
	}
}

func parseLines(b []byte, allowIP, allowDomain bool) (*Parsed, error) {
	out := &Parsed{Entries: []Entry{}}
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), maxLine)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if lineNo == 1 {
			if v, ok := header(line, "Title:"); ok {
				out.Title = v
				continue
			}
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "!") {
			if v, ok := header(line, "# Title:"); ok {
				out.Title = v
			}
			if v, ok := header(line, "# Description:"); ok {
				out.Description = v
			}
			continue
		}
		if allowDomain && (strings.HasPrefix(line, "||") || strings.HasPrefix(line, "@@||")) {
			if !addAdblock(out, seen, line) {
				out.Invalid++
			}
			continue
		}
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		fields := strings.FieldsFunc(line, func(r rune) bool { return unicode.IsSpace(r) || r == ',' })
		if len(fields) == 0 {
			continue
		}
		// A hosts file has an address first, then one or more names. The
		// address is where the names are sent (0.0.0.0, 127.0.0.1), not
		// something blocked, and each name blocks that host exactly.
		if allowDomain && len(fields) > 1 {
			if _, err := netip.ParseAddr(stripZone(fields[0])); err == nil {
				for _, name := range fields[1:] {
					if hostsBoilerplate[strings.ToLower(name)] || strings.HasPrefix(strings.ToLower(name), "ip6-") {
						continue
					}
					if !addHost(out, seen, name) {
						out.Invalid++
					}
				}
				continue
			}
		}
		for _, f := range fields {
			if allowIP && addIP(out, seen, f) {
				continue
			}
			if allowDomain && !looksNumeric(f) && addDomain(out, seen, f) {
				continue
			}
			out.Invalid++
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out.Entries) == 0 {
		return nil, fmt.Errorf("blocklist has no entries")
	}
	return out, nil
}

// hostsBoilerplate are the names every hosts file maps to itself.
var hostsBoilerplate = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"0.0.0.0": true, "localhost4": true, "localhost6": true,
}

func stripZone(s string) string {
	if i := strings.IndexByte(s, '%'); i >= 0 {
		return s[:i]
	}
	return s
}

// looksNumeric is an address-like token that failed to parse as one: it is
// not a domain either.
func looksNumeric(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r == '.' || r == '/' || r == ':' || r == '-') {
			return false
		}
	}
	return true
}

func header(line, prefix string) (string, bool) {
	if strings.HasPrefix(strings.ToLower(line), strings.ToLower(prefix)) {
		return strings.TrimSpace(line[len(prefix):]), true
	}
	return "", false
}

func addIP(out *Parsed, seen map[string]bool, s string) bool {
	v, ok := normalizeIP(s)
	if !ok {
		return false
	}
	return add(out, seen, Entry{Kind: "ip", Value: v})
}

func addDomain(out *Parsed, seen map[string]bool, s string) bool {
	v, ok := normalizeDomain(s)
	if !ok {
		return false
	}
	return add(out, seen, Entry{Kind: "domain", Value: v})
}

// addAdblock reads one AdGuard/Adblock domain rule: ||name^ blocks a name and
// its subdomains, @@||name^ excepts them. A rule with modifiers ($client,
// $dnsrewrite, ...) or a wildcard means more than a name, and is not read as
// one: $important only orders rules, so it is the one modifier accepted.
func addAdblock(out *Parsed, seen map[string]bool, line string) bool {
	kind := "domain"
	if rest, ok := strings.CutPrefix(line, "@@"); ok {
		kind, line = "except", rest
	}
	line = strings.TrimPrefix(line, "||")
	if rule, mods, ok := strings.Cut(line, "$"); ok {
		if strings.TrimSpace(mods) != "important" {
			return false
		}
		line = rule
	}
	line, ok := strings.CutSuffix(strings.TrimSpace(line), "^")
	if !ok || strings.ContainsAny(line, "*/|^") {
		return false
	}
	v, ok := normalizeDomain(line)
	if !ok {
		return false
	}
	return add(out, seen, Entry{Kind: kind, Value: v})
}

func addHost(out *Parsed, seen map[string]bool, s string) bool {
	v, ok := normalizeDomain(s)
	if !ok {
		return false
	}
	return add(out, seen, Entry{Kind: "host", Value: v})
}

func add(out *Parsed, seen map[string]bool, e Entry) bool {
	if len(out.Entries) >= maxEntries {
		return false
	}
	k := e.Kind + ":" + e.Value
	if seen[k] {
		return true
	}
	seen[k] = true
	out.Entries = append(out.Entries, e)
	return true
}

// NormalizeName lower-cases a DNS name and checks it is one: letters, digits,
// hyphens, underscores and dots, at most 253 characters. A leading "*." and a
// trailing dot are dropped.
func NormalizeName(s string) (string, bool) { return normalizeDomain(s) }

func normalizeDomain(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > maxDomain {
		return "", false
	}
	for _, r := range s {
		if r > unicode.MaxASCII || !(r == '-' || r == '_' || r == '.' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return "", false
		}
	}
	if strings.Contains(s, "..") || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return "", false
	}
	return s, true
}

func normalizeIP(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if a, b, ok := strings.Cut(s, "-"); ok {
		x, err1 := netip.ParseAddr(strings.TrimSpace(a))
		y, err2 := netip.ParseAddr(strings.TrimSpace(b))
		if err1 != nil || err2 != nil || x.Is4() != y.Is4() || x.Compare(y) > 0 {
			return "", false
		}
		return x.Unmap().String() + "-" + y.Unmap().String(), true
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", false
		}
		return p.Masked().String(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	return a.Unmap().String(), true
}

// SortEntries gives deterministic storage and API output.
func SortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Kind != entries[j].Kind {
			return entries[i].Kind < entries[j].Kind
		}
		return entries[i].Value < entries[j].Value
	})
}

// lsRules is the subset of the Little Snitch rule file netgraph understands.
// It is data, not a promise to execute every Little Snitch feature.
type lsRules struct {
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Rules       []lsRule          `json:"rules"`
	Denied      []json.RawMessage `json:"denied-remote"`
	Domains     []string          `json:"denied-remote-domains"`
	Hosts       []string          `json:"denied-remote-hosts"`
	Addresses   []string          `json:"denied-remote-addresses"`
}

type lsRule struct {
	Action string          `json:"action"`
	Remote json.RawMessage `json:"remote"`
	// Little Snitch's own keys: a string or a list of strings.
	RemoteDomains   json.RawMessage `json:"remote-domains"`
	RemoteHosts     json.RawMessage `json:"remote-hosts"`
	RemoteAddresses json.RawMessage `json:"remote-addresses"`
	// Some exporters put the values at the rule level.
	Domains   []string `json:"denied-remote-domains"`
	Hosts     []string `json:"denied-remote-hosts"`
	Addresses []string `json:"denied-remote-addresses"`
}

// stringOrList reads a JSON string or list of strings, and nothing else.
func stringOrList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	return nil
}

func parseLSRules(b []byte) (*Parsed, error) {
	var doc lsRules
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&doc); err != nil {
		// Some files are a bare array of rules.
		var rules []lsRule
		if err2 := json.Unmarshal(b, &rules); err2 != nil {
			return nil, err
		}
		doc.Rules = rules
	}
	out := &Parsed{Title: doc.Title, Description: doc.Description, Entries: []Entry{}}
	seen := map[string]bool{}
	addValues := func(kind string, values []string) {
		for _, v := range values {
			var ok bool
			switch kind {
			case "ip":
				ok = addIP(out, seen, v)
			case "host":
				ok = addHost(out, seen, v)
			default:
				ok = addDomain(out, seen, v)
			}
			if !ok {
				out.Invalid++
			}
		}
	}
	addValues("domain", doc.Domains)
	addValues("host", doc.Hosts)
	addValues("ip", doc.Addresses)
	for _, raw := range doc.Denied {
		kind, values := remoteValues(raw)
		addValues(kind, values)
	}
	for _, r := range doc.Rules {
		// Only explicit denies: an allow or an unlabelled rule is not a block.
		if !strings.EqualFold(r.Action, "deny") {
			continue
		}
		kind, values := remoteValues(r.Remote)
		addValues(kind, values)
		addValues("domain", stringOrList(r.RemoteDomains))
		addValues("host", stringOrList(r.RemoteHosts))
		addValues("ip", stringOrList(r.RemoteAddresses))
		addValues("domain", r.Domains)
		addValues("host", r.Hosts)
		addValues("ip", r.Addresses)
	}
	if len(out.Entries) == 0 {
		return nil, fmt.Errorf("blocklist has no entries")
	}
	return out, nil
}

func remoteValues(raw json.RawMessage) (string, []string) {
	if len(raw) == 0 {
		return "domain", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		// A bare string is one of Little Snitch's keywords (any, local-net,
		// bonjour, ...), not a name: a blocklist can't express those.
		return "domain", nil
	}
	var obj struct {
		Type   string   `json:"type"`
		Values []string `json:"values"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		kind := "domain"
		switch strings.ToLower(obj.Type) {
		case "ip", "address", "ipv4", "ipv6":
			kind = "ip"
		case "host":
			kind = "host"
		case "domain", "dns":
			kind = "domain"
		}
		return kind, obj.Values
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return "domain", list
	}
	return "domain", nil
}
