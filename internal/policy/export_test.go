package policy

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func testPolicy() *Policy {
	return &Policy{
		Version:  1,
		Zones:    []Zone{{Name: "iot", Devices: []string{"device:aa:bb:cc:00:00:01", "role:printer"}}, {Name: "empty", Devices: []string{"device:ff:ff:ff:ff:ff:ff"}}},
		Defaults: Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"},
		Rules: []Rule{
			{Name: "cloud", From: "zone:iot", To: "site:example.com", Ports: []string{"443/tcp"}, Action: "allow"},
			{Name: "ntp", From: "zone:iot", To: "ip:192.0.2.0/24", Ports: []string{"123/udp"}, Action: "allow"},
			{Name: "both protocols", From: "zone:iot", To: "ip:192.0.2.9", Ports: []string{"53"}, Action: "allow"},
			{Name: "no such site--really", From: "zone:iot", To: "site:never-seen.org", Action: "deny"},
			{Name: "block one", From: "zone:iot", To: "198.51.100.7", Action: "deny"},
		},
	}
}

func testObserved() Observed {
	return Observed{
		Devices: []ObservedDevice{
			{ID: "device:aa:bb:cc:00:00:01", Label: "lamp", IPs: []string{"192.168.1.20", "2001:db8::20", "fe80::1%eth0", "fe80::5", "0.0.0.0", "224.0.0.251", "127.0.0.1"}},
			{ID: "device:aa:bb:cc:00:00:02", Label: "printer", Role: "printer", IPs: []string{"192.168.1.21"}},
			{ID: "device:aa:bb:cc:00:00:09", Label: "laptop", IPs: []string{"192.168.1.30"}},
		},
		Remotes: []ObservedRemote{
			{Name: "api.example.com", IP: "93.184.216.34"},
			{Name: "cdn.example.com", IP: "2606:2800:220:1::1"},
			{Name: "other.net", IP: "203.0.113.5"},
		},
	}
}

func export(t *testing.T, p *Policy, format string, obs Observed) *Exported {
	t.Helper()
	out, err := ExportPolicy(p, format, obs, "2026-11-04")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestNftablesExport(t *testing.T) {
	out := export(t, testPolicy(), FormatNftables, testObserved())
	for _, want := range []string{
		"ip saddr { 192.168.1.20, 192.168.1.21 } ip daddr 93.184.216.34 tcp dport 443 accept",
		"ip6 saddr 2001:db8::20 ip6 daddr 2606:2800:220:1::1 tcp dport 443 accept",
		"ip saddr { 192.168.1.20, 192.168.1.21 } ip daddr 192.0.2.0/24 udp dport 123 accept",
		"ip daddr 192.0.2.9 tcp dport 53 accept",
		"ip daddr 192.0.2.9 udp dport 53 accept",
		"# LEFT OUT: nothing was seen for site:never-seen.org",
		"ip daddr 198.51.100.7 drop",
		"ip saddr { 192.168.1.20, 192.168.1.21 } ip daddr { 192.168.1.20, 192.168.1.21 } accept",
		"ip saddr { 192.168.1.20, 192.168.1.21 } drop",
		"ip daddr { 192.168.1.20, 192.168.1.21 } drop",
		"ct state established,related accept",
	} {
		if !strings.Contains(out.Config, want) {
			t.Errorf("no %q in:\n%s", want, out.Config)
		}
	}
	if strings.Contains(out.Config, "192.168.1.30") {
		t.Error("a device in no zone got into the rules")
	}
	for _, bad := range []string{"fe80", "0.0.0.0", "224.0.0.251", "127.0.0.1"} {
		if strings.Contains(out.Config, bad) {
			t.Errorf("%s got into the rules", bad)
		}
	}
	// Rule order is what makes first-match mean the same.
	if a, b := strings.Index(out.Config, "tcp dport 443 accept"), strings.Index(out.Config, "default leaving zones"); a < 0 || b < a {
		t.Error("defaults came before rules")
	}
	warned := strings.Join(out.Warnings, "\n")
	for _, want := range []string{"WHAT IT DENIES IS NOT DENIED", "can't match names", `zone "empty" matches no device`} {
		if !strings.Contains(warned, want) {
			t.Errorf("no warning %q in:\n%s", want, warned)
		}
	}
}

func TestExportWarnsAboutDNS(t *testing.T) {
	p := testPolicy()
	p.DNS.Block = []string{"*.tracker.example"}
	if out := export(t, p, FormatNftables, testObserved()); !strings.Contains(strings.Join(out.Warnings, " "), "DNS rules aren't exported") {
		t.Errorf("%+v", out.Warnings)
	}
}

// Labels and names come off the network, and rule names from whoever typed them.
func TestExportCantBeInjected(t *testing.T) {
	const evil = "x\"; flush ruleset; #\n accept'<script>--&`$(reboot)"
	p := testPolicy()
	p.Rules[0].Name = evil
	p.Zones[0].Name = "iot"
	obs := testObserved()
	obs.Devices[0].Label = evil
	obs.Devices[0].IPs = append(obs.Devices[0].IPs, evil, "1.2.3.4; drop")
	obs.Remotes = append(obs.Remotes, ObservedRemote{Name: "api.example.com", IP: evil})
	for _, f := range []string{FormatNftables, FormatOpenWrt, FormatOPNsense} {
		out := export(t, p, f, obs)
		// The words are inert with their punctuation gone: it's the punctuation that matters.
		for _, bad := range []string{`"; `, "'<", "<script", "$(", "`", "1.2.3.4"} {
			if strings.Contains(out.Config, bad) {
				t.Errorf("%s: %q reached the output:\n%s", f, bad, out.Config)
			}
		}
		if strings.Contains(out.Config, "\n accept") {
			t.Errorf("%s: a newline in a name made a line:\n%s", f, out.Config)
		}
	}
}

func TestOpenWrtExport(t *testing.T) {
	out := export(t, testPolicy(), FormatOpenWrt, testObserved())
	for _, want := range []string{
		"config rule\n	option name 'netgraph 1 cloud'",
		"	option family 'ipv4'\n	option target 'ACCEPT'\n	option proto 'tcp'\n	list src_ip '192.168.1.20'\n	list src_ip '192.168.1.21'\n	list dest_ip '93.184.216.34'\n	list dest_port '443'",
		"	option target 'DROP'",
		"# LEFT OUT: nothing was seen",
	} {
		if !strings.Contains(out.Config, want) {
			t.Errorf("no %q in:\n%s", want, out.Config)
		}
	}
}

func TestOPNsenseExportIsXML(t *testing.T) {
	p := testPolicy()
	p.Rules[0].Name = `a&b<c>"d`
	out := export(t, p, FormatOPNsense, testObserved())
	var doc struct {
		XMLName xml.Name `xml:"filter"`
		Rules   []struct {
			Type     string `xml:"type"`
			IP       string `xml:"ipprotocol"`
			Protocol string `xml:"protocol"`
			Descr    string `xml:"descr"`
			Source   struct {
				Address string  `xml:"address"`
				Any     *string `xml:"any"`
			} `xml:"source"`
			Destination struct {
				Address string `xml:"address"`
				Port    string `xml:"port"`
			} `xml:"destination"`
		} `xml:"rule"`
	}
	if err := xml.Unmarshal([]byte(out.Config), &doc); err != nil {
		t.Fatalf("%v\n%s", err, out.Config)
	}
	if len(doc.Rules) == 0 {
		t.Fatal("no rules")
	}
	first := doc.Rules[0]
	if first.Type != "pass" || first.IP != "inet" || first.Protocol != "tcp" || first.Source.Address != "192.168.1.20" || first.Destination.Address != "93.184.216.34" || first.Destination.Port != "443" {
		t.Errorf("%+v", first)
	}
}

func TestOPNsenseBound(t *testing.T) {
	obs := testObserved()
	for i := range 200 {
		obs.Remotes = append(obs.Remotes, ObservedRemote{Name: "api.example.com", IP: "93.184.1." + itoa(i)})
		obs.Devices[0].IPs = append(obs.Devices[0].IPs, "10.0.0."+itoa(i))
	}
	p := testPolicy()
	out := export(t, p, FormatOPNsense, obs)
	if n := strings.Count(out.Config, "<rule>"); n > maxExpandedRules {
		t.Errorf("%d rules", n)
	}
	if !strings.Contains(strings.Join(out.Warnings, " "), "DEFAULTS ARE MISSING") {
		t.Errorf("cut short without saying so: %v", out.Warnings)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestUnknownFormat(t *testing.T) {
	if _, err := ExportPolicy(testPolicy(), "iptables", testObserved(), ""); err == nil {
		t.Error("exported to nothing")
	}
}

// nft's own parser, where it's installed, is the check on what's generated.
func TestNftAcceptsIt(t *testing.T) {
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("no nft")
	}
	path := filepath.Join(t.TempDir(), "n.nft")
	if err := os.WriteFile(path, []byte(export(t, testPolicy(), FormatNftables, testObserved()).Config), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(nft, "-c", "-f", path).CombinedOutput(); err != nil {
		// Unprivileged, nft can't even open netlink: that's not about the file.
		if strings.Contains(string(out), "Operation not permitted") {
			t.Skip("nft needs CAP_NET_ADMIN to check")
		}
		t.Errorf("%v\n%s", err, out)
	}
}

func FuzzExport(f *testing.F) {
	f.Add("name", "lamp", "192.168.1.1", "api.example.com", "site:example.com", "443/tcp")
	f.Add("x\"; drop\n", "a'b", "not an address", "<x>", "*", "53")
	f.Add("a--b---c", "l", "10.0.0.1", "r", "site:never.example", "53")
	f.Fuzz(func(t *testing.T, name, label, ip, remote, to, port string) {
		p := &Policy{
			Zones: []Zone{{Name: "z", Devices: []string{"any"}}},
			Rules: []Rule{{Name: name, From: "zone:z", To: to, Ports: []string{port}, Action: "deny"}},
		}
		obs := Observed{
			Devices: []ObservedDevice{{ID: "device:aa:bb:cc:00:00:01", Label: label, IPs: []string{ip}}},
			Remotes: []ObservedRemote{{Name: remote, IP: ip}},
		}
		for _, format := range []string{FormatNftables, FormatOpenWrt, FormatOPNsense} {
			out, err := ExportPolicy(p, format, obs, "now")
			if err != nil {
				continue // it didn't validate
			}
			if len(safe(name)) > 0 && strings.ContainsAny(safe(name), "\"'\n<>;`$\\") {
				t.Fatalf("safe let through %q", safe(name))
			}
			if strings.Contains(out.Config, "\x00") {
				t.Fatal("a NUL reached the output")
			}
			if format == FormatOPNsense {
				var v struct{}
				if err := xml.Unmarshal([]byte(out.Config), &v); err != nil {
					t.Fatalf("%v\n%s", err, out.Config)
				}
			}
		}
	})
}

func TestExportVersion2Rules(t *testing.T) {
	p := &Policy{
		Version:  2,
		Zones:    []Zone{{Name: "iot", Devices: []string{"device:aa:bb:cc:00:00:01"}}},
		Defaults: Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"},
		RulesV2: []RuleV2{{
			Name: "cloud", Action: ActionAllow, Direction: "out",
			Local:  Selector{Type: "zone", Values: []string{"iot"}},
			Remote: Selector{Type: "domain", Values: []string{"example.com"}},
			Ports:  []string{"443"}, Protocol: "tcp",
		}},
	}
	out := export(t, p, FormatNftables, testObserved())
	if !strings.Contains(out.Config, "tcp dport 443 accept") {
		t.Fatalf("v2 rule not exported:\n%s", out.Config)
	}
	if !strings.Contains(strings.Join(out.Warnings, "\n"), "a firewall can't match names") {
		t.Fatalf("missing v2 warning: %v", out.Warnings)
	}
}

// A firewall takes the first match, a version 2 policy the highest-ranked
// rule: the narrow deny written after a broad allow must come out first, and
// a domain covers its subdomains as it does when evaluated.
func TestExportVersion2Precedence(t *testing.T) {
	p := &Policy{
		Version:  2,
		Zones:    []Zone{{Name: "iot", Devices: []string{"device:aa:bb:cc:00:00:01"}}},
		Defaults: Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"},
		RulesV2: []RuleV2{
			{Name: "web", Action: ActionAllow, Direction: "out", Local: Selector{Type: "zone", Values: []string{"iot"}}, Ports: []string{"443/tcp"}},
			{Name: "not that", Action: ActionDeny, Direction: "out", Local: Selector{Type: "zone", Values: []string{"iot"}}, Remote: Selector{Type: "domain", Values: []string{"example.com"}}},
		},
	}
	conn := Conn{Zone: "iot", Direction: "out", Name: "api.example.com", IP: "93.184.216.34", Port: "443", Proto: "tcp"}
	if d := p.Evaluate(conn); d.Action != ActionDeny {
		t.Fatalf("evaluated %+v", d)
	}
	out := export(t, p, FormatNftables, testObserved())
	deny := strings.Index(out.Config, "93.184.216.34")
	allow := strings.Index(out.Config, "tcp dport 443 accept")
	if deny < 0 || allow < 0 || deny > allow {
		t.Fatalf("the deny for api.example.com must precede the broad allow:\n%s", out.Config)
	}
}
