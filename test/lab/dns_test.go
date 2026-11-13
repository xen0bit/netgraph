//go:build lab

package lab

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/apiclient"
	"github.com/xen0bit/netgraph/internal/model"
)

// checkDNSServer asks netgraph's own DNS server (NETGRAPH_DNS_LISTEN in
// compose.yml, forwarding to the router's dnsmasq) from the laptop: names are
// answered, blocked ones refused with 0.0.0.0, a device's own allow beats a
// block for everyone, a CNAME to a blocked name is refused, and every lookup
// is recorded with what blocked it.
func checkDNSServer(t *testing.T, c *apiclient.Client, f model.Filter) {
	ctx := context.Background()
	st, err := c.DNSServer(ctx)
	if err != nil || !st.Enabled || len(st.Upstreams) != 1 || st.Upstreams[0].Name != "udp://10.77.0.10:53" {
		t.Fatalf("status = %+v, %v", st, err)
	}
	dig := func(name string) string {
		t.Helper()
		return strings.TrimSpace(compose(t, "exec", "-T", "laptop", "dig", "+short", "+tries=1", "+time=3", "@10.77.0.20", "-p", "5353", name, "A"))
	}
	if got := dig("hold.lab.test"); got != "198.18.0.30" {
		t.Fatalf("hold.lab.test answered %q", got)
	}
	// checkPolicy put www.lab.test on a blocklist: the server refuses it.
	if got := dig("www.lab.test"); got != "0.0.0.0" {
		t.Errorf("www.lab.test, on the lab's blocklist, answered %q", got)
	}
	for _, r := range []model.DNSRule{
		{Action: model.DNSBlock, Pattern: "plain.lab.test"},
		{Action: model.DNSBlock, Pattern: "quic.lab.test"},
		{Scope: model.DNSScopeDevice, ScopeValue: laptopMAC, Action: model.DNSAllow, Pattern: "quic.lab.test"},
	} {
		if _, err := c.SaveDNSRule(ctx, &r); err != nil {
			t.Fatal(err)
		}
	}
	// A change through the API is read at once; give it a moment.
	waitFor(t, "the DNS rules to apply", 15*time.Second, func() bool { return dig("plain.lab.test") == "0.0.0.0" })
	if got := dig("quic.lab.test"); got != "198.18.0.30" {
		t.Errorf("quic.lab.test, allowed for the laptop, answered %q", got)
	}
	if got := dig("alias.lab.test"); got != "0.0.0.0" { // a CNAME to www.lab.test
		t.Errorf("alias.lab.test, a CNAME to a blocked name, answered %q", got)
	}
	var blocked model.DNSQuery
	waitFor(t, "the refused lookup to be recorded", 15*time.Second, func() bool {
		qs, err := c.DNS(ctx, model.Filter{From: f.From, To: time.Now().Add(time.Minute), Domain: "plain.lab.test"})
		if err != nil {
			return false
		}
		for _, q := range qs {
			if q.RCode == "BLOCKED" {
				blocked = q
				return true
			}
		}
		return false
	})
	if !strings.HasPrefix(blocked.BlockedBy, "rule:") || blocked.Device != model.EntityID(model.KindDevice, laptopMAC) || blocked.Server != "10.77.0.20" {
		t.Errorf("recorded as %+v", blocked)
	}
	qs, err := c.DNS(ctx, model.Filter{From: f.From, To: time.Now().Add(time.Minute), Domain: "www.lab.test"})
	listed := false
	for _, q := range qs {
		listed = listed || q.BlockedBy == "list:lab list"
	}
	if err != nil || !listed {
		t.Errorf("www.lab.test not recorded as refused by the lab list: %+v, %v", qs, err)
	}
	stats, err := c.DNSStats(ctx, model.Filter{From: f.From, To: time.Now().Add(time.Minute)})
	if err != nil || stats.Blocked < 2 {
		t.Errorf("stats = %+v, %v", stats, err)
	}
}
