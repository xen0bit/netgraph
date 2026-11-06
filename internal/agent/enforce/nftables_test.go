package enforce

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/xen0bit/netgraph/internal/agent"
)

func TestNftablesDropsOnlyExplicitHostWideDenies(t *testing.T) {
	var scripts []string
	n := &Nftables{Table: "netgraph_agent", Protect: []netip.Addr{netip.MustParseAddr("192.0.2.10")},
		Run: func(_ context.Context, script string) error { scripts = append(scripts, script); return nil }}
	conns := []agent.Connection{
		{Key: "deny", Proto: "tcp6", RemoteIP: "2001:db8::9", RemotePort: 443, Predicted: "deny", Scope: agent.ScopeHost},
		{Key: "default", RemoteIP: "203.0.113.1", Predicted: "deny", Scope: agent.ScopeDefault},
		{Key: "app", RemoteIP: "203.0.113.2", Predicted: "deny", Scope: agent.ScopeProcess},
		{Key: "server", RemoteIP: "192.0.2.10", Predicted: "deny", Scope: agent.ScopeHost},
		{Key: "allow", RemoteIP: "198.51.100.7", Predicted: "allow", Scope: agent.ScopeHost},
		{Key: "ask", RemoteIP: "192.0.2.1", Predicted: "ask", Scope: agent.ScopeHost},
	}
	actuals, err := n.Apply(context.Background(), conns)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"deny": "deny", "default": "none", "app": "none", "server": "none", "allow": "none", "ask": "none"}
	for _, a := range actuals {
		if want[a.Key] != a.Action {
			t.Errorf("%s: %+v", a.Key, a)
		}
	}
	if len(scripts) != 1 {
		t.Fatalf("scripts = %q", scripts)
	}
	s := scripts[0]
	if !strings.Contains(s, "ip6 daddr 2001:db8::9 tcp dport 443 drop") || strings.Count(s, "drop") != 1 {
		t.Fatalf("script:\n%s", s)
	}
	if !strings.HasPrefix(s, "table inet netgraph_agent {}\ndelete table inet netgraph_agent\n") {
		t.Fatalf("the table isn't replaced whole:\n%s", s)
	}
	// The same predictions change nothing; a policy that stops denying empties the table.
	if _, err := n.Apply(context.Background(), conns); err != nil || len(scripts) != 1 {
		t.Fatalf("reapplied: %d scripts, %v", len(scripts), err)
	}
	conns[0].Predicted = "allow"
	if _, err := n.Apply(context.Background(), conns); err != nil || len(scripts) != 2 || strings.Contains(scripts[1], "drop") {
		t.Fatalf("after the deny went: %q, %v", scripts, err)
	}
	if err := n.Close(); err != nil || !strings.Contains(scripts[len(scripts)-1], "delete table inet netgraph_agent") {
		t.Fatalf("close: %v %q", err, scripts)
	}

	dry := &Nftables{Table: "netgraph_agent", DryRun: true, Run: func(context.Context, string) error {
		t.Fatal("dry run ran nft")
		return nil
	}}
	got, err := dry.Apply(context.Background(), conns[1:2])
	if err != nil || got[0].Action != "none" {
		t.Fatalf("dry run = %+v, %v", got, err)
	}
	if _, err := NewNftables("x; flush ruleset"); err == nil {
		t.Fatal("a table name that isn't one was accepted")
	}
}
