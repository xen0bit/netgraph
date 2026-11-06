package enforce

import (
	"context"
	"strings"
	"testing"

	"github.com/xen0bit/netgraph/internal/agent"
)

func TestNftablesApply(t *testing.T) {
	var calls []string
	n := &Nftables{Table: "netgraph_agent", Run: func(_ context.Context, args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		return nil
	}}
	actuals, err := n.Apply(context.Background(), []agent.Connection{
		{Key: "deny", RemoteIP: "203.0.113.9", Predicted: "deny"},
		{Key: "allow", RemoteIP: "198.51.100.7", Predicted: "allow"},
		{Key: "ask", RemoteIP: "192.0.2.1", Predicted: "ask"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(actuals) != 3 || actuals[0].Action != "deny" || actuals[1].Action != "none" || actuals[2].Action != "ask" {
		t.Fatalf("actuals = %+v", actuals)
	}
	if !strings.Contains(strings.Join(calls, "\n"), "daddr 203.0.113.9 drop") {
		t.Fatalf("no drop rule: %v", calls)
	}
}
