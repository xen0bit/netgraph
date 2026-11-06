package store

import (
	"context"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/policy"
)

func TestDecisionScanAndAnswer(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	p := &policy.Policy{
		Version: 2, Name: "ask all",
		Zones:    []policy.Zone{{Name: "all", Devices: []string{"any"}}},
		Defaults: policy.Defaults{Egress: "allow", Ingress: "allow", IntraZone: "allow", DNS: "allow"},
		RulesV2: []policy.RuleV2{{
			Name: "review", Action: policy.ActionAsk,
			Local: policy.Selector{Type: "any"}, Remote: policy.Selector{Type: "any"},
		}},
	}
	saved, err := st.SavePolicy(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ActivatePolicy(ctx, saved.ID); err != nil {
		t.Fatal(err)
	}
	n, err := st.ScanDecisions(ctx, win(0, time.Hour), 1000)
	if err != nil || n == 0 {
		t.Fatalf("scan = %d, %v", n, err)
	}
	list, err := st.Decisions(ctx, DecisionOpen, 100)
	if err != nil || len(list) == 0 {
		t.Fatalf("decisions = %+v, %v", list, err)
	}
	if err := st.DecideDecision(ctx, list[0].ID, DecisionAllowed, "alice", "once"); err != nil {
		t.Fatal(err)
	}
	d, err := st.Decision(ctx, list[0].ID)
	if err != nil || d.Status != DecisionAllowed || d.Unconfirmed {
		t.Fatalf("answered = %+v, %v", d, err)
	}
}
