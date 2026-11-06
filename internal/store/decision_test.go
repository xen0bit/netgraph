package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"

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
	if _, err := st.AnswerDecision(ctx, list[0].ID, "allow", "", "alice", "once"); err != nil {
		t.Fatal(err)
	}
	d, err := st.Decision(ctx, list[0].ID)
	if err != nil || d.Status != DecisionAllowed || d.Unconfirmed || d.DecidedBy != "alice" {
		t.Fatalf("answered = %+v, %v", d, err)
	}
	// A second scan of the same window must not bring answered connections back.
	again, err := st.ScanDecisions(ctx, win(0, time.Hour), 1000)
	if err != nil || again != 0 {
		t.Fatalf("rescan created %d, %v", again, err)
	}
	// Forget takes the device's decisions with it.
	if d.Device == "" {
		t.Fatal("decision has no device")
	}
	mac := strings.TrimPrefix(d.Device, "device:")
	if _, err := st.ForgetDevice(ctx, mac); err != nil {
		t.Fatal(err)
	}
	all, err := st.Decisions(ctx, "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range all {
		if x.Device == d.Device {
			t.Fatalf("forget left decision %+v", x)
		}
	}
}

func TestDecisionRuleIsExact(t *testing.T) {
	r := DecisionRule(model.PolicyDecision{ID: 4, Device: "device:aa:bb:cc:dd:ee:ff", Remote: "203.0.113.9", Port: "443/tcp", Direction: "out"})
	if r.Remote.Type != "ip" || r.Local.Type != "device" || len(r.Ports) != 1 || r.Ports[0] != "443/tcp" || r.Direction != "out" {
		t.Fatalf("rule = %+v", r)
	}
	r = DecisionRule(model.PolicyDecision{Remote: "api.example.com", Port: "0/udp"})
	if r.Remote.Type != "host" || r.Local.Type != "any" || len(r.Ports) != 0 {
		t.Fatalf("rule = %+v", r)
	}
}
