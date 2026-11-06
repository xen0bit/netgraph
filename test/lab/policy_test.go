//go:build lab

package lab

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/xen0bit/netgraph/internal/apiclient"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy"
)

// checkPolicy drives saved policies, blocklists, decisions and connection
// groups over the lab's real traffic.
func checkPolicy(t *testing.T, c *apiclient.Client, f model.Filter) {
	ctx := context.Background()
	laptop := model.EntityID(model.KindDevice, laptopMAC)
	p, err := c.SavePolicy(ctx, &policy.Policy{
		Version: 2, Name: "lab",
		Defaults: policy.Defaults{Egress: "allow", Ingress: "allow", IntraZone: "allow", DNS: "allow"},
		RulesV2: []policy.RuleV2{
			{Name: "ask about plain http", Action: policy.ActionAsk, Direction: "out",
				Local: policy.Selector{Type: "device", Values: []string{laptop}}, Remote: policy.Selector{Type: "host", Values: []string{"plain.lab.test"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ActivatePolicy(ctx, p.ID); err != nil {
		t.Fatal(err)
	}

	// A blocklist denies what the laptop reached out to...
	bl, err := c.SaveBlocklist(ctx, &model.Blocklist{Name: "lab list", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ImportBlocklist(ctx, bl.ID, "www.lab.test\n", "domains"); err != nil {
		t.Fatal(err)
	}
	blocked := func(pol *policy.Policy) bool {
		t.Helper()
		res, err := c.WhatIf(ctx, pol, f, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range append(res.Blocked, res.Essential...) {
			if imp.Destination == "www.lab.test" && imp.Rule == "blocklist" && imp.Device == laptop {
				return true
			}
		}
		return false
	}
	if !blocked(p) {
		t.Error("what-if: the blocklisted www.lab.test was not blocked")
	}
	// ...unless a person ranks an allow above it.
	exception := *p
	exception.RulesV2 = append(append([]policy.RuleV2(nil), p.RulesV2...), policy.RuleV2{
		Name: "www is fine", Action: policy.ActionAllow, Priority: policy.PriorityHigh,
		Remote: policy.Selector{Type: "host", Values: []string{"www.lab.test"}},
	})
	exception.ID = ""
	if blocked(&exception) {
		t.Error("what-if: a high allow rule did not make an exception to the blocklist")
	}

	// Decisions: one per connection that matched the ask rule, answered once.
	n, err := c.ScanDecisions(ctx, f, 2000)
	if err != nil || n == 0 {
		t.Fatalf("scan = %d, %v", n, err)
	}
	ds, err := c.Decisions(ctx, "open")
	if err != nil {
		t.Fatal(err)
	}
	var d *model.PolicyDecision
	for i := range ds {
		if ds[i].Remote == "plain.lab.test" && ds[i].Device == laptop {
			d = &ds[i]
		}
		if ds[i].Remote != "plain.lab.test" {
			t.Errorf("decision for a connection no ask rule covers: %+v", ds[i])
		}
	}
	if d == nil {
		t.Fatalf("no decision for plain.lab.test in %+v", ds)
	}
	answered, err := c.AnswerDecision(ctx, d.ID, "rule", "deny", "", "lab")
	if err != nil {
		t.Fatal(err)
	}
	if answered.Status != "rule-created" || answered.RuleID == "" {
		t.Fatalf("answered = %+v", answered)
	}
	got, err := c.Policy(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	last := got.RulesV2[len(got.RulesV2)-1]
	if last.ID != answered.RuleID || last.Action != policy.ActionDeny || last.Remote.Values[0] != "plain.lab.test" || last.Ports[0] != "80/tcp" {
		t.Errorf("rule from the decision = %+v", last)
	}
	if again, err := c.ScanDecisions(ctx, f, 2000); err != nil || again != 0 {
		t.Errorf("rescan created %d decisions, %v", again, err)
	}

	// Connection groups: by device, the laptop's connections fold into one
	// group holding the names it used.
	groups, err := c.ConnectionGroups(ctx, f, "device")
	if err != nil {
		t.Fatal(err)
	}
	var mine *model.ConnectionGroup
	for i := range groups {
		if groups[i].Key == laptop {
			mine = &groups[i]
		}
	}
	if mine == nil || mine.BytesIn == 0 || !slices.Contains(mine.Destinations, "hold.lab.test") || !slices.Contains(mine.Destinations, "plain.lab.test") {
		t.Errorf("laptop group = %+v (of %d groups)", mine, len(groups))
	}

	// The laptop looked up every name it used: none is a name mismatch.
	rep, err := c.Anomalies(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range rep.Anomalies {
		if a.Kind == model.AnomalyNameMismatch && a.Device == laptop && strings.HasSuffix(a.Entity, ".lab.test") {
			t.Errorf("false name mismatch: %+v", a)
		}
	}
}
