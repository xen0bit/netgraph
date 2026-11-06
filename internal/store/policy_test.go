package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/xen0bit/netgraph/internal/policy"
)

func TestPolicyCRUDAndActive(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if p, err := st.ActivePolicy(ctx); err != nil || p != nil {
		t.Fatalf("active before save = %+v, %v", p, err)
	}
	p := &policy.Policy{
		Version: 2, Name: "home",
		Zones:    []policy.Zone{{Name: "iot", Devices: []string{"role:camera"}}},
		Defaults: policy.Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"},
		DNS:      policy.DNS{Block: []string{"ads.example"}, Allow: []string{}},
		RulesV2: []policy.RuleV2{{
			Name: "https", Action: policy.ActionAllow, Direction: "out",
			Local:  policy.Selector{Type: "zone", Values: []string{"iot"}},
			Remote: policy.Selector{Type: "domain", Values: []string{"vendor.example"}},
			Ports:  []string{"443/tcp"}, Protocol: "tcp",
		}},
	}
	saved, err := st.SavePolicy(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if saved.ID == "" || saved.RulesV2[0].ID == "" {
		t.Fatalf("generated IDs missing: %+v", saved)
	}
	list, err := st.Policies(ctx)
	if err != nil || len(list) != 1 || list[0].Rules != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if err := st.ActivatePolicy(ctx, saved.ID); err != nil {
		t.Fatal(err)
	}
	active, err := st.ActivePolicy(ctx)
	if err != nil || active == nil || active.ID != saved.ID || !active.Active {
		t.Fatalf("active = %+v, %v", active, err)
	}
	d := active.Evaluate(policy.Conn{Zone: "iot", Direction: "out", Name: "api.vendor.example", Port: "443", Proto: "tcp"})
	if d.Action != policy.ActionAllow || d.Rule != "https" {
		t.Fatalf("decision = %+v", d)
	}
	// An update keeps the created time and replaces the rules.
	saved.Name = "home v2"
	saved.RulesV2 = append(saved.RulesV2, policy.RuleV2{
		Name: "deny ads", Action: policy.ActionDeny,
		Local: policy.Selector{Type: "any"}, Remote: policy.Selector{Type: "domain", Values: []string{"ads.example"}},
	})
	updated, err := st.SavePolicy(ctx, saved)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Created != saved.Created || len(updated.RulesV2) != 2 {
		t.Fatalf("updated = %+v", updated)
	}
	if err := st.DeletePolicy(ctx, saved.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Policy(ctx, saved.ID); err == nil {
		t.Fatal("deleted policy still loads")
	}
}
