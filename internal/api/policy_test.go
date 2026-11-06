package api

import (
	"context"
	"testing"

	"github.com/xen0bit/netgraph/internal/apiclient"
	"github.com/xen0bit/netgraph/internal/policy"
)

func TestPolicyAPI(t *testing.T) {
	srv, _ := serve(t, nil)
	c := apiclient.NewClient(srv.URL, "rd-tok")
	ctx := context.Background()
	p := &policy.Policy{
		Version: 2, Name: "api policy",
		Zones:    []policy.Zone{{Name: "lan", Devices: []string{"any"}}},
		Defaults: policy.Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"},
		RulesV2: []policy.RuleV2{{
			Name: "allow web", Action: policy.ActionAllow, Direction: "out",
			Local:  policy.Selector{Type: "zone", Values: []string{"lan"}},
			Remote: policy.Selector{Type: "domain", Values: []string{"example.com"}},
			Ports:  []string{"443/tcp"},
		}},
	}
	saved, err := c.SavePolicy(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if saved.ID == "" || len(saved.RulesV2) != 1 {
		t.Fatalf("saved = %+v", saved)
	}
	list, err := c.Policies(ctx)
	if err != nil || len(list) != 1 || list[0].ID != saved.ID || list[0].Rules != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if err := c.ActivatePolicy(ctx, saved.ID); err != nil {
		t.Fatal(err)
	}
	active, err := c.ActivePolicy(ctx)
	if err != nil || active == nil || active.ID != saved.ID {
		t.Fatalf("active = %+v, %v", active, err)
	}
	ex, err := c.ExplainPolicy(ctx, active, policy.Conn{
		Zone: "lan", Direction: "out", Name: "www.example.com", IP: "203.0.113.9", Port: "443", Proto: "tcp",
	})
	if err != nil || ex.Decision.Action != policy.ActionAllow || ex.Decision.Rule != "allow web" {
		t.Fatalf("explain = %+v, %v", ex, err)
	}
	if err := c.DeletePolicy(ctx, saved.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Policies(ctx); err != nil {
		t.Fatal(err)
	}
}
