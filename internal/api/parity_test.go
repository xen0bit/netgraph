package api

import (
	"context"
	"testing"

	"github.com/xen0bit/netgraph/internal/apiclient"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy"
)

func TestParitySurfaces(t *testing.T) {
	srv, _ := serve(t, nil)
	c := apiclient.NewClient(srv.URL, "rd-tok")
	ctx := context.Background()

	bl, err := c.SaveBlocklist(ctx, &model.Blocklist{Name: "test", Format: "hosts", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ImportBlocklist(ctx, bl.ID, "0.0.0.0 ads.example\n", "hosts"); err != nil {
		t.Fatal(err)
	}
	entries, err := c.BlocklistEntries(ctx, bl.ID, true)
	if err != nil || len(entries) == 0 {
		t.Fatalf("entries = %+v, %v", entries, err)
	}

	prof, err := c.SaveProfile(ctx, &model.Profile{Name: "home", Mode: "alert", IsDefault: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SaveNetworkTrigger(ctx, &model.NetworkTrigger{ProfileID: prof.ID, Signature: "*", Action: "activate", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if got, err := c.EvaluateProfile(ctx); err != nil || got == nil || got.ID != prof.ID {
		t.Fatalf("profile = %+v, %v", got, err)
	}

	pol, err := c.SavePolicy(ctx, &policy.Policy{
		Version: 2, Name: "ask all",
		Zones:    []policy.Zone{{Name: "all", Devices: []string{"any"}}},
		Defaults: policy.Defaults{Egress: "allow", Ingress: "allow", IntraZone: "allow", DNS: "allow"},
		RulesV2:  []policy.RuleV2{{Name: "review", Action: policy.ActionAsk, Local: policy.Selector{Type: "any"}, Remote: policy.Selector{Type: "any"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ActivatePolicy(ctx, pol.ID); err != nil {
		t.Fatal(err)
	}
	n, err := c.ScanDecisions(ctx, window, 100)
	if err != nil || n == 0 {
		t.Fatalf("scan = %d, %v", n, err)
	}
	ds, err := c.Decisions(ctx, "open")
	if err != nil || len(ds) == 0 {
		t.Fatalf("decisions = %+v, %v", ds, err)
	}
	if err := c.DecideDecision(ctx, ds[0].ID, "allow", "test", ""); err != nil {
		t.Fatal(err)
	}
}
