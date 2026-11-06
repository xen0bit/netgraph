package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/xen0bit/netgraph/internal/policy"
)

func TestBundleRoundTrip(t *testing.T) {
	src, err := Open(filepath.Join(t.TempDir(), "src.db"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	ctx := context.Background()
	if _, err := src.SavePolicy(ctx, &policy.Policy{
		Version: 2, Name: "home",
		Defaults: policy.Defaults{Egress: "deny", Ingress: "deny", IntraZone: "allow", DNS: "allow"},
		RulesV2:  []policy.RuleV2{{Name: "web", Action: policy.ActionAllow, Local: policy.Selector{Type: "any"}, Remote: policy.Selector{Type: "domain", Values: []string{"example.com"}}}},
	}); err != nil {
		t.Fatal(err)
	}
	b, err := src.ExportBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	dst, err := Open(filepath.Join(t.TempDir(), "dst.db"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	counts, err := dst.ImportBundle(ctx, b)
	if err != nil || counts["policies"] == 0 {
		t.Fatalf("import = %+v, %v", counts, err)
	}
	got, err := dst.Policies(ctx)
	if err != nil || len(got) != 1 || got[0].Name != "home" {
		t.Fatalf("policies = %+v, %v", got, err)
	}
}
