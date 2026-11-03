package store

import (
	"context"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/policy"
)

func TestWhatIfAllowAndDeny(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	allow := &policy.Policy{
		Version: 1, Zones: []policy.Zone{{Name: "all", Devices: []string{"any"}}},
		Defaults: policy.Defaults{Egress: "allow", Ingress: "allow", IntraZone: "allow", DNS: "allow"},
	}
	allowRes, err := st.WhatIf(ctx, allow, win(0, time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if allowRes.Summary.Blocked != 0 || allowRes.Summary.Connections == 0 {
		t.Fatalf("allow result = %+v", allowRes.Summary)
	}
	deny := &policy.Policy{
		Version: 1, Zones: []policy.Zone{{Name: "all", Devices: []string{"any"}}},
		Defaults: policy.Defaults{Egress: "deny", Ingress: "deny", IntraZone: "deny", DNS: "deny"},
	}
	denyRes, err := st.WhatIf(ctx, deny, win(0, time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if denyRes.Summary.Blocked == 0 || denyRes.Summary.Unchanged != 0 {
		t.Fatalf("deny result = %+v", denyRes.Summary)
	}
	if len(denyRes.ByDevice) == 0 || len(denyRes.ByDestination) == 0 {
		t.Fatalf("missing groups: %+v", denyRes)
	}
}
