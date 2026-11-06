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

func TestWhatIfAccounting(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	p := &policy.Policy{
		Zones: []policy.Zone{{Name: "all", Devices: []string{"label:alice-*"}}},
		DNS:   policy.DNS{Block: []string{"*"}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	res, err := st.WhatIf(ctx, p, win(0, time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	s := res.Summary
	if s.Blocked+s.Unknown+s.Unchanged+s.OutOfScope+s.WouldAsk != s.Connections {
		t.Errorf("connections do not add up: %+v", s)
	}
	if s.Unknown == 0 || s.Lookups == 0 {
		t.Errorf("summary = %+v", s)
	}
	// Blocking a name is the point of a blocklist, not a broken dependency.
	for _, x := range res.Essential {
		if x.Kind == "dns" {
			t.Fatalf("a blocked name counted as essential: %+v", x)
		}
	}
	// A scope narrows what is evaluated.
	scoped, err := st.WhatIf(ctx, p, win(0, time.Hour), "device:3c:22:fb:01:02:03")
	if err != nil {
		t.Fatal(err)
	}
	if scoped.Summary.Connections == 0 || scoped.Summary.Connections >= s.Connections {
		t.Errorf("scope: %d of %d", scoped.Summary.Connections, s.Connections)
	}
	if _, err := st.WhatIf(ctx, p, win(0, time.Hour), "nonsense"); err == nil {
		t.Error("bad scope accepted")
	}
}
