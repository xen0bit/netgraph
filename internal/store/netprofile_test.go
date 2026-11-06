package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/xen0bit/netgraph/internal/model"
)

func TestProfileTrigger(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	home, err := st.SaveProfile(ctx, &model.Profile{Name: "home", Mode: "alert", IsDefault: true})
	if err != nil {
		t.Fatal(err)
	}
	cafe, err := st.SaveProfile(ctx, &model.Profile{Name: "cafe", Mode: "silent-deny"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveNetworkTrigger(ctx, &model.NetworkTrigger{
		ProfileID: cafe.ID, Signature: "*", Action: "activate", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	p, err := st.EvaluateProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil || p.ID != cafe.ID || !p.Active {
		t.Fatalf("evaluated = %+v", p)
	}
	active, err := st.ActiveProfile(ctx)
	if err != nil || active == nil || active.Name != "cafe" {
		t.Fatalf("active = %+v, %v", active, err)
	}
	if home.ID == cafe.ID {
		t.Fatal("profiles share an ID")
	}
	nc, err := st.NetworkContext(ctx)
	if err != nil || nc == nil || nc.Signature == "" {
		t.Fatalf("network context = %+v, %v", nc, err)
	}
}
