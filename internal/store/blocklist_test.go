package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/policy/blocklist"
)

func TestBlocklistStore(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	b, err := st.SaveBlocklist(ctx, &model.Blocklist{Name: "test", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if b.ID == 0 || b.AUID == "" {
		t.Fatalf("saved = %+v", b)
	}
	parsed, err := blocklist.Parse(strings.NewReader("0.0.0.0 ads.example\n1.2.3.0/24\n"), blocklist.FormatHosts)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceBlocklistEntries(ctx, b.ID, parsed); err != nil {
		t.Fatal(err)
	}
	m, err := st.BlocklistMatcher(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.MatchName("x.ads.example"); !ok {
		t.Fatal("domain not matched")
	}
	if _, ok := m.MatchIP("1.2.3.7"); !ok {
		t.Fatal("address not matched")
	}
	entries, err := st.BlocklistEntries(ctx, b.ID, true, 10, 0)
	if err != nil || len(entries) == 0 {
		t.Fatalf("entries = %+v, %v", entries, err)
	}
	if err := st.SetBlocklistEntry(ctx, b.ID, entries[0].ID, false); err != nil {
		t.Fatal(err)
	}
	m, err = st.BlocklistMatcher(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.MatchName("x.ads.example"); ok && entries[0].Kind == "domain" {
		t.Fatal("disabled entry still matched")
	}
}
