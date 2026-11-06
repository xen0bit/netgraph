package store

import (
	"context"
	"errors"
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
	if _, ok := m.MatchName("ads.example"); !ok {
		t.Fatal("host not matched")
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
	if entries[0].Kind != "host" {
		t.Fatalf("first entry = %+v", entries[0])
	}
	if _, ok := m.MatchName("ads.example"); ok {
		t.Fatal("disabled entry still matched")
	}
	// Renaming a list keeps what the server knows about it.
	renamed, err := st.SaveBlocklist(ctx, &model.Blocklist{ID: b.ID, Name: "renamed", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if renamed.ID != b.ID || renamed.EntryCount != 2 || renamed.LastSuccess == 0 || renamed.Created != b.Created {
		t.Fatalf("rename lost state: %+v", renamed)
	}
	if _, err := st.SaveBlocklist(ctx, &model.Blocklist{ID: 999, Name: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("save to a missing ID = %v", err)
	}
	if err := st.ReplaceBlocklistEntries(ctx, 999, parsed); !errors.Is(err, ErrNotFound) {
		t.Fatalf("import to a missing list = %v", err)
	}
	if _, err := st.SaveBlocklist(ctx, &model.Blocklist{Name: "x", URL: "file:///etc/passwd"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("file URL = %v", err)
	}
	// A backup carries the disabled entry, and restoring it keeps it off.
	bundle, err := st.ExportBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st2, err := Open(filepath.Join(t.TempDir(), "ng2.db"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if _, err := st2.ImportBundle(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	m2, err := st2.BlocklistMatcher(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m2.MatchName("ads.example"); ok {
		t.Fatal("restore re-enabled a disabled entry")
	}
	if _, ok := m2.MatchIP("1.2.3.7"); !ok {
		t.Fatal("restore lost an entry")
	}
}
