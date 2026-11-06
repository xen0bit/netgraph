package store

import (
	"context"
	"testing"
	"time"
)

func TestConnectionGroups(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	for _, group := range []string{"device", "app", "domain", "host", "destination", "remote"} {
		out, err := st.ConnectionGroups(ctx, win(0, time.Hour), group)
		if err != nil {
			t.Fatalf("%s: %v", group, err)
		}
		if len(out) == 0 {
			t.Fatalf("%s: no groups", group)
		}
		total := 0
		for _, g := range out {
			total += g.Connections
		}
		if total == 0 {
			t.Fatalf("%s: zero connections", group)
		}
	}
	if _, err := st.ConnectionGroups(ctx, win(0, time.Hour), "nonsense"); err == nil {
		t.Fatal("bad group accepted")
	}
}
