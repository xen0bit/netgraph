package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

func TestAudit(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	long := strings.Repeat("x", 5000)
	for _, a := range []string{"first", "second"} {
		if err := st.AddAudit(ctx, model.AuditEntry{Actor: "alice", Role: "admin", Action: a, Target: long}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.Audit(ctx, 0)
	if err != nil || len(got) != 2 || got[0].Action != "second" || len(got[0].Target) != maxAuditField || got[0].TS == 0 {
		t.Fatalf("%+v, %v", got, err)
	}
	if got, _ := st.Audit(ctx, 1); len(got) != 1 {
		t.Errorf("limit: %d", len(got))
	}
}

// db forget and db purge take the record of what was done to a device.
func TestAuditIsErased(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	mac := deviceByLabel(t, st, "alice-iphone").MAC
	for _, target := range []string{mac, "something else"} {
		if err := st.AddAudit(ctx, model.AuditEntry{Actor: "a", Role: "admin", Action: "x", Target: target}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.ForgetDevice(ctx, mac); err != nil {
		t.Fatal(err)
	}
	if n := tableCount(t, st, `SELECT count(*) FROM audit_log WHERE instr(lower(target), ?) > 0`, mac); n != 0 {
		t.Errorf("%d entries still name it", n)
	}
	if n := tableCount(t, st, `SELECT count(*) FROM audit_log`); n != 1 {
		t.Errorf("%d entries left", n)
	}
	if _, err := st.PurgeBefore(ctx, st.cfg.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := tableCount(t, st, `SELECT count(*) FROM audit_log`); n != 0 {
		t.Errorf("a purge left %d", n)
	}
}
