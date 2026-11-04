package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestIncidentLifecycleAndAutopsy(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	rep, err := st.Anomalies(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Anomalies) == 0 {
		t.Skip("lab capture produced no anomaly")
	}
	a := rep.Anomalies[0]
	inc, err := st.CreateIncident(ctx, a, "test incident", time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if inc.ID == 0 || inc.Status != "open" {
		t.Fatalf("incident = %+v", inc)
	}
	list, err := st.Incidents(ctx, "open", 10)
	if err != nil || len(list) == 0 {
		t.Fatalf("list = %+v %v", list, err)
	}
	if _, err := st.UpdateIncident(ctx, inc.ID, "resolved", "", "", "handled", "test"); err != nil {
		t.Fatal(err)
	}
	d, err := st.IncidentDetail(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "resolved" || len(d.Notes) != 1 {
		t.Fatalf("detail = %+v", d)
	}
	aut, err := st.IncidentAutopsy(ctx, inc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if aut.Incident != inc.ID || len(aut.Scenes) == 0 {
		t.Fatalf("autopsy = %+v", aut)
	}
	if err := st.PinEvidence(ctx, inc.ID, "timeline:1"); err != nil {
		t.Fatal(err)
	}
	bundle, err := st.ExportIncident(ctx, inc.ID)
	if err != nil || !strings.Contains(string(bundle), "netgraph.incident.v1") {
		t.Fatalf("bundle = %.120s %v", bundle, err)
	}
	if err := st.DeleteIncident(ctx, inc.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Incident(ctx, inc.ID); err == nil {
		t.Fatal("deleted incident still exists")
	}
}
