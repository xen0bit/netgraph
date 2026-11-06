package store

import (
	"context"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
)

// A device whose lookups the sensor sees is flagged for a name it never
// looked up, once; a device whose lookups it never sees (DNS over HTTPS) is
// not flagged at all.
func TestNameMismatch(t *testing.T) {
	n := &anomalyNet{t: t}
	at := window.From.Add(10 * time.Minute)
	n.lookup(laptop, at, "seen.example.com", "NOERROR")
	n.flow(laptop, at.Add(time.Second), "seen.example.com", "203.0.113.10", 443, 100)
	n.flow(laptop, at.Add(2*time.Second), "hidden.example.com", "203.0.113.11", 443, 100)
	n.flow(laptop, at.Add(3*time.Second), "hidden.example.com", "203.0.113.11", 443, 100)
	n.flow(plug, at.Add(time.Second), "doh.example.com", "203.0.113.12", 443, 100)
	st := n.store(testutil.Base.Add(7 * 24 * time.Hour))
	rep, err := st.Anomalies(context.Background(), window)
	if err != nil {
		t.Fatal(err)
	}
	var got []model.Anomaly
	for _, a := range rep.Anomalies {
		if a.Kind == model.AnomalyNameMismatch {
			got = append(got, a)
		}
	}
	if len(got) != 1 || got[0].Entity != "domain:hidden.example.com" || got[0].Device != "device:"+laptop.mac || got[0].Severity != model.SeverityLow {
		t.Fatalf("name mismatches = %+v", got)
	}
}
