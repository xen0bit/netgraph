package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAskDeviceAndAnomalies(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	a, err := st.Ask(ctx, "what did alice-iphone do?", win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(a.Answer), "alice") || len(a.Claims) == 0 {
		t.Fatalf("answer = %+v", a)
	}
	for _, c := range a.Claims {
		if len(c.Evidence) == 0 {
			t.Fatalf("claim without evidence: %+v", c)
		}
	}
	b, err := st.Ask(ctx, "any anomalies?", win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(b.Answer), "anomal") {
		t.Fatalf("anomaly answer = %+v", b)
	}
}
