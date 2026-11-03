package store

import (
	"context"
	"testing"
	"time"
)

func TestInsights(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	exp, err := st.Exposure(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if exp.FromMS == 0 || exp.Findings == nil {
		t.Fatalf("exposure = %+v", exp)
	}
	cov, err := st.Coverage(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(cov.Sensors) == 0 {
		t.Fatalf("coverage = %+v", cov)
	}
	air, err := st.Airspace(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if air.Networks == nil {
		t.Fatalf("airspace = %+v", air)
	}
	w, err := st.Weather(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Points) == 0 || w.StepMS == 0 {
		t.Fatalf("weather = %+v", w)
	}
}
