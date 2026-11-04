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

func TestAskIntentIsByWord(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	plan := func(q string) []string {
		t.Helper()
		a, err := st.Ask(ctx, q, win(0, time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		var tools []string
		for _, p := range a.Plan {
			tools = append(tools, p.Tool)
		}
		return tools
	}
	// "then" inside "authentication" is not a question about a moment, and
	// "diff" inside "different" counts only as the whole word.
	if p := strings.Join(plan("who used authentication"), " "); strings.Contains(p, "frame") {
		t.Errorf("substring matched an intent: %s", p)
	}
	if p := strings.Join(plan("what changed?"), " "); !strings.Contains(p, "diff") {
		t.Errorf("changed: %s", p)
	}
	if p := strings.Join(plan("what happened then?"), " "); !strings.Contains(p, "frame") {
		t.Errorf("moment: %s", p)
	}
	// A named device wins over the generic moment.
	if p := strings.Join(plan("what happened to alice-iphone?"), " "); !strings.Contains(p, "story") {
		t.Errorf("entity: %s", p)
	}
}

func TestAskIsHonest(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	a, err := st.Ask(ctx, "what did zzz-no-such-thing do?", win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Claims) != 0 || len(a.Gaps) == 0 || a.Confidence != "low" {
		t.Fatalf("no match = %+v", a)
	}
	// The window is what is answered; a time in the question is not read.
	a, err = st.Ask(ctx, "what did alice-iphone do yesterday?", win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Claims) == 0 || !strings.Contains(strings.Join(a.Gaps, " "), "selected window") {
		t.Fatalf("time word = %+v", a)
	}
	if len(a.Evidence) == 0 {
		t.Fatalf("answer lists no evidence: %+v", a)
	}
	// The same device, outside its window, has nothing to be sure of.
	a, err = st.Ask(ctx, "what did alice-iphone do?", win(-48*time.Hour, -47*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if a.Confidence == "high" {
		t.Fatalf("no activity, high confidence: %+v", a)
	}
}
