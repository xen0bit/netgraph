package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
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
	// A time it can't read says so, and answers the window it was given.
	a, err = st.Ask(ctx, "what did alice-iphone do next month?", win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Claims) == 0 || !strings.Contains(strings.Join(a.Gaps, " "), "selected window") || len(a.Evidence) == 0 {
		t.Fatalf("time word = %+v", a)
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

func TestAskTimes(t *testing.T) {
	loc := time.FixedZone("here", -5*3600)
	// A Wednesday, 16:30 here.
	now := time.Date(2026, 10, 28, 16, 30, 0, 0, loc)
	day := func(d, h, m int) time.Time { return time.Date(2026, 10, d, h, m, 0, 0, loc) }
	for _, c := range []struct {
		q        string
		from, to time.Time
		rest     string
	}{
		{"what did alice do yesterday", day(27, 0, 0), day(28, 0, 0), "what did alice do"},
		{"yesterday at 3pm what happened", day(27, 14, 30), day(27, 15, 30), "what happened"},
		{"what happened at 3pm yesterday", day(27, 14, 30), day(27, 15, 30), "what happened"},
		{"what happened at 15:00", day(28, 14, 30), day(28, 15, 30), "what happened"},
		{"what happened at 5pm", day(27, 16, 30), day(27, 17, 30), "what happened"},
		{"what happened at 9", day(28, 8, 30), day(28, 9, 30), "what happened"},
		{"who was on today", day(28, 0, 0), now, "who was on"},
		{"who was on this morning", day(28, 6, 0), day(28, 12, 0), "who was on"},
		{"who was on this afternoon", day(28, 12, 0), day(28, 18, 0).Add(-90 * time.Minute), "who was on"},
		{"who was on last night", day(27, 18, 0), day(28, 6, 0), "who was on"},
		{"busiest last week", now.Add(-7 * 24 * time.Hour), now, "busiest"},
		{"busiest in the last 3 hours", now.Add(-3 * time.Hour), now, "busiest in the"},
		{"busiest past two days", now.Add(-48 * time.Hour), now, "busiest"},
		{"what happened 2 hours ago", now.Add(-150 * time.Minute), now.Add(-90 * time.Minute), "what happened"},
		{"what happened on monday", day(26, 0, 0), day(27, 0, 0), "what happened"},
		{"what happened wednesday", day(21, 0, 0), day(22, 0, 0), "what happened"},
		{"tuesday at 9am", day(27, 8, 30), day(27, 9, 30), ""},
	} {
		w, rest := parseAskTime(questionWords(c.q), now, loc)
		if w == nil {
			t.Errorf("%q: no time", c.q)
			continue
		}
		if !w.from.Equal(c.from) || !w.to.Equal(c.to) || strings.Join(rest, " ") != c.rest {
			t.Errorf("%q: %s to %s, left %q; want %s to %s, left %q", c.q, w.from, w.to, strings.Join(rest, " "), c.from, c.to, c.rest)
		}
	}
	// Not times.
	for _, q := range []string{"what did alice do", "traffic on port 22", "who uses 192.168.1.1", "last", "25:00", "13pm", "what about 3"} {
		if w, _ := parseAskTime(questionWords(q), now, loc); w != nil {
			t.Errorf("%q read as %+v", q, w)
		}
	}
}

// A time in the question moves what's answered, and says so.
func TestAskReadsItsTime(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	a, err := st.Ask(ctx, "what did alice-iphone do yesterday?", win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// The capture is from today, so yesterday has nothing to be sure of.
	if a.Confidence == "high" || strings.Contains(strings.Join(a.Gaps, " "), "selected window") {
		t.Errorf("yesterday: %+v", a)
	}
	now := st.cfg.Now()
	if a.ToMS > now.UnixMilli() || a.FromMS >= a.ToMS || now.UnixMilli()-a.FromMS < 12*3600*1000 {
		t.Errorf("window %d-%d, now %d", a.FromMS, a.ToMS, now.UnixMilli())
	}
}

func TestAskByKindAndRanking(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	ask := func(q string) string {
		t.Helper()
		a, err := st.Ask(ctx, q, win(0, time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range a.Claims {
			if len(c.Evidence) == 0 {
				t.Errorf("%q: an uncited claim: %+v", q, c)
			}
		}
		return a.Answer + " | " + a.Focus
	}
	if got := ask("what did the printer do?"); !strings.Contains(got, "BRN001BA9") || !strings.Contains(got, "device:") {
		t.Errorf("the printer: %s", got)
	}
	if got := ask("who is the biggest uploader?"); !strings.Contains(got, "alice-iphone sent the most") {
		t.Errorf("uploader: %s", got)
	}
	if got := ask("who downloaded most?"); !strings.Contains(got, "alice-iphone received the most") {
		t.Errorf("downloader: %s", got)
	}
	if got := ask("what are the top sites?"); !strings.Contains(got, "example") {
		t.Errorf("sites: %s", got)
	}
	if got := ask("who's home?"); !strings.Contains(got, "seen") {
		t.Errorf("home: %s", got)
	}
	if got := ask("any new devices?"); !strings.Contains(got, "new device") {
		t.Errorf("new: %s", got)
	}
	if got := ask("why is the internet slow?"); !strings.Contains(got, "wrong") && !strings.Contains(got, "few connections") && !strings.Contains(got, "your own network") {
		t.Errorf("slow: %s", got)
	}
	// An owner a person set is a word Ask knows.
	alice := "Alice"
	if err := st.SetDeviceProfile(ctx, deviceByLabel(t, st, "alice-iphone").MAC, model.DeviceProfile{Owner: &alice}); err != nil {
		t.Fatal(err)
	}
	if got := ask("what did alice's devices do?"); !strings.Contains(got, "alice-iphone") {
		t.Errorf("owner: %s", got)
	}
}

func TestAskCompound(t *testing.T) {
	st, _, _ := homeStore(t)
	a, err := st.Ask(context.Background(), "who's home and any anomalies?", win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Answer, "seen") || !strings.Contains(a.Answer, "anomal") || len(a.Plan) < 3 {
		t.Errorf("compound: %+v", a)
	}
	// "and" in a name or a list isn't two questions.
	if got := splitCompound("what did salt and pepper do"); len(got) != 1 {
		t.Errorf("split: %q", got)
	}
	if got := splitCompound("what did alice do and what did bob do"); len(got) != 2 {
		t.Errorf("split: %q", got)
	}
}

// A question off the network or a person is only ever words: nothing here panics.
func FuzzAskParsing(f *testing.F) {
	for _, s := range []string{"yesterday at 3pm", "last 99999999999999 hours", "::: at", "at", "last", "on monday", "3:", ":30pm", "12am and and and"} {
		f.Add(s)
	}
	now := time.Date(2026, 10, 28, 16, 30, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, q string) {
		w, _ := parseAskTime(questionWords(q), now, time.UTC)
		if w != nil && w.to.After(now) {
			t.Errorf("%q: a window into the future: %+v", q, w)
		}
		_ = splitCompound(q)
		_ = isRanking(questionWords(q))
	})
}
