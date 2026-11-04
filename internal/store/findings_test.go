package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
)

func findingOf(t *testing.T, st *Store, kind string) model.Finding {
	t.Helper()
	l, err := st.Findings(context.Background(), model.FindingQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range l.Findings {
		if f.Kind == kind {
			return f
		}
	}
	t.Fatalf("no %s in %+v", kind, l.Findings)
	return model.Finding{}
}

func TestFindingsRemember(t *testing.T) {
	st := homeWeek(t).store(testutil.Base)
	ctx := context.Background()
	first, err := st.ScanFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 {
		t.Fatal("the week's anomalies made no findings")
	}
	for _, e := range first {
		if e.Type != FindingNew || e.Finding.ID == 0 {
			t.Errorf("event %+v", e)
		}
	}
	// The same events, read again: no news, and no extra occurrences.
	again, err := st.ScanFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Errorf("a rescan reported %d", len(again))
	}
	l, err := st.Findings(ctx, model.FindingQuery{Status: "open"})
	if err != nil {
		t.Fatal(err)
	}
	if l.Counts[model.FindingNew] != len(first) || l.ScannedMS == 0 {
		t.Errorf("counts %v, %d events, scanned %d", l.Counts, len(first), l.ScannedMS)
	}
	for _, f := range l.Findings {
		if f.Occurrences != 1 {
			t.Errorf("%s: %d occurrences after one event", f.Kind, f.Occurrences)
		}
	}
}

// A resolved finding must not reopen for the same event, only a later one.
func TestResolvedFindingReturnsOnlyForSomethingNew(t *testing.T) {
	st := homeWeek(t).store(testutil.Base)
	ctx := context.Background()
	if _, err := st.ScanFindings(ctx); err != nil {
		t.Fatal(err)
	}
	f := findingOf(t, st, model.AnomalyBeacon)
	if err := st.SetFindingStatus(ctx, f.ID, model.FindingResolved, "looked at it"); err != nil {
		t.Fatal(err)
	}
	if ev, err := st.ScanFindings(ctx); err != nil || len(ev) != 0 {
		t.Fatalf("a rescan reopened: %+v, %v", ev, err)
	}
	if got, _ := st.Finding(ctx, f.ID); got.Status != model.FindingResolved || got.Note != "looked at it" {
		t.Errorf("after a rescan: %+v", got)
	}
	// The same thing, happening later, is the same finding back again.
	a := f.Anomaly
	a.TS = f.LastSeen + 1000
	tx, err := st.w.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := upsertFinding(ctx, tx, a, st.cfg.Now())
	if err != nil || ev == nil || ev.Type != FindingRecurred {
		t.Fatalf("return: %+v, %v", ev, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, err := st.Finding(ctx, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.FindingNew || got.Recurrences != 1 || got.Occurrences != 2 || got.LastSeen != a.TS {
		t.Errorf("returned: %+v", got)
	}
	if got.Why == "" || got.Advice == "" || got.Usual == "" {
		t.Errorf("not explained: %+v", got)
	}
}

// "This is fine" stops it being reported, and can be undone by unmuting.
func TestFineStopsAFinding(t *testing.T) {
	st := homeWeek(t).store(testutil.Base)
	ctx := context.Background()
	if _, err := st.ScanFindings(ctx); err != nil {
		t.Fatal(err)
	}
	f := findingOf(t, st, model.AnomalyBeacon)
	if err := st.FindingFine(ctx, f.ID, "it's the thermostat"); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Finding(ctx, f.ID)
	if got.Status != model.FindingDismissed {
		t.Errorf("status %q", got.Status)
	}
	// A note changes the note, not the decision.
	if err := st.SetFindingStatus(ctx, f.ID, "", "still the thermostat"); err != nil {
		t.Fatal(err)
	}
	if got, _ = st.Finding(ctx, f.ID); got.Status != model.FindingDismissed || got.Note != "still the thermostat" {
		t.Errorf("after a note: %+v", got)
	}
	rep, err := st.Anomalies(ctx, window)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range rep.Anomalies {
		if findingKey(a) == findingKey(f.Anomaly) {
			t.Errorf("still reported: %+v", a)
		}
	}
	// Only this one: another finding on the same device still reports.
	mutes, err := st.AnomalyMutes(ctx, true)
	if err != nil || len(mutes) != 1 || mutes[0].Kind != f.Kind || mutes[0].Device != f.Device || mutes[0].Entity != f.Entity {
		t.Errorf("mutes: %+v, %v", mutes, err)
	}
}

func TestFindingsGoQuietThenResolve(t *testing.T) {
	st := homeWeek(t).store(testutil.Base)
	ctx := context.Background()
	if _, err := st.ScanFindings(ctx); err != nil {
		t.Fatal(err)
	}
	f := findingOf(t, st, model.AnomalyBeacon)
	st.cfg.Now = func() time.Time { return time.UnixMilli(f.LastSeen).Add(findingStale + 24*time.Hour) }
	if _, err := st.ScanFindings(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Finding(ctx, f.ID)
	if got.Status != model.FindingResolved || !got.AutoResolved {
		t.Errorf("after a quiet week: %+v", got)
	}
}

func TestFindingStatusRejects(t *testing.T) {
	st := homeWeek(t).store(testutil.Base)
	ctx := context.Background()
	if _, err := st.ScanFindings(ctx); err != nil {
		t.Fatal(err)
	}
	f := findingOf(t, st, model.AnomalyBeacon)
	if err := st.SetFindingStatus(ctx, f.ID, "dismissed", ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("dismissing without the mute: %v", err)
	}
	if err := st.SetFindingStatus(ctx, 99999, model.FindingSeen, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("no such finding: %v", err)
	}
	if _, err := st.Findings(ctx, model.FindingQuery{Status: "nonsense"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("a bad status: %v", err)
	}
	if err := st.MarkFindingsSeen(ctx); err != nil {
		t.Fatal(err)
	}
	if l, _ := st.Findings(ctx, model.FindingQuery{}); l.Counts[model.FindingNew] != 0 || l.Counts[model.FindingSeen] == 0 {
		t.Errorf("after marking seen: %v", l.Counts)
	}
}

// One device's findings close together are a story; a lone one isn't.
func TestFindingGroups(t *testing.T) {
	mk := func(id int64, dev string, at int64) model.Finding {
		return model.Finding{Anomaly: model.Anomaly{Device: dev, Severity: model.SeverityLow}, ID: id, FirstSeen: at, LastSeen: at}
	}
	hour := time.Hour.Milliseconds()
	got := groupFindings([]model.Finding{mk(1, "a", 0), mk(2, "a", hour/2), mk(3, "a", 10*hour), mk(4, "b", 0), mk(5, "", 0), mk(6, "", 0)})
	if len(got) != 1 || got[0].Device != "a" || len(got[0].IDs) != 2 {
		t.Errorf("groups: %+v", got)
	}
}

// db forget is a privacy control: findings copy names and evidence.
func TestForgetTakesFindings(t *testing.T) {
	st := homeWeek(t).store(testutil.Base)
	ctx := context.Background()
	if _, err := st.ScanFindings(ctx); err != nil {
		t.Fatal(err)
	}
	f := findingOf(t, st, model.AnomalyBeacon)
	mac := f.Device[len("device:"):]
	if _, err := st.ForgetDevice(ctx, mac); err != nil {
		t.Fatal(err)
	}
	if n := tableCount(t, st, `SELECT count(*) FROM findings WHERE device = ? OR instr(lower(evidence), ?) > 0 OR instr(lower(summary), ?) > 0`, f.Device, mac, mac); n != 0 {
		t.Errorf("%d findings still name it", n)
	}
	if n := tableCount(t, st, `SELECT count(*) FROM findings`); n == 0 {
		t.Error("forgetting one device took every finding")
	}
}
