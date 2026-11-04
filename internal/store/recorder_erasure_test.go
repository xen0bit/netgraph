package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
)

const aliceMAC = "3c:22:fb:01:02:03"

func tableCount(t *testing.T, st *Store, q string, args ...any) int {
	t.Helper()
	var n int
	if err := st.w.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// remember attaches a note, a bookmark and an incident to a device.
func remember(t *testing.T, st *Store, device string) *model.Incident {
	t.Helper()
	ctx := context.Background()
	at := testutil.Base.Add(time.Minute).UnixMilli()
	if _, err := st.CreateAnnotation(ctx, model.Annotation{TS: at, Entity: device, Text: "moved to the guest VLAN"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateBookmark(ctx, model.Bookmark{TS: at, Entity: device, Name: "before"}); err != nil {
		t.Fatal(err)
	}
	inc, err := st.CreateIncident(ctx, model.Anomaly{Kind: model.AnomalyNewDevice, TS: at, Device: device, Evidence: map[string]string{"k": "v"}}, "", time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateIncident(ctx, inc.ID, "", "", "", "looked at it", "test"); err != nil {
		t.Fatal(err)
	}
	return inc
}

// db forget is a privacy control: the recorder's copies count too.
func TestForgetErasesRecorderData(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	devID := model.EntityID(model.KindDevice, aliceMAC)
	// A MAC typed in capitals must still be found.
	remember(t, st, "device:"+strings.ToUpper(aliceMAC))
	if _, err := st.CreateAnnotation(ctx, model.Annotation{TS: testutil.Base.UnixMilli(), Text: "unplugged " + aliceMAC + " today"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAnnotation(ctx, model.Annotation{TS: testutil.Base.UnixMilli(), Text: "someone else"}); err != nil {
		t.Fatal(err)
	}
	onRail := func() int {
		return tableCount(t, st, `SELECT count(*) FROM timeline_events WHERE entity_key = ? OR instr(title, ?) > 0`, devID, aliceMAC)
	}
	if onRail() == 0 {
		t.Fatal("the device has no rail events to erase")
	}

	dry, err := st.ForgetDeviceWithOptions(ctx, aliceMAC, ForgetOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Timeline == 0 || dry.Notes != 3 || dry.Incidents != 1 {
		t.Fatalf("dry run = %+v", dry)
	}
	if onRail() == 0 || tableCount(t, st, `SELECT count(*) FROM incidents`) != 1 {
		t.Fatal("a dry run erased something")
	}

	if _, err := st.ForgetDevice(ctx, aliceMAC); err != nil {
		t.Fatal(err)
	}
	if n := onRail(); n != 0 {
		t.Errorf("%d rail events still name the device", n)
	}
	for _, q := range []string{
		`SELECT count(*) FROM bookmarks`,
		`SELECT count(*) FROM incidents`,
		`SELECT count(*) FROM incident_entities`,
		`SELECT count(*) FROM incident_notes`,
		`SELECT count(*) FROM incident_evidence`,
	} {
		if n := tableCount(t, st, q); n != 0 {
			t.Errorf("%s = %d", q, n)
		}
	}
	// A note about something else is not the device's.
	if n := tableCount(t, st, `SELECT count(*) FROM annotations`); n != 1 {
		t.Errorf("annotations left = %d, want the unrelated one", n)
	}
}

func TestPurgeErasesRecorderData(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	remember(t, st, model.EntityID(model.KindDevice, aliceMAC))
	r, err := st.PurgeBefore(ctx, testutil.Base.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if r.Timeline == 0 || r.Notes != 2 || r.Incidents != 1 {
		t.Fatalf("purge = %+v", r)
	}
	for _, table := range []string{"timeline_events", "annotations", "bookmarks", "incidents", "incident_entities", "incident_notes", "incident_evidence"} {
		if n := tableCount(t, st, `SELECT count(*) FROM `+table); n != 0 {
			t.Errorf("%s = %d", table, n)
		}
	}
}

// Retention ages the derived rail and leaves what a person wrote.
func TestRetentionKeepsNotesOnTheRail(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	remember(t, st, model.EntityID(model.KindDevice, aliceMAC))
	st.cfg.Now = func() time.Time { return testutil.Base.Add(90 * 24 * time.Hour) }
	r, err := st.Retain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.Timeline == 0 {
		t.Fatalf("retention = %+v", r)
	}
	page, err := st.Timeline(ctx, win(0, time.Hour), model.TimelineQuery{})
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, e := range page.Events {
		kinds[e.Kind]++
	}
	if kinds["annotation"] != 1 || kinds["bookmark"] != 1 || len(kinds) != 2 {
		t.Fatalf("rail after retention = %v", kinds)
	}
	if n := tableCount(t, st, `SELECT count(*) FROM incidents`); n != 1 {
		t.Errorf("incidents = %d", n)
	}
}

// The disk guard must be able to reclaim the rail, and only what is derived.
func TestEmergencyTrimReclaimsTheRail(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	remember(t, st, model.EntityID(model.KindDevice, aliceMAC))
	r, err := st.EmergencyTrim(ctx, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if r.Timeline == 0 {
		t.Fatalf("trim = %+v", r)
	}
	if n := tableCount(t, st, `SELECT count(*) FROM timeline_events WHERE kind IN ('annotation', 'bookmark')`); n != 2 {
		t.Errorf("memory rail events = %d", n)
	}
}

// A backfill over a live index adds nothing, and one over a dropped index
// rebuilds the same rail, entity filters and human memory included.
func TestBackfillMatchesIngest(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	remember(t, st, model.EntityID(model.KindDevice, aliceMAC))
	before := tableCount(t, st, `SELECT count(*) FROM timeline_events WHERE kind != 'sensor'`)
	if n, err := st.BackfillTimeline(ctx, testutil.Base.Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("backfill over a live index added %d: %v", n, err)
	}
	const rows = `SELECT kind, ref_table, ref_key, entity_id, entity_key, related_key, title FROM timeline_events WHERE kind != 'sensor' ORDER BY kind, ref_table, ref_key, entity_id`
	read := func() []string {
		r, err := st.w.QueryContext(ctx, rows)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		var out []string
		for r.Next() {
			var a, b, c, e, f, g string
			var d int64
			if err := r.Scan(&a, &b, &c, &d, &e, &f, &g); err != nil {
				t.Fatal(err)
			}
			// A rebuilt device_new takes the name the device has by now.
			if a == "device_new" {
				g = ""
			}
			out = append(out, strings.Join([]string{a, b, c, e, f, g}, "|"))
		}
		return out
	}
	want := read()
	if _, err := st.w.ExecContext(ctx, `DELETE FROM timeline_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.BackfillTimeline(ctx, testutil.Base.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	got := read()
	if len(got) != before {
		t.Errorf("rebuilt %d rows, had %d", len(got), before)
	}
	for i := range min(len(got), len(want)) {
		if got[i] != want[i] {
			t.Fatalf("row %d:\n got %s\nwant %s", i, got[i], want[i])
		}
	}
}

// Traffic passing through has no device: no event may claim the empty one.
func TestTimelineHasNoEmptyDevice(t *testing.T) {
	st, _, _ := homeStore(t)
	if n := tableCount(t, st, `SELECT count(*) FROM timeline_events WHERE entity_key = 'device:'`); n != 0 {
		t.Errorf("%d events name the empty device", n)
	}
}

func TestIncidentRejects(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	inc := remember(t, st, model.EntityID(model.KindDevice, aliceMAC))
	if _, err := st.UpdateIncident(ctx, inc.ID, "pending", "", "", "", ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad status = %v", err)
	}
	notes := tableCount(t, st, `SELECT count(*) FROM incident_notes`)
	if _, err := st.UpdateIncident(ctx, 999, "resolved", "", "", "orphan", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("update missing = %v", err)
	}
	if n := tableCount(t, st, `SELECT count(*) FROM incident_notes`); n != notes {
		t.Errorf("a note was added to a missing incident")
	}
	if err := st.DeleteIncident(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing = %v", err)
	}
	if err := st.PinEvidence(ctx, 999, "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("pin missing = %v", err)
	}
	if _, err := st.CreateIncident(ctx, model.Anomaly{}, "", time.Time{}, time.Time{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("no kind = %v", err)
	}
	a := model.Anomaly{Kind: "x", TS: 1000}
	if _, err := st.CreateIncident(ctx, a, "", time.UnixMilli(5000), time.UnixMilli(1000)); !errors.Is(err, ErrInvalid) {
		t.Errorf("inverted window = %v", err)
	}
	if _, err := st.CreateAnnotation(ctx, model.Annotation{Text: "x", Entity: "nonsense"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad entity = %v", err)
	}
	if _, err := st.CreateAnnotation(ctx, model.Annotation{Text: "x", Entity: "device:nope"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad device = %v", err)
	}
	if _, err := st.CreateAnnotation(ctx, model.Annotation{Text: strings.Repeat("x", maxNoteText+1)}); !errors.Is(err, ErrInvalid) {
		t.Errorf("long note = %v", err)
	}
}

// The CLI opens a database read-only by default: changing it is an error, not
// a nil dereference.
func TestMemoryOnReadOnlyStore(t *testing.T) {
	st := &Store{cfg: Config{Now: time.Now}}
	ctx := context.Background()
	if _, err := st.CreateAnnotation(ctx, model.Annotation{Text: "x"}); err == nil {
		t.Error("annotation accepted")
	}
	if _, err := st.CreateBookmark(ctx, model.Bookmark{Name: "x"}); err == nil {
		t.Error("bookmark accepted")
	}
	if _, err := st.CreateIncident(ctx, model.Anomaly{Kind: "x", TS: 1}, "", time.Time{}, time.Time{}); err == nil {
		t.Error("incident accepted")
	}
	if err := st.DeleteIncident(ctx, 1); err == nil {
		t.Error("delete accepted")
	}
	if err := st.DeleteAnnotation(ctx, 1); err == nil {
		t.Error("annotation delete accepted")
	}
}
