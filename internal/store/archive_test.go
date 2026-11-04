package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/archive"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

const archMAC = "3c:22:fb:01:02:03"

// archStore is the home scenario, with its clock far enough on that everything has expired.
func archStore(t *testing.T, raw bool) (*Store, string) {
	t.Helper()
	st, _, _ := homeStore(t)
	dir := filepath.Join(t.TempDir(), "archive")
	st.cfg.ArchiveDir, st.cfg.ArchiveRaw = dir, raw
	if err := st.recordArchiveDir(context.Background()); err != nil {
		t.Fatal(err)
	}
	st.cfg.Now = func() time.Time { return testutil.Base.Add(400 * 24 * time.Hour) }
	return st, dir
}

func archiveRows(t *testing.T, dir, table string) []map[string]any {
	t.Helper()
	var out []map[string]any
	if err := (archive.Dir{Path: dir}).Read(archive.Query{Table: table}, func(line string) error {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return err
		}
		out = append(out, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func countRows(t *testing.T, st *Store, table string) int {
	t.Helper()
	var n int
	if err := st.r.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRetentionArchivesBeforeDeleting(t *testing.T) {
	st, dir := archStore(t, true)
	ctx := context.Background()
	want := map[string]int{}
	for _, table := range []string{"traffic_hourly", "dns_hourly", "connections", "dns"} {
		want[table] = countRows(t, st, table)
		if want[table] == 0 {
			t.Fatalf("no %s to test with", table)
		}
	}
	if _, err := st.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	for table, n := range want {
		if got := countRows(t, st, table); got != 0 {
			t.Errorf("%s: %d left in the database", table, got)
		}
		rows := archiveRows(t, dir, table)
		if len(rows) != n {
			t.Errorf("%s: %d archived of %d", table, len(rows), n)
		}
	}
	// A row stands alone: it says whose it is, when, and nothing that needs the database.
	found := false
	for _, r := range archiveRows(t, dir, "traffic_hourly") {
		if _, ok := r[archive.TimeKey].(float64); !ok {
			t.Fatalf("no time: %+v", r)
		}
		if _, ok := r["client_device"]; ok {
			t.Fatalf("a database id got out: %+v", r)
		}
		if r[archive.DeviceKey] == archMAC {
			found = true
		}
	}
	if !found {
		t.Error("no row says it's the device's")
	}
	// Doing it again finds nothing more, and changes nothing.
	if _, err := st.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	for table, n := range want {
		if rows := archiveRows(t, dir, table); len(rows) != n {
			t.Errorf("%s: %d after a second pass, was %d", table, len(rows), n)
		}
	}
}

// A one-off `db retain` from the command line carries on what the server set up, rather than
// deleting what it would have kept.
func TestRetainFromTheCommandLineKeepsArchiving(t *testing.T) {
	st, dir := archStore(t, true)
	ctx := context.Background()
	before := countRows(t, st, "connections")
	st.cfg.ArchiveDir, st.cfg.ArchiveRaw = "", false
	if err := st.UseRecordedArchive(ctx); err != nil {
		t.Fatal(err)
	}
	if st.cfg.ArchiveDir == "" || !st.cfg.ArchiveRaw {
		t.Fatalf("%+v", st.cfg.ArchiveDir)
	}
	if _, err := st.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	if got := archiveRows(t, dir, "connections"); len(got) != before {
		t.Errorf("%d of %d kept", len(got), before)
	}
}

func TestRollupsOnlyByDefault(t *testing.T) {
	st, dir := archStore(t, false)
	if _, err := st.Retain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rows := archiveRows(t, dir, "traffic_hourly"); len(rows) == 0 {
		t.Error("rollups weren't archived")
	}
	if rows := archiveRows(t, dir, "connections"); len(rows) != 0 {
		t.Errorf("raw rows archived without asking: %d", len(rows))
	}
	if got := countRows(t, st, "connections"); got != 0 {
		t.Errorf("raw retention stopped working: %d", got)
	}
}

// Whatever's wrong with the archive, nothing is deleted that hasn't been kept.
func TestArchiveFailureKeepsTheData(t *testing.T) {
	st, dir := archStore(t, true)
	if err := os.WriteFile(dir, []byte("a file where the directory should go"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := countRows(t, st, "traffic_hourly")
	beforeConn := countRows(t, st, "connections")
	if _, err := st.Retain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, st, "traffic_hourly"); got != before {
		t.Errorf("rollups deleted without being archived: %d of %d left", got, before)
	}
	if got := countRows(t, st, "connections"); got != beforeConn {
		t.Errorf("connections deleted without being archived: %d of %d left", got, beforeConn)
	}
}

// A day isn't archived until all of it is past, so it never needs archiving twice.
func TestDayIsArchivedWhole(t *testing.T) {
	st, dir := archStore(t, false)
	ctx := context.Background()
	// Now is partway through the day after the cutoff's: rows in the cutoff's own day stay.
	var newest int64
	if err := st.r.QueryRow(`SELECT max(bucket) FROM traffic_hourly`).Scan(&newest); err != nil {
		t.Fatal(err)
	}
	st.cfg.Now = func() time.Time { return time.UnixMilli(newest).Add(st.cfg.RollupRetention) }
	before := countRows(t, st, "traffic_hourly")
	if _, err := st.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	if rows := archiveRows(t, dir, "traffic_hourly"); len(rows) != 0 {
		t.Errorf("archived part of a day: %d rows", len(rows))
	}
	if got := countRows(t, st, "traffic_hourly"); got != before {
		t.Errorf("deleted part of a day: %d of %d", got, before)
	}
}

func TestForgetReachesTheArchive(t *testing.T) {
	st, dir := archStore(t, true)
	ctx := context.Background()
	if _, err := st.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	has := func() int {
		n := 0
		for _, table := range []string{"traffic_hourly", "dns_hourly", "connections", "dns"} {
			for _, r := range archiveRows(t, dir, table) {
				if r[archive.DeviceKey] == archMAC || r[archive.MACKey] == archMAC {
					n++
				}
			}
		}
		return n
	}
	before := has()
	if before == 0 {
		t.Fatal("nothing of the device's in the archive")
	}
	dry, err := st.ForgetDeviceWithOptions(ctx, archMAC, ForgetOptions{DryRun: true})
	if err != nil || dry.Archived != int64(before) {
		t.Errorf("dry run counted %d, not %d: %v", dry.Archived, before, err)
	}
	if has() != before {
		t.Error("a dry run changed the archive")
	}
	// As `db forget` would: a process that was never told where the archive is.
	st.cfg.ArchiveDir = ""
	res, err := st.ForgetDevice(ctx, archMAC)
	if err != nil {
		t.Fatal(err)
	}
	if res.Archived != int64(before) {
		t.Errorf("removed %d, not %d", res.Archived, before)
	}
	if n := has(); n != 0 {
		t.Errorf("%d rows of the device's survive", n)
	}
	// Nor does it survive as text somewhere else in a row.
	if err := (archive.Dir{Path: dir}).Read(archive.Query{}, func(line string) error {
		if strings.Contains(line, `"device":"`+archMAC) {
			t.Errorf("%s", line)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPurgeReachesTheArchive(t *testing.T) {
	st, dir := archStore(t, true)
	ctx := context.Background()
	if _, err := st.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	before := len(archiveRows(t, dir, "traffic_hourly"))
	if before == 0 {
		t.Fatal("nothing archived")
	}
	st.cfg.ArchiveDir = ""
	res, err := st.PurgeBeforeWithOptions(ctx, testutil.Base.Add(30*24*time.Hour), PurgeOptions{DryRun: true})
	if err != nil || res.Archived == 0 {
		t.Errorf("%+v, %v", res, err)
	}
	if len(archiveRows(t, dir, "traffic_hourly")) != before {
		t.Error("a dry run changed the archive")
	}
	if _, err := st.PurgeBefore(ctx, testutil.Base.Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := archiveRows(t, dir, "traffic_hourly"); len(got) != 0 {
		t.Errorf("%d rows survive a purge", len(got))
	}
}

func TestArchiveLimit(t *testing.T) {
	st, dir := archStore(t, true)
	st.cfg.ArchiveMaxBytes = 1
	if _, err := st.Retain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if size, _ := (archive.Dir{Path: dir}).Size(); size > 1 {
		t.Errorf("%d bytes", size)
	}
}

func TestArchiveStatus(t *testing.T) {
	st, _ := archStore(t, true)
	ctx := context.Background()
	if _, err := st.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := st.ArchiveStatus(ctx)
	if err != nil || !got.Enabled || got.Files == 0 || got.Bytes == 0 || got.Oldest == 0 {
		t.Errorf("%+v, %v", got, err)
	}
	st.cfg.ArchiveDir = ""
	got, err = st.ArchiveStatus(ctx)
	if err != nil || got.Enabled || got.Files == 0 {
		t.Errorf("%+v, %v", got, err)
	}
}

// New rows arriving after an old day was archived join its file rather than replace it.
func TestLateRowsJoinTheDay(t *testing.T) {
	st, dir := archStore(t, false)
	ctx := context.Background()
	if _, err := st.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	before := len(archiveRows(t, dir, "traffic_hourly"))
	if _, err := st.Ingest(ctx, "router", "boot2", []wire.Event{{Seq: 1, Type: wire.TypeFlow, TS: testutil.Base, Flow: &wire.Flow{
		ID: 999, Proto: 6, Src: netip.MustParseAddr("192.168.1.99"), SrcPort: 5000, Dst: netip.MustParseAddr("93.184.216.99"), DstPort: 443,
		FirstSeen: testutil.Base, Start: testutil.Base, End: testutil.Base.Add(time.Second), BytesOut: 10, Final: true,
	}}}); err != nil {
		t.Fatal(err)
	}
	if countRows(t, st, "traffic_hourly") == 0 {
		t.Skip("ingest doesn't roll up a row this old")
	}
	if _, err := st.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	if got := len(archiveRows(t, dir, "traffic_hourly")); got <= before {
		t.Errorf("%d rows, was %d", got, before)
	}
}
