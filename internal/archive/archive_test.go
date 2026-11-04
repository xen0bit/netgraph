package archive

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var day1 = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

func rows(list ...Row) func() (Row, bool, error) {
	i := 0
	return func() (Row, bool, error) {
		if i >= len(list) {
			return nil, false, nil
		}
		i++
		return list[i-1], true, nil
	}
}

func at(d time.Duration, device string, n int) Row {
	return Row{TimeKey: day1.Add(d).UnixMilli(), DeviceKey: device, "bytes": n}
}

func readAll(t *testing.T, d Dir, q Query) []Row {
	t.Helper()
	var out []Row
	if err := d.Read(q, func(line string) error {
		var r Row
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

func TestWriteAndRead(t *testing.T) {
	d := Dir{Path: filepath.Join(t.TempDir(), "a")}
	n, err := d.WriteDay("traffic", day1, rows(at(time.Hour, "aa", 1), at(2*time.Hour, "bb", 2)))
	if err != nil || n != 2 {
		t.Fatalf("%d, %v", n, err)
	}
	if _, err := d.WriteDay("traffic", day1.Add(24*time.Hour), rows(at(25*time.Hour, "aa", 3))); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, d, Query{Table: "traffic"}); len(got) != 3 {
		t.Errorf("%+v", got)
	}
	if got := readAll(t, d, Query{Device: "aa"}); len(got) != 2 {
		t.Errorf("%+v", got)
	}
	// Half-open: To itself isn't included, and From is.
	got := readAll(t, d, Query{From: day1.Add(time.Hour), To: day1.Add(2 * time.Hour)})
	if len(got) != 1 || got[0]["bytes"] != float64(1) {
		t.Errorf("%+v", got)
	}
	files, err := d.List()
	if err != nil || len(files) != 2 || files[0].Bytes == 0 {
		t.Fatalf("%+v, %v", files, err)
	}
	info, err := os.Stat(files[0].path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("%v, %v", info.Mode(), err)
	}
	dirInfo, err := os.Stat(filepath.Dir(files[0].path))
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("%v, %v", dirInfo.Mode(), err)
	}
}

// After a crash between writing a day and deleting it from the database, it's written again.
func TestWritingAgainChangesNothing(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	a, b := at(time.Hour, "aa", 1), at(2*time.Hour, "bb", 2)
	if _, err := d.WriteDay("traffic", day1, rows(a, b)); err != nil {
		t.Fatal(err)
	}
	n, err := d.WriteDay("traffic", day1, rows(a, b))
	if err != nil || n != 0 {
		t.Errorf("%d, %v", n, err)
	}
	if got := readAll(t, d, Query{}); len(got) != 2 {
		t.Errorf("%+v", got)
	}
	// A row that arrived late joins them.
	n, err = d.WriteDay("traffic", day1, rows(a, at(3*time.Hour, "cc", 3)))
	if err != nil || n != 1 {
		t.Errorf("%d, %v", n, err)
	}
	if got := readAll(t, d, Query{}); len(got) != 3 {
		t.Errorf("%+v", got)
	}
}

func TestFailedWriteLeavesTheOldFile(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	if _, err := d.WriteDay("traffic", day1, rows(at(time.Hour, "aa", 1))); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	_, err := d.WriteDay("traffic", day1, func() (Row, bool, error) { return nil, false, boom })
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if got := readAll(t, d, Query{}); len(got) != 1 {
		t.Errorf("%+v", got)
	}
	left, _ := filepath.Glob(filepath.Join(d.Path, "traffic", ".partial-*"))
	if len(left) != 0 {
		t.Errorf("left behind %v", left)
	}
}

func TestCorruptFileIsntOverwritten(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	if _, err := d.WriteDay("traffic", day1, rows(at(time.Hour, "aa", 1))); err != nil {
		t.Fatal(err)
	}
	path, _ := d.file("traffic", day1)
	if err := os.WriteFile(path, []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.WriteDay("traffic", day1, rows(at(2*time.Hour, "bb", 2))); err == nil {
		t.Fatal("wrote over a file it couldn't read")
	}
	if b, _ := os.ReadFile(path); string(b) != "not gzip" {
		t.Error("the unreadable file was changed")
	}
}

func TestForget(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	if _, err := d.WriteDay("traffic", day1, rows(at(time.Hour, "aa", 1), at(2*time.Hour, "bb", 2))); err != nil {
		t.Fatal(err)
	}
	if _, err := d.WriteDay("conn", day1.Add(24*time.Hour), rows(Row{TimeKey: day1.Add(25 * time.Hour).UnixMilli(), MACKey: "aa"})); err != nil {
		t.Fatal(err)
	}
	// A dry run counts and changes nothing.
	if n, err := d.Forget("aa", true); err != nil || n != 2 {
		t.Errorf("%d, %v", n, err)
	}
	if got := readAll(t, d, Query{}); len(got) != 3 {
		t.Errorf("a dry run changed things: %+v", got)
	}
	if n, err := d.Forget("aa", false); err != nil || n != 2 {
		t.Errorf("%d, %v", n, err)
	}
	got := readAll(t, d, Query{})
	if len(got) != 1 || got[0][DeviceKey] != "bb" {
		t.Errorf("%+v", got)
	}
	// The second file held only that device, so it's gone rather than left empty.
	if files, _ := d.List(); len(files) != 1 {
		t.Errorf("%+v", files)
	}
	// What was forgotten isn't lying in the compressed bytes either.
	files, _ := d.List()
	f, _ := os.Open(files[0].path)
	defer f.Close()
	gz, _ := gzip.NewReader(f)
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := gz.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	if strings.Contains(sb.String(), `"aa"`) {
		t.Errorf("still there: %s", sb.String())
	}
}

func TestPurgeBefore(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	if _, err := d.WriteDay("traffic", day1, rows(at(time.Hour, "a", 1))); err != nil {
		t.Fatal(err)
	}
	if _, err := d.WriteDay("traffic", day1.Add(24*time.Hour), rows(at(25*time.Hour, "b", 2), at(30*time.Hour, "c", 3))); err != nil {
		t.Fatal(err)
	}
	if _, err := d.WriteDay("traffic", day1.Add(48*time.Hour), rows(at(50*time.Hour, "d", 4))); err != nil {
		t.Fatal(err)
	}
	cut := day1.Add(28 * time.Hour) // partway through the second day
	if n, err := d.PurgeBefore(cut, true); err != nil || n != 2 {
		t.Errorf("%d, %v", n, err)
	}
	if n, err := d.PurgeBefore(cut, false); err != nil || n != 2 {
		t.Errorf("%d, %v", n, err)
	}
	got := readAll(t, d, Query{})
	if len(got) != 2 || got[0][DeviceKey] != "c" || got[1][DeviceKey] != "d" {
		t.Errorf("%+v", got)
	}
}

func TestTrimTakesOldestFirst(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	for i := range 4 {
		day := day1.Add(time.Duration(i) * 24 * time.Hour)
		if _, err := d.WriteDay("traffic", day, rows(at(time.Duration(i)*24*time.Hour, "a", i))); err != nil {
			t.Fatal(err)
		}
	}
	size, _ := d.Size()
	gone, err := d.Trim(size / 2)
	if err != nil || len(gone) == 0 || !gone[0].Day.Equal(day1) {
		t.Fatalf("%+v, %v", gone, err)
	}
	if now, _ := d.Size(); now > size/2 {
		t.Errorf("%d > %d", now, size/2)
	}
	if gone, _ := d.Trim(0); gone != nil {
		t.Error("no limit should trim nothing")
	}
}

func TestMissingArchiveIsEmpty(t *testing.T) {
	d := Dir{Path: filepath.Join(t.TempDir(), "never-made")}
	if files, err := d.List(); err != nil || files != nil {
		t.Errorf("%v, %v", files, err)
	}
	if n, err := d.Forget("aa", false); err != nil || n != 0 {
		t.Errorf("%d, %v", n, err)
	}
}

func TestTableNameIsNotAPath(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	if _, err := d.WriteDay("../../etc/evil", day1, rows()); err == nil {
		t.Error("a table name got to choose a path")
	}
}

// Other tools can read these files, which is the point of the format.
func TestOtherToolsCanReadIt(t *testing.T) {
	zcat, err := exec.LookPath("zcat")
	if err != nil {
		t.Skip("no zcat")
	}
	d := Dir{Path: t.TempDir()}
	if _, err := d.WriteDay("traffic", day1, rows(at(time.Hour, "aa", 7))); err != nil {
		t.Fatal(err)
	}
	path, _ := d.file("traffic", day1)
	out, err := exec.Command(zcat, path).Output()
	if err != nil {
		t.Fatal(err)
	}
	var r Row
	if err := json.Unmarshal(out, &r); err != nil || r["bytes"] != float64(7) {
		t.Errorf("%s: %v", out, err)
	}
}
