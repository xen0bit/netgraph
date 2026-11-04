// Package archive keeps what retention would delete, in files outside the database: one
// gzip-compressed JSON-lines file per table per day, named table/YYYY-MM-DD.jsonl.gz. Anything
// that reads JSON can use them, such as zcat, jq or DuckDB, without netgraph.
//
// Files are written beside their final name and renamed, so a crash leaves the last good
// file. Writing a day again merges with what's there, so repeating one after a crash changes
// nothing. This holds people's traffic history, so it's private to the server's user, and
// erasing from the database reaches here too (Forget, PurgeBefore).
package archive

import (
	"bufio"
	"cmp"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Row is one archived record. It always has TimeKey, and DeviceKey if a device is known.
type Row map[string]any

// Fields every row carries, whatever its table.
const (
	TimeKey   = "t"          // unix milliseconds: which day it belongs to, and how it's filtered
	DeviceKey = "device"     // the device's MAC, if known
	MACKey    = "client_mac" // the MAC a connection's client sent from, which forgetting also matches
)

const (
	dayFormat = "2006-01-02"
	suffix    = ".jsonl.gz"
	// maxLine bounds one row when reading back.
	maxLine = 16 << 20
)

// tableName limits what can become a path. Tables come from code, not input, but a path is
// no place to find out otherwise.
var tableName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Dir is an archive directory.
type Dir struct {
	Path string
}

// DayOf is the start of the UTC day holding a moment.
func DayOf(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func (d Dir) file(table string, day time.Time) (string, error) {
	if !tableName.MatchString(table) {
		return "", fmt.Errorf("archive: table name %q", table)
	}
	return filepath.Join(d.Path, table, day.UTC().Format(dayFormat)+suffix), nil
}

// WriteDay adds rows to a day's file, keeping what's already there and dropping exact
// repeats. next yields rows until it returns false.
func (d Dir) WriteDay(table string, day time.Time, next func() (Row, bool, error)) (int, error) {
	path, err := d.file(table, day)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, err
	}
	var seen map[string]bool
	var existing []string
	if _, err := os.Stat(path); err == nil {
		seen = map[string]bool{}
		if err := readLines(path, func(line string) error {
			if !seen[line] {
				seen[line] = true
				existing = append(existing, line)
			}
			return nil
		}); err != nil {
			return 0, fmt.Errorf("archive: %s is unreadable, so it's been left alone: %w", path, err)
		}
	}
	added := 0
	err = replace(path, func(w io.Writer) error {
		for _, line := range existing {
			if _, err := io.WriteString(w, line+"\n"); err != nil {
				return err
			}
		}
		for {
			row, ok, err := next()
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
			b, err := json.Marshal(row)
			if err != nil {
				return err
			}
			if seen[string(b)] {
				continue
			}
			if _, err := w.Write(append(b, '\n')); err != nil {
				return err
			}
			added++
		}
	})
	if err != nil {
		return 0, err
	}
	return added, nil
}

// replace writes a compressed file through a temporary one, so what's at path is always whole.
func replace(path string, write func(io.Writer) error) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".partial-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	buf := bufio.NewWriterSize(tmp, 256<<10)
	gz := gzip.NewWriter(buf)
	if err := write(gz); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	if err := buf.Flush(); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		dir.Close()
	}
	return nil
}

func readLines(path string, line func(string) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	for sc.Scan() {
		if err := line(sc.Text()); err != nil {
			return err
		}
	}
	return sc.Err()
}

// File is one day of one table.
type File struct {
	Table string    `json:"table"`
	Day   time.Time `json:"day"`
	Bytes int64     `json:"bytes"`
	path  string
}

// List says what's archived, oldest first. A missing directory is an empty archive.
func (d Dir) List() ([]File, error) {
	tables, err := os.ReadDir(d.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []File
	for _, t := range tables {
		if !t.IsDir() || !tableName.MatchString(t.Name()) {
			continue
		}
		days, err := os.ReadDir(filepath.Join(d.Path, t.Name()))
		if err != nil {
			return nil, err
		}
		for _, e := range days {
			name, ok := strings.CutSuffix(e.Name(), suffix)
			if !ok {
				continue
			}
			day, err := time.Parse(dayFormat, name)
			if err != nil {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			out = append(out, File{Table: t.Name(), Day: day, Bytes: info.Size(), path: filepath.Join(d.Path, t.Name(), e.Name())})
		}
	}
	slices.SortFunc(out, func(a, b File) int {
		return cmp.Or(a.Day.Compare(b.Day), cmp.Compare(a.Table, b.Table))
	})
	return out, nil
}

// Size is what the archive takes up.
func (d Dir) Size() (int64, error) {
	files, err := d.List()
	if err != nil {
		return 0, err
	}
	var n int64
	for _, f := range files {
		n += f.Bytes
	}
	return n, nil
}

// Query narrows a Read. A zero field doesn't narrow. Windows are half-open: [From, To).
type Query struct {
	Table    string
	From, To time.Time
	Device   string
}

func rowTime(r Row) (time.Time, bool) {
	v, ok := r[TimeKey].(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.UnixMilli(int64(v)), true
}

func (q Query) wants(r Row) bool {
	t, ok := rowTime(r)
	if !ok {
		return false
	}
	if !q.From.IsZero() && t.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && !t.Before(q.To) {
		return false
	}
	if q.Device != "" && !belongsTo(r, q.Device) {
		return false
	}
	return true
}

func belongsTo(r Row, mac string) bool {
	return r[DeviceKey] == mac || r[MACKey] == mac
}

// Read yields matching rows as the lines they're stored as, oldest day first.
func (d Dir) Read(q Query, yield func(line string) error) error {
	files, err := d.List()
	if err != nil {
		return err
	}
	for _, f := range files {
		if q.Table != "" && f.Table != q.Table {
			continue
		}
		if !q.To.IsZero() && !f.Day.Before(q.To) {
			continue
		}
		if !q.From.IsZero() && !f.Day.Add(24*time.Hour).After(q.From) {
			continue
		}
		if err := readLines(f.path, func(line string) error {
			var r Row
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				return nil // not one of ours: leave it out
			}
			if q.wants(r) {
				return yield(line)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("archive: %s: %w", f.path, err)
		}
	}
	return nil
}

// filter rewrites a file without the rows drop says to, removing it if none are left.
// It returns how many went, and writes nothing if none did.
func filter(f File, dry bool, drop func(Row) bool) (int64, error) {
	var kept []string
	var gone int64
	if err := readLines(f.path, func(line string) error {
		var r Row
		if err := json.Unmarshal([]byte(line), &r); err == nil && drop(r) {
			gone++
			return nil
		}
		kept = append(kept, line)
		return nil
	}); err != nil {
		return 0, fmt.Errorf("archive: %s: %w", f.path, err)
	}
	if gone == 0 || dry {
		return gone, nil
	}
	if len(kept) == 0 {
		return gone, os.Remove(f.path)
	}
	return gone, replace(f.path, func(w io.Writer) error {
		for _, line := range kept {
			if _, err := io.WriteString(w, line+"\n"); err != nil {
				return err
			}
		}
		return nil
	})
}

// Forget removes a device's rows everywhere, and reports how many there were. With dry set
// it only counts.
func (d Dir) Forget(mac string, dry bool) (int64, error) {
	files, err := d.List()
	if err != nil {
		return 0, err
	}
	var total int64
	var firstErr error
	for _, f := range files {
		// Carry on past a bad file: the rest should still be erased, and the error still said.
		n, err := filter(f, dry, func(r Row) bool { return belongsTo(r, mac) })
		total += n
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return total, firstErr
}

// PurgeBefore removes everything older than a moment. A row with no readable time goes too,
// when its whole day is older: nothing can say it should stay.
func (d Dir) PurgeBefore(before time.Time, dry bool) (int64, error) {
	files, err := d.List()
	if err != nil {
		return 0, err
	}
	var total int64
	var firstErr error
	for _, f := range files {
		if !f.Day.Before(DayOf(before).Add(24 * time.Hour)) {
			continue
		}
		wholeDay := !f.Day.Add(24 * time.Hour).After(before)
		n, err := filter(f, dry, func(r Row) bool {
			t, ok := rowTime(r)
			if !ok {
				return wholeDay
			}
			return t.Before(before)
		})
		total += n
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return total, firstErr
}

// Trim removes the oldest days until the archive fits, and reports what went.
func (d Dir) Trim(maxBytes int64) ([]File, error) {
	if maxBytes <= 0 {
		return nil, nil
	}
	files, err := d.List()
	if err != nil {
		return nil, err
	}
	var size int64
	for _, f := range files {
		size += f.Bytes
	}
	var gone []File
	for _, f := range files {
		if size <= maxBytes {
			break
		}
		if err := os.Remove(f.path); err != nil {
			return gone, err
		}
		size -= f.Bytes
		gone = append(gone, f)
	}
	return gone, nil
}
