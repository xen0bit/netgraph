package tools

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
)

type fake struct {
	Backend
	f    model.Filter
	devs []model.Device
	id   string
}

func (b *fake) Devices(_ context.Context, f model.Filter) ([]model.Device, error) {
	b.f = f
	return b.devs, nil
}
func (b *fake) Entity(_ context.Context, id string, f model.Filter) (*model.EntityDetail, error) {
	b.id, b.f = id, f
	return &model.EntityDetail{ID: id}, nil
}
func (b *fake) Flows(_ context.Context, f model.Filter) ([]model.Flow, error) {
	b.f = f
	return nil, errors.New("database busy")
}
func (b *fake) Diff(_ context.Context, x, y model.Filter, _ string) (*model.Diff, error) {
	b.f = y
	return &model.Diff{}, nil
}

var now = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

func call(t *testing.T, b Backend, name, raw string) (Result, error) {
	t.Helper()
	tool := Find(name)
	if tool == nil {
		t.Fatalf("no tool %s", name)
	}
	return tool.Call(context.Background(), b, json.RawMessage(raw), now)
}

func TestWindowDefaultsAndFilters(t *testing.T) {
	b := &fake{devs: []model.Device{{ID: "device:a", Label: "a"}}}
	r, err := call(t, b, "devices", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if !b.f.To.Equal(now) || !b.f.From.Equal(now.Add(-24*time.Hour)) || b.f.Limit != maxRows {
		t.Errorf("filter %+v", b.f)
	}
	if !strings.Contains(r.Text, "device:a") {
		t.Errorf("result %s", r.Text)
	}
	if _, err := call(t, b, "devices", `{"from": "-1h", "device": "type:printer"}`); err != nil {
		t.Fatal(err)
	}
	if !b.f.From.Equal(now.Add(-time.Hour)) || b.f.Device != "type:printer" {
		t.Errorf("filter %+v", b.f)
	}
	if _, err := call(t, b, "diff", `{"a": "-1h", "lookback": "15m"}`); err != nil {
		t.Fatal(err)
	}
	if !b.f.From.Equal(now.Add(-15 * time.Minute)) {
		t.Errorf("diff %+v", b.f)
	}
}

// A model wrote these. None of them may do anything but fail politely.
func TestBadArguments(t *testing.T) {
	b := &fake{}
	for name, raw := range map[string]string{
		"devices": `{"from": "not a time"}`,
		"entity":  `{}`,
		"story":   `{"id": ""}`,
		"search":  `{"q": "   "}`,
		"dns":     `{"limit": 100000}`,
		"diff":    `{"b": "-1h"}`,
	} {
		if _, err := call(t, b, name, raw); err == nil {
			t.Errorf("%s %s was accepted", name, raw)
		}
	}
	for _, raw := range []string{`[1,2]`, `"x"`, `{`, `{"from": {"a": 1}}`} {
		if _, err := call(t, b, "devices", raw); err == nil {
			t.Errorf("devices %s was accepted", raw)
		}
	}
	if _, err := call(t, b, "devices", `{"from": "-1h", "to": "-2h"}`); err == nil {
		t.Error("a backwards window was accepted")
	}
	if _, err := call(t, b, "connections", `{}`); err == nil || !strings.Contains(err.Error(), "database busy") {
		t.Errorf("a backend error: %v", err)
	}
}

func TestLongResultsAreCutAndSaySo(t *testing.T) {
	devs := make([]model.Device, 2000)
	for i := range devs {
		devs[i] = model.Device{ID: "device:x", Label: strings.Repeat("y", 200)}
	}
	r, err := call(t, &fake{devs: devs}, "devices", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || len(r.Text) > MaxResult || !strings.Contains(r.Text, "of 2000 rows") {
		t.Errorf("truncated %v, %d bytes", r.Truncated, len(r.Text))
	}
	if !json.Valid([]byte(r.Text)) {
		t.Error("cutting broke the JSON")
	}
	// Too big, and not a list.
	r, err = Render(map[string]string{"x": strings.Repeat("y", MaxResult*2)})
	if err != nil || !r.Truncated || len(r.Text) > 1000 || !json.Valid([]byte(r.Text)) {
		t.Errorf("%v, %d bytes, %v", r.Truncated, len(r.Text), err)
	}
}

// The promise of this package: nothing in the backend writes. A method with a name
// like one would be a mistake to be noticed here, in review.
func TestBackendOnlyReads(t *testing.T) {
	typ := reflect.TypeFor[Backend]()
	for i := range typ.NumMethod() {
		name := typ.Method(i).Name
		for _, w := range []string{"Set", "Create", "Update", "Delete", "Forget", "Purge", "Ingest", "Decide", "Mark", "Mute", "Pin"} {
			if strings.HasPrefix(name, w) {
				t.Errorf("Backend has %s, which looks like a write", name)
			}
		}
	}
}

func TestEveryToolDescribesItself(t *testing.T) {
	seen := map[string]bool{}
	for i := range List {
		tool := &List[i]
		if tool.Name == "" || len(tool.Description) < 20 || seen[tool.Name] || tool.run == nil {
			t.Errorf("tool %+v", tool.Name)
		}
		seen[tool.Name] = true
		if _, err := json.Marshal(tool.Schema()); err != nil {
			t.Errorf("%s: %v", tool.Name, err)
		}
	}
}
