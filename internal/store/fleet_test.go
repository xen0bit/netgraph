package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/wire"
)

func fleetStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func reportOf(t *testing.T, st *Store, seq *uint64, hello *wire.Hello, stats ...wire.Stats) model.Sensor {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	var evs []wire.Event
	if hello != nil {
		evs = append(evs, wire.Event{Type: wire.TypeHello, TS: now, Hello: hello})
	}
	for i := range stats {
		evs = append(evs, wire.Event{Type: wire.TypeStats, TS: now, Stats: &stats[i]})
	}
	for i := range evs {
		*seq++
		evs[i].Seq = *seq
	}
	if _, err := st.Ingest(ctx, "router", "boot", evs); err != nil {
		t.Fatal(err)
	}
	all, err := st.Sensors(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("%+v, %v", all, err)
	}
	return all[0]
}

func TestSensorHealthIsAboutNow(t *testing.T) {
	st := fleetStore(t)
	var seq uint64
	hello := &wire.Hello{Name: "router", Version: "v1.0.0", OS: "linux", Arch: "mipsle"}
	sn := reportOf(t, st, &seq, hello, wire.Stats{Uptime: time.Hour, Packets: 1000})
	if sn.Status != model.SensorOK || sn.OS != "linux" || sn.Arch != "mipsle" {
		t.Errorf("%+v", sn)
	}
	// Dropping now.
	sn = reportOf(t, st, &seq, nil, wire.Stats{Uptime: 2 * time.Hour, Packets: 1900, KernelDrops: 100, SendErrors: 3, EventsDropped: 7, FlowsEvicted: 9})
	if sn.Status != model.SensorStruggling || len(sn.Problems) != 4 {
		t.Errorf("%+v", sn)
	}
	// The same totals a minute later: those are history, and it's fine again.
	sn = reportOf(t, st, &seq, nil, wire.Stats{Uptime: 3 * time.Hour, Packets: 2900, KernelDrops: 100, SendErrors: 3, EventsDropped: 7, FlowsEvicted: 9})
	if sn.Status != model.SensorOK || len(sn.Problems) != 0 {
		t.Errorf("old drops still count: %+v", sn)
	}
	// A restart resets the counters: what it reports is all since then.
	sn = reportOf(t, st, &seq, nil, wire.Stats{Uptime: time.Minute, Packets: 10, SendErrors: 2})
	if sn.Status != model.SensorStruggling {
		t.Errorf("%+v", sn)
	}
}

func TestSensorQuiet(t *testing.T) {
	sn := model.Sensor{LastSeen: time.Now().Add(-time.Hour).UnixMilli()}
	sensorHealth(&sn, "{}", time.Now())
	if sn.Status != model.SensorQuiet {
		t.Errorf("%+v", sn)
	}
}

func TestUpgradePrompt(t *testing.T) {
	st := fleetStore(t)
	was := serverVersion
	serverVersion = func() string { return "v1.2.0" }
	defer func() { serverVersion = was }()
	var seq uint64
	if sn := reportOf(t, st, &seq, &wire.Hello{Version: "v1.1.0"}); sn.UpgradeTo != "v1.2.0" {
		t.Errorf("%+v", sn)
	}
	if sn := reportOf(t, st, &seq, &wire.Hello{Version: "v1.2.0"}); sn.UpgradeTo != "" {
		t.Errorf("%+v", sn)
	}
	if sn := reportOf(t, st, &seq, &wire.Hello{Version: "dev"}); sn.UpgradeTo != "" {
		t.Errorf("%+v", sn)
	}
}

func TestSensorConfigLayers(t *testing.T) {
	st := fleetStore(t)
	ctx := context.Background()
	off := false
	if err := st.SetSensorConfig(ctx, FleetDefault, wire.SensorConfig{LogLevel: "warn", FlushS: 5}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSensorConfig(ctx, "router", wire.SensorConfig{FlushS: 9, RDNS: &off}); err != nil {
		t.Fatal(err)
	}
	c, err := st.SensorConfigFor(ctx, "router")
	if err != nil || c.LogLevel != "warn" || c.FlushS != 9 || c.RDNS == nil || *c.RDNS {
		t.Fatalf("%+v, %v", c, err)
	}
	other, _ := st.SensorConfigFor(ctx, "ap")
	if other.FlushS != 5 || other.RDNS != nil {
		t.Errorf("%+v", other)
	}
	// What it says it's doing against what's asked, the fleet's part included.
	var seq uint64
	doing := wire.SensorConfig{LogLevel: "warn", FlushS: 9, RDNS: &off, ActiveTimeoutS: 30}
	sn := reportOf(t, st, &seq, &wire.Hello{Version: "v1.0.0", Config: &doing})
	if !sn.TakesConfig || !sn.ConfigApplied || sn.Config.FlushS != 9 || sn.Config.LogLevel != "" {
		t.Errorf("%+v", sn)
	}
	stale := wire.SensorConfig{LogLevel: "info", FlushS: 9, RDNS: &off}
	if sn := reportOf(t, st, &seq, &wire.Hello{Version: "v1.0.0", Config: &stale}); sn.ConfigApplied {
		t.Error("a sensor ignoring the fleet's level reads as applied")
	}
	if sn := reportOf(t, st, &seq, &wire.Hello{Version: "v1.0.0"}); sn.TakesConfig || sn.ConfigApplied || !sn.Settable {
		t.Errorf("%+v", sn)
	}
	// Empty clears.
	if err := st.SetSensorConfig(ctx, "router", wire.SensorConfig{}); err != nil {
		t.Fatal(err)
	}
	if c, _ := st.SensorConfigOwn(ctx, "router"); c != (wire.SensorConfig{}) {
		t.Errorf("%+v", c)
	}
	if err := st.SetSensorConfig(ctx, "router", wire.SensorConfig{FlushS: 999}); !errors.Is(err, ErrInvalid) {
		t.Errorf("%v", err)
	}
	if err := st.SetSensorConfig(ctx, "", wire.SensorConfig{FlushS: 5}); !errors.Is(err, ErrInvalid) {
		t.Errorf("%v", err)
	}
}

func TestSourceHasNoSettings(t *testing.T) {
	st := fleetStore(t)
	var seq uint64
	if sn := reportOf(t, st, &seq, &wire.Hello{Version: sourceVersion}); sn.Settable || sn.Config != nil || sn.UpgradeTo != "" {
		t.Errorf("%+v", sn)
	}
}
