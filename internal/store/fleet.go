package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/xen0bit/netgraph/internal/buildinfo"
	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/wire"
)

// FleetDefault is the name settings for every sensor go under.
const FleetDefault = "*"

// serverVersion is replaced in tests of what the fleet says about versions.
var serverVersion = func() string { return buildinfo.Version }

func (s *Store) readSensorConfig(ctx context.Context, name string) (wire.SensorConfig, error) {
	var out wire.SensorConfig
	var raw string
	err := s.r.QueryRowContext(ctx, `SELECT settings FROM sensor_config WHERE name = ?`, name).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return wire.SensorConfig{}, fmt.Errorf("sensor config for %q: %w", name, err)
	}
	return out, nil
}

// SensorConfigFor is what a sensor should do: the fleet's settings, with its own on top.
func (s *Store) SensorConfigFor(ctx context.Context, name string) (wire.SensorConfig, error) {
	all, err := s.readSensorConfig(ctx, FleetDefault)
	if err != nil {
		return all, err
	}
	own, err := s.readSensorConfig(ctx, name)
	if err != nil {
		return all, err
	}
	return all.Merge(own), nil
}

// SensorConfigOwn is what's been set for this name alone, or for the fleet, unmerged.
func (s *Store) SensorConfigOwn(ctx context.Context, name string) (wire.SensorConfig, error) {
	return s.readSensorConfig(ctx, name)
}

// SetSensorConfig replaces what's asked of a sensor, or of them all. Setting nothing clears it.
func (s *Store) SetSensorConfig(ctx context.Context, name string, c wire.SensorConfig) error {
	if name == "" || len(name) > 253 {
		return fmt.Errorf("%w: a sensor's name is 1 to 253 characters", ErrInvalid)
	}
	if err := c.Validate(); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalid, err.Error())
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if c == (wire.SensorConfig{}) {
			_, err := tx.ExecContext(ctx, `DELETE FROM sensor_config WHERE name = ?`, name)
			return err
		}
		b, err := json.Marshal(c)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO sensor_config (name, settings, updated_at) VALUES (?, ?, ?)
			ON CONFLICT(name) DO UPDATE SET settings = excluded.settings, updated_at = excluded.updated_at`, name, string(b), ms(s.cfg.Now()))
		return err
	})
}

// sensorHealth reads a sensor's last two reports. The counters run from when it started, so
// only their difference says what's happening now rather than last week.
func sensorHealth(sn *model.Sensor, statsPrev string, now time.Time) {
	var cur, prev wire.Stats
	if b, err := json.Marshal(sn.Stats); err == nil {
		_ = json.Unmarshal(b, &cur)
	}
	_ = json.Unmarshal([]byte(statsPrev), &prev)
	// A restart resets them: everything so far is since then.
	if cur.Uptime < prev.Uptime {
		prev = wire.Stats{}
	}
	diff := func(a, b uint64) uint64 {
		if a < b {
			return a
		}
		return a - b
	}
	sn.Problems = nil
	drops, packets := diff(cur.KernelDrops, prev.KernelDrops), diff(cur.Packets, prev.Packets)
	if drops > 0 && drops*100 >= packets+drops {
		sn.Problems = append(sn.Problems, fmt.Sprintf("The kernel dropped %d%% of packets lately: it's capturing faster than it can read, so give it a larger -ring-mb, or more CPU.", drops*100/(packets+drops)))
	}
	if n := diff(cur.EventsDropped, prev.EventsDropped); n > 0 {
		sn.Problems = append(sn.Problems, fmt.Sprintf("It lost %d events waiting to send them: its queue filled, because the server was out of reach or -spool-mb is small.", n))
	}
	if n := diff(cur.SendErrors, prev.SendErrors); n > 0 {
		sn.Problems = append(sn.Problems, fmt.Sprintf("Sending to this server failed %d times lately.", n))
	}
	if n := diff(cur.FlowsEvicted, prev.FlowsEvicted); n > 0 {
		sn.Problems = append(sn.Problems, fmt.Sprintf("Its flow table is full, and it pushed out %d connections early: raise -max-flows if it has the memory.", n))
	}
	switch {
	case now.Sub(time.UnixMilli(sn.LastSeen)) > homeQuiet:
		sn.Status = model.SensorQuiet
	case len(sn.Problems) > 0:
		sn.Status = model.SensorStruggling
	default:
		sn.Status = model.SensorOK
	}
}

// fillFleet adds what the fleet view says about a sensor to what it reported.
func (s *Store) fillFleet(ctx context.Context, sn *model.Sensor, hello wire.Hello, statsPrev string, now time.Time) error {
	sn.OS, sn.Arch = hello.OS, hello.Arch
	sensorHealth(sn, statsPrev, now)
	if v := serverVersion(); buildinfo.Older(sn.Version, v) {
		sn.UpgradeTo = v
	}
	if sn.Version == sourceVersion {
		return nil // a source lives in the server: nothing to set, nothing to upgrade
	}
	sn.Settable = true
	want, err := s.SensorConfigOwn(ctx, sn.Name)
	if err != nil {
		return err
	}
	all, err := s.SensorConfigOwn(ctx, FleetDefault)
	if err != nil {
		return err
	}
	sn.Config = &want
	merged := all.Merge(want)
	sn.TakesConfig = hello.Config != nil
	sn.InEffect = hello.Config
	sn.ConfigApplied = hello.Config != nil && hello.Config.Satisfies(merged)
	return nil
}

// sourceVersion is what a source on the server calls itself in its hello.
const sourceVersion = "source"
