package main

import (
	"log/slog"
	"sync"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

// settings is what the server may change while the sensor runs. The flags stay the
// starting point, so clearing a setting on the server puts the flag back. Nothing is
// written down: after a restart the sensor asks again.
type settings struct {
	level *slog.LevelVar
	apply func(wire.SensorConfig) // tells the rest of the sensor

	mu      sync.Mutex
	started wire.SensorConfig
	current wire.SensorConfig
	active  time.Duration // the flag as given: it can be under a second
}

func newSettings(level string, rdns bool, active, flush time.Duration, levelVar *slog.LevelVar) *settings {
	start := wire.SensorConfig{LogLevel: level, RDNS: &rdns, ActiveTimeoutS: int(active / time.Second), FlushS: int(flush / time.Second)}
	return &settings{level: levelVar, started: start, current: start, active: active}
}

// shipperWanted says the sensor is shipping to a server, which is who could set these.
func shipperWanted(server string) bool { return server != "-" }

func (s *settings) inEffect() wire.SensorConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

func (s *settings) summary() map[string]any {
	c := s.inEffect()
	out := map[string]any{"log_level": c.LogLevel, "active_timeout_s": c.ActiveTimeoutS, "flush_s": c.FlushS}
	if c.RDNS != nil {
		out["rdns"] = *c.RDNS
	}
	return out
}

func (s *settings) activeTimeout() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current.ActiveTimeoutS == s.started.ActiveTimeoutS {
		return s.active
	}
	return time.Duration(s.current.ActiveTimeoutS) * time.Second
}

// update lays what the server asked over the flags, and acts on anything that changed.
func (s *settings) update(want wire.SensorConfig) (changed bool) {
	s.mu.Lock()
	next := s.started.Merge(want)
	changed = !next.Satisfies(s.current) || !s.current.Satisfies(next)
	s.current = next
	s.mu.Unlock()
	if !changed {
		return false
	}
	if s.level != nil {
		_ = s.level.UnmarshalText([]byte(next.LogLevel))
	}
	if s.apply != nil {
		s.apply(next)
	}
	return true
}
