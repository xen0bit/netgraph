package main

import (
	"log/slog"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/wire"
)

func TestSettingsLayOverFlagsAndClear(t *testing.T) {
	var level slog.LevelVar
	s := newSettings("info", true, 30*time.Second, 2*time.Second, &level)
	var told []wire.SensorConfig
	s.apply = func(c wire.SensorConfig) { told = append(told, c) }
	if s.update(wire.SensorConfig{}) {
		t.Error("nothing asked, but something changed")
	}
	off := false
	if !s.update(wire.SensorConfig{LogLevel: "debug", RDNS: &off, ActiveTimeoutS: 60, FlushS: 5}) {
		t.Fatal("no change seen")
	}
	if level.Level() != slog.LevelDebug || s.activeTimeout() != time.Minute || *s.inEffect().RDNS || len(told) != 1 || told[0].FlushS != 5 {
		t.Errorf("%v %v %+v %+v", level.Level(), s.activeTimeout(), s.inEffect(), told)
	}
	if s.update(wire.SensorConfig{LogLevel: "debug", RDNS: &off, ActiveTimeoutS: 60, FlushS: 5}) {
		t.Error("the same again counts as a change")
	}
	// Cleared on the server: back to what the flags said.
	if !s.update(wire.SensorConfig{}) {
		t.Fatal("clearing changed nothing")
	}
	c := s.inEffect()
	if level.Level() != slog.LevelInfo || c.ActiveTimeoutS != 30 || c.FlushS != 2 || !*c.RDNS {
		t.Errorf("%v %+v", level.Level(), c)
	}
}
