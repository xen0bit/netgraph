package wire

import "testing"

func TestSensorConfigValidate(t *testing.T) {
	for _, bad := range []SensorConfig{
		{LogLevel: "loud"}, {ActiveTimeoutS: 4}, {ActiveTimeoutS: 601}, {FlushS: 61}, {FlushS: -1},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v passed", bad)
		}
	}
	for _, good := range []SensorConfig{{}, {LogLevel: "debug", ActiveTimeoutS: 5, FlushS: 60}} {
		if err := good.Validate(); err != nil {
			t.Errorf("%+v: %v", good, err)
		}
	}
}

func TestSensorConfigMergeAndSatisfies(t *testing.T) {
	on, off := true, false
	got := SensorConfig{LogLevel: "warn", RDNS: &on, FlushS: 5}.Merge(SensorConfig{RDNS: &off, ActiveTimeoutS: 60})
	if got.LogLevel != "warn" || *got.RDNS || got.FlushS != 5 || got.ActiveTimeoutS != 60 {
		t.Errorf("%+v", got)
	}
	doing := SensorConfig{LogLevel: "warn", RDNS: &off, ActiveTimeoutS: 60, FlushS: 5}
	if !doing.Satisfies(SensorConfig{}) || !doing.Satisfies(SensorConfig{RDNS: &off}) {
		t.Error("should satisfy")
	}
	if doing.Satisfies(SensorConfig{RDNS: &on}) || doing.Satisfies(SensorConfig{FlushS: 2}) || (SensorConfig{}).Satisfies(SensorConfig{RDNS: &off}) {
		t.Error("shouldn't satisfy")
	}
}
