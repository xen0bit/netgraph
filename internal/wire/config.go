package wire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SensorConfig is what a server can ask of a sensor while it runs. An unset field leaves
// the sensor's own flag in charge. The list is deliberately short and bounded: this reaches
// routers, so nothing here runs anything, names a path, or changes where data goes.
//
// A sensor holds it in memory only, and asks again when it starts.
type SensorConfig struct {
	LogLevel       string `json:"log_level,omitempty"`        // debug, info, warn, error
	RDNS           *bool  `json:"rdns,omitempty"`             // reverse DNS lookups
	ActiveTimeoutS int    `json:"active_timeout_s,omitempty"` // seconds between records of a long flow
	FlushS         int    `json:"flush_s,omitempty"`          // seconds between batches
}

// Limits on what can be asked of a sensor.
const (
	MinActiveTimeoutS = 5
	MaxActiveTimeoutS = 600 // store.MaxRecordSpan: longer records would have to be split
	MinFlushS         = 1
	MaxFlushS         = 60
)

// Validate says what's wrong with a config, in terms a person can act on.
func (c SensorConfig) Validate() error {
	switch c.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level %q is not debug, info, warn or error", c.LogLevel)
	}
	if c.ActiveTimeoutS != 0 && (c.ActiveTimeoutS < MinActiveTimeoutS || c.ActiveTimeoutS > MaxActiveTimeoutS) {
		return fmt.Errorf("active_timeout_s must be %d to %d", MinActiveTimeoutS, MaxActiveTimeoutS)
	}
	if c.FlushS != 0 && (c.FlushS < MinFlushS || c.FlushS > MaxFlushS) {
		return fmt.Errorf("flush_s must be %d to %d", MinFlushS, MaxFlushS)
	}
	return nil
}

// Merge lays a sensor's own settings over the fleet's.
func (c SensorConfig) Merge(over SensorConfig) SensorConfig {
	if over.LogLevel != "" {
		c.LogLevel = over.LogLevel
	}
	if over.RDNS != nil {
		c.RDNS = over.RDNS
	}
	if over.ActiveTimeoutS != 0 {
		c.ActiveTimeoutS = over.ActiveTimeoutS
	}
	if over.FlushS != 0 {
		c.FlushS = over.FlushS
	}
	return c
}

// Satisfies says the settings in effect are the ones wanted. What's not wanted can be anything.
func (c SensorConfig) Satisfies(want SensorConfig) bool {
	return (want.LogLevel == "" || want.LogLevel == c.LogLevel) &&
		(want.RDNS == nil || (c.RDNS != nil && *want.RDNS == *c.RDNS)) &&
		(want.ActiveTimeoutS == 0 || want.ActiveTimeoutS == c.ActiveTimeoutS) &&
		(want.FlushS == 0 || want.FlushS == c.FlushS)
}

// ErrNoRemoteConfig is a server too old to know about this.
var ErrNoRemoteConfig = errors.New("the server doesn't offer sensor settings")

// FetchConfig asks the server what it wants of this sensor. Whatever comes back is checked:
// a bad answer leaves things as they are.
func (s *Shipper) FetchConfig(ctx context.Context) (SensorConfig, error) {
	var out SensorConfig
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.URL+"/api/v1/sensor/config", nil)
	if err != nil {
		return out, err
	}
	req.Header.Set(HeaderSensor, s.cfg.Sensor)
	if s.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return out, ErrNoRemoteConfig
	}
	if resp.StatusCode/100 != 2 {
		return out, fmt.Errorf("fetch sensor config: %s", resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return SensorConfig{}, err
	}
	if err := out.Validate(); err != nil {
		return SensorConfig{}, err
	}
	return out, nil
}

// SetFlushInterval changes how often batches are sealed. It can be called at any time.
func (s *Shipper) SetFlushInterval(d time.Duration) {
	if d <= 0 {
		return
	}
	select {
	case s.flushEvery <- d:
	default: // one is waiting to be picked up; the next sync says this again
	}
}
