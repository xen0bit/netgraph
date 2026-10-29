// Package anomaly holds the statistics behind netgraph's anomaly checks:
// pure functions over numbers the store has already gathered, so each rule
// can be tested on its own and its verdict explained from its inputs.
package anomaly

import (
	"math"
	"slices"
	"strings"
)

// Periodic describes regularly spaced events: Period is the median gap in
// milliseconds, Jitter the median distance of a gap from it as a fraction
// of the period, Events how many there were after merging bursts.
type Periodic struct {
	Period float64
	Jitter float64
	Events int
}

// Beacon rules: enough events to call it a pattern, a period long enough
// not to be a burst, and gaps that agree.
const (
	BeaconMinEvents   = 8
	BeaconMinPeriodMS = 10_000
	BeaconMaxJitter   = 0.1
	beaconBurstMS     = 1_000 // starts closer than this are one event
	beaconAgree       = 0.8   // of gaps within ±25% of the period
)

// Beacon reports whether connection start times (ms, any order) recur on a
// fixed period, the way malware calls home or a device polls. Starts
// within a second of each other are one event, so a client opening
// several connections at once counts once.
func Beacon(starts []int64) (Periodic, bool) {
	ts := slices.Sorted(slices.Values(starts))
	var events []int64
	for _, t := range ts {
		if len(events) == 0 || t-events[len(events)-1] >= beaconBurstMS {
			events = append(events, t)
		}
	}
	p := Periodic{Events: len(events)}
	if len(events) < BeaconMinEvents {
		return p, false
	}
	gaps := make([]float64, 0, len(events)-1)
	for i := 1; i < len(events); i++ {
		gaps = append(gaps, float64(events[i]-events[i-1]))
	}
	p.Period = Median(gaps)
	if p.Period < BeaconMinPeriodMS {
		return p, false
	}
	dev := make([]float64, len(gaps))
	agree := 0
	for i, g := range gaps {
		dev[i] = math.Abs(g - p.Period)
		if dev[i] <= 0.25*p.Period {
			agree++
		}
	}
	p.Jitter = Median(dev) / p.Period
	return p, p.Jitter <= BeaconMaxJitter && float64(agree) >= beaconAgree*float64(len(gaps))
}

// Median of xs (0 for none). xs is not modified.
func Median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Sorted(slices.Values(xs))
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// Spike rules: a device's upload in a window against its busiest hours.
const (
	SpikeMinHours    = 24       // active hours of history needed
	SpikeMinBytes    = 20 << 20 // per hour: below this nothing is a spike
	SpikeOverMedian  = 4        // and at least this many times the median hour
	SpikeHighOverMax = 5        // high severity: this many times the busiest hour
	SpikeHighBytes   = 200 << 20
)

// Spike compares a rate (bytes per hour) with the rates of a device's past
// active hours. It is a spike when it exceeds every one of them and the
// median several times over: an absolute, explainable bar rather than a
// z-score, which a device idle most of the week would trip constantly.
func Spike(rate float64, hours []float64) (spike, high bool, median, peak float64) {
	if len(hours) < SpikeMinHours {
		return false, false, 0, 0
	}
	median = Median(hours)
	peak = slices.Max(hours)
	spike = rate >= SpikeMinBytes && rate > peak && rate >= SpikeOverMedian*median
	high = spike && rate >= SpikeHighOverMax*peak && rate >= SpikeHighBytes
	return spike, high, median, peak
}

// Surge rules: connections from outside to a device in an hour against its
// busiest recent hours.
const (
	SurgeMinHours = 24   // active hours of history needed
	SurgeMinRate  = 1000 // connections an hour: below this nothing is a surge
	SurgeOverMax  = 4    // and at least this many times the busiest hour
	SurgeHighOver = 10   // high severity: this many times the busiest hour
	SurgeHighRate = 10000
)

// Surge compares a rate (connections per hour) with a device's past active
// hours. Unlike Spike it measures against the busiest hour, not the
// median: a server's traffic swings with the day, and its own peak is the
// honest bar.
func Surge(rate float64, hours []float64) (surge, high bool, peak float64) {
	if len(hours) < SurgeMinHours {
		return false, false, 0
	}
	peak = slices.Max(hours)
	surge = rate >= SurgeMinRate && rate >= SurgeOverMax*peak
	high = surge && rate >= SurgeHighOver*peak && rate >= SurgeHighRate
	return surge, high, peak
}

// LocalName reports names that fail to resolve as a matter of course:
// single labels (search-domain probes, WPAD), reverse lookups and
// local-only suffixes. They are not evidence of anything.
func LocalName(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if !strings.Contains(name, ".") {
		return true
	}
	for _, s := range []string{".arpa", ".local", ".lan", ".home", ".internal", ".localdomain", ".home.arpa", ".corp"} {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// FirstLabel is a name's leftmost label: where DNS tunnels put their data.
func FirstLabel(name string) string {
	l, _, _ := strings.Cut(name, ".")
	return l
}
