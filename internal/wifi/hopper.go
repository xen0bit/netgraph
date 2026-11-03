package wifi

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ErrHopUnsupported means the platform has no wireless-extension ioctl to
// change channels. Monitor interfaces on such a platform can still be
// captured on a fixed channel.
var ErrHopUnsupported = fmt.Errorf("wifi: channel hopping not supported on this platform")

// Hopper visits a list of channels, dwelling on each. It is how a monitor
// interface follows traffic across a 2.4/5 GHz network.
type Hopper struct {
	Interface string
	Channels  []int
	// Frequencies, when non-empty, is a channel plan in MHz. It is how a
	// 6 GHz interface is hopped: channel numbers overlap between 5 and
	// 6 GHz, so the frequency is the only unambiguous identifier.
	Frequencies []int
	Dwell       time.Duration // default 250ms
	// Set and SetFrequency override the platform ioctl, for tests.
	Set          func(channel int) error
	SetFrequency func(mhz int) error
	Logger       *slog.Logger
}

// Run hops until ctx is cancelled. A failure to set one channel is logged
// and the hopper moves on: a missing channel is not a reason to stop
// capturing the others.
func (h *Hopper) Run(ctx context.Context) error {
	if len(h.Channels) == 0 && len(h.Frequencies) == 0 {
		return fmt.Errorf("wifi: no channels to hop")
	}
	if h.Dwell <= 0 {
		h.Dwell = 250 * time.Millisecond
	}
	if h.Logger == nil {
		h.Logger = slog.Default()
	}
	set := h.Set
	if set == nil {
		set = func(ch int) error { return SetChannel(h.Interface, ch) }
	}
	setFreq := h.SetFrequency
	if setFreq == nil {
		setFreq = func(mhz int) error { return SetFrequency(h.Interface, mhz) }
	}
	for {
		if len(h.Frequencies) > 0 {
			for _, mhz := range h.Frequencies {
				if err := ctx.Err(); err != nil {
					return nil
				}
				if err := setFreq(mhz); err != nil {
					h.Logger.Warn("set wifi frequency", "iface", h.Interface, "mhz", mhz, "err", err)
				} else {
					h.Logger.Debug("wifi frequency", "iface", h.Interface, "mhz", mhz)
				}
				if !h.dwell(ctx) {
					return nil
				}
			}
			continue
		}
		for _, ch := range h.Channels {
			if err := ctx.Err(); err != nil {
				return nil
			}
			if err := set(ch); err != nil {
				h.Logger.Warn("set wifi channel", "iface", h.Interface, "channel", ch, "err", err)
			} else {
				h.Logger.Debug("wifi channel", "iface", h.Interface, "channel", ch)
			}
			if !h.dwell(ctx) {
				return nil
			}
		}
	}
}

func (h *Hopper) dwell(ctx context.Context) bool {
	t := time.NewTimer(h.Dwell)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// DefaultChannels is a conservative scan list: 2.4 GHz channels 1-13 and
// the common non-DFS 5 GHz channels. Drivers that reject a channel simply
// log it and move on.
func DefaultChannels() []int {
	return []int{1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161, 165}
}

// DefaultFrequencies is the same conservative plan in MHz, for drivers that
// select channels by frequency. It is the starting point for adding 6 GHz.
func DefaultFrequencies() []int {
	return []int{2412, 2437, 2462, 5180, 5200, 5220, 5240, 5745, 5765, 5785, 5805, 5825}
}

// SixGHzFrequencies is the 20 MHz 6 GHz plan: channels 1, 5, 9, ... 233.
func SixGHzFrequencies() []int {
	out := make([]int, 0, 59)
	for ch := 1; ch <= 233; ch += 4 {
		out = append(out, 5950+ch*5)
	}
	return out
}

// ParseFrequencies parses "2412,5180,5955-5975" into sorted unique MHz values.
func ParseFrequencies(s string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi := part, part
		if a, b, ok := strings.Cut(part, "-"); ok {
			lo, hi = strings.TrimSpace(a), strings.TrimSpace(b)
		}
		l, err := strconv.Atoi(lo)
		if err != nil {
			return nil, fmt.Errorf("wifi: frequency %q", part)
		}
		r, err := strconv.Atoi(hi)
		if err != nil || r < l || r-l > 10000 {
			return nil, fmt.Errorf("wifi: frequency range %q", part)
		}
		for f := l; f <= r; f++ {
			if f < 2400 || f > 7125 {
				return nil, fmt.Errorf("wifi: frequency %d MHz outside 2.4/5/6 GHz", f)
			}
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("wifi: no frequencies")
	}
	slices.Sort(out)
	return out, nil
}

// ParseChannels parses "1,6,11" or "1-6,36-48" into channel numbers.
func ParseChannels(s string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi := part, part
		if a, b, ok := strings.Cut(part, "-"); ok {
			lo, hi = strings.TrimSpace(a), strings.TrimSpace(b)
		}
		l, err := strconv.Atoi(lo)
		if err != nil {
			return nil, fmt.Errorf("wifi: channel %q", part)
		}
		r, err := strconv.Atoi(hi)
		if err != nil {
			return nil, fmt.Errorf("wifi: channel %q", part)
		}
		if l < 1 || r > 233 || l > r {
			return nil, fmt.Errorf("wifi: channel range %q", part)
		}
		for ch := l; ch <= r; ch++ {
			if !seen[ch] {
				seen[ch] = true
				out = append(out, ch)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("wifi: no channels")
	}
	return out, nil
}
