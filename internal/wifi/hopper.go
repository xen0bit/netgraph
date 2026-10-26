package wifi

import (
	"context"
	"fmt"
	"log/slog"
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
	Dwell     time.Duration // default 250ms
	// Set overrides the platform ioctl, for tests.
	Set    func(channel int) error
	Logger *slog.Logger
}

// Run hops until ctx is cancelled. A failure to set one channel is logged
// and the hopper moves on: a missing channel is not a reason to stop
// capturing the others.
func (h *Hopper) Run(ctx context.Context) error {
	if len(h.Channels) == 0 {
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
	for {
		for _, ch := range h.Channels {
			if err := ctx.Err(); err != nil {
				return nil
			}
			if err := set(ch); err != nil {
				h.Logger.Warn("set wifi channel", "iface", h.Interface, "channel", ch, "err", err)
			} else {
				h.Logger.Debug("wifi channel", "iface", h.Interface, "channel", ch)
			}
			t := time.NewTimer(h.Dwell)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil
			case <-t.C:
			}
		}
	}
}

// DefaultChannels is a conservative scan list: 2.4 GHz channels 1-13 and
// the common non-DFS 5 GHz channels. Drivers that reject a channel simply
// log it and move on.
func DefaultChannels() []int {
	return []int{1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161, 165}
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
