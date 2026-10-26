package wifi

import (
	"context"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestParseChannels(t *testing.T) {
	got, err := ParseChannels("1, 6,11")
	if err != nil || !slices.Equal(got, []int{1, 6, 11}) {
		t.Fatalf("channels = %v %v", got, err)
	}
	got, err = ParseChannels("36-40,1,40")
	if err != nil || !slices.Equal(got, []int{36, 37, 38, 39, 40, 1}) {
		t.Fatalf("ranges = %v %v", got, err)
	}
	for _, bad := range []string{"", "x", "0", "40-36", "1-300"} {
		if _, err := ParseChannels(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestHopperVisitsChannels(t *testing.T) {
	var mu sync.Mutex
	var seen []int
	h := &Hopper{
		Channels: []int{1, 6, 11},
		Dwell:    5 * time.Millisecond,
		Set: func(ch int) error {
			mu.Lock()
			seen = append(seen, ch)
			mu.Unlock()
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := h.Run(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, ch := range []int{1, 6, 11} {
		if !slices.Contains(seen, ch) {
			t.Errorf("never visited channel %d: %v", ch, seen)
		}
	}
	if len(seen) < 6 {
		t.Errorf("hopper ran only %d times", len(seen))
	}
}

func TestSetChannelRejectsBadInput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux ioctl")
	}
	if err := SetChannel("", 1); err == nil {
		t.Error("accepted an empty interface")
	}
	if err := SetChannel("this-name-is-too-long", 1); err == nil {
		t.Error("accepted an over-long interface name")
	}
	if err := SetChannel("lo", 0); err == nil {
		t.Error("accepted channel 0")
	}
}

func TestDefaultChannels(t *testing.T) {
	ch := DefaultChannels()
	if !slices.Contains(ch, 1) || !slices.Contains(ch, 36) || !slices.Contains(ch, 165) {
		t.Errorf("defaults = %v", ch)
	}
}
