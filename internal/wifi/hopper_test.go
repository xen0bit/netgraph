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

func TestParseFrequencies(t *testing.T) {
	got, err := ParseFrequencies("5955, 5975, 6115-6125")
	want := append([]int{5955, 5975}, []int{6115, 6116, 6117, 6118, 6119, 6120, 6121, 6122, 6123, 6124, 6125}...)
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("frequencies = %v %v", got, err)
	}
	for _, bad := range []string{"", "x", "1000", "7125-7130", "5975-5955"} {
		if _, err := ParseFrequencies(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestHopperVisitsFrequencies(t *testing.T) {
	var mu sync.Mutex
	var seen []int
	h := &Hopper{
		Frequencies: []int{2412, 5955, 6115},
		Dwell:       5 * time.Millisecond,
		SetFrequency: func(mhz int) error {
			mu.Lock()
			seen = append(seen, mhz)
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
	for _, mhz := range []int{2412, 5955, 6115} {
		if !slices.Contains(seen, mhz) {
			t.Errorf("never visited %d MHz: %v", mhz, seen)
		}
	}
}

func TestSixGHzPlan(t *testing.T) {
	f := SixGHzFrequencies()
	if len(f) != 59 || f[0] != 5955 || f[len(f)-1] != 7115 {
		t.Fatalf("6GHz plan = %v", f)
	}
	if FrequencyForChannel6GHz(1) != 5955 || FrequencyForChannel6GHz(233) != 7115 {
		t.Fatal("channel-to-frequency mapping")
	}
}

func TestSetFrequencyRejectsBadInput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux ioctl")
	}
	if err := SetFrequency("", 5955); err == nil {
		t.Error("accepted an empty interface")
	}
	if err := SetFrequency("lo", 1000); err == nil {
		t.Error("accepted an out-of-band frequency")
	}
}
