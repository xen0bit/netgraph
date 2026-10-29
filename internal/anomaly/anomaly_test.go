package anomaly

import (
	"math/rand/v2"
	"testing"
)

func every(n int, period, jitter int64, r *rand.Rand) []int64 {
	var out []int64
	t := int64(1_000_000)
	for range n {
		out = append(out, t)
		t += period
		if jitter > 0 {
			t += r.Int64N(2*jitter) - jitter
		}
	}
	return out
}

func TestBeacon(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	if p, ok := Beacon(every(12, 60_000, 0, r)); !ok || p.Period != 60_000 || p.Events != 12 {
		t.Errorf("exact minute: %+v %v", p, ok)
	}
	if p, ok := Beacon(every(20, 30_000, 1_500, r)); !ok || p.Jitter > BeaconMaxJitter {
		t.Errorf("30s ±5%%: %+v %v", p, ok)
	}
	// Each beat opens three connections at once: still one event each.
	var bursty []int64
	for _, s := range every(10, 120_000, 0, r) {
		bursty = append(bursty, s, s+40, s+300)
	}
	if p, ok := Beacon(bursty); !ok || p.Events != 10 {
		t.Errorf("bursts: %+v %v", p, ok)
	}

	if _, ok := Beacon(every(6, 60_000, 0, r)); ok {
		t.Error("6 events called a beacon")
	}
	if _, ok := Beacon(every(30, 5_000, 0, r)); ok {
		t.Error("a 5s period called a beacon")
	}
	if p, ok := Beacon(every(30, 60_000, 30_000, r)); ok {
		t.Errorf("±50%% jitter called a beacon: %+v", p)
	}
	// A person browsing: irregular gaps.
	if _, ok := Beacon([]int64{0, 12_000, 95_000, 101_000, 260_000, 300_000, 480_000, 482_000, 700_000, 905_000}); ok {
		t.Error("browsing called a beacon")
	}
}

func TestSurge(t *testing.T) {
	week := make([]float64, 48)
	for i := range week {
		week[i] = float64(100 + 10*i) // 100 .. 570 connections an hour
	}
	for _, c := range []struct {
		rate        float64
		hours       []float64
		surge, high bool
	}{
		{900, week, false, false},        // under the floor
		{2000, week, false, false},       // over the floor, under 4x the peak
		{2400, week, true, false},        // 4x the peak
		{6000, week, true, false},        // 10x the peak, under the high floor
		{60000, week, true, true},        // both
		{60000, week[:10], false, false}, // too little history
	} {
		surge, high, _ := Surge(c.rate, c.hours)
		if surge != c.surge || high != c.high {
			t.Errorf("Surge(%v, %d hours) = %v %v, want %v %v", c.rate, len(c.hours), surge, high, c.surge, c.high)
		}
	}
}

func TestSpike(t *testing.T) {
	week := make([]float64, 48)
	for i := range week {
		week[i] = float64(2<<20 + i<<18) // 2 MB .. 14 MB an hour
	}
	if spike, _, _, _ := Spike(10<<20, week); spike {
		t.Error("an ordinary hour is a spike")
	}
	if spike, _, _, _ := Spike(15<<20, week); spike {
		t.Error("over the peak but under the absolute floor")
	}
	if spike, high, _, peak := Spike(60<<20, week); !spike || high || peak != week[47] {
		t.Errorf("60 MB/h: spike=%v high=%v", spike, high)
	}
	if spike, high, _, _ := Spike(500<<20, week); !spike || !high {
		t.Errorf("500 MB/h: spike=%v high=%v", spike, high)
	}
	if spike, _, _, _ := Spike(500<<20, week[:10]); spike {
		t.Error("judged with too little history")
	}
}

func TestLocalName(t *testing.T) {
	for name, want := range map[string]bool{
		"wpad": true, "printer.local": true, "1.8.168.192.in-addr.arpa": true, "nas.lan": true,
		"www.example.com": false, "xj3k2q.example.net": false,
	} {
		if LocalName(name) != want {
			t.Errorf("LocalName(%q) = %v", name, !want)
		}
	}
}
