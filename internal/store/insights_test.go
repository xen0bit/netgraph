package store

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/testutil"
	"github.com/xen0bit/netgraph/internal/wire"
)

func TestInsights(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	exp, err := st.Exposure(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if exp.FromMS == 0 || exp.Findings == nil {
		t.Fatalf("exposure = %+v", exp)
	}
	cov, err := st.Coverage(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(cov.Sensors) == 0 {
		t.Fatalf("coverage = %+v", cov)
	}
	air, err := st.Airspace(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if air.Networks == nil {
		t.Fatalf("airspace = %+v", air)
	}
	w, err := st.Weather(ctx, win(0, time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Points) == 0 || w.StepMS == 0 {
		t.Fatalf("weather = %+v", w)
	}
}

// wifiInsights holds one protected network with an open twin, one new access
// point on it, a WEP network, a WPA network, and a radio known only through
// its clients.
func wifiInsights(t *testing.T) (*Store, model.Filter) {
	t.Helper()
	ctx := context.Background()
	at := testutil.Base.Add(30 * 24 * time.Hour)
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return at.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	beacon := func(seq uint64, ts time.Time, bssid, ssid, sec string) wire.Event {
		return wire.Event{Seq: seq, Type: wire.TypeWiFi, TS: ts, WiFi: &wire.WiFi{Kind: "beacon", BSSID: bssid, SSID: ssid, Channel: 6, Security: sec}}
	}
	if _, err := st.Ingest(ctx, "mon", "boot", []wire.Event{
		beacon(1, at, "aa:bb:cc:00:00:01", "home", "wpa2"),
		beacon(2, at.Add(time.Minute), "aa:bb:cc:00:00:02", "home", "open"),
		beacon(3, at, "aa:bb:cc:00:00:03", "old", "wep"),
		beacon(4, at, "aa:bb:cc:00:00:04", "older", "wpa"),
		beacon(5, at, "aa:bb:cc:00:00:05", "modern", "wpa3"),
		{Seq: 6, Type: wire.TypeWiFi, TS: at, WiFi: &wire.WiFi{Kind: "association_request", BSSID: "aa:bb:cc:00:00:06", Client: "3c:22:fb:01:02:03"}},
		{Seq: 7, Type: wire.TypeWiFi, TS: at, WiFi: &wire.WiFi{Kind: "association_request", BSSID: "aa:bb:cc:00:00:01", Client: "3c:22:fb:01:02:03", SSID: "home"}},
	}); err != nil {
		t.Fatal(err)
	}
	return st, model.Filter{From: at.Add(-time.Hour), To: at.Add(time.Hour)}
}

func TestExposureWeakWiFi(t *testing.T) {
	st, f := wifiInsights(t)
	rep, err := st.Exposure(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, x := range rep.Findings {
		if x.Kind == "wifi_weak_security" {
			got[x.Label] = x.Severity
		}
	}
	want := map[string]string{"home": model.SeverityHigh, "old": model.SeverityHigh, "older": model.SeverityMedium}
	if len(got) != len(want) {
		t.Fatalf("weak networks = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
}

func TestAirspaceRogueIsTheRightRadio(t *testing.T) {
	st, f := wifiInsights(t)
	rep, err := st.Airspace(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Networks) < 5 {
		t.Fatalf("networks = %+v", rep.Networks)
	}
	for _, n := range rep.Networks {
		// Only the open twin. The real AP shares its name, and a radio with
		// no name "contains" in every summary.
		if want := n.BSSID == "aa:bb:cc:00:00:02"; n.Rogue != want {
			t.Errorf("%s (%q %s) rogue = %v", n.BSSID, n.SSID, n.Security, n.Rogue)
		}
		if n.BSSID == "aa:bb:cc:00:00:01" && len(n.Clients) != 1 {
			t.Errorf("clients = %v", n.Clients)
		}
	}
}

func TestWeatherUsesTheStepItGot(t *testing.T) {
	st, _, _ := homeStore(t)
	ctx := context.Background()
	// Old enough to be answered from hourly rollups, whatever was asked for.
	st.cfg.Now = func() time.Time { return testutil.Base.Add(30 * 24 * time.Hour) }
	if _, err := st.Retain(ctx); err != nil {
		t.Fatal(err)
	}
	w, err := st.Weather(ctx, win(-12*time.Hour, 12*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if w.StepMS < time.Hour.Milliseconds() {
		t.Errorf("step = %d on hourly data", w.StepMS)
	}
	var forecast []model.WeatherPoint
	for i, p := range w.Points {
		if p.Forecast {
			forecast = append(forecast, p)
			if i > 0 && p.TS != w.Points[i-1].TS+w.StepMS {
				t.Errorf("point %d is not one step on: %+v", i, p)
			}
		}
	}
	if len(forecast) != 6 {
		t.Fatalf("forecast = %+v", forecast)
	}
	if forecast[0].Upper == 0 || forecast[0].Lower > forecast[0].Upper {
		t.Errorf("band = %+v", forecast[0])
	}
}

// The forecast knows that evenings are busy: a moving mean over a quiet morning
// would predict a quiet evening.
func TestWeatherFollowsTheHourOfTheWeek(t *testing.T) {
	hour := time.Hour.Milliseconds()
	// A Sunday, 18:00 UTC, on an hour boundary.
	now := time.Date(2026, 10, 25, 18, 0, 0, 0, time.UTC)
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	end := now.UnixMilli()
	// Three weeks: 1 MB an hour from 18:00 to 23:00, 1 kB otherwise.
	for b := end - 3*7*24*hour; b < end; b += hour {
		bytes := int64(1000)
		if h := time.UnixMilli(b).UTC().Hour(); h >= 18 {
			bytes = 1_000_000
		}
		if _, err := st.w.ExecContext(ctx, `INSERT INTO traffic_hourly (bucket, flow_key, client_device, client_ip, remote_ip, remote_port, proto, name, direction, app, multicast, flows, bytes_out, bytes_in)
			VALUES (?, 'k', 1, '10.0.0.1', '1.1.1.1', 443, 6, '', 'out', '', 0, 1, ?, 0)`, b, bytes); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := st.Weather(ctx, model.Filter{From: now.Add(-6 * time.Hour), To: now})
	if err != nil {
		t.Fatal(err)
	}
	var forecast int
	for _, p := range rep.Points {
		if !p.Forecast {
			continue
		}
		forecast++
		hourly := float64(p.Upper) / (float64(rep.StepMS) / float64(hour))
		if hourly < 500_000 || hourly > 2_000_000 {
			t.Errorf("forecast at %s: %.0f an hour, want about 1 MB", time.UnixMilli(p.TS).UTC(), hourly)
		}
	}
	if forecast != 6 {
		t.Errorf("%d forecast points", forecast)
	}
	if !slices.ContainsFunc(rep.Gaps, func(g string) bool { return strings.Contains(g, "usual traffic") }) {
		t.Errorf("gaps: %v", rep.Gaps)
	}
}
