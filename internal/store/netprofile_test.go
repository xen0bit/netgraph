package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/xen0bit/netgraph/internal/model"
	"github.com/xen0bit/netgraph/internal/wire"
)

func TestProfileTrigger(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	home, err := st.SaveProfile(ctx, &model.Profile{Name: "home", Mode: "alert", IsDefault: true})
	if err != nil {
		t.Fatal(err)
	}
	cafe, err := st.SaveProfile(ctx, &model.Profile{Name: "cafe", Mode: "silent-deny"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveNetworkTrigger(ctx, &model.NetworkTrigger{
		ProfileID: cafe.ID, Signature: "*", Action: "activate", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	p, err := st.EvaluateProfile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p == nil || p.ID != cafe.ID || !p.Active {
		t.Fatalf("evaluated = %+v", p)
	}
	active, err := st.ActiveProfile(ctx)
	if err != nil || active == nil || active.Name != "cafe" {
		t.Fatalf("active = %+v, %v", active, err)
	}
	if home.ID == cafe.ID {
		t.Fatal("profiles share an ID")
	}
	nc, err := st.NetworkContext(ctx)
	if err != nil || nc == nil || nc.Signature == "" {
		t.Fatalf("network context = %+v, %v", nc, err)
	}
}

// The network is the sensor's own: a neighbour's beacon doesn't change it,
// the sensor's own SSID does, and a profile picked by hand stays until the
// network changes.
func TestProfileTriggerFollowsTheSensorsNetwork(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "ng.db"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	home, err := st.SaveProfile(ctx, &model.Profile{Name: "home"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := st.SaveProfile(ctx, &model.Profile{Name: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveNetworkTrigger(ctx, &model.NetworkTrigger{ProfileID: home.ID, Signature: `*"ssid":"Home-Net"*`, Action: "activate", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveNetworkTrigger(ctx, &model.NetworkTrigger{ProfileID: 999, Signature: "*", Enabled: true}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("trigger for a missing profile = %v", err)
	}
	at := time.Now()
	ingest := func(seq uint64, ev wire.Event) {
		t.Helper()
		ev.Seq, ev.TS = seq, at
		if _, err := st.Ingest(ctx, "router", "b1", []wire.Event{ev}); err != nil {
			t.Fatal(err)
		}
	}
	ingest(1, wire.Event{Type: wire.TypeHello, Hello: &wire.Hello{Name: "router", Interfaces: []wire.Interface{{Name: "br-lan", MAC: "02:00:00:00:00:01"}}}})
	ingest(2, wire.Event{Type: wire.TypeWiFi, WiFi: &wire.WiFi{Kind: "beacon", BSSID: "aa:bb:cc:00:00:09", SSID: "Home-Net", Channel: 6}})
	if p, _ := st.ActiveProfile(ctx); p != nil {
		t.Fatalf("a neighbour's beacon activated %+v", p)
	}
	ingest(3, wire.Event{Type: wire.TypeWiFi, WiFi: &wire.WiFi{Kind: "beacon", BSSID: "02:00:00:00:00:01", SSID: "Home-Net", Channel: 6}})
	if p, _ := st.ActiveProfile(ctx); p == nil || p.ID != home.ID {
		t.Fatalf("the sensor's own SSID didn't activate home: %+v", p)
	}
	if err := st.ActivateProfile(ctx, other.ID); err != nil {
		t.Fatal(err)
	}
	ingest(4, wire.Event{Type: wire.TypeWiFi, WiFi: &wire.WiFi{Kind: "beacon", BSSID: "02:00:00:00:00:01", SSID: "Home-Net", Channel: 6}})
	if p, _ := st.ActiveProfile(ctx); p == nil || p.ID != other.ID {
		t.Fatalf("the same network undid a choice made by hand: %+v", p)
	}
}
